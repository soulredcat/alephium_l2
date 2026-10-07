use super::{backup::materialize_backup, files, types::ReplayReport};
use crate::protocol::checkpoint::ExecutionCheckpoint;
use crate::{
    execution,
    protocol::{BlockCommit, Genesis, Head, Pending, ReplayBlock},
    storage::{ReadView, Store},
};
use alloy_primitives::B256;
use std::path::Path;

// An offline development profile, not a partial checkpoint or production SLA.
pub(super) const MAX_REPLAY_BLOCKS: u64 = 10_000;

/// Reexecute committed signed inputs from genesis into a separate fresh store.
/// This uses the same pinned REVM as the producer, not a second EVM implementation.
/// Rejected intent metadata is preserved: its original admission/execution
/// interleaving is absent, so rejection policy is not independently reevaluated.
/// The immutable backup is verified/copied before opening only its working copy.
pub fn verify_replay(
    backup: &Path,
    genesis: &Genesis,
    work_dir: &Path,
) -> Result<ReplayReport, String> {
    Ok(replay_with_checkpoint(backup, genesis, work_dir, None)?.0)
}

/// Capture the actual replay state at a boundary, before later commits exist.
pub(super) fn verify_replay_at(
    backup: &Path,
    genesis: &Genesis,
    work_dir: &Path,
    height: u64,
) -> Result<(ReplayReport, ExecutionCheckpoint), String> {
    let (report, checkpoint) = replay_with_checkpoint(backup, genesis, work_dir, Some(height))?;
    Ok((
        report,
        checkpoint.ok_or("Requested replay checkpoint was not captured")?,
    ))
}

fn replay_with_checkpoint(
    backup: &Path,
    genesis: &Genesis,
    work_dir: &Path,
    checkpoint_height: Option<u64>,
) -> Result<(ReplayReport, Option<ExecutionCheckpoint>), String> {
    genesis.validate()?;
    // Reject another execution profile before creating any working directories
    // or opening Fjall. The immutable backup remains owned by its old runtime.
    files::owned_directory(&backup.join("data"))?;
    let work_dir = files::fresh_directory(work_dir, backup)?;
    let source_path = work_dir.join("source");
    let manifest = materialize_backup(backup, &source_path)?;
    if manifest.chain_id != genesis.chain_id
        || manifest.head.height > MAX_REPLAY_BLOCKS
        || checkpoint_height.is_some_and(|height| height > manifest.head.height)
    {
        return Err("Backup identity or height exceeds the offline replay profile".into());
    }
    let source = Store::open_existing(&source_path, genesis)?;
    let source_view = source.view()?;
    let pending = source.pending()?;
    if source_view.head != manifest.head
        || source_view.state_digest()? != manifest.state_digest
        || pending.len() != manifest.pending_count
    {
        return Err("Backup manifest differs from its recovered working copy".into());
    }
    validate_pending(&source_view, &pending)?;

    let target_path = work_dir.join("replayed");
    let mut target = Store::open(&target_path, genesis)?;
    let genesis_head = source_view.block(0)?.ok_or("Missing source genesis")?.head;
    if target.view()?.head != genesis_head {
        return Err("Replay genesis identity mismatch".into());
    }
    let mut checkpoint = if checkpoint_height == Some(0) {
        Some(target.view()?.execution_checkpoint()?)
    } else {
        None
    };
    let mut executed_transactions = 0_u64;
    let mut rejected_intents = 0_u64;
    for height in 1..=manifest.head.height {
        let expected = source_view
            .replay_block(height)?
            .ok_or("Missing retained replay block")?;
        replay_block(&source_view, &mut target, &expected)?;
        if checkpoint_height == Some(height) {
            checkpoint = Some(target.view()?.execution_checkpoint()?);
        }
        executed_transactions = add_count(executed_transactions, expected.transactions.len())?;
        rejected_intents = add_count(rejected_intents, expected.rejected.len())?;
    }
    // Intents the producer rejected outside any block are local outcomes, not
    // block inputs. Recreate them so admission counts and statuses still match.
    let discarded = source.discarded()?;
    for (hash, reason) in &discarded {
        admit(&mut target, load_intent(&source_view, *hash)?)?;
        let status = target.discard(*hash, reason)?;
        if Some(status) != source_view.status(*hash)? {
            return Err("Replayed discarded intent status differs".into());
        }
    }
    let discarded_intents = add_count(0, discarded.len())?;
    let admitted_count = add_count(
        executed_transactions
            .checked_add(rejected_intents)
            .and_then(|count| count.checked_add(discarded_intents))
            .ok_or("Replay count overflow")?,
        pending.len(),
    )?;
    if source_view.pending_counter()? != admitted_count {
        return Err("Source admission counter differs from retained intent count".into());
    }

    // Restore unresolved intents after execution. Admission ordinals may differ
    // because original interleaving is unavailable; queue order and identity must not.
    admit_group(&mut target, &pending)?;
    verify_result(
        &source_view,
        &target,
        &pending,
        &manifest.head,
        manifest.state_digest,
    )?;
    drop(target);

    // Restart validation checks all authoritative records, pending order bounds
    // and retained commit identity. No result is accepted before this succeeds.
    let target = Store::open_existing(&target_path, genesis)?;
    verify_result(
        &source_view,
        &target,
        &pending,
        &manifest.head,
        manifest.state_digest,
    )?;
    Ok((
        ReplayReport {
            head: manifest.head,
            state_digest: manifest.state_digest,
            blocks: source_view.head.height,
            executed_transactions,
            discarded_intents,
            rejected_intents,
            pending_count: pending.len(),
            rejected_policy_revalidated: false,
            execution_engine: "REVM 43.0.3/Cancun (same library as producer)".into(),
        },
        checkpoint,
    ))
}

fn replay_block(
    source: &ReadView,
    target: &mut Store,
    expected: &ReplayBlock,
) -> Result<(), String> {
    if target.view()?.head != expected.parent {
        return Err(format!(
            "Replay parent differs at height {}",
            expected.head.height
        ));
    }
    let mut inputs = Vec::with_capacity(expected.transactions.len());
    let count = expected
        .transactions
        .len()
        .checked_add(expected.rejected.len())
        .ok_or("Replay intent count overflow")?;
    if count > target.capacity().max_pending {
        return Err("Replay block intent count exceeds pinned profile".into());
    }
    let mut intents = Vec::with_capacity(count);
    for hash in &expected.transactions {
        let intent = load_intent(source, *hash)?;
        inputs.push(intent.raw.clone());
        intents.push(intent);
    }
    for (hash, _) in &expected.rejected {
        intents.push(load_intent(source, *hash)?);
    }
    // All signed identities are checked before this single existing SyncAll
    // group admission. Avoid rebuilding the pending queue once per envelope.
    admit_group(target, &intents)?;
    drop(intents);
    let result = execution::execute_block(target.view()?, &inputs, expected.context)?;
    if !result.rejected.is_empty() || result.receipts.len() != expected.receipts.len() {
        return Err(format!(
            "Reexecution unexpectedly rejects inputs at height {}",
            expected.head.height
        ));
    }
    for (actual, recorded) in result.receipts.iter().zip(&expected.receipts) {
        let mut normalized = actual.clone();
        normalized.block_hash = expected.head.commit_id;
        if normalized != *recorded {
            return Err(format!(
                "Reexecuted receipt differs at height {}",
                expected.head.height
            ));
        }
    }
    let actual = target.commit(BlockCommit {
        parent: expected.parent.clone(),
        context: expected.context,
        transactions: result.receipts.iter().map(|receipt| receipt.hash).collect(),
        changes: result.changes,
        receipts: result.receipts,
        rejected: expected.rejected.clone(),
    })?;
    if actual.head != expected.head {
        return Err(format!(
            "Reexecuted commit differs at height {}",
            expected.head.height
        ));
    }
    for recorded in &expected.receipts {
        if actual.receipt(recorded.hash)?.as_ref() != Some(recorded)
            || source.receipt(recorded.hash)?.as_ref() != Some(recorded)
            || actual.status(recorded.hash)? != source.status(recorded.hash)?
        {
            return Err("Replayed receipt or resolution identity differs".into());
        }
    }
    for (hash, _) in &expected.rejected {
        if actual.status(*hash)? != source.status(*hash)? || actual.receipt(*hash)?.is_some() {
            return Err("Preserved rejection resolution differs".into());
        }
    }
    if !target.pending()?.is_empty() {
        return Err("Replayed block leaves an unresolved selected intent".into());
    }
    Ok(())
}

fn load_intent(source: &ReadView, hash: B256) -> Result<Pending, String> {
    let raw = source
        .raw_transaction(hash)?
        .ok_or("Missing retained signed envelope")?;
    let info = execution::inspect_for_chain(&raw, source.chain_id())
        .map_err(|_| "Invalid retained signed envelope")?;
    if info.hash != hash {
        return Err("Retained canonical transaction identity differs".into());
    }
    Ok(Pending {
        hash,
        sender: info.sender,
        raw,
    })
}

fn admit(target: &mut Store, intent: Pending) -> Result<(), String> {
    admit_group(target, std::slice::from_ref(&intent))
}

fn admit_group(target: &mut Store, intents: &[Pending]) -> Result<(), String> {
    let statuses = target.admit_batch(intents)?;
    if statuses.len() != intents.len() {
        return Err("Replay admission status count differs".into());
    }
    for (status, intent) in statuses.iter().zip(intents) {
        if status.hash != intent.hash
            || status.status != "durably_accepted"
            || status.block_height.is_some()
            || status.error.is_some()
        {
            return Err("Replay intent was previously resolved or admission order differs".into());
        }
    }
    Ok(())
}

fn validate_pending(view: &ReadView, pending: &[Pending]) -> Result<(), String> {
    let capacity = view.capacity();
    if pending.len() > capacity.max_pending {
        return Err("Replay pending queue exceeds profile".into());
    }
    for intent in pending {
        let inspected = load_intent(view, intent.hash)?;
        if inspected.sender != intent.sender || inspected.raw != intent.raw {
            return Err("Pending signed identity differs".into());
        }
        let info = execution::inspect_for_chain(&intent.raw, view.chain_id())
            .map_err(|_| "Invalid pending signed envelope")?;
        if info.gas_limit == 0 || info.gas_limit > capacity.block_gas {
            return Err("Pending gas limit exceeds the development profile".into());
        }
        view.pending_nonce(intent.sender)?;
    }
    Ok(())
}

fn verify_result(
    source: &ReadView,
    target: &Store,
    pending: &[Pending],
    expected_head: &Head,
    expected_digest: B256,
) -> Result<(), String> {
    let view = target.view()?;
    let actual_pending = target.pending()?;
    if view.head != *expected_head || view.state_digest()? != expected_digest {
        return Err("Complete replay head or logical state differs".into());
    }
    if actual_pending.len() != pending.len() {
        return Err("Replayed pending queue length differs".into());
    }
    if view.pending_counter()? != source.pending_counter()? {
        return Err("Replayed admission counter differs".into());
    }
    validate_pending(&view, &actual_pending)?;
    for (actual, original) in actual_pending.iter().zip(pending) {
        if actual.hash != original.hash
            || actual.sender != original.sender
            || actual.raw != original.raw
            || view.status(actual.hash)? != source.status(original.hash)?
            || view.account(actual.sender)? != source.account(original.sender)?
            || view.pending_nonce(actual.sender)? != source.pending_nonce(original.sender)?
        {
            return Err("Replayed pending order, identity or account view differs".into());
        }
    }
    Ok(())
}

fn add_count(total: u64, count: usize) -> Result<u64, String> {
    total
        .checked_add(u64::try_from(count).map_err(|_| "Replay count overflow")?)
        .ok_or_else(|| "Replay count overflow".into())
}
