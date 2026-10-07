//! One synthetic near-capacity correctness input; no load or throughput claim.
//! Retains the native-agreed suffix and its development-only signed envelopes.
use alephium_l2_transition_core::{
    MAX_CHECKPOINT_WIRE_BYTES, MAX_CONTINUATION_CHECKPOINT_BYTES, ProofInput, decode_input,
    encode_checkpoint_transition,
    protocol::checkpoint::{CheckpointAccount, CheckpointCode, ExecutionCheckpoint},
    prove_checkpoint_transition,
};
use alloy_primitives::{Address, B256, U256, keccak256};
use sha2::{Digest, Sha256};
use std::{fs, io::Write, path::Path};

const HASH_WINDOW_RESERVE: usize = 256 * 40;
const MAX_CODE_BYTES: usize = 24_576;
const ACCOUNT_CODE_OVERHEAD: usize = 105 + 36;

fn main() -> Result<(), String> {
    let target_checkpoint_bytes = checkpoint_target()?;
    let source = std::env::var_os("L2_CHECKPOINT_BOUNDARY_INPUT")
        .ok_or("Set L2_CHECKPOINT_BOUNDARY_INPUT to the existing binary suffix export")?;
    let output = std::env::var_os("L2_CHECKPOINT_BOUNDARY_OUTPUT")
        .ok_or("Set L2_CHECKPOINT_BOUNDARY_OUTPUT to a fresh private directory")?;
    if fs::metadata(&source).map_err(io_error)?.len() > MAX_CHECKPOINT_WIRE_BYTES as u64 {
        return Err("Baseline input exceeds its binary bound".into());
    }
    let bytes = fs::read(source).map_err(io_error)?;
    let ProofInput::Checkpoint(mut input) = decode_input(&bytes).map_err(str::to_owned)? else {
        return Err("Boundary example requires a schema-three checkpoint suffix".into());
    };
    let baseline = prove_checkpoint_transition(&input)?;
    if logical_digest(&input.checkpoint)? != baseline.journal.before_state_digest
        || logical_digest(&baseline.checkpoint)? != baseline.journal.after_state_digest
    {
        return Err("Independent digest differs from the native-agreed baseline".into());
    }
    let mut expected = baseline.checkpoint.clone();
    let baseline_input_bytes = input.checkpoint.encode()?.len();
    let baseline_output_bytes = expected.encode()?.len();
    let mut remaining = target_checkpoint_bytes
        .checked_sub(HASH_WINDOW_RESERVE)
        .and_then(|size| size.checked_sub(baseline_input_bytes.max(baseline_output_bytes)))
        .ok_or("Baseline leaves no synthetic checkpoint capacity")?;
    let mut count = 0u32;
    while remaining >= ACCOUNT_CODE_OVERHEAD + 4 {
        count = count
            .checked_add(1)
            .ok_or("Synthetic account count overflow")?;
        let length = MAX_CODE_BYTES.min(remaining - ACCOUNT_CODE_OVERHEAD);
        let (account, code) = synthetic_account(count, length);
        for checkpoint in [&mut input.checkpoint, &mut expected] {
            if checkpoint
                .accounts
                .iter()
                .any(|item| item.address == account.address)
                || checkpoint.codes.iter().any(|item| item.hash == code.hash)
            {
                return Err("Synthetic account/code collides with the retained baseline".into());
            }
            checkpoint.accounts.push(account.clone());
            checkpoint.codes.push(code.clone());
        }
        remaining -= ACCOUNT_CODE_OVERHEAD + length;
    }
    for checkpoint in [&mut input.checkpoint, &mut expected] {
        checkpoint.accounts.sort_by_key(|account| account.address);
        checkpoint.codes.sort_by_key(|code| code.hash);
        checkpoint.validate()?;
    }
    let input_checkpoint_bytes = input.checkpoint.encode()?.len();
    let output_checkpoint_bytes = expected.encode()?.len();
    if count == 0
        || input_checkpoint_bytes.max(output_checkpoint_bytes) + HASH_WINDOW_RESERVE
            > target_checkpoint_bytes
        || input_checkpoint_bytes.max(output_checkpoint_bytes)
            < target_checkpoint_bytes - HASH_WINDOW_RESERVE - ACCOUNT_CODE_OVERHEAD - 4
    {
        return Err("Synthetic fixture does not fit its intended near-capacity profile".into());
    }
    input.expected_state_digest = logical_digest(&expected)?;
    let native = prove_checkpoint_transition(&input)?;
    if native.checkpoint != expected
        || native.journal.transactions_commitment != baseline.journal.transactions_commitment
        || native.journal.context_commitment != baseline.journal.context_commitment
        || native.journal.receipts_commitment != baseline.journal.receipts_commitment
        || native.journal.before_total_balance != baseline.journal.before_total_balance
        || native.journal.after_total_balance != baseline.journal.after_total_balance
        || native.journal.before_account_count != baseline.journal.before_account_count + count
        || native.journal.after_account_count != baseline.journal.after_account_count + count
        || native.journal.old_state_root == baseline.journal.old_state_root
    {
        return Err("Synthetic dormant state changes the retained execution or accounting".into());
    }
    let private_input = encode_checkpoint_transition(&input)?;
    let ProofInput::Checkpoint(roundtrip) = decode_input(&private_input).map_err(str::to_owned)?
    else {
        return Err("Encoded boundary input lost its checkpoint schema".into());
    };
    if encode_checkpoint_transition(&roundtrip)? != private_input {
        return Err("Boundary input is not a canonical binary roundtrip".into());
    }
    let journal = native.journal.encode()?;
    // A declared checkpoint frame above the fixed profile is rejected before
    // allocation, including when this correctness fixture selects a lower target.
    let mut oversized = private_input.clone();
    let checkpoint_frame_offset = b"ALEPHIUM-L2/TRANSITION/WIRE/V3\0".len()
        + 4
        + 4
        + input.rpc_profile.len()
        + 4
        + input.execution_engine.len()
        + 65;
    oversized[checkpoint_frame_offset..checkpoint_frame_offset + 4]
        .copy_from_slice(&((MAX_CONTINUATION_CHECKPOINT_BYTES + 1) as u32).to_be_bytes());
    if decode_input(&oversized).is_ok() {
        return Err("Oversized continuation checkpoint frame was not rejected".into());
    }
    let report = serde_json::json!({
        "status": "native-boundary-fixture-prepared",
        "scope": "synthetic-unsettled-checkpoint/execution-only-resource-qualification",
        "initial_checkpoint_structurally_synthetic": true,
        "initial_checkpoint_canonically_settled": false,
        "reachable_state_proven_by_this_example": false,
        "guest_execution_performed_by_this_example": false,
        "guest_receipt_generated_by_this_example": false,
        "settlement_verified": false,
        "chain_id": input.checkpoint.chain_id,
        "genesis_id": input.checkpoint.genesis_id,
        "parent_height": input.checkpoint.head.height,
        "head_height": input.head.height,
        "blocks": input.blocks.len(),
        "executed_transactions": native.journal.executed_transactions,
        "synthetic_accounts": count,
        "input_checkpoint_bytes": input_checkpoint_bytes,
        "output_checkpoint_bytes": output_checkpoint_bytes,
        "reserved_future_hash_bytes": HASH_WINDOW_RESERVE,
        "fixture_target_checkpoint_bytes": target_checkpoint_bytes,
        "checkpoint_profile_bound": MAX_CONTINUATION_CHECKPOINT_BYTES,
        "binary_input_bytes": private_input.len(),
        "binary_input_bound": MAX_CHECKPOINT_WIRE_BYTES,
        "binary_input_headroom_bytes": MAX_CHECKPOINT_WIRE_BYTES - private_input.len(),
        "input_sha256": hash(&private_input),
        "journal_sha256": hash(&journal),
        "journal_bytes": journal.len(),
        "old_state_root": native.journal.old_state_root,
        "new_state_root": native.journal.new_state_root,
        "da_commitment": native.journal.da_commitment,
        "independent_checkpoint_digest_agreement": true,
        "retained_execution_and_exact_balance_agreement": true,
        "binary_roundtrip_verified": true,
        "oversized_checkpoint_rejected": true,
        "oversized_checkpoint_rejection": "binary-frame-length-above-fixed-profile",
    });
    let output = Path::new(&output);
    create_private_directory(output)?;
    write_new(output.join("transition.bin").as_path(), &private_input)?;
    write_new(output.join("journal.bin").as_path(), &journal)?;
    write_new(
        output.join("journal.json").as_path(),
        &serde_json::to_vec_pretty(&native.journal)
            .map_err(|_| "Cannot encode safe native journal")?,
    )?;
    write_new(
        output.join("report.json").as_path(),
        &serde_json::to_vec_pretty(&report).map_err(|_| "Cannot encode safe boundary report")?,
    )?;
    println!(
        "{}",
        serde_json::to_string(&report).map_err(|_| "Cannot encode safe report")?
    );
    Ok(())
}

fn checkpoint_target() -> Result<usize, String> {
    match std::env::var("L2_CHECKPOINT_BOUNDARY_BYTES") {
        Err(std::env::VarError::NotPresent) => Ok(MAX_CONTINUATION_CHECKPOINT_BYTES),
        Ok(value) if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) => value
            .parse::<usize>()
            .ok()
            .filter(|bytes| {
                *bytes > HASH_WINDOW_RESERVE + ACCOUNT_CODE_OVERHEAD + 4
                    && *bytes <= MAX_CONTINUATION_CHECKPOINT_BYTES
            })
            .ok_or_else(|| "Boundary byte target is outside the fixed checkpoint profile".into()),
        _ => Err("Boundary byte target must contain only decimal ASCII digits".into()),
    }
}

fn synthetic_account(index: u32, bytes: usize) -> (CheckpointAccount, CheckpointCode) {
    let mut address = [0xff; 20];
    address[16..].copy_from_slice(&index.to_be_bytes());
    // STOP-prefixed dormant code; a distinct suffix makes each exact code hash unique.
    let mut code = vec![0; bytes];
    code[bytes - 4..].copy_from_slice(&index.to_be_bytes());
    let code_hash = keccak256(&code);
    (
        CheckpointAccount {
            address: Address::from(address),
            balance: U256::ZERO,
            nonce: 1,
            code_hash,
            storage_epoch: 0,
            deleted: false,
            slots: Vec::new(),
        },
        CheckpointCode {
            hash: code_hash,
            bytes: code,
        },
    )
}

/// Independent canonical logical-state digest over the validated checkpoint.
/// The unchanged suffix's expected final checkpoint comes from native agreement;
/// the added dormant accounts affect this digest but no executed state delta.
fn logical_digest(checkpoint: &ExecutionCheckpoint) -> Result<B256, String> {
    checkpoint.validate()?;
    let mut digest = Sha256::new();
    digest.update(b"alephium-l2-development/logical-state/v1");
    digest.update(
        (checkpoint
            .accounts
            .iter()
            .filter(|account| !account.deleted)
            .count() as u64)
            .to_be_bytes(),
    );
    for account in checkpoint
        .accounts
        .iter()
        .filter(|account| !account.deleted)
    {
        digest.update(account.address);
        digest.update(account.balance.to_be_bytes::<32>());
        digest.update(account.nonce.to_be_bytes());
        digest.update(account.code_hash);
        digest.update((account.slots.len() as u64).to_be_bytes());
        for slot in &account.slots {
            digest.update(slot.key.to_be_bytes::<32>());
            digest.update(slot.value.to_be_bytes::<32>());
        }
    }
    digest.update((checkpoint.codes.len() as u64).to_be_bytes());
    for code in &checkpoint.codes {
        digest.update(code.hash);
        digest.update((code.bytes.len() as u64).to_be_bytes());
        digest.update(&code.bytes);
    }
    Ok(B256::from_slice(&digest.finalize()))
}

fn hash(bytes: &[u8]) -> B256 {
    B256::from_slice(&Sha256::digest(bytes))
}

fn create_private_directory(path: &Path) -> Result<(), String> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(io_error)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(io_error)?;
    file.write_all(bytes).map_err(io_error)?;
    file.sync_all().map_err(io_error)
}

fn io_error(error: std::io::Error) -> String {
    format!("Boundary fixture I/O failed: {error}")
}
