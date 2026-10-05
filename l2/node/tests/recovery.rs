//! One bounded offline backup/replay flow over fresh development-only state.
#[path = "support/recovery_fixture.rs"]
mod fixture;

use alephium_l2_node::{
    development,
    operator::{self, BackupManifest},
    protocol::Pending,
    storage::Store,
};
use alloy_primitives::{Address, U256};
use fixture::{admit, commit, context, copy_tree, empty_existing_fixture, file_hashes, io_error};
use std::fs;

#[test]
fn offline_backup_replays_history_preserves_pending_and_rejects_tampering() -> Result<(), String> {
    let owned = tempfile::Builder::new()
        .prefix("l2-c4-recovery-")
        .tempdir()
        .map_err(io_error)?;
    let source = owned.path().join("source");
    let backup = owned.path().join("backup");
    let active_backup = owned.path().join("active-backup");
    let work = owned.path().join("verified");
    let genesis = development::genesis();
    let sender = development::address();
    let recipient = Address::from([0x44; 20]);
    let mut store = Store::open(&source, &genesis)?;

    let transfer = development::sign(0, Some(recipient), U256::from(1_000), vec![], 21_000)?;
    admit(&mut store, &transfer, 1)?;
    let mut receipts = commit(&mut store, &[transfer], 1)?;
    let deployment = development::sign_type2(
        1,
        None,
        U256::ZERO,
        development::contract_init(),
        300_000,
        10,
        3,
        Default::default(),
    )?;
    admit(&mut store, &deployment, 2)?;
    receipts.extend(commit(&mut store, &[deployment], 2)?);
    let contract = receipts[1].contract.ok_or("missing fixture deployment")?;
    let write = development::sign_type2(
        2,
        Some(contract),
        U256::ZERO,
        development::contract_input(1, None),
        100_000,
        10,
        5,
        Default::default(),
    )?;
    admit(&mut store, &write, 3)?;
    receipts.extend(commit(&mut store, &[write], 3)?);
    let revert = development::sign_type2(
        3,
        Some(contract),
        U256::from(77),
        development::contract_input(2, None),
        100_000,
        10,
        1,
        Default::default(),
    )?;
    admit(&mut store, &revert, 4)?;
    receipts.extend(commit(&mut store, &[revert], 4)?);
    assert!(receipts[..3].iter().all(|receipt| receipt.success));
    assert!(!receipts[3].success);
    assert!(receipts[3].logs.is_empty());
    assert_eq!(receipts[0].gas_used, 21_000);
    assert_eq!(receipts[2].logs.len(), 1);
    assert_eq!(
        receipts
            .iter()
            .map(|receipt| receipt.gas_price)
            .collect::<Vec<_>>(),
        vec![1, 3, 5, 1]
    );
    let fees: U256 = receipts
        .iter()
        .map(|receipt| U256::from(receipt.gas_used) * U256::from(receipt.gas_price))
        .sum();

    let committed = store.view()?;
    let head = committed.head.clone();
    let digest = committed.state_digest()?;
    assert_eq!(head.height, 4);
    assert_eq!(head.timestamp, context(4).timestamp);
    assert_eq!(committed.account(sender)?.ok_or("missing sender")?.nonce, 4);
    assert_eq!(
        committed.account(sender)?.ok_or("missing sender")?.balance,
        U256::from(development::INITIAL_BALANCE) - U256::from(1_000) - fees
    );
    assert_eq!(
        committed
            .account(recipient)?
            .ok_or("missing recipient")?
            .balance,
        U256::from(1_000)
    );
    assert_eq!(
        committed
            .account(Address::ZERO)?
            .ok_or("missing fee recipient")?
            .balance,
        fees
    );
    assert_eq!(
        committed
            .account(contract)?
            .ok_or("missing contract")?
            .balance,
        U256::ZERO
    );
    assert_eq!(committed.slot(contract, U256::ZERO)?, U256::from(42));
    let contract_hash = committed
        .account(contract)?
        .ok_or("missing contract")?
        .code_hash;
    assert!(committed.code(contract_hash)? == development::contract_runtime());
    drop(committed);

    let pending_raw = development::sign(4, Some(recipient), U256::from(11), vec![], 21_000)?;
    let pending_hash = admit(&mut store, &pending_raw, 5)?;
    let pinned = store.view()?;
    assert_eq!(pinned.head, head);
    assert_eq!(pinned.state_digest()?, digest);
    assert_eq!(pinned.pending_nonce(sender)?, 5);
    assert!(pinned.receipt(pending_hash)?.is_none());
    let active_error = match operator::backup(&source, &active_backup, &genesis) {
        Ok(_) => return Err("active source backup was accepted".into()),
        Err(error) => error,
    };
    assert_eq!(
        active_error,
        "Development database lock is held; stop its owned node before backup"
    );
    assert!(!active_backup.exists());
    drop(pinned);
    drop(store);

    let source_files = file_hashes(&source)?;
    let report = operator::backup(&source, &backup, &genesis)?;
    assert_eq!(report.head, head);
    assert_eq!(report.state_digest, digest);
    assert_eq!(report.pending_count, 1);
    assert!(report.file_count > 0 && report.bytes > 0);
    assert_eq!(file_hashes(&source)?, source_files);
    let backup_files = file_hashes(&backup)?;
    let manifest: BackupManifest =
        serde_json::from_slice(&fs::read(backup.join("manifest.json")).map_err(io_error)?)
            .map_err(|error| error.to_string())?;
    assert_eq!(manifest.schema, 1);
    assert_eq!(manifest.chain_id, genesis.chain_id);
    assert_eq!(manifest.head, head);
    assert_eq!(manifest.state_digest, digest);
    assert_eq!(manifest.pending_count, 1);
    assert_eq!(report.file_count, manifest.files.len());
    assert_eq!(
        report.bytes,
        manifest.files.iter().map(|entry| entry.length).sum::<u64>()
    );

    let replay = operator::verify_replay(&backup, &genesis, &work)?;
    assert_eq!(replay.head, head);
    assert_eq!(replay.state_digest, digest);
    assert_eq!(replay.blocks, 4);
    assert_eq!(replay.executed_transactions, 4);
    assert_eq!(replay.rejected_intents, 0);
    assert_eq!(replay.pending_count, 1);
    assert!(!replay.rejected_policy_revalidated);
    assert_eq!(
        replay.execution_engine,
        "REVM 43.0.3/Cancun (same library as producer)"
    );
    assert_eq!(file_hashes(&source)?, source_files);
    assert_eq!(file_hashes(&backup)?, backup_files);

    let mut restored = Store::open(&work.join("replayed"), &genesis)?;
    let restored_view = restored.view()?;
    assert_eq!(restored_view.head, head);
    assert_eq!(restored_view.state_digest()?, digest);
    assert_eq!(restored_view.slot(contract, U256::ZERO)?, U256::from(42));
    assert!(restored_view.code(contract_hash)? == development::contract_runtime());
    for receipt in &receipts {
        assert_eq!(restored_view.receipt(receipt.hash)?.as_ref(), Some(receipt));
    }
    let pending = restored.pending()?;
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].hash, pending_hash);
    assert_eq!(pending[0].sender, sender);
    // Boolean assertions never print signed envelopes on failure.
    assert!(pending[0].raw == pending_raw);
    assert_eq!(
        restored_view
            .status(pending_hash)?
            .ok_or("missing pending status")?
            .status,
        "durably_accepted"
    );
    assert!(restored_view.receipt(pending_hash)?.is_none());
    assert_eq!(restored_view.pending_nonce(sender)?, 5);
    drop(restored_view);

    let pending_receipt = commit(&mut restored, std::slice::from_ref(&pending[0].raw), 5)?;
    assert!(pending_receipt[0].success);
    assert_eq!(pending_receipt[0].hash, pending_hash);
    assert_eq!(pending_receipt[0].gas_used, 21_000);
    assert_eq!(pending_receipt[0].gas_price, 1);
    assert!(restored.pending()?.is_empty());
    let pending_head = restored.view()?.head;
    let pending_digest = restored.state_digest()?;
    let reconciled = restored.admit(Pending {
        hash: pending_hash,
        sender,
        raw: pending_raw,
    })?;
    assert_eq!(reconciled.status, "committed");
    assert_eq!(reconciled.block_height, Some(5));
    assert_eq!(restored.view()?.head, pending_head);
    assert_eq!(restored.state_digest()?, pending_digest);
    assert!(restored.pending()?.is_empty());
    assert_eq!(
        restored.view()?.receipt(pending_hash)?.as_ref(),
        Some(&pending_receipt[0])
    );
    let next = development::sign(5, Some(recipient), U256::from(13), vec![], 21_000)?;
    let next_hash = admit(&mut restored, &next, 6)?;
    let next_receipt = commit(&mut restored, std::slice::from_ref(&next), 6)?;
    assert!(next_receipt[0].success);
    assert_eq!(next_receipt[0].gas_used, 21_000);
    assert_eq!(next_receipt[0].gas_price, 1);
    let advanced = restored.view()?;
    assert_eq!(advanced.head.height, 6);
    assert_eq!(
        advanced
            .account(sender)?
            .ok_or("missing restored sender")?
            .nonce,
        6
    );
    assert_eq!(
        advanced
            .account(recipient)?
            .ok_or("missing restored recipient")?
            .balance,
        U256::from(1_024)
    );
    assert_eq!(
        advanced
            .account(sender)?
            .ok_or("missing restored sender")?
            .balance,
        U256::from(development::INITIAL_BALANCE) - U256::from(1_024) - fees - U256::from(42_000)
    );
    assert_eq!(
        advanced
            .account(Address::ZERO)?
            .ok_or("missing restored fee recipient")?
            .balance,
        fees + U256::from(42_000)
    );
    let advanced_head = advanced.head.clone();
    let advanced_digest = advanced.state_digest()?;
    drop(advanced);
    let duplicate = restored.admit(Pending {
        hash: next_hash,
        sender,
        raw: next,
    })?;
    assert_eq!(duplicate.status, "committed");
    assert_eq!(duplicate.block_height, Some(6));
    assert!(restored.pending()?.is_empty());
    assert_eq!(restored.view()?.head, advanced_head);
    assert_eq!(restored.state_digest()?, advanced_digest);
    drop(restored);

    let tampered = owned.path().join("tampered-backup");
    copy_tree(&backup, &tampered)?;
    let entry = manifest
        .files
        .iter()
        .filter(|entry| {
            entry.length > 0 && entry.path != "lock" && entry.path != ".alephium-l2-development"
        })
        .min_by_key(|entry| {
            if entry.path.starts_with("journals/") {
                0
            } else if entry.path.starts_with("keyspaces/") {
                1
            } else {
                2
            }
        })
        .ok_or("backup manifest has no nonempty engine file")?;
    let tamper_file = tampered.join("data").join(&entry.path);
    let mut bytes = fs::read(&tamper_file).map_err(io_error)?;
    bytes[0] ^= 1;
    fs::write(tamper_file, bytes).map_err(io_error)?;
    let rejected_work = owned.path().join("rejected-replay");
    let tamper_error = match operator::verify_replay(&tampered, &genesis, &rejected_work) {
        Ok(_) => return Err("tampered backup was accepted".into()),
        Err(error) => error,
    };
    assert_eq!(
        tamper_error,
        "Backup file list, lengths or checksums do not match its manifest"
    );
    assert!(!rejected_work.join("source").exists());
    assert!(!rejected_work.join("replayed").exists());

    let missing_genesis = owned.path().join("missing-genesis");
    let invalid_backup = owned.path().join("missing-genesis-backup");
    empty_existing_fixture(&missing_genesis, &genesis)?;
    let identity_error = match operator::backup(&missing_genesis, &invalid_backup, &genesis) {
        Ok(_) => return Err("database without persisted genesis was accepted".into()),
        Err(error) => error,
    };
    assert!(identity_error.contains("persisted genesis"));
    assert!(!invalid_backup.join("manifest.json").exists());
    assert_eq!(file_hashes(&source)?, source_files);
    assert_eq!(file_hashes(&backup)?, backup_files);
    Ok(())
}
