//! One bounded export flow reusing the runtime's transfer/contract recovery fixture.
#[allow(dead_code)]
#[path = "support/recovery_fixture.rs"]
mod fixture;

use alephium_l2_node::{
    development,
    operator::{self, BatchTransitionBundle, SettlementDomain},
    protocol::Receipt,
    storage::Store,
};
use alloy_primitives::{Address, B256, U256, keccak256};
use fixture::{admit, commit, file_hashes, io_error};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

#[test]
fn export_actual_transfer_deploy_write_revert_with_full_prefix() -> Result<(), String> {
    let temporary = tempfile::Builder::new()
        .prefix("l2-p4-transition-")
        .tempdir()
        .map_err(io_error)?;
    let root = if let Some(path) = std::env::var_os("L2_TRANSITION_OUTPUT") {
        let root = PathBuf::from(path);
        fs::create_dir(&root).map_err(io_error)?;
        root
    } else {
        temporary.path().to_path_buf()
    };
    let genesis = development::genesis();
    let mut store = Store::open(&root.join("source"), &genesis)?;
    let receipts = exercise_history(&mut store, &root)?;
    // Exercise export/core agreement from a history containing a local discard,
    // without changing any of the four committed proof inputs or their state.
    let recipient = Address::repeat_byte(0x66);
    persist_intent(
        &root,
        "05-discarded",
        serde_json::json!({
            "type": 0, "nonce": 4, "to": recipient, "value": "1", "gas": 21000,
            "gas_price": 1, "data_keccak": keccak256([]),
        }),
    )?;
    let raw = development::sign(4, Some(recipient), U256::from(1), vec![], 21_000)?;
    let discarded = admit(&mut store, &raw, 5)?;
    let status = store.discard(discarded, "local discard fixture")?;
    assert_eq!(status.status, "rejected");
    assert_eq!(status.block_height, None);
    let view = store.view()?;
    assert_eq!(view.pending_counter()?, 5);
    assert!(view.receipt(discarded)?.is_none());
    assert!(store.pending()?.is_empty());
    let head = view.head.clone();
    let digest = view.state_digest()?;
    let contract = receipts[1].contract.ok_or("Missing contract deployment")?;
    assert_eq!(view.slot(contract, U256::ZERO)?, U256::from(42));
    assert_eq!(view.account(development::address())?.unwrap().nonce, 4);
    assert_eq!(
        view.code(view.account(contract)?.unwrap().code_hash)?,
        development::contract_runtime()
    );
    drop(view);
    drop(store);

    let backup = root.join("backup");
    operator::backup(&root.join("source"), &backup, &genesis)?;
    let inventory = file_hashes(&backup)?;
    // Synthetic explicit identities for local evidence only; no network is contacted.
    let domain = SettlementDomain {
        l1_network: 1,
        l1_genesis_id: B256::from([0x11; 32]),
        settlement_contract_id: B256::from([0x22; 32]),
    };
    let report = operator::prepare_transition_batch(
        &backup,
        &genesis,
        &root.join("export"),
        1,
        domain.clone(),
    )?;
    assert_eq!(report.schema, 2);
    assert_eq!(report.head, head);
    assert_eq!(report.blocks, 4);
    assert_eq!(report.batch_start, 1);
    assert_eq!(report.executed_transactions, 4);
    assert_eq!(report.expected_state_digest, digest);
    assert_eq!(report.domain, domain);
    assert_eq!(report.parent.height, 0);
    assert_eq!(report.rejected_intents, 0);
    assert_eq!(report.pending_count, 0);
    assert!(report.semantic_replay_verified);
    assert!(!report.guest_proof_generated && !report.settlement_verified);
    let private = fs::read(&report.bundle_path).map_err(io_error)?;
    let bundle: BatchTransitionBundle =
        serde_json::from_slice(&private).map_err(|_| "Invalid exported private batch witness")?;
    assert_eq!(bundle.blocks.len(), 4);
    assert_eq!(bundle.batch_start, 1);
    assert_eq!(bundle.parent, report.parent);
    assert_eq!(bundle.domain, domain);
    for (index, block) in bundle.blocks.iter().enumerate() {
        assert_eq!(block.context.number, index as u64 + 1);
        assert_eq!(block.transactions.len(), 1);
        assert_eq!(block.transactions[0].expected_receipt, receipts[index]);
        assert_eq!(block.transactions[0].transaction_hash, receipts[index].hash);
        let predecessor = if index == 0 {
            &bundle.parent
        } else {
            &bundle.blocks[index - 1].head
        };
        assert_eq!(&block.parent, predecessor);
    }
    assert_eq!(file_hashes(&backup)?, inventory);

    let invalid_work = root.join("invalid-domain");
    let mut invalid_domain = domain.clone();
    invalid_domain.settlement_contract_id = B256::ZERO;
    assert!(
        operator::prepare_transition_batch(&backup, &genesis, &invalid_work, 1, invalid_domain,)
            .is_err()
    );
    assert!(!invalid_work.exists());
    assert!(
        operator::prepare_transition_batch(&backup, &genesis, &invalid_work, 0, domain.clone(),)
            .is_err()
    );
    assert!(
        operator::prepare_transition_batch(&backup, &genesis, &invalid_work, 257, domain,).is_err()
    );
    // The original height-one export retains its bounded scope.
    assert!(operator::prepare_transition(&backup, &genesis, &invalid_work).is_err());
    assert!(!invalid_work.exists());

    fs::write(
        root.join("genesis.json"),
        serde_json::to_vec_pretty(&genesis).map_err(|_| "Cannot encode genesis fixture")?,
    )
    .map_err(io_error)?;
    fs::write(
        root.join("report.json"),
        serde_json::to_vec_pretty(&report).map_err(|_| "Cannot encode safe batch report")?,
    )
    .map_err(io_error)?;
    Ok(())
}

fn exercise_history(store: &mut Store, intent_directory: &Path) -> Result<Vec<Receipt>, String> {
    let recipient = Address::from([0x44; 20]);
    persist_intent(
        intent_directory,
        "01-transfer",
        serde_json::json!({
            "type": 0, "nonce": 0, "to": recipient, "value": "1000", "gas": 21000,
            "gas_price": 1, "data_keccak": keccak256([]),
        }),
    )?;
    let transfer = development::sign(0, Some(recipient), U256::from(1_000), vec![], 21_000)?;
    admit(store, &transfer, 1)?;
    let mut receipts = commit(store, &[transfer], 1)?;
    let init = development::contract_init();
    persist_intent(
        intent_directory,
        "02-deploy",
        serde_json::json!({
            "type": 2, "nonce": 1, "to": null, "value": "0", "gas": 300000,
            "max_fee": 10, "priority_fee": 3, "access_list": [], "data_keccak": keccak256(&init),
        }),
    )?;
    let deployment = development::sign_type2(
        1,
        None,
        U256::ZERO,
        init,
        300_000,
        10,
        3,
        Default::default(),
    )?;
    admit(store, &deployment, 2)?;
    receipts.extend(commit(store, &[deployment], 2)?);
    let contract = receipts[1].contract.ok_or("Missing contract deployment")?;
    let write_input = development::contract_input(1, None);
    persist_intent(
        intent_directory,
        "03-write",
        serde_json::json!({
            "type": 2, "nonce": 2, "to": contract, "value": "0", "gas": 100000,
            "max_fee": 10, "priority_fee": 5, "access_list": [], "data_keccak": keccak256(&write_input),
        }),
    )?;
    let write = development::sign_type2(
        2,
        Some(contract),
        U256::ZERO,
        write_input,
        100_000,
        10,
        5,
        Default::default(),
    )?;
    admit(store, &write, 3)?;
    receipts.extend(commit(store, &[write], 3)?);
    let revert_input = development::contract_input(2, None);
    persist_intent(
        intent_directory,
        "04-revert",
        serde_json::json!({
            "type": 2, "nonce": 3, "to": contract, "value": "77", "gas": 100000,
            "max_fee": 10, "priority_fee": 1, "access_list": [], "data_keccak": keccak256(&revert_input),
        }),
    )?;
    let revert = development::sign_type2(
        3,
        Some(contract),
        U256::from(77),
        revert_input,
        100_000,
        10,
        1,
        Default::default(),
    )?;
    admit(store, &revert, 4)?;
    receipts.extend(commit(store, &[revert], 4)?);
    assert!(receipts[..3].iter().all(|receipt| receipt.success));
    assert!(!receipts[3].success);
    assert!(receipts[3].logs.is_empty());
    assert_eq!(receipts[2].logs.len(), 1);
    Ok(receipts)
}

fn persist_intent(directory: &Path, name: &str, intent: serde_json::Value) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(&serde_json::json!({
        "schema": 1,
        "scope": "isolated-development-fixture",
        "chain_id": alephium_l2_node::protocol::CHAIN_ID,
        "intent": intent,
    }))
    .map_err(|_| "Cannot encode fixture signing intent")?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join(format!("{name}.intent.json")))
        .map_err(io_error)?;
    file.write_all(&bytes).map_err(io_error)?;
    file.sync_all().map_err(io_error)
}
