//! An intent that fails validation at execution is resolved outside any block,
//! so every committed block stays representable by the transition witness.
use alephium_l2_node::{
    config::Config, development, execution, operator, protocol::*, service, storage::Store,
};
use alloy_consensus::{SignableTransaction, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, B256, Bytes, TxKind, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use std::{
    path::Path,
    time::{Duration, Instant},
};

fn resolve(data: &Path, genesis: &Genesis) -> service::NodeHandle {
    let config = Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        data_dir: data.to_path_buf(),
        genesis: genesis.clone(),
        min_gas_price: 0,
        max_checkpoint_bytes: operator::MAX_CONTINUATION_CHECKPOINT_BYTES,
        rpc: Default::default(),
        verification_workers_per_cpu: 1,
        verification_backend: alephium_l2_node::config::VerificationBackend::Cpu,
        gpu_device: 0,
    };
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (node, worker) = service::start(&config).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while node.pending_count() != 0 {
        assert!(node.failure().is_none(), "producer failed");
        assert!(Instant::now() < deadline, "intents were not resolved");
        std::thread::sleep(Duration::from_millis(20));
    }
    runtime.block_on(node.stop());
    worker.join().unwrap();
    assert!(node.failure().is_none());
    node
}

fn domain() -> operator::SettlementDomain {
    operator::SettlementDomain {
        l1_network: 1,
        l1_genesis_id: B256::repeat_byte(0x11),
        settlement_contract_id: B256::repeat_byte(0x22),
    }
}

fn pending(raw: Vec<u8>) -> Pending {
    let info = execution::inspect(&raw).unwrap();
    Pending {
        hash: info.hash,
        sender: info.sender,
        raw,
    }
}

/// Public scalar-two fixture; unfunded, so a nonce gap makes it unexecutable.
fn nonce_gap() -> Vec<u8> {
    let signer = PrivateKeySigner::from_bytes(&B256::from(U256::from(2))).unwrap();
    let transaction = TxLegacy {
        chain_id: Some(CHAIN_ID),
        nonce: 5,
        gas_price: 0,
        gas_limit: 21_000,
        to: TxKind::Call(Address::repeat_byte(0x61)),
        value: U256::ZERO,
        input: Bytes::new(),
    };
    let signature = signer
        .sign_hash_sync(&transaction.signature_hash())
        .unwrap();
    let envelope: TxEnvelope = transaction.into_signed(signature).into();
    envelope.encoded_2718()
}

#[test]
fn execution_rejections_stay_out_of_blocks_and_survive_restart_and_replay() {
    let directory = tempfile::tempdir().unwrap();
    let data = directory.path().join("data");
    let genesis = development::genesis();
    let valid = pending(
        development::sign(
            0,
            Some(Address::repeat_byte(0x62)),
            U256::from(1),
            vec![],
            21_000,
        )
        .unwrap(),
    );
    // Admission validation would refuse this intent; persisting it directly
    // models an intent that became invalid between admission and execution.
    let invalid = pending(nonce_gap());
    {
        let mut store = Store::open(&data, &genesis).unwrap();
        store.admit(valid.clone()).unwrap();
        store.admit(invalid.clone()).unwrap();
    }
    let node = resolve(&data, &genesis);

    let view = node.view().unwrap();
    assert_eq!(view.head.height, 1);
    let block = view.replay_block(1).unwrap().unwrap();
    assert_eq!(block.transactions, vec![valid.hash]);
    assert!(block.rejected.is_empty());
    assert_eq!(
        view.status(valid.hash).unwrap().unwrap().status,
        "committed"
    );
    let rejected = view.status(invalid.hash).unwrap().unwrap();
    assert_eq!(rejected.status, "rejected");
    assert_eq!(rejected.block_height, None);
    let reason = rejected.error.unwrap();
    assert!(reason.starts_with("invalid transaction:"), "{reason}");
    assert!(view.receipt(invalid.hash).unwrap().is_none());
    drop(view);
    drop(node);

    // Restart validation explains the discarded records; a resubmission
    // returns the terminal status instead of admitting the intent again.
    let mut store = Store::open(&data, &genesis).unwrap();
    assert_eq!(store.discarded().unwrap(), vec![(invalid.hash, reason)]);
    assert_eq!(store.admit(invalid.clone()).unwrap().status, "rejected");
    assert!(store.pending().unwrap().is_empty());
    drop(store);

    let backup = directory.path().join("backup");
    operator::backup(&data, &backup, &genesis).unwrap();
    let report =
        operator::verify_replay(&backup, &genesis, &directory.path().join("replay")).unwrap();
    assert_eq!(
        (
            report.executed_transactions,
            report.discarded_intents,
            report.rejected_intents,
            report.pending_count
        ),
        (1, 1, 0, 0)
    );

    // Local discards increase admission counts but are not proof inputs. Every
    // export schema must still represent the exact committed transfer.
    let single =
        operator::prepare_transition(&backup, &genesis, &directory.path().join("single")).unwrap();
    assert_eq!(single.transaction_hash, valid.hash);
    assert_eq!(single.head, report.head);
    let batch = operator::prepare_transition_batch(
        &backup,
        &genesis,
        &directory.path().join("batch"),
        1,
        domain(),
    )
    .unwrap();
    assert_eq!(batch.transaction_hashes, vec![valid.hash]);
    assert_eq!(batch.head, report.head);
    let checkpoint = operator::prepare_transition_checkpoint(
        &backup,
        &genesis,
        &directory.path().join("checkpoint"),
        1,
        domain(),
    )
    .unwrap();
    assert_eq!(checkpoint.transaction_hashes, vec![valid.hash]);
    assert_eq!(checkpoint.head, report.head);
    assert_eq!(checkpoint.expected_state_digest, report.state_digest);
}

#[test]
fn only_discarded_intents_leave_genesis_unchanged_and_have_no_export() {
    let directory = tempfile::tempdir().unwrap();
    let data = directory.path().join("data");
    let genesis = development::genesis();
    let invalid = pending(nonce_gap());
    let mut store = Store::open(&data, &genesis).unwrap();
    let original_head = store.view().unwrap().head;
    let original_digest = store.state_digest().unwrap();
    store.admit(invalid.clone()).unwrap();
    drop(store);

    let node = resolve(&data, &genesis);
    let view = node.view().unwrap();
    assert_eq!(view.head, original_head);
    assert_eq!(view.state_digest().unwrap(), original_digest);
    assert_eq!(view.pending_counter().unwrap(), 1);
    assert_eq!(
        view.status(invalid.hash).unwrap().unwrap().status,
        "rejected"
    );
    assert!(view.receipt(invalid.hash).unwrap().is_none());
    drop(view);
    drop(node);

    let backup = directory.path().join("backup");
    operator::backup(&data, &backup, &genesis).unwrap();
    let report =
        operator::verify_replay(&backup, &genesis, &directory.path().join("replay")).unwrap();
    assert_eq!(report.head, original_head);
    assert_eq!(report.state_digest, original_digest);
    assert_eq!(report.executed_transactions, 0);
    assert_eq!(report.discarded_intents, 1);
    assert_eq!(report.rejected_intents, 0);
    assert_eq!(report.pending_count, 0);
    let paths = ["single", "batch", "checkpoint"].map(|name| directory.path().join(name));
    assert!(operator::prepare_transition(&backup, &genesis, &paths[0]).is_err());
    assert!(operator::prepare_transition_batch(&backup, &genesis, &paths[1], 1, domain()).is_err());
    assert!(
        operator::prepare_transition_checkpoint(&backup, &genesis, &paths[2], 1, domain()).is_err()
    );
    assert!(paths.iter().all(|path| !path.exists()));
}

#[test]
fn restart_between_block_commit_and_discard_resolves_the_remaining_intent() {
    let directory = tempfile::tempdir().unwrap();
    let data = directory.path().join("data");
    let genesis = development::genesis();
    let valid = pending(
        development::sign(
            0,
            Some(Address::repeat_byte(0x62)),
            U256::from(1),
            vec![],
            21_000,
        )
        .unwrap(),
    );
    let invalid = pending(nonce_gap());
    let mut store = Store::open(&data, &genesis).unwrap();
    store.admit(valid.clone()).unwrap();
    store.admit(invalid.clone()).unwrap();
    let view = store.view().unwrap();
    let context = BlockContext {
        number: 1,
        timestamp: 1,
        gas_limit: BLOCK_GAS,
    };
    let result = execution::execute_block(
        view.clone(),
        &[valid.raw.clone(), invalid.raw.clone()],
        context,
    )
    .unwrap();
    assert_eq!(result.rejected.len(), 1);
    let committed = store
        .commit(BlockCommit {
            parent: view.head.clone(),
            context,
            transactions: vec![valid.hash],
            changes: result.changes,
            receipts: result.receipts,
            rejected: Vec::new(),
        })
        .unwrap();
    let head = committed.head.clone();
    let digest = committed.state_digest().unwrap();
    let receipt = committed.receipt(valid.hash).unwrap();
    drop(committed);
    drop(view);
    // Model a process stop at the durable boundary before the discard batch.
    drop(store);
    let store = Store::open(&data, &genesis).unwrap();
    assert_eq!(store.pending().unwrap()[0].hash, invalid.hash);
    assert!(store.discarded().unwrap().is_empty());
    drop(store);
    let node = resolve(&data, &genesis);
    let view = node.view().unwrap();
    assert_eq!(view.head, head);
    assert_eq!(view.state_digest().unwrap(), digest);
    assert_eq!(view.receipt(valid.hash).unwrap(), receipt);
    assert_eq!(
        view.status(invalid.hash).unwrap().unwrap().status,
        "rejected"
    );
    assert!(view.receipt(invalid.hash).unwrap().is_none());
}
