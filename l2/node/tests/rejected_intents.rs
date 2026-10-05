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
use std::time::{Duration, Instant};

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
    let config = Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        data_dir: data.clone(),
        genesis: genesis.clone(),
        min_gas_price: 0,
        max_checkpoint_bytes: operator::MAX_CONTINUATION_CHECKPOINT_BYTES,
    };
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (node, worker) = service::start(&config).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while node.pending_count() != 0 {
        assert!(Instant::now() < deadline, "intents were not resolved");
        std::thread::sleep(Duration::from_millis(20));
    }
    runtime.block_on(node.stop());
    worker.join().unwrap();
    assert!(node.failure().is_none());

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
            report.rejected_intents,
            report.pending_count
        ),
        (1, 0, 0)
    );
}
