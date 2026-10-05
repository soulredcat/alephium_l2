//! The producer never commits a block whose execution checkpoint would exceed
//! the configured capacity; an intent that cannot fit is rejected off-chain.
use alephium_l2_node::{config::Config, development, protocol::*, service, storage::Store};
use alloy_primitives::{Address, B256, U256, keccak256};
use std::time::{Duration, Instant};

fn transfer(nonce: u64, to: Address) -> Vec<u8> {
    development::sign(nonce, Some(to), U256::from(1), vec![], 21_000).unwrap()
}

fn resolved(node: &service::NodeHandle, hash: B256) -> TransactionStatus {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let status = node.view().unwrap().status(hash).unwrap().unwrap();
        if status.status != "durably_accepted" {
            return status;
        }
        assert!(Instant::now() < deadline, "intent was not resolved");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn intents_that_would_exceed_the_checkpoint_bound_are_rejected_off_chain() {
    let directory = tempfile::tempdir().unwrap();
    let data = directory.path().join("data");
    let genesis = development::genesis();
    let initial = {
        let store = Store::open(&data, &genesis).unwrap();
        let checkpoint = store.view().unwrap().execution_checkpoint().unwrap();
        checkpoint.encode().unwrap().len()
    };
    // Block 1 adds the recipient and the zero-address fee beneficiary (105
    // bytes each) plus a block hash entry (40). Leave room for two more block
    // hash entries but not for another new account.
    let limit = initial + 2 * 105 + 3 * 40 + 50;
    let config = Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        data_dir: data.clone(),
        genesis: genesis.clone(),
        min_gas_price: 0,
        max_checkpoint_bytes: limit,
    };
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (node, worker) = service::start(&config).unwrap();
    assert_eq!(node.checkpoint_capacity(), (initial, limit));
    let known = Address::repeat_byte(0x81);
    let submit = |raw: Vec<u8>| {
        let hash = keccak256(&raw);
        runtime.block_on(node.submit(raw)).unwrap();
        resolved(&node, hash)
    };
    assert_eq!(submit(transfer(0, known)).status, "committed");
    let refused = submit(transfer(1, Address::repeat_byte(0x82)));
    assert_eq!(refused.status, "rejected");
    assert_eq!(refused.block_height, None);
    assert!(
        refused
            .error
            .unwrap()
            .starts_with("state capacity exhausted")
    );
    // The unexecuted nonce is reused; growth limited to a block hash entry fits.
    assert_eq!(submit(transfer(1, known)).status, "committed");
    let (used, _) = node.checkpoint_capacity();
    assert_eq!(used, initial + 2 * 105 + 2 * 40);
    runtime.block_on(node.stop());
    worker.join().unwrap();
    assert!(node.failure().is_none());
    assert_eq!(node.view().unwrap().head.height, 2);
    drop(node);
    let store = Store::open(&data, &genesis).unwrap();
    let checkpoint = store.view().unwrap().execution_checkpoint().unwrap();
    assert_eq!(checkpoint.encode().unwrap().len(), used);
    // A node whose committed state already exceeds a lower bound refuses to start.
    drop(store);
    let lower = Config {
        max_checkpoint_bytes: used - 1,
        ..config
    };
    let error = service::start(&lower).err().unwrap();
    assert!(error.contains("already exceeds"), "{error}");
}
