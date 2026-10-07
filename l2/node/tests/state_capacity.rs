//! The producer never commits a block whose execution checkpoint would exceed
//! the configured capacity; an intent that cannot fit is rejected off-chain.
use alephium_l2_node::{
    config::Config, development, execution, operator, protocol::*, service, storage::Store,
};
use alloy_consensus::{SignableTransaction, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, B256, Bytes, TxKind, U256, keccak256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
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

/// Public scalar fixtures for isolated development tests only.
fn fixture_transfer(scalar: u64, to: Address) -> (Address, Vec<u8>) {
    let signer = PrivateKeySigner::from_bytes(&B256::from(U256::from(scalar))).unwrap();
    let transaction = TxLegacy {
        chain_id: Some(CHAIN_ID),
        nonce: 0,
        gas_price: 1,
        gas_limit: 21_000,
        to: TxKind::Call(to),
        value: U256::from(1),
        input: Bytes::new(),
    };
    let signature = signer
        .sign_hash_sync(&transaction.signature_hash())
        .unwrap();
    let envelope: TxEnvelope = transaction.into_signed(signature).into();
    (signer.address(), envelope.encoded_2718())
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
    // Fill the state budget exactly with the recipient and fee beneficiary.
    // Reserve the complete future hash window: growth must be refused even
    // though actual encoded bytes still have room before height 255.
    let limit = initial + 2 * 105 + 255 * 40;
    let config = Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        data_dir: data.clone(),
        genesis: genesis.clone(),
        min_gas_price: 0,
        max_checkpoint_bytes: limit,
        rpc: Default::default(),
        verification_workers_per_cpu: 1,
        verification_backend: alephium_l2_node::config::VerificationBackend::Cpu,
        gpu_device: 0,
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
    assert_eq!(submit(transfer(2, known)).status, "committed");
    let (used, _) = node.checkpoint_capacity();
    assert_eq!(used, initial + 2 * 105 + 3 * 40);
    runtime.block_on(node.stop());
    worker.join().unwrap();
    assert!(node.failure().is_none());
    assert_eq!(node.view().unwrap().head.height, 3);
    drop(node);
    let store = Store::open(&data, &genesis).unwrap();
    let checkpoint = store.view().unwrap().execution_checkpoint().unwrap();
    assert_eq!(checkpoint.encode().unwrap().len(), used);
    // A node whose committed state already exceeds a lower bound refuses to start.
    drop(store);
    let lower = Config {
        max_checkpoint_bytes: limit - 1,
        ..config
    };
    let error = service::start(&lower).err().unwrap();
    assert!(error.contains("already exceeds"), "{error}");
}

#[test]
fn oversized_batches_retry_and_resolve_the_oldest_intent_without_blocking_followers() {
    let directory = tempfile::tempdir().unwrap();
    let data = directory.path().join("data");
    let mut genesis = development::genesis();
    let first = transfer(0, Address::repeat_byte(0x83));
    let (second_sender, second) = fixture_transfer(2, Address::repeat_byte(0x84));
    let (third_sender, third) = fixture_transfer(3, development::address());
    for address in [second_sender, third_sender] {
        genesis.accounts.push(GenesisAccount {
            address,
            balance: U256::from(development::INITIAL_BALANCE),
        });
    }
    let hashes = [&first, &second, &third].map(keccak256);
    let initial = {
        let mut store = Store::open(&data, &genesis).unwrap();
        let bytes = store
            .view()
            .unwrap()
            .execution_checkpoint()
            .unwrap()
            .encode()
            .unwrap()
            .len();
        // Persist the whole admission-ordered queue before starting the worker,
        // so the fallback is exercised regardless of scheduling or machine load.
        for raw in [first, second, third] {
            let info = execution::inspect(&raw).unwrap();
            store
                .admit(Pending {
                    hash: info.hash,
                    sender: info.sender,
                    raw,
                })
                .unwrap();
        }
        bytes
    };
    let limit = initial + 2 * 105 + 255 * 40;
    let config = Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        data_dir: data,
        genesis,
        min_gas_price: 0,
        max_checkpoint_bytes: limit,
        rpc: Default::default(),
        verification_workers_per_cpu: 1,
        verification_backend: alephium_l2_node::config::VerificationBackend::Cpu,
        gpu_device: 0,
    };
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let (node, worker) = service::start(&config).unwrap();
    // The three-intent block is too large, but its oldest intent fits alone.
    let first = resolved(&node, hashes[0]);
    assert_eq!(
        (first.status.as_str(), first.block_height),
        ("committed", Some(1))
    );
    // The remaining two-intent block is still too large. Its oldest intent
    // cannot fit alone either, so it is discarded without dropping its follower.
    let second = resolved(&node, hashes[1]);
    assert_eq!(
        (second.status.as_str(), second.block_height),
        ("rejected", None)
    );
    assert!(
        second
            .error
            .unwrap()
            .starts_with("state capacity exhausted")
    );
    let third = resolved(&node, hashes[2]);
    assert_eq!(
        (third.status.as_str(), third.block_height),
        ("committed", Some(2))
    );
    runtime.block_on(node.stop());
    worker.join().unwrap();
    assert!(node.failure().is_none());
    assert_eq!(node.pending_count(), 0);
    let view = node.view().unwrap();
    assert_eq!(
        view.replay_block(1).unwrap().unwrap().transactions,
        vec![hashes[0]]
    );
    assert_eq!(
        view.replay_block(2).unwrap().unwrap().transactions,
        vec![hashes[2]]
    );
    assert!(view.receipt(hashes[1]).unwrap().is_none());
    let bytes = view.execution_checkpoint().unwrap().encode().unwrap().len();
    assert_eq!(bytes, initial + 2 * 105 + 2 * 40);
    assert_eq!(node.checkpoint_capacity(), (bytes, limit));
}

#[test]
fn service_rejects_invalid_capacity_before_opening_storage() {
    let directory = tempfile::tempdir().unwrap();
    let data = directory.path().join("data");
    for limit in [0, operator::MAX_CONTINUATION_CHECKPOINT_BYTES + 1] {
        let config = Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            data_dir: data.clone(),
            genesis: development::genesis(),
            min_gas_price: 0,
            max_checkpoint_bytes: limit,
            rpc: Default::default(),
            verification_workers_per_cpu: 1,
            verification_backend: alephium_l2_node::config::VerificationBackend::Cpu,
            gpu_device: 0,
        };
        let error = service::start(&config).err().unwrap();
        assert!(error.contains("Checkpoint capacity must be"), "{error}");
        assert!(
            !data.exists(),
            "invalid capacity must not initialize storage"
        );
    }
}
