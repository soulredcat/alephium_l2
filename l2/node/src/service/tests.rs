use super::{Core, NodeHandle, start};
use crate::{
    config::Config,
    development,
    protocol::{BLOCK_GAS, BLOCK_INTERVAL_MS, GenesisAccount, Pending},
    storage::{ReadView, Store},
};
use alloy_primitives::{Address, B256, U256};
use std::{
    sync::{Arc, RwLock, atomic::AtomicUsize, mpsc},
    time::Duration,
};

pub(super) fn config(directory: &std::path::Path, min_gas_price: u128) -> Config {
    Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        data_dir: directory.join("data"),
        genesis: development::genesis(),
        min_gas_price,
        verification_workers_per_cpu: 1,
        rpc: Default::default(),
        max_checkpoint_bytes: crate::operator::MAX_CONTINUATION_CHECKPOINT_BYTES,
    }
}

pub(super) fn type2(max_fee: u128, priority: u128) -> Vec<u8> {
    development::sign_type2(
        0,
        Some(Address::repeat_byte(0x42)),
        U256::from(1),
        vec![],
        21_000,
        max_fee,
        priority,
        Default::default(),
    )
    .unwrap()
}

async fn stop(node: &NodeHandle, worker: std::thread::JoinHandle<()>) {
    tokio::time::timeout(Duration::from_secs(2), async {
        node.stop().await;
        tokio::task::spawn_blocking(move || worker.join().unwrap())
            .await
            .unwrap();
    })
    .await
    .expect("Stop must wake an idle or fail-stopped worker");
}

async fn committed(node: &NodeHandle, hash: B256) -> Arc<ReadView> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let view = node.view().unwrap();
            if view.status(hash).unwrap().unwrap().status == "committed"
                && node.pending_count() == 0
            {
                break view;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("Accepted or recovered intent must wake production")
}

#[tokio::test]
async fn admission_enforces_the_minimum_effective_gas_price() {
    let directory = tempfile::tempdir().unwrap();
    let (node, worker) = start(&config(directory.path(), 2)).unwrap();
    let legacy = development::sign(
        0,
        Some(Address::repeat_byte(0x42)),
        U256::from(1),
        vec![],
        21_000,
    )
    .unwrap();
    // Legacy fixture pays 1 wei; type 2 pays its priority fee at a zero base fee.
    for below in [legacy, type2(10, 1), type2(1, 1)] {
        let error = node.submit(below).await.unwrap_err();
        assert_eq!(error, "Gas price is below the node minimum");
    }
    let accepted = node.submit(type2(10, 2)).await.unwrap();
    assert_eq!(accepted.status, "durably_accepted");
    stop(&node, worker).await;
    assert!(node.failure().is_none());
}

#[tokio::test]
async fn idle_worker_wakes_drains_and_stops_with_durable_state() {
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path(), 0);
    let (node, worker) = start(&config).unwrap();
    let idle_period = Duration::from_millis(2 * BLOCK_INTERVAL_MS);
    tokio::time::sleep(idle_period).await;
    assert_eq!(node.view().unwrap().head.height, 0);
    assert_eq!(node.pending_count(), 0);
    assert!(node.submit(Vec::new()).await.is_err());

    let raw = type2(10, 2);
    let hash = alloy_primitives::keccak256(&raw);
    assert_eq!(node.submit(raw).await.unwrap().status, "durably_accepted");
    let view = committed(&node, hash).await;
    let head = view.head.clone();
    let receipt = view.receipt(hash).unwrap().unwrap();
    assert_eq!(head.height, 1);
    assert!(receipt.success);
    assert_eq!(receipt.gas_used, 21_000);
    assert_eq!(node.pending_count(), 0);
    tokio::time::sleep(idle_period).await;
    assert_eq!(node.view().unwrap().head, head);
    drop(view);
    stop(&node, worker).await;
    assert!(node.failure().is_none());
    drop(node);

    let mut store = Store::open(&config.data_dir, &config.genesis).unwrap();
    let restored = store.view().unwrap();
    assert_eq!(restored.head, head);
    assert_eq!(restored.receipt(hash).unwrap().unwrap(), receipt);
    drop(restored);
    // Recovered durable work must progress without another client submission.
    let raw = development::sign(
        1,
        Some(Address::repeat_byte(0x42)),
        U256::from(1),
        vec![],
        21_000,
    )
    .unwrap();
    let hash = alloy_primitives::keccak256(&raw);
    assert_eq!(
        store
            .admit(Pending {
                hash,
                sender: development::address(),
                raw,
            })
            .unwrap()
            .status,
        "durably_accepted"
    );
    drop(store);
    let (node, worker) = start(&config).unwrap();
    assert_eq!(committed(&node, hash).await.head.height, 2);
    assert_eq!(node.pending_count(), 0);
    node.mark_failed();
    assert_eq!(
        node.submit(type2(10, 2)).await.unwrap_err(),
        "Recovery required"
    );
    stop(&node, worker).await;
}

/// Own the core directly so capacity and ACK assertions are independent of
/// wall-clock scheduling or test-host load. Production uses this same core.
pub(super) fn core(config: &Config) -> Core {
    let mut store = Store::open(&config.data_dir, &config.genesis).unwrap();
    store.enable_capacity(config.max_checkpoint_bytes).unwrap();
    let (bytes, limit) = store.checkpoint_capacity().unwrap();
    let view = store.view().unwrap();
    let head = view.head.clone();
    let capacity = view.capacity();
    let (sender, _) = mpsc::channel();
    let (available_cpus, hardware_verification_budget) = super::preparation::detected_budget();
    let workers_per_cpu = config.verification_workers_per_cpu;
    let verification_workers =
        super::preparation::configured_budget(available_cpus, workers_per_cpu).unwrap();
    let handle = NodeHandle {
        sender,
        queued: Arc::new(tokio::sync::Semaphore::new(capacity.max_pending)),
        view: Arc::new(RwLock::new(Arc::new(view))),
        failure: Arc::new(RwLock::new(None)),
        pending: Arc::new(AtomicUsize::new(0)),
        min_gas_price: config.min_gas_price,
        checkpoint_bytes: Arc::new(AtomicUsize::new(bytes)),
        checkpoint_limit: limit,
        capacity,
        metrics: Arc::new(super::metrics::Metrics::default()),
        available_cpus,
        hardware_verification_budget,
        workers_per_cpu,
        verification_workers,
    };
    Core {
        store,
        head,
        pending: Vec::new(),
        prepared: std::collections::HashMap::new(),
        handle,
    }
}

pub(super) fn second_transfer(config: &mut Config) -> Vec<u8> {
    second_transfer_priced(config, 21_000, 1)
}

pub(super) fn second_transfer_priced(
    config: &mut Config,
    gas_limit: u64,
    gas_price: u128,
) -> Vec<u8> {
    use alloy_consensus::{SignableTransaction, TxEnvelope, TxLegacy};
    use alloy_eips::eip2718::Encodable2718;
    use alloy_primitives::{Bytes, TxKind};
    use alloy_signer::SignerSync;
    use alloy_signer_local::PrivateKeySigner;

    // Public scalar two is an isolated development fixture, never a secret.
    let signer = PrivateKeySigner::from_bytes(&B256::from(U256::from(2))).unwrap();
    config.genesis.accounts.push(GenesisAccount {
        address: signer.address(),
        balance: U256::from(development::INITIAL_BALANCE),
    });
    let candidate = TxLegacy {
        chain_id: Some(config.genesis.chain_id),
        nonce: 0,
        gas_price,
        gas_limit,
        to: TxKind::Call(Address::repeat_byte(0x44)),
        value: U256::from(1),
        input: Bytes::new(),
    };
    let signature = signer.sign_hash_sync(&candidate.signature_hash()).unwrap();
    let envelope: TxEnvelope = candidate.into_signed(signature).into();
    envelope.encoded_2718()
}

#[test]
fn accepted_queue_spans_blocks_when_declared_gas_does_not_fit_one_block() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path(), 0);
    let candidate = second_transfer(&mut config);
    let candidate_hash = alloy_primitives::keccak256(&candidate);
    let heavy = development::sign(
        0,
        Some(Address::repeat_byte(0x43)),
        U256::from(1),
        vec![],
        BLOCK_GAS,
    )
    .unwrap();
    let heavy_hash = alloy_primitives::keccak256(&heavy);
    let mut core = core(&config);
    let arrival_head = core.head.clone();
    assert_eq!(core.submit(heavy).unwrap().status, "durably_accepted");
    assert_eq!(
        core.admit_group(vec![(candidate, arrival_head.clone())])
            .pop()
            .unwrap()
            .unwrap()
            .status,
        "durably_accepted"
    );
    assert_eq!(core.store.pending().unwrap().len(), 2);
    core.produce().unwrap();
    assert_eq!(core.head.height, 1);
    assert_eq!(core.pending.len(), 1);
    assert_eq!(
        core.handle
            .view()
            .unwrap()
            .receipt(heavy_hash)
            .unwrap()
            .unwrap()
            .block_height,
        1
    );
    assert!(
        core.handle
            .view()
            .unwrap()
            .receipt(candidate_hash)
            .unwrap()
            .is_none()
    );
    core.produce().unwrap();
    assert_eq!(core.head.height, 2);
    assert!(core.pending.is_empty());
    let receipt = core
        .handle
        .view()
        .unwrap()
        .receipt(candidate_hash)
        .unwrap()
        .unwrap();
    assert!(receipt.success);
    assert_eq!(receipt.block_height, 2);
    assert!(receipt.block_height > arrival_head.height + 1);
    assert!(core.handle.failure().is_none());
}
