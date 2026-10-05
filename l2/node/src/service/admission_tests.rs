use super::tests::{config, core, second_transfer, type2};
use crate::storage::Store;

#[test]
fn queued_group_deduplicates_and_splits_invalid_inputs_before_durable_admission() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path(), 0);
    let second = second_transfer(&mut config);
    let first = type2(10, 2);
    let conflicting = development::sign(
        0,
        Some(Address::repeat_byte(0x45)),
        U256::from(1),
        vec![],
        21_000,
    )
    .unwrap();
    let mut core = core(&config);
    let head = core.head.clone();
    let results = core.admit_group(
        [
            first.clone(),
            first.clone(),
            conflicting,
            Vec::new(),
            second.clone(),
        ]
        .into_iter()
        .map(|raw| (raw, head.clone()))
        .collect(),
    );
    assert_eq!(results[0].as_ref().unwrap(), results[1].as_ref().unwrap());
    assert_eq!(results[0].as_ref().unwrap().status, "durably_accepted");
    assert_eq!(results[4].as_ref().unwrap().status, "durably_accepted");
    assert_eq!(
        results[2].as_ref().unwrap_err(),
        "One pending transaction per sender is supported"
    );
    assert_eq!(
        results[3].as_ref().unwrap_err(),
        "Transaction encoding exceeds admission bounds"
    );
    assert_eq!(core.pending.len(), 2);
    assert_eq!(core.prepared.len(), 2);
    assert_eq!(core.store.pending().unwrap().len(), 2);
    assert_eq!(core.handle.view().unwrap().pending_counter().unwrap(), 2);
    let admitted = core.handle.metrics();
    assert_eq!(admitted.admitted_transactions, 2);
    assert_eq!(admitted.validation.samples, 1);
    assert_eq!(admitted.durable_admission.samples, 1);
    core.produce().unwrap();
    assert_eq!(core.head.height, 1);
    assert!(core.prepared.is_empty());
    let executed = core.handle.metrics();
    assert_eq!(executed.executed_transactions, 2);
    assert_eq!(executed.selection.samples, 1);
    assert_eq!(executed.execution.samples, 1);
    assert_eq!(executed.durable_block_commit.samples, 1);
    for raw in [first, second] {
        assert_eq!(
            core.handle
                .view()
                .unwrap()
                .receipt(alloy_primitives::keccak256(raw))
                .unwrap()
                .unwrap()
                .block_height,
            1
        );
    }
}

#[test]
fn stale_original_head_is_a_target_and_does_not_refuse_valid_late_admission() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path(), 0);
    let second = second_transfer(&mut config);
    let hash = alloy_primitives::keccak256(&second);
    let mut core = core(&config);
    let original = core.head.clone();
    core.submit(type2(10, 2)).unwrap();
    core.produce().unwrap();
    assert_eq!(core.head.height, 1);
    let accepted = core
        .admit_group(vec![(second, original.clone())])
        .pop()
        .unwrap()
        .unwrap();
    assert_eq!(accepted.status, "durably_accepted");
    core.produce().unwrap();
    let receipt = core.handle.view().unwrap().receipt(hash).unwrap().unwrap();
    assert_eq!(original.height + 1, 1);
    assert_eq!(receipt.block_height, 2);
    assert!(receipt.block_height > original.height + 1);
    assert!(core.handle.failure().is_none());
}

#[test]
fn service_and_selection_use_the_pinned_genesis_capacity() {
    use crate::{development, protocol::Capacity};
    use alloy_primitives::{Address, U256};
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path(), 0);
    config.genesis.capacity = Capacity {
        block_gas: 60_000_000,
        block_bytes: 2 * 1024 * 1024,
        max_pending: 1000,
    };
    let mut core = core(&config);
    assert_eq!(core.handle.capacity(), config.genesis.capacity);
    assert_eq!(core.context().unwrap().gas_limit, 60_000_000);
    let raw = development::sign(
        0,
        Some(Address::repeat_byte(0x49)),
        U256::from(1),
        vec![],
        60_000_000,
    )
    .unwrap();
    let hash = alloy_primitives::keccak256(&raw);
    assert_eq!(core.submit(raw).unwrap().status, "durably_accepted");
    core.produce().unwrap();
    assert_eq!(core.head.height, 1);
    let view = core.handle.view().unwrap();
    assert_eq!(view.capacity(), config.genesis.capacity);
    assert_eq!(
        view.replay_block(1).unwrap().unwrap().context.gas_limit,
        60_000_000
    );
    assert!(view.receipt(hash).unwrap().unwrap().success);
}

#[test]
fn maximum_gas_requests_are_acknowledged_then_selected_in_two_safe_blocks() {
    use crate::development;
    use alloy_primitives::{Address, U256, keccak256};
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path(), 0);
    config.genesis.capacity.block_gas = u64::MAX;
    let second = super::tests::second_transfer_priced(&mut config, u64::MAX, 0);
    let second_hash = keccak256(&second);
    let first = development::sign_type2(
        0,
        Some(Address::repeat_byte(0x4a)),
        U256::from(1),
        vec![],
        u64::MAX,
        0,
        0,
        Default::default(),
    )
    .unwrap();
    let first_hash = keccak256(&first);
    let mut core = core(&config);
    assert_eq!(core.submit(first).unwrap().status, "durably_accepted");
    assert_eq!(core.submit(second).unwrap().status, "durably_accepted");
    assert_eq!(core.pending.len(), 2);
    assert_eq!(core.store.pending().unwrap().len(), 2);
    let view = core.handle.view().unwrap();
    assert_eq!(
        view.status(second_hash).unwrap().unwrap().status,
        "durably_accepted"
    );
    assert!(view.raw_transaction(second_hash).unwrap().is_some());
    let before = view.account(development::address()).unwrap().unwrap();
    assert_eq!(before.nonce, 0);
    assert_eq!(before.balance, U256::from(development::INITIAL_BALANCE));
    drop(view);
    core.produce().unwrap();
    let view = core.handle.view().unwrap();
    let receipt = view.receipt(first_hash).unwrap().unwrap();
    assert!(receipt.success);
    assert_eq!(receipt.block_height, 1);
    assert_eq!(receipt.gas_price, 0);
    let after = view.account(development::address()).unwrap().unwrap();
    assert_eq!(after.nonce, 1);
    assert_eq!(
        after.balance,
        U256::from(development::INITIAL_BALANCE) - U256::from(1)
    );
    assert_eq!(
        view.account(Address::repeat_byte(0x4a))
            .unwrap()
            .unwrap()
            .balance,
        U256::from(1)
    );
    assert!(view.receipt(second_hash).unwrap().is_none());
    drop(view);
    assert_eq!(core.pending.len(), 1);
    assert_eq!(core.prepared.len(), 1);
    core.produce().unwrap();
    let view = core.handle.view().unwrap();
    let receipt = view.receipt(second_hash).unwrap().unwrap();
    assert!(receipt.success);
    assert_eq!(receipt.block_height, 2);
    assert_eq!(receipt.gas_price, 0);
    assert_eq!(view.account(receipt.from).unwrap().unwrap().nonce, 1);
    assert_eq!(
        view.account(receipt.from).unwrap().unwrap().balance,
        U256::from(development::INITIAL_BALANCE) - U256::from(1)
    );
    assert!(core.pending.is_empty());
    assert!(core.handle.failure().is_none());
}

#[test]
fn failed_group_suppresses_existing_and_new_successes_and_preserves_durable_state() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path(), 0);
    let second = second_transfer(&mut config);
    let second_hash = alloy_primitives::keccak256(&second);
    let first = type2(10, 2);
    let mut core = core(&config);
    core.submit(first.clone()).unwrap();
    core.store.fail_next_commit_for_test();
    let head = core.head.clone();
    let results = core.admit_group(
        [first, second, Vec::new()]
            .into_iter()
            .map(|raw| (raw, head.clone()))
            .collect(),
    );
    assert_eq!(
        results[0].as_ref().unwrap_err(),
        "Durable admission failed; reconcile after recovery"
    );
    assert_eq!(
        results[1].as_ref().unwrap_err(),
        "Durable admission failed; reconcile after recovery"
    );
    assert_eq!(
        results[2].as_ref().unwrap_err(),
        "Transaction encoding exceeds admission bounds"
    );
    assert!(core.handle.failure().is_some());
    assert_eq!(core.pending.len(), 1);
    assert_eq!(core.prepared.len(), 1);
    assert_eq!(core.head.height, 0);
    drop(core);
    let store = Store::open_existing(&config.data_dir, &config.genesis).unwrap();
    assert_eq!(store.pending().unwrap().len(), 1);
    assert_eq!(store.view().unwrap().pending_counter().unwrap(), 1);
    assert!(store.view().unwrap().status(second_hash).unwrap().is_none());
}
use crate::development;
use alloy_primitives::{Address, U256};

#[test]
fn direct_invalid_worker_factor_cannot_create_or_open_node_data() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = config(directory.path(), 0);
    config.verification_workers_per_cpu = 0;
    assert_eq!(
        super::start(&config).err().unwrap(),
        "Verification workers per CPU must be positive"
    );
    assert!(!config.data_dir.exists());
    if super::preparation::detected_budget().1 > 1 {
        config.verification_workers_per_cpu = usize::MAX;
        assert_eq!(
            super::start(&config).err().unwrap(),
            "Verification worker count overflows platform limit"
        );
        assert!(!config.data_dir.exists());
    }
}

#[test]
fn pending_preparation_mismatch_fails_before_execution_or_commit() {
    let directory = tempfile::tempdir().unwrap();
    let config = config(directory.path(), 0);
    let mut core = core(&config);
    let raw = type2(10, 2);
    let hash = alloy_primitives::keccak256(&raw);
    core.submit(raw).unwrap();
    assert_eq!(core.prepared.len(), 1);
    core.pending[0].raw[0] ^= 1;
    let error = core.produce().unwrap_err();
    assert!(error.contains("cache binding mismatch"));
    assert!(core.handle.failure().is_some());
    assert_eq!(core.head.height, 0);
    assert_eq!(core.handle.metrics().execution.samples, 0);
    assert_eq!(core.handle.metrics().durable_block_commit.samples, 0);
    assert!(core.handle.view().unwrap().receipt(hash).unwrap().is_none());
}
