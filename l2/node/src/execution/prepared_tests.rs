use super::{
    ExecutionBatch, execute_block, execute_prepared_block, prepare_for_chain, validate,
    validate_prepared,
};
use crate::{development, protocol::*, storage::Store};
use alloy_eips::eip2930::AccessList;
use alloy_primitives::{Address, U256};

fn context(store: &Store) -> BlockContext {
    let view = store.view().unwrap();
    BlockContext {
        number: view.head.height + 1,
        timestamp: view.head.timestamp,
        gas_limit: view.capacity().block_gas,
    }
}

fn assert_same(left: &ExecutionBatch, right: &ExecutionBatch) {
    assert_eq!(left.receipts, right.receipts);
    assert_eq!(left.rejected, right.rejected);
    assert_eq!(left.changes.len(), right.changes.len());
    for (left, right) in left.changes.iter().zip(&right.changes) {
        assert_eq!(left.address, right.address);
        assert_eq!(left.balance, right.balance);
        assert_eq!(left.nonce, right.nonce);
        assert_eq!(left.code_hash, right.code_hash);
        assert_eq!(left.code, right.code);
        assert_eq!(left.deleted, right.deleted);
        assert_eq!(left.storage_reset, right.storage_reset);
        assert_eq!(left.slots, right.slots);
    }
}

#[test]
fn prepared_and_raw_share_transfer_contract_revert_and_state_rejection_results() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(&directory.path().join("data"), &development::genesis()).unwrap();
    let contract = development::address().create(1);
    let raw = vec![
        development::sign(
            0,
            Some(Address::repeat_byte(0x91)),
            U256::from(7),
            vec![],
            21_000,
        )
        .unwrap(),
        development::sign_type2(
            1,
            None,
            U256::ZERO,
            development::contract_init(),
            200_000,
            5,
            2,
            AccessList::default(),
        )
        .unwrap(),
        development::sign(
            2,
            Some(contract),
            U256::ZERO,
            development::contract_input(1, None),
            200_000,
        )
        .unwrap(),
        development::sign(
            3,
            Some(contract),
            U256::ZERO,
            development::contract_input(2, None),
            200_000,
        )
        .unwrap(),
        // Canonical/signature-valid, but nonce 3 is stale in the evolving overlay.
        development::sign(3, Some(contract), U256::ZERO, vec![], 21_000).unwrap(),
    ];
    let prepared: Vec<_> = raw
        .iter()
        .map(|raw| prepare_for_chain(raw, CHAIN_ID).unwrap())
        .collect();
    let view = store.view().unwrap();
    let raw_result = execute_block(view.clone(), &raw, context(&store)).unwrap();
    let cached_result = execute_prepared_block(view, &prepared, context(&store)).unwrap();
    assert_same(&raw_result, &cached_result);
    assert_eq!(cached_result.receipts.len(), 4);
    assert!(cached_result.receipts[0].success);
    assert_eq!(cached_result.receipts[1].contract, Some(contract));
    assert_eq!(cached_result.receipts[1].gas_price, 2);
    assert_eq!(cached_result.receipts[2].logs.len(), 1);
    assert!(!cached_result.receipts[3].success);
    assert!(cached_result.receipts[3].logs.is_empty());
    assert_eq!(cached_result.rejected.len(), 1);
}

#[test]
fn prepared_validation_uses_current_nonce_and_never_changes_the_view() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = Store::open(&directory.path().join("data"), &development::genesis()).unwrap();
    let raw = development::sign(
        0,
        Some(Address::repeat_byte(0x92)),
        U256::ONE,
        vec![],
        21_000,
    )
    .unwrap();
    let prepared = prepare_for_chain(&raw, CHAIN_ID).unwrap();
    let view = store.view().unwrap();
    let before = view.account(development::address()).unwrap();
    let checked = validate_prepared(view.clone(), &prepared, context(&store)).unwrap();
    assert_eq!(
        checked.hash,
        validate(view.clone(), &raw, context(&store)).unwrap().hash
    );
    assert_eq!(view.account(development::address()).unwrap(), before);
    store
        .admit(Pending {
            hash: checked.hash,
            sender: checked.sender,
            raw,
        })
        .unwrap();
    let result = execute_prepared_block(
        view.clone(),
        std::slice::from_ref(&prepared),
        context(&store),
    )
    .unwrap();
    store
        .commit(BlockCommit {
            parent: view.head.clone(),
            context: context(&store),
            transactions: result.receipts.iter().map(|receipt| receipt.hash).collect(),
            changes: result.changes,
            receipts: result.receipts,
            rejected: result.rejected,
        })
        .unwrap();
    let latest = store.view().unwrap();
    let before = latest.account(development::address()).unwrap();
    let error = validate_prepared(latest.clone(), &prepared, context(&store)).unwrap_err();
    assert!(error.starts_with("invalid transaction:"));
    assert_eq!(latest.account(development::address()).unwrap(), before);
    let result = execute_prepared_block(latest, &[prepared], context(&store)).unwrap();
    assert!(result.receipts.is_empty());
    assert!(result.changes.is_empty());
    assert_eq!(result.rejected.len(), 1);
}

#[test]
fn prepared_identity_binds_exact_bytes_and_chain_and_canonical_decode_is_unchanged() {
    let raw = development::sign(
        0,
        Some(Address::repeat_byte(0x93)),
        U256::ONE,
        vec![],
        21_000,
    )
    .unwrap();
    let prepared = prepare_for_chain(&raw, CHAIN_ID).unwrap();
    assert!(prepared.matches(&raw, CHAIN_ID));
    assert!(!prepared.matches(&raw, CHAIN_ID + 1));
    let mut different = raw.clone();
    different.push(0);
    assert!(!prepared.matches(&different, CHAIN_ID));
    assert_eq!(
        prepare_for_chain(&different, CHAIN_ID).err(),
        super::inspect_for_chain(&different, CHAIN_ID).err()
    );
    assert!(prepare_for_chain(&raw, CHAIN_ID + 1).is_err());
    let directory = tempfile::tempdir().unwrap();
    let genesis = development::genesis_for_chain(CHAIN_ID + 1).unwrap();
    let store = Store::open(&directory.path().join("data"), &genesis).unwrap();
    let error = validate_prepared(store.view().unwrap(), &prepared, context(&store)).unwrap_err();
    assert_eq!(error, "prepared transaction belongs to a different chain");
    assert!(super::is_infrastructure_error(&error));
    assert!(execute_prepared_block(store.view().unwrap(), &[prepared], context(&store)).is_err());
}
