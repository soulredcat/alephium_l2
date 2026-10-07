//! Capacity is chain identity, not a mutable machine tuning knob.
use super::{Store, block, records};
use crate::{development, execution, protocol::*};
use alloy_primitives::{Address, B256, U256, b256};

#[test]
fn default_identity_is_exact_and_each_extended_limit_is_bound() {
    let genesis = development::genesis();
    let default = records::genesis_bytes(&genesis).unwrap();
    // Independently pinned pre-extension schema-2 default fixture identity.
    assert_eq!(
        records::identity(&default),
        b256!("04599fe2667b810a96578fb7ff9c967cfa46b569ac4042da277e67ee86e63973")
    );
    for capacity in [
        Capacity {
            block_gas: BLOCK_GAS * 2,
            ..Capacity::default()
        },
        Capacity {
            block_bytes: BLOCK_BYTES * 2,
            ..Capacity::default()
        },
        Capacity {
            max_pending: 10_000,
            ..Capacity::default()
        },
    ] {
        let mut extended = genesis.clone();
        extended.capacity = capacity;
        let bytes = records::genesis_bytes(&extended).unwrap();
        assert!(bytes.starts_with(&default));
        assert_ne!(records::identity(&bytes), records::identity(&default));
    }
}

#[test]
fn profile_pending_bound_and_reopen_mismatch_are_enforced() {
    let directory = tempfile::tempdir().unwrap();
    let mut genesis = development::genesis();
    genesis.capacity.max_pending = 1;
    let mut store = Store::open(directory.path(), &genesis).unwrap();
    assert_eq!(store.capacity(), genesis.capacity);
    assert_eq!(store.view().unwrap().capacity(), genesis.capacity);
    let raw = development::sign(
        0,
        Some(Address::repeat_byte(0x61)),
        U256::from(1),
        vec![],
        21_000,
    )
    .unwrap();
    let info = execution::inspect(&raw).unwrap();
    let first = Pending {
        hash: info.hash,
        sender: info.sender,
        raw,
    };
    store.admit(first.clone()).unwrap();
    // A distinct identity still cannot exceed this profile's pending count.
    let raw = vec![0x22];
    let other = Pending {
        hash: alloy_primitives::keccak256(&raw),
        sender: Address::repeat_byte(0x62),
        raw,
    };
    assert!(store.admit(other.clone()).is_err());
    assert!(store.view().unwrap().status(other.hash).unwrap().is_none());
    assert_eq!(store.view().unwrap().pending_counter().unwrap(), 1);
    // Canonical duplicates are still reconciled at full capacity.
    assert_eq!(store.admit(first.clone()).unwrap().hash, first.hash);
    let head = store.view().unwrap().head;
    drop(store);

    for changed in [
        Capacity {
            block_gas: BLOCK_GAS + 1,
            ..genesis.capacity
        },
        Capacity {
            block_bytes: BLOCK_BYTES + 1,
            ..genesis.capacity
        },
        Capacity {
            max_pending: 2,
            ..genesis.capacity
        },
        Capacity::default(),
    ] {
        let mut incompatible = genesis.clone();
        incompatible.capacity = changed;
        assert!(Store::open_existing(directory.path(), &incompatible).is_err());
    }
    let reopened = Store::open_existing(directory.path(), &genesis).unwrap();
    assert_eq!(reopened.view().unwrap().head, head);
    assert_eq!(reopened.capacity(), genesis.capacity);
    assert_eq!(reopened.pending().unwrap().len(), 1);
    assert_eq!(
        reopened
            .view()
            .unwrap()
            .pending_nonce(first.sender)
            .unwrap(),
        1
    );
}

#[test]
fn custom_gas_and_payload_profile_commits_and_recovers_exactly() {
    let directory = tempfile::tempdir().unwrap();
    let mut genesis = development::genesis();
    genesis.capacity = Capacity {
        block_gas: BLOCK_GAS * 2,
        block_bytes: BLOCK_BYTES * 2,
        max_pending: 10_000,
    };
    let mut store = Store::open(directory.path(), &genesis).unwrap();
    store
        .enable_capacity(genesis.capacity.producer_checkpoint_bytes().unwrap())
        .unwrap();
    let initial = store.view().unwrap().execution_checkpoint().unwrap();
    assert_eq!(initial.capacity, genesis.capacity);
    assert_eq!(initial.schema, 2);
    let mut default_header = initial.clone();
    default_header.schema = 1;
    default_header.capacity = Capacity::default();
    assert_eq!(
        initial.encode().unwrap().len(),
        default_header.encode().unwrap().len() + 24
    );
    assert_eq!(
        store.checkpoint_capacity().unwrap().0,
        initial.encode().unwrap().len()
    );
    let recipient = Address::repeat_byte(0x63);
    let raw = development::sign(0, Some(recipient), U256::from(7), vec![], 21_000).unwrap();
    let info = execution::inspect(&raw).unwrap();
    store
        .admit(Pending {
            hash: info.hash,
            sender: info.sender,
            raw: raw.clone(),
        })
        .unwrap();
    let view = store.view().unwrap();
    let context = BlockContext {
        number: 1,
        timestamp: view.head.timestamp,
        gas_limit: genesis.capacity.block_gas,
    };
    let executed = execution::execute_block(view.clone(), &[raw], context).unwrap();
    assert_eq!(executed.receipts.len(), 1);
    assert!(executed.rejected.is_empty());
    let commit = BlockCommit {
        parent: view.head.clone(),
        context,
        transactions: vec![info.hash],
        changes: executed.changes,
        receipts: executed.receipts,
        rejected: vec![],
    };
    drop(view);
    assert!(block::validate(&commit).is_err());
    assert!(block::validate_with_capacity(&commit, genesis.capacity).is_ok());
    // A complete logical payload above the legacy 1 MiB bound is validated
    // against the explicit profile, without running a synthetic load test.
    let payload = vec![0u8; BLOCK_BYTES];
    assert!(block::logical_bytes(&commit, [payload.as_slice()].into_iter()).is_err());
    assert!(
        block::logical_bytes_with_capacity(
            &commit,
            [payload.as_slice()].into_iter(),
            genesis.capacity
        )
        .is_ok()
    );
    let committed = store.commit_bounded(commit).unwrap().unwrap();
    let checkpoint = committed.execution_checkpoint().unwrap();
    assert_eq!(checkpoint.capacity, genesis.capacity);
    assert_eq!(
        store.checkpoint_capacity().unwrap().0,
        checkpoint.encode().unwrap().len()
    );
    assert_eq!(
        committed.block(0).unwrap().unwrap().context.gas_limit,
        genesis.capacity.block_gas
    );
    assert_eq!(
        committed.block(1).unwrap().unwrap().context.gas_limit,
        genesis.capacity.block_gas
    );
    assert_eq!(
        committed.account(recipient).unwrap().unwrap().balance,
        U256::from(7)
    );
    let head = committed.head.clone();
    let state = committed.state_digest().unwrap();
    let checkpoint_bytes = checkpoint.encode().unwrap();
    drop(committed);
    drop(store);

    let reopened = Store::open_existing(directory.path(), &genesis).unwrap();
    let recovered = reopened.view().unwrap();
    assert_eq!(recovered.head, head);
    assert_eq!(recovered.state_digest().unwrap(), state);
    assert!(
        recovered.execution_checkpoint().unwrap().encode().unwrap() == checkpoint_bytes,
        "encoded checkpoint changed after restart"
    );
    assert_eq!(recovered.block_hash(1).unwrap(), head.commit_id);
    assert_eq!(
        recovered
            .replay_block(1)
            .unwrap()
            .unwrap()
            .context
            .gas_limit,
        genesis.capacity.block_gas
    );
    assert!(recovered.receipt(info.hash).unwrap().unwrap().success);
    assert_eq!(
        recovered.receipt(info.hash).unwrap().unwrap().block_height,
        1
    );
    assert!(recovered.block_by_hash(B256::ZERO).unwrap().is_none());
}
