use super::super::super::{Store, encoding::key};
use crate::{development, protocol::*};
use alloy_consensus::{SignableTransaction, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, B256, Bytes, TxKind, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;

fn intent(scalar: u64, nonce: u64) -> Pending {
    // Public test scalar only, used in a fresh, isolated development store.
    let signer = PrivateKeySigner::from_bytes(&B256::from(U256::from(scalar))).unwrap();
    let transaction = TxLegacy {
        chain_id: Some(CHAIN_ID),
        nonce,
        gas_price: 1,
        gas_limit: 21_000,
        to: TxKind::Call(Address::repeat_byte(0x73)),
        value: U256::from(1),
        input: Bytes::new(),
    };
    let signature = signer
        .sign_hash_sync(&transaction.signature_hash())
        .expect("fixture signing succeeds");
    let envelope: TxEnvelope = transaction.into_signed(signature).into();
    let raw = envelope.encoded_2718();
    let info = crate::execution::inspect(&raw).unwrap();
    Pending {
        hash: info.hash,
        sender: info.sender,
        raw,
    }
}

fn genesis(pending: &[Pending]) -> Genesis {
    Genesis {
        chain_id: CHAIN_ID,
        capacity: Default::default(),
        accounts: pending
            .iter()
            .map(|item| GenesisAccount {
                address: item.sender,
                balance: U256::from(development::INITIAL_BALANCE),
            })
            .collect(),
    }
}

fn assert_missing(store: &Store, items: &[Pending]) {
    let view = store.view().unwrap();
    for item in items {
        assert!(view.status(item.hash).unwrap().is_none());
        assert!(view.raw_transaction(item.hash).unwrap().is_none());
    }
}

#[test]
fn grouped_intents_and_duplicates_preserve_order_and_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let items = [intent(1, 0), intent(2, 0), intent(3, 0)];
    let genesis = genesis(&items);
    let mut store = Store::open(directory.path(), &genesis).unwrap();
    let original_state = store.state_digest().unwrap();
    let submitted = [items[0].clone(), items[0].clone(), items[1].clone()];
    let statuses = store.admit_batch(&submitted).unwrap();
    assert_eq!(statuses.len(), submitted.len());
    for (status, item) in statuses.iter().zip(&submitted) {
        assert_eq!(status.hash, item.hash);
        assert_eq!(status.status, "durably_accepted");
        assert!(status.block_height.is_none() && status.error.is_none());
    }
    assert_eq!(store.pending().unwrap().len(), 2);
    assert_eq!(store.view().unwrap().pending_counter().unwrap(), 2);
    let next = store
        .admit_batch(&[items[1].clone(), items[2].clone(), items[0].clone()])
        .unwrap();
    assert_eq!(next[0].hash, items[1].hash);
    assert_eq!(next[1].hash, items[2].hash);
    assert_eq!(next[2].hash, items[0].hash);
    assert_eq!(store.view().unwrap().pending_counter().unwrap(), 3);
    assert_eq!(store.state_digest().unwrap(), original_state);
    drop(store);

    let mut reopened = Store::open(directory.path(), &genesis).unwrap();
    let recovered = reopened.pending().unwrap();
    assert_eq!(recovered.len(), 3);
    for (actual, expected) in recovered.iter().zip(&items) {
        assert_eq!(actual.hash, expected.hash);
        assert_eq!(actual.sender, expected.sender);
        assert!(actual.raw == expected.raw, "canonical envelope changed");
        assert_eq!(
            reopened
                .view()
                .unwrap()
                .pending_nonce(expected.sender)
                .unwrap(),
            1
        );
    }
    assert_eq!(
        reopened.admit(items[0].clone()).unwrap().status,
        "durably_accepted"
    );
    assert_eq!(reopened.view().unwrap().pending_counter().unwrap(), 3);
}

#[test]
fn reservation_or_identity_error_writes_no_part_of_group() {
    let directory = tempfile::tempdir().unwrap();
    let items = [intent(1, 0), intent(2, 0), intent(3, 0)];
    let genesis = genesis(&items);
    let mut store = Store::open(directory.path(), &genesis).unwrap();
    store.admit(items[0].clone()).unwrap();

    // The first input is valid, but the second sender is already reserved.
    assert!(
        store
            .admit_batch(&[items[1].clone(), intent(1, 1)])
            .is_err()
    );
    assert_missing(&store, &items[1..]);
    assert_eq!(store.view().unwrap().pending_counter().unwrap(), 1);

    // Two different intents cannot reserve the same sender within the group.
    assert!(
        store
            .admit_batch(&[items[1].clone(), intent(2, 1)])
            .is_err()
    );
    assert_missing(&store, &items[1..]);
    assert_eq!(store.view().unwrap().pending_counter().unwrap(), 1);

    let mut invalid = items[2].clone();
    invalid.hash = B256::ZERO;
    assert!(store.admit_batch(&[items[1].clone(), invalid]).is_err());
    let mut conflicting = items[1].clone();
    conflicting.sender = items[2].sender;
    assert!(store.admit_batch(&[items[1].clone(), conflicting]).is_err());
    assert_missing(&store, &items[1..]);
    assert_eq!(store.pending().unwrap().len(), 1);
    assert_eq!(store.view().unwrap().pending_counter().unwrap(), 1);
    // Ordinary validation errors leave the store usable.
    assert!(store.admit_batch(&items[1..]).is_ok());
}

#[test]
fn ordinal_exhaustion_and_duplicate_only_groups_do_not_write() {
    let directory = tempfile::tempdir().unwrap();
    let items = [intent(1, 0), intent(2, 0), intent(3, 0)];
    let genesis = genesis(&items);
    let mut store = Store::open(directory.path(), &genesis).unwrap();
    store.admit(items[0].clone()).unwrap();
    store
        .items
        .insert([0x03], (u64::MAX - 1).to_be_bytes().to_vec())
        .unwrap();
    assert!(store.admit_batch(&items[1..]).is_err());
    assert_missing(&store, &items[1..]);
    assert_eq!(
        store.view().unwrap().pending_counter().unwrap(),
        u64::MAX - 1
    );

    store.fail_next_commit_for_test();
    assert!(store.admit_batch(&[]).unwrap().is_empty());
    assert_eq!(
        store
            .admit_batch(&[items[0].clone(), items[0].clone()])
            .unwrap()
            .len(),
        2
    );
    // Empty and duplicate-only calls never consume the durable write barrier.
    assert!(store.admit(items[1].clone()).is_err());
    assert!(store.view().is_err());
}

#[test]
fn failed_group_commit_is_terminal_and_publishes_no_success() {
    let directory = tempfile::tempdir().unwrap();
    let items = [intent(1, 0), intent(2, 0), intent(3, 0)];
    let genesis = genesis(&items);
    let mut store = Store::open(directory.path(), &genesis).unwrap();
    store.admit(items[0].clone()).unwrap();
    let original_head = store.view().unwrap().head;
    let original_state = store.state_digest().unwrap();
    let published = store.view().unwrap();
    store.fail_next_commit_for_test();
    assert!(store.admit_batch(&items[1..]).is_err());
    assert!(store.view().is_err());
    assert!(store.pending().is_err());
    assert!(published.status(items[0].hash).is_err());
    assert!(store.admit(items[1].clone()).is_err());
    drop(published);
    drop(store);

    let reopened = Store::open(directory.path(), &genesis).unwrap();
    assert_eq!(reopened.view().unwrap().head, original_head);
    assert_eq!(reopened.state_digest().unwrap(), original_state);
    assert_eq!(reopened.view().unwrap().pending_counter().unwrap(), 1);
    assert_eq!(reopened.pending().unwrap().len(), 1);
    assert_missing(&reopened, &items[1..]);
    assert!(
        reopened
            .view()
            .unwrap()
            .raw_transaction(items[0].hash)
            .unwrap()
            .is_some()
    );
    assert!(
        reopened
            .view()
            .unwrap()
            .get(key(0x23, &2u64.to_be_bytes()))
            .unwrap()
            .is_none()
    );
}
