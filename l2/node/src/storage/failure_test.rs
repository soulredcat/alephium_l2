use super::Store;
use crate::protocol::{CHAIN_ID, Genesis, GenesisAccount, Pending};
use alloy_primitives::{Address, U256, keccak256};

#[test]
fn injected_batch_failure_stops_success_and_reopening_preserves_state() {
    let directory = tempfile::tempdir().unwrap();
    let genesis = Genesis {
        chain_id: CHAIN_ID,
        accounts: vec![GenesisAccount {
            address: Address::repeat_byte(1),
            balance: U256::from(1000),
        }],
    };
    let mut store = Store::open(directory.path(), &genesis).unwrap();
    let original_head = store.view().unwrap().head;
    let original_state = store.state_digest().unwrap();
    let raw = vec![1, 2, 3];
    let hash = keccak256(&raw);
    store.fail_next_commit_for_test();
    assert!(
        store
            .admit(Pending {
                hash,
                sender: Address::repeat_byte(1),
                raw
            })
            .is_err()
    );
    assert!(store.view().is_err());
    assert!(store.pending().is_err());
    drop(store);
    let recovered = Store::open(directory.path(), &genesis).unwrap();
    assert_eq!(recovered.view().unwrap().head, original_head);
    assert_eq!(recovered.state_digest().unwrap(), original_state);
    assert!(recovered.pending().unwrap().is_empty());
    assert!(recovered.view().unwrap().status(hash).unwrap().is_none());
    assert!(
        recovered
            .view()
            .unwrap()
            .raw_transaction(hash)
            .unwrap()
            .is_none()
    );
}
