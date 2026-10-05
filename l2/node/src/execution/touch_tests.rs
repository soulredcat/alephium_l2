//! EIP-161 removal of an absent account must not create a persistent record.
use crate::{development, execution, protocol::*, storage::Store};
use alloy_primitives::{Address, U256};

fn execute(store: &mut Store, nonce: u64, to: Option<Address>, data: Vec<u8>) -> Receipt {
    let raw = development::sign(nonce, to, U256::ZERO, data, 200_000).unwrap();
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
        number: view.head.height + 1,
        timestamp: view.head.timestamp,
        gas_limit: BLOCK_GAS,
    };
    let result = execution::execute_block(view.clone(), &[raw], context).unwrap();
    let receipt = result.receipts[0].clone();
    assert!(receipt.success);
    store
        .commit(BlockCommit {
            parent: view.head.clone(),
            context,
            transactions: vec![receipt.hash],
            changes: result.changes,
            receipts: result.receipts,
            rejected: result.rejected,
        })
        .unwrap();
    receipt
}

fn recorded(store: &Store, address: Address) -> bool {
    let checkpoint = store.view().unwrap().execution_checkpoint().unwrap();
    checkpoint
        .accounts
        .iter()
        .any(|account| account.address == address)
}

#[test]
fn touching_an_absent_account_leaves_no_record() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = Store::open(&directory.path().join("data"), &development::genesis()).unwrap();
    let fixture = execute(&mut store, 0, None, development::contract_init())
        .contract
        .unwrap();
    // Top-level zero-value transfer to a fresh address.
    let fresh = Address::repeat_byte(0x51);
    execute(&mut store, 1, Some(fresh), vec![]);
    // Zero-value CALL from a contract to a fresh address and to a precompile.
    let called = Address::repeat_byte(0x52);
    let sha256 = Address::with_last_byte(2);
    for (nonce, target) in [(2, called), (3, sha256)] {
        let input = development::contract_input(3, Some(target));
        execute(&mut store, nonce, Some(fixture), input);
    }
    // A contract created and self-destructed in one transaction (EIP-6780).
    let destroyed = execute(&mut store, 4, None, vec![0x33, 0xff])
        .contract
        .unwrap();
    for address in [fresh, called, sha256, destroyed] {
        assert!(!recorded(&store, address), "{address} must stay absent");
        assert!(store.view().unwrap().account(address).unwrap().is_none());
    }
    // Existing accounts still persist their changes.
    assert!(recorded(&store, fixture));
    assert!(recorded(&store, development::address()));
    // Restart validation replays the retained commits over the same records.
    drop(store);
    let store = Store::open(&directory.path().join("data"), &development::genesis()).unwrap();
    assert!(!recorded(&store, fresh));
}
