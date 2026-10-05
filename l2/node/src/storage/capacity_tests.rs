//! The tracked checkpoint size must equal the real encoding after each commit.
use super::{CapacityExceeded, Store};
use crate::{development, execution, protocol::*};
use alloy_primitives::{Address, U256, keccak256};

const GAS: u64 = 1_000_000;

fn block(store: &mut Store, raw: Vec<u8>) -> Result<Receipt, CapacityExceeded> {
    block_with(store, raw, Vec::new())
}

/// Commits `raw` with `extra` appended to its changes. Store::commit trusts
/// execution for changes, so this reaches lifecycles Cancun cannot produce.
fn block_with(
    store: &mut Store,
    raw: Vec<u8>,
    extra: Vec<AccountChange>,
) -> Result<Receipt, CapacityExceeded> {
    let info = execution::inspect(&raw).unwrap();
    let pending = Pending {
        hash: info.hash,
        sender: info.sender,
        raw: raw.clone(),
    };
    store.admit(pending).unwrap();
    let view = store.view().unwrap();
    let context = BlockContext {
        number: view.head.height + 1,
        timestamp: view.head.timestamp,
        gas_limit: BLOCK_GAS,
    };
    let result = execution::execute_block(view.clone(), &[raw], context).unwrap();
    assert!(result.rejected.is_empty());
    let receipt = result.receipts[0].clone();
    let mut changes = result.changes;
    changes.extend(extra);
    let committed = store
        .commit_bounded(BlockCommit {
            parent: view.head.clone(),
            context,
            transactions: vec![receipt.hash],
            changes,
            receipts: result.receipts,
            rejected: Vec::new(),
        })
        .unwrap();
    committed.map(|_| receipt)
}

fn exact(store: &Store) -> usize {
    let actual = store.view().unwrap().execution_checkpoint().unwrap();
    let actual = actual.encode().unwrap().len();
    assert_eq!(store.checkpoint_capacity().unwrap().0, actual);
    actual
}

struct Signer(u64);

impl Signer {
    fn next(&mut self, to: Option<Address>, value: u64, data: Vec<u8>) -> Vec<u8> {
        self.0 += 1;
        development::sign(self.0 - 1, to, U256::from(value), data, GAS).unwrap()
    }

    /// Address of the contract this signer creates at nonce `ahead` from now.
    fn future_contract(&self, ahead: u64) -> Address {
        development::address().create(self.0 + ahead)
    }
}

fn open(directory: &tempfile::TempDir, limit: usize) -> Store {
    let mut store = Store::open(&directory.path().join("data"), &development::genesis()).unwrap();
    store.enable_capacity(limit).unwrap();
    store
}

#[test]
fn tracked_size_matches_the_encoded_checkpoint() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = open(&directory, usize::MAX);
    exact(&store);
    let mut signer = Signer(0);
    let recipient = Address::repeat_byte(0x71);
    let run = |store: &mut Store, raw: Vec<u8>| {
        let receipt = block(store, raw).unwrap();
        assert!(receipt.success);
        exact(store);
        receipt
    };
    // New recipient and the zero-address fee beneficiary.
    run(&mut store, signer.next(Some(recipient), 1, vec![]));
    // Code is counted once even when several accounts share it.
    let mut shared = Vec::new();
    for _ in 0..2 {
        let created = run(
            &mut store,
            signer.next(None, 0, development::contract_init()),
        );
        shared.push(created.contract.unwrap());
    }
    let fixture = shared[0];
    // A new slot, then a contract whose constructor sets a slot its runtime clears.
    run(
        &mut store,
        signer.next(Some(fixture), 0, development::contract_input(1, None)),
    );
    let clearing = hex::decode("60016000556006601160003960066000f3600060005500").unwrap();
    let clearing = run(&mut store, signer.next(None, 0, clearing))
        .contract
        .unwrap();
    run(&mut store, signer.next(Some(clearing), 0, vec![]));
    // Creation at a pre-funded live address resets its storage epoch, both
    // when the new contract self-destructs and when it is kept.
    for (init, kept) in [
        (vec![0x33, 0xff], false),
        (development::contract_init(), true),
    ] {
        let target = signer.future_contract(1);
        run(&mut store, signer.next(Some(target), 1, vec![]));
        let created = run(&mut store, signer.next(None, 0, init));
        assert_eq!(created.contract, Some(target));
        if kept {
            shared.push(target);
        }
    }
    // Zero-value calls to a fresh address and to a precompile add nothing.
    for target in [Address::repeat_byte(0x72), Address::with_last_byte(2)] {
        let input = development::contract_input(3, Some(target));
        run(&mut store, signer.next(Some(fixture), 0, input));
    }
    // Defensive lifecycles Cancun cannot reach: a storage reset of a live
    // account holding slots, then removal of every account sharing one code.
    let code_hash = keccak256(development::contract_runtime());
    let reset = AccountChange {
        address: fixture,
        balance: U256::ZERO,
        nonce: 1,
        code_hash,
        code: None,
        deleted: false,
        storage_reset: true,
        slots: vec![(U256::from(1), U256::from(7))],
    };
    let mut extras = vec![reset];
    for address in &shared {
        extras.push(AccountChange {
            address: *address,
            deleted: true,
            storage_reset: true,
            ..Default::default()
        });
    }
    for extra in extras {
        let raw = signer.next(Some(recipient), 1, vec![]);
        block_with(&mut store, raw, vec![extra]).unwrap();
        exact(&store);
    }
    let checkpoint = store.view().unwrap().execution_checkpoint().unwrap();
    assert!(checkpoint.codes.iter().all(|code| code.hash != code_hash));
    // The historical block hash window stops growing after 256 entries.
    while store.view().unwrap().head.height < 258 {
        let raw = signer.next(Some(recipient), 1, vec![]);
        block(&mut store, raw).unwrap();
        let height = store.view().unwrap().head.height;
        if height >= 254 {
            exact(&store);
        }
    }
}

#[test]
fn a_block_over_the_bound_is_refused_without_writing() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = open(&directory, usize::MAX);
    let mut signer = Signer(0);
    let recipient = Address::repeat_byte(0x73);
    block(&mut store, signer.next(Some(recipient), 1, vec![])).unwrap();
    let used = exact(&store);
    drop(store);
    // Room for one more block hash entry plus 104 bytes: less than a new account.
    let mut store = open(&directory, used + 40 + 104);
    let head = store.view().unwrap().head;
    let fresh = signer.next(Some(Address::repeat_byte(0x74)), 1, vec![]);
    let hash = execution::inspect(&fresh).unwrap().hash;
    assert_eq!(block(&mut store, fresh), Err(CapacityExceeded));
    assert_eq!(store.view().unwrap().head, head);
    assert_eq!(store.checkpoint_capacity(), Some((used, used + 144)));
    assert_eq!(store.pending().unwrap().len(), 1);
    store.discard(hash, "state capacity exhausted").unwrap();
    // A transfer between existing accounts only adds the block hash entry.
    signer.0 -= 1;
    block(&mut store, signer.next(Some(recipient), 1, vec![])).unwrap();
    assert_eq!(exact(&store), used + 40);
    drop(store);
    let error = Store::open(&directory.path().join("data"), &development::genesis())
        .unwrap()
        .enable_capacity(used + 39)
        .unwrap_err();
    assert!(error.contains("already exceeds"), "{error}");
}
