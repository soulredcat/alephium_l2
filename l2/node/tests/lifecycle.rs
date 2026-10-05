//! One durable Cancun lifecycle flow, using independent hand-authored opcode expectations.
#[path = "support/lifecycle_fixture.rs"]
mod fixture;

use alephium_l2_node::{
    development, operator,
    protocol::GenesisAccount,
    storage::{ReadView, Store},
};
use alloy_primitives::{Address, U256, keccak256};
use fixture::{commit, context, destroy_init, init, input, runtime, second_address, sign_second};

#[test]
fn contract_lifecycle_deltas_survive_restart_and_semantic_replay() -> Result<(), String> {
    let owned = tempfile::Builder::new()
        .prefix("l2-c6-lifecycle-")
        .tempdir()
        .map_err(|error| error.to_string())?;
    let source = owned.path().join("source");
    let sender = development::address();
    let second = second_address();
    let contract = sender.create(0);
    let empty_contract = second.create(0);
    let destroyed_contract = second.create(3);
    let beneficiary = Address::from([0x66; 20]);
    let initial = U256::from(development::INITIAL_BALANCE);
    let mut genesis = development::genesis();
    genesis.accounts.push(GenesisAccount {
        address: second,
        balance: initial,
    });
    let mut store = Store::open(&source, &genesis)?;

    let mut receipts = commit(
        &mut store,
        &[
            development::sign(0, None, U256::from(1_000), init(), 300_000)?,
            // RETURN an empty runtime. EIP-161 creation nonce 1 prevents empty clearing.
            sign_second(0, None, U256::ZERO, vec![0x60, 0, 0x60, 0, 0xf3], 100_000)?,
        ],
        1,
    )?;
    assert_eq!(receipts[0].contract, Some(contract));
    assert_eq!(receipts[1].contract, Some(empty_contract));
    let created = store.view()?;
    let empty = created
        .account(empty_contract)?
        .ok_or("empty deployment disappeared")?;
    assert_eq!(empty.nonce, 1);
    assert_eq!(empty.balance, U256::ZERO);
    assert_eq!(empty.code_hash, keccak256([]));
    assert!(created.code(empty.code_hash)?.is_empty());
    assert_eq!(
        created.account(contract)?.ok_or("missing contract")?.nonce,
        1
    );
    drop(created);

    // The second transaction rereads the first transaction's write from the private overlay.
    // Both slots must survive normalization even when REVM rebaselines the first slot.
    receipts.extend(commit(
        &mut store,
        &[
            development::sign(
                1,
                Some(contract),
                U256::ZERO,
                input(1, U256::from(7)),
                100_000,
            )?,
            sign_second(1, Some(contract), U256::ZERO, input(2, U256::ZERO), 100_000)?,
        ],
        2,
    )?);
    assert_slots(&store.view()?, contract, 7, 7)?;

    // Zero writes delete old logical slot records; the same-block reread observes zero.
    receipts.extend(commit(
        &mut store,
        &[
            development::sign(2, Some(contract), U256::ZERO, input(1, U256::ZERO), 100_000)?,
            sign_second(2, Some(contract), U256::ZERO, input(2, U256::ZERO), 100_000)?,
        ],
        3,
    )?);
    let cleared = store.view()?;
    assert_slots(&cleared, contract, 0, 0)?;
    // A digest rejects noncanonical persisted zero slots as well as checking logical state.
    cleared.state_digest()?;
    drop(cleared);

    receipts.extend(commit(
        &mut store,
        &[
            development::sign(
                3,
                Some(contract),
                U256::ZERO,
                input(1, U256::from(9)),
                100_000,
            )?,
            sign_second(3, None, U256::from(333), destroy_init(beneficiary), 100_000)?,
        ],
        4,
    )?);
    let destroyed = store.view()?;
    assert!(destroyed.account(destroyed_contract)?.is_none());
    assert_eq!(destroyed.slot(destroyed_contract, U256::ZERO)?, U256::ZERO);
    assert_eq!(
        destroyed
            .account(beneficiary)?
            .ok_or("missing beneficiary")?
            .balance,
        U256::from(333)
    );
    assert_slots(&destroyed, contract, 9, 0)?;
    drop(destroyed);

    // EIP-6780: an older contract transfers balance but retains code/storage/nonce.
    // A distinct sender calls it afterward in this block, proving overlay retention too.
    receipts.extend(commit(
        &mut store,
        &[
            development::sign(
                4,
                Some(contract),
                U256::ZERO,
                input(3, U256::from_be_slice(beneficiary.as_slice())),
                100_000,
            )?,
            sign_second(4, Some(contract), U256::ZERO, input(2, U256::ZERO), 100_000)?,
        ],
        5,
    )?);
    assert_eq!(receipts.len(), 10);
    let fee_for = |address| -> U256 {
        receipts
            .iter()
            .filter(|receipt| receipt.from == address)
            .map(|receipt| U256::from(receipt.gas_used) * U256::from(receipt.gas_price))
            .sum()
    };
    let sender_fees = fee_for(sender);
    let second_fees = fee_for(second);
    let final_view = store.view()?;
    assert_final_state(
        &final_view,
        contract,
        empty_contract,
        destroyed_contract,
        beneficiary,
    )?;
    assert_eq!(
        final_view.account(sender)?.ok_or("missing sender")?.nonce,
        5
    );
    assert_eq!(
        final_view
            .account(second)?
            .ok_or("missing second sender")?
            .nonce,
        5
    );
    assert_eq!(
        final_view.account(sender)?.ok_or("missing sender")?.balance,
        initial - U256::from(1_000) - sender_fees
    );
    assert_eq!(
        final_view
            .account(second)?
            .ok_or("missing second sender")?
            .balance,
        initial - U256::from(333) - second_fees
    );
    assert_eq!(
        final_view
            .account(Address::ZERO)?
            .ok_or("missing fee recipient")?
            .balance,
        sender_fees + second_fees
    );
    for (index, receipt) in receipts.iter().enumerate() {
        assert_eq!(receipt.block_height, index as u64 / 2 + 1);
        assert_eq!(receipt.transaction_index, index as u64 % 2);
        assert_eq!(receipt.gas_price, 1);
        assert!(receipt.gas_used > 0);
        assert!(receipt.logs.is_empty());
    }
    let head = final_view.head.clone();
    let digest = final_view.state_digest()?;
    assert_eq!(head.height, 5);
    assert_eq!(head.timestamp, context(5).timestamp);
    drop(final_view);
    drop(store);

    let reopened = Store::open_existing(&source, &genesis)?;
    let reopened_view = reopened.view()?;
    assert_eq!(reopened_view.head, head);
    assert_eq!(reopened_view.state_digest()?, digest);
    assert_final_state(
        &reopened_view,
        contract,
        empty_contract,
        destroyed_contract,
        beneficiary,
    )?;
    for receipt in &receipts {
        assert_eq!(reopened_view.receipt(receipt.hash)?.as_ref(), Some(receipt));
    }
    drop(reopened_view);
    drop(reopened);

    // Reuse C4's immutable backup and signed-input reexecution; do not replay recorded deltas.
    let backup = owned.path().join("backup");
    let work = owned.path().join("replay");
    operator::backup(&source, &backup, &genesis)?;
    let replay = operator::verify_replay(&backup, &genesis, &work)?;
    assert_eq!(replay.head, head);
    assert_eq!(replay.state_digest, digest);
    assert_eq!(replay.blocks, 5);
    assert_eq!(replay.executed_transactions, 10);
    assert_eq!(replay.pending_count, 0);
    let replayed = Store::open_existing(&work.join("replayed"), &genesis)?;
    assert_final_state(
        &replayed.view()?,
        contract,
        empty_contract,
        destroyed_contract,
        beneficiary,
    )?;
    Ok(())
}

fn assert_slots(view: &ReadView, contract: Address, first: u64, second: u64) -> Result<(), String> {
    assert_eq!(view.slot(contract, U256::ZERO)?, U256::from(first));
    assert_eq!(view.slot(contract, U256::from(1))?, U256::from(second));
    Ok(())
}

fn assert_final_state(
    view: &ReadView,
    contract: Address,
    empty_contract: Address,
    destroyed_contract: Address,
    beneficiary: Address,
) -> Result<(), String> {
    let retained = view
        .account(contract)?
        .ok_or("older contract was deleted")?;
    assert_eq!(retained.balance, U256::ZERO);
    assert_eq!(retained.nonce, 1);
    assert_eq!(retained.code_hash, keccak256(runtime()));
    assert!(view.code(retained.code_hash)? == runtime());
    assert_slots(view, contract, 9, 9)?;
    let empty = view
        .account(empty_contract)?
        .ok_or("empty-runtime contract was deleted")?;
    assert_eq!(empty.nonce, 1);
    assert_eq!(empty.balance, U256::ZERO);
    assert_eq!(empty.code_hash, keccak256([]));
    assert!(view.account(destroyed_contract)?.is_none());
    assert_eq!(view.slot(destroyed_contract, U256::ZERO)?, U256::ZERO);
    assert_eq!(
        view.account(beneficiary)?
            .ok_or("missing beneficiary")?
            .balance,
        U256::from(1_333)
    );
    Ok(())
}
