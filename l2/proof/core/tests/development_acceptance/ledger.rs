//! Exact integer ledger and contract-state checks after independent portable execution.
use super::{TOTAL, TRANSFERS};
use alephium_l2_transition_core::{
    CheckpointTransitionBundle,
    protocol::{Genesis, checkpoint::ExecutionCheckpoint},
};
use alloy_primitives::{Address, B256, U256, keccak256};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Deserialize)]
struct WalletTransfer {
    sender: Address,
    nonce: u64,
    to: Address,
    value: U256,
    gas_limit: u64,
    gas_price: u128,
    input_keccak: B256,
}

#[derive(Deserialize)]
pub(super) struct UnsignedPlan {
    pub(super) genesis: Genesis,
    total_transactions: usize,
    setup_transactions: usize,
    wallet_transfers: Vec<WalletTransfer>,
    root_transactions: Vec<Value>,
}

pub(super) fn verify(
    plan: &UnsignedPlan,
    bundle: &CheckpointTransitionBundle,
    checkpoint: &ExecutionCheckpoint,
) -> (u64, U256) {
    assert!(plan.total_transactions == TOTAL && plan.setup_transactions == 0);
    assert!(plan.wallet_transfers.len() == TRANSFERS && plan.root_transactions.len() == 4);
    let senders: BTreeSet<_> = plan
        .wallet_transfers
        .iter()
        .map(|item| item.sender)
        .collect();
    assert!(senders.len() == TRANSFERS);
    let roots: Vec<_> = plan
        .genesis
        .accounts
        .iter()
        .filter(|a| !senders.contains(&a.address))
        .collect();
    assert!(roots.len() == 1, "exactly one development root allocation");
    let root = roots[0];
    let contract_address = root.address.create(1);
    let root_recipient: Address = serde_json::from_value(plan.root_transactions[0]["to"].clone())
        .unwrap_or_else(|_| panic!("unsigned root recipient rejected"));
    let accounts: BTreeMap<_, _> = checkpoint.accounts.iter().map(|a| (a.address, a)).collect();
    let allocations: BTreeMap<_, _> = plan
        .genesis
        .accounts
        .iter()
        .map(|a| (a.address, a.balance))
        .collect();
    let mut fees = U256::ZERO;
    let mut root_fees = U256::ZERO;
    let mut gas = 0_u64;
    let mut receipt_ids = BTreeSet::new();
    let mut root_receipts = Vec::new();
    let mut wallet_receipts = BTreeMap::new();
    for input in bundle.blocks.iter().flat_map(|block| &block.transactions) {
        // prove_input has independently executed and compared every retained receipt.
        let receipt = &input.expected_receipt;
        assert!(receipt_ids.insert(receipt.hash) && receipt.hash == input.transaction_hash);
        gas = gas.checked_add(receipt.gas_used).expect("exact gas sum");
        let fee = U256::from(receipt.gas_used)
            .checked_mul(U256::from(receipt.gas_price))
            .expect("exact transaction fee");
        fees = fees.checked_add(fee).expect("exact total fees");
        if receipt.from == root.address {
            root_fees = root_fees.checked_add(fee).expect("exact root fees");
            root_receipts.push(receipt);
        } else {
            assert!(wallet_receipts.insert(receipt.from, receipt).is_none());
        }
    }
    assert!(receipt_ids.len() == TOTAL && wallet_receipts.len() == TRANSFERS);
    for intent in &plan.wallet_transfers {
        let sender = accounts.get(&intent.sender).expect("final funded wallet");
        let receiver = accounts.get(&intent.to).expect("final wallet recipient");
        let receipt = wallet_receipts.get(&intent.sender).expect("wallet receipt");
        assert!(intent.nonce == 0 && intent.gas_limit == 21_000 && intent.gas_price == 1);
        assert!(intent.input_keccak == keccak256([]));
        assert!(receipt.success && receipt.to == Some(intent.to) && receipt.gas_used == 21_000);
        assert!(receipt.gas_price == 1 && receipt.contract.is_none() && receipt.logs.is_empty());
        let balance = allocations[&intent.sender]
            .checked_sub(intent.value)
            .and_then(|balance| balance.checked_sub(U256::from(21_000)))
            .expect("wallet integer debits");
        assert!(sender.balance == balance && sender.nonce == 1 && sender.slots.is_empty());
        assert!(
            receiver.balance == intent.value && receiver.nonce == 0 && receiver.slots.is_empty()
        );
        assert!(
            (sender.code_hash == keccak256([]) || sender.code_hash == B256::ZERO)
                && (receiver.code_hash == keccak256([]) || receiver.code_hash == B256::ZERO)
        );
    }
    assert!(root_receipts.len() == 4);
    assert!(root_receipts[0].to == Some(root_recipient) && root_receipts[0].success);
    assert!(root_receipts[1].contract == Some(contract_address) && root_receipts[1].success);
    assert!(root_receipts[2].to == Some(contract_address) && root_receipts[2].logs.len() == 1);
    assert!(!root_receipts[3].success && root_receipts[3].logs.is_empty());
    let root_account = accounts[&root.address];
    let root_balance = root
        .balance
        .checked_sub(U256::from(1_000))
        .and_then(|balance| balance.checked_sub(root_fees))
        .expect("root integer debits");
    assert!(root_account.balance == root_balance && root_account.nonce == 4);
    assert!(accounts[&root_recipient].balance == U256::from(1_000));
    let contract = accounts[&contract_address];
    assert!(contract.balance.is_zero() && contract.nonce == 1);
    assert!(contract.slots.len() == 1 && contract.slots[0].key.is_zero());
    assert!(contract.slots[0].value == U256::from(42));
    assert!(checkpoint.codes.len() == 1 && contract.code_hash == checkpoint.codes[0].hash);
    assert!(accounts[&Address::ZERO].balance == fees && accounts[&Address::ZERO].nonce == 0);
    assert!(checkpoint.accounts.iter().all(|account| {
        !account.deleted && (account.address == contract_address || account.slots.is_empty())
    }));
    (gas, fees)
}
