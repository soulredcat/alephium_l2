use crate::{
    block::StoredChange,
    canonical,
    journal::TransferAccounting,
    protocol::{Account, AccountChange, Genesis, Receipt},
};
use alloy_primitives::{Address, B256, U256, keccak256};
use std::collections::BTreeMap;

/// Complete small genesis state, followed by production-normalized writes.
/// No sparse witness, externally supplied account or hidden state is accepted.
#[derive(Clone)]
pub(crate) struct NativeState {
    accounts: BTreeMap<Address, Account>,
}

impl NativeState {
    pub(crate) fn genesis(genesis: &Genesis) -> Result<Self, String> {
        genesis.validate()?;
        let accounts = genesis
            .accounts
            .iter()
            .filter(|account| !account.balance.is_zero())
            .map(|account| {
                (
                    account.address,
                    Account {
                        balance: account.balance,
                        code_hash: keccak256([]),
                        ..Default::default()
                    },
                )
            })
            .collect();
        Ok(Self { accounts })
    }

    pub(crate) fn accounts(&self) -> &BTreeMap<Address, Account> {
        &self.accounts
    }

    pub(crate) fn account_count(&self) -> u32 {
        self.accounts.len() as u32
    }

    pub(crate) fn balance(&self, address: Address) -> U256 {
        self.accounts
            .get(&address)
            .map_or(U256::ZERO, |account| account.balance)
    }

    pub(crate) fn total_balance(&self) -> Result<U256, String> {
        self.accounts
            .values()
            .try_fold(U256::ZERO, |total, account| {
                total
                    .checked_add(account.balance)
                    .ok_or("native state total balance overflow".into())
            })
    }

    pub(crate) fn digest(&self) -> Result<B256, String> {
        canonical::native_state_digest(&self.accounts)
    }

    /// Match Store::commit's normalization and storage epoch selection. Epochs
    /// bind the local commit but are excluded from the logical state digest.
    pub(crate) fn apply(&mut self, changes: &[AccountChange]) -> Result<Vec<StoredChange>, String> {
        let mut stored = Vec::with_capacity(changes.len());
        for change in changes {
            if change.code.is_some()
                || !change.slots.is_empty()
                || (!change.deleted
                    && change.code_hash != B256::ZERO
                    && change.code_hash != keccak256([]))
            {
                return Err("native proof excludes code and storage state".into());
            }
            let mut change = change.clone();
            let mut epoch = self
                .accounts
                .get(&change.address)
                .map_or(0, |account| account.storage_epoch);
            if change.storage_reset || change.deleted {
                epoch = epoch.checked_add(1).ok_or("storage epoch exhausted")?;
            }
            if change.deleted {
                change.balance = U256::ZERO;
                change.nonce = 0;
                change.code_hash = B256::ZERO;
                self.accounts.remove(&change.address);
            } else {
                self.accounts.insert(
                    change.address,
                    Account {
                        balance: change.balance,
                        nonce: change.nonce,
                        code_hash: change.code_hash,
                        storage_epoch: epoch,
                    },
                );
            }
            stored.push(StoredChange { change, epoch });
        }
        Ok(stored)
    }
}

/// Independently check exact balances, nonce and conservation after REVM, with
/// aliases handled by ordered debit/credit rather than assumed distinct actors.
pub(crate) fn check_accounting(
    before: &NativeState,
    after: &NativeState,
    receipt: &Receipt,
    value: U256,
    beneficiary: Address,
) -> Result<TransferAccounting, String> {
    let recipient = receipt.to.ok_or("native receipt has no recipient")?;
    let fee = U256::from(receipt.gas_used)
        .checked_mul(U256::from(receipt.gas_price))
        .ok_or("native gas fee overflow")?;
    let debit = value
        .checked_add(fee)
        .ok_or("native sender debit overflow")?;
    let mut expected = before.clone();
    let sender = expected
        .accounts
        .get_mut(&receipt.from)
        .ok_or("native sender is absent from funded genesis")?;
    sender.balance = sender
        .balance
        .checked_sub(debit)
        .ok_or("native sender underflow")?;
    sender.nonce = sender
        .nonce
        .checked_add(1)
        .ok_or("native sender nonce overflow")?;
    credit(&mut expected, recipient, value)?;
    credit(&mut expected, beneficiary, fee)?;
    if expected.accounts.len() != after.accounts.len()
        || expected.accounts.iter().any(|(address, account)| {
            after.accounts.get(address).is_none_or(|actual| {
                actual.balance != account.balance
                    || actual.nonce != account.nonce
                    || actual.code_hash != account.code_hash
            })
        })
        || before.total_balance()? != after.total_balance()?
    {
        return Err("REVM native state fails exact nonce, balance or conservation checks".into());
    }
    Ok(TransferAccounting {
        sender: receipt.from,
        recipient,
        beneficiary,
        value,
        gas_fee: fee,
        base_fee: 0,
        burned_fee: U256::ZERO,
        sender_balance_before: before.balance(receipt.from),
        sender_balance_after: after.balance(receipt.from),
        recipient_balance_before: before.balance(recipient),
        recipient_balance_after: after.balance(recipient),
        beneficiary_balance_before: before.balance(beneficiary),
        beneficiary_balance_after: after.balance(beneficiary),
    })
}

fn credit(state: &mut NativeState, address: Address, value: U256) -> Result<(), String> {
    if value.is_zero() {
        return Ok(());
    }
    let account = state.accounts.entry(address).or_insert_with(|| Account {
        code_hash: keccak256([]),
        ..Default::default()
    });
    account.balance = account
        .balance
        .checked_add(value)
        .ok_or("native credit overflow")?;
    Ok(())
}
