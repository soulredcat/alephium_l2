use crate::protocol::AccountChange;
use alloy_primitives::{Address, U256};
use revm::state::EvmState;
use std::collections::BTreeMap;

#[derive(Default)]
pub(super) struct Changes {
    accounts: BTreeMap<Address, AccountChange>,
    slots: BTreeMap<Address, BTreeMap<U256, U256>>,
}

impl Changes {
    /// Fold every transaction's changed slots. REVM rebaselines originals each
    /// transaction, so reading just the final transaction loses earlier writes.
    pub fn absorb(&mut self, state: &mut EvmState) {
        for (address, account) in state {
            if !account.is_touched() {
                continue;
            }
            let deleted = account.is_selfdestructed() || account.is_empty();
            let reset = deleted || account.is_created();
            let previous = self.accounts.get(address);
            let reset_in_block = reset || previous.is_some_and(|value| value.storage_reset);
            let prior_code = previous.and_then(|value| value.code.clone());
            let slots = self.slots.entry(*address).or_default();
            if reset {
                slots.clear();
            }
            if deleted {
                // CacheDB does not itself implement EIP-161 empty-account
                // clearing. Normalize its private overlay to nonexistence too.
                account.mark_selfdestruct();
                self.accounts.insert(
                    *address,
                    AccountChange {
                        address: *address,
                        deleted: true,
                        storage_reset: true,
                        ..Default::default()
                    },
                );
                continue;
            }
            for (slot, value) in account.changed_storage_slots() {
                slots.insert(*slot, value.present_value());
            }
            let code = account
                .info
                .code
                .as_ref()
                .filter(|code| !code.is_empty())
                .filter(|_| {
                    account.is_created()
                        || account.info.code_hash != account.original_info().code_hash
                })
                .map(|code| code.original_bytes().to_vec())
                .or(prior_code);
            self.accounts.insert(
                *address,
                AccountChange {
                    address: *address,
                    balance: account.info.balance,
                    nonce: account.info.nonce,
                    code_hash: account.info.code_hash,
                    code,
                    deleted: false,
                    storage_reset: reset_in_block,
                    slots: Vec::new(),
                },
            );
        }
    }

    pub fn finish(mut self) -> Vec<AccountChange> {
        self.accounts
            .into_values()
            .map(|mut account| {
                account.slots = self
                    .slots
                    .remove(&account.address)
                    .unwrap_or_default()
                    .into_iter()
                    .collect();
                account
            })
            .collect()
    }
}
