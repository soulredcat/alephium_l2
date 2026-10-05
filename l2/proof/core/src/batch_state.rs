mod checkpoint;

use crate::{
    block::StoredChange,
    protocol::{Account, AccountChange, Genesis, Head},
    records,
};
use alloy_primitives::{Address, B256, U256, keccak256};
use revm::database_interface::{DBErrorMarker, DatabaseRef};
use revm::state::{AccountInfo, Bytecode};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Complete execution state from genesis or a parent-root-bound checkpoint.
/// Tombstone epochs affect local commit encoding, although they are excluded
/// from the logical digest. Keeping them prevents recreate-after-delete drift.
pub(crate) struct FullState {
    chain_id: u64,
    genesis_id: B256,
    head: Option<Head>,
    accounts: BTreeMap<Address, (Account, bool)>,
    slots: BTreeMap<Address, BTreeMap<U256, U256>>,
    codes: BTreeMap<B256, Vec<u8>>,
    blocks: BTreeMap<u64, B256>,
}

impl FullState {
    pub(crate) fn genesis(genesis: &Genesis) -> Result<Self, String> {
        genesis.validate()?;
        let accounts = genesis
            .accounts
            .iter()
            .filter(|funded| !funded.balance.is_zero())
            .map(|funded| {
                (
                    funded.address,
                    (
                        Account {
                            balance: funded.balance,
                            code_hash: keccak256([]),
                            ..Default::default()
                        },
                        false,
                    ),
                )
            })
            .collect();
        Ok(Self {
            chain_id: genesis.chain_id,
            genesis_id: records::identity(&records::genesis_bytes(genesis)?),
            head: None,
            accounts,
            slots: BTreeMap::new(),
            codes: BTreeMap::new(),
            blocks: BTreeMap::new(),
        })
    }

    pub(crate) fn account_count(&self) -> u32 {
        self.accounts
            .values()
            .filter(|(_, deleted)| !deleted)
            .count() as u32
    }

    pub(crate) fn total_balance(&self) -> Result<U256, String> {
        self.accounts
            .values()
            .filter(|(_, deleted)| !deleted)
            .try_fold(U256::ZERO, |total, (account, _)| {
                total
                    .checked_add(account.balance)
                    .ok_or("state total balance overflow".into())
            })
    }

    /// Only locally rederived heads may be supplied by proof orchestration.
    pub(crate) fn commit_head(&mut self, head: &Head) -> Result<(), String> {
        if head.genesis_id != self.genesis_id {
            return Err("executed block belongs to a different genesis".into());
        }
        if let Some(previous) = &self.head {
            if head.height
                != previous
                    .height
                    .checked_add(1)
                    .ok_or("block height overflow")?
                || head.timestamp < previous.timestamp
            {
                return Err("nonconsecutive executed block history".into());
            }
        } else if head.height != 0
            || head.timestamp != 0
            || head.commit_id != crate::protocol::checkpoint::genesis_commit(self.genesis_id)
        {
            return Err("nonconsecutive executed block history".into());
        }
        self.blocks.insert(head.height, head.commit_id);
        self.blocks
            .retain(|height, _| *height >= head.height.saturating_sub(255));
        self.head = Some(head.clone());
        Ok(())
    }

    fn code(&self, hash: B256) -> Result<&[u8], String> {
        if hash == B256::ZERO || hash == keccak256([]) {
            return Ok(&[]);
        }
        let bytes = self
            .codes
            .get(&hash)
            .ok_or("missing executed contract code")?;
        records::verify_code(hash, bytes)?;
        Ok(bytes)
    }

    /// Exactly ReadView::state_digest: ordered live accounts/current slots and
    /// referenced code. Orphaned code, stale storage and tombstones are excluded.
    pub(crate) fn digest(&self) -> Result<B256, String> {
        let mut digest = Sha256::new();
        digest.update(b"alephium-l2-development/logical-state/v1");
        digest.update(u64::from(self.account_count()).to_be_bytes());
        let mut code_hashes = BTreeSet::new();
        for (address, (account, deleted)) in &self.accounts {
            if *deleted {
                continue;
            }
            digest.update(address);
            digest.update(account.balance.to_be_bytes::<32>());
            digest.update(account.nonce.to_be_bytes());
            digest.update(account.code_hash);
            let slots = self.slots.get(address);
            digest.update((slots.map_or(0, BTreeMap::len) as u64).to_be_bytes());
            if let Some(slots) = slots {
                for (slot, value) in slots {
                    if value.is_zero() {
                        return Err("noncanonical zero logical storage".into());
                    }
                    digest.update(slot.to_be_bytes::<32>());
                    digest.update(value.to_be_bytes::<32>());
                }
            }
            if account.code_hash != B256::ZERO && account.code_hash != keccak256([]) {
                code_hashes.insert(account.code_hash);
            }
        }
        digest.update((code_hashes.len() as u64).to_be_bytes());
        for hash in code_hashes {
            let bytes = self.code(hash)?;
            digest.update(hash);
            digest.update((bytes.len() as u64).to_be_bytes());
            digest.update(bytes);
        }
        Ok(B256::from_slice(&digest.finalize()))
    }

    /// Match Store::commit normalization, code validation and storage epochs.
    /// Inputs are derived by REVM; no exported state delta enters this method.
    pub(crate) fn apply(&mut self, changes: &[AccountChange]) -> Result<Vec<StoredChange>, String> {
        if changes
            .windows(2)
            .any(|pair| pair[0].address >= pair[1].address)
        {
            return Err("noncanonical executed account changes".into());
        }
        let mut new_codes = BTreeMap::new();
        for change in changes {
            if let Some(code) = &change.code {
                records::verify_code(change.code_hash, code)?;
                if self
                    .codes
                    .get(&change.code_hash)
                    .is_some_and(|existing| existing != code)
                    || new_codes
                        .insert(change.code_hash, code)
                        .is_some_and(|existing| existing != code)
                {
                    return Err("conflicting content-addressed code".into());
                }
            }
        }
        let mut stored = Vec::with_capacity(changes.len());
        for change in changes {
            if change.slots.windows(2).any(|pair| pair[0].0 >= pair[1].0)
                || change.deleted && (!change.slots.is_empty() || change.code.is_some())
            {
                return Err("invalid executed storage lifecycle".into());
            }
            let mut change = change.clone();
            let mut epoch = self
                .accounts
                .get(&change.address)
                .map_or(0, |(account, _)| account.storage_epoch);
            if change.storage_reset || change.deleted {
                epoch = epoch.checked_add(1).ok_or("storage epoch exhausted")?;
            }
            if change.code.is_none()
                && !change.deleted
                && !new_codes.contains_key(&change.code_hash)
            {
                self.code(change.code_hash)?;
            }
            if change.deleted {
                change.balance = U256::ZERO;
                change.nonce = 0;
                change.code_hash = B256::ZERO;
            }
            stored.push(StoredChange { change, epoch });
        }
        for (hash, code) in new_codes {
            if !code.is_empty() {
                self.codes.insert(hash, code.clone());
            }
        }
        for item in &stored {
            let change = &item.change;
            self.accounts.insert(
                change.address,
                (
                    Account {
                        balance: change.balance,
                        nonce: change.nonce,
                        code_hash: change.code_hash,
                        storage_epoch: item.epoch,
                    },
                    change.deleted,
                ),
            );
            if change.storage_reset || change.deleted {
                self.slots.remove(&change.address);
            }
            if !change.slots.is_empty() {
                let slots = self.slots.entry(change.address).or_default();
                for (slot, value) in &change.slots {
                    if value.is_zero() {
                        slots.remove(slot);
                    } else {
                        slots.insert(*slot, *value);
                    }
                }
            }
        }
        Ok(stored)
    }
}

#[derive(Debug)]
pub(crate) struct ReadError(String);

impl std::fmt::Display for ReadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for ReadError {}
impl DBErrorMarker for ReadError {}

impl DatabaseRef for FullState {
    type Error = ReadError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        Ok(self.accounts.get(&address).and_then(|(account, deleted)| {
            (!deleted).then_some(AccountInfo {
                balance: account.balance,
                nonce: account.nonce,
                code_hash: account.code_hash,
                code: None,
                ..Default::default()
            })
        }))
    }

    fn code_by_hash_ref(&self, hash: B256) -> Result<Bytecode, Self::Error> {
        self.code(hash)
            .map(|code| Bytecode::new_raw(code.to_vec().into()))
            .map_err(ReadError)
    }

    fn storage_ref(&self, address: Address, slot: U256) -> Result<U256, Self::Error> {
        if self
            .accounts
            .get(&address)
            .is_none_or(|(_, deleted)| *deleted)
        {
            return Ok(U256::ZERO);
        }
        Ok(self
            .slots
            .get(&address)
            .and_then(|slots| slots.get(&slot))
            .copied()
            .unwrap_or_default())
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        self.blocks
            .get(&number)
            .copied()
            .ok_or_else(|| ReadError("missing executed historical block".into()))
    }
}
