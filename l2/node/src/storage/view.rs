use super::{
    block,
    encoding::{key, slot_key},
    records,
};
use crate::protocol::{Account, Capacity, Head, MAX_TRANSACTION_BYTES, Receipt, TransactionStatus};
use alloy_primitives::{Address, B256, U256, keccak256};
use fjall::{Keyspace, Readable, Snapshot};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

/// A matching durable head and engine snapshot, pinned for one bounded operation.
#[derive(Clone)]
pub struct ReadView {
    pub head: Head,
    pub(super) chain_id: u64,
    pub(super) profile_capacity: Capacity,
    // Recovery verified every index at open; each later atomic commit adds one.
    pub(super) block_index_complete: bool,
    pub(super) snapshot: Snapshot,
    pub(super) items: Keyspace,
    pub(super) terminal: Arc<AtomicBool>,
}

impl ReadView {
    /// Validated against the persisted canonical genesis before publication.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Immutable limits authenticated by the persisted canonical genesis.
    pub fn capacity(&self) -> Capacity {
        self.profile_capacity
    }

    pub fn pending_counter(&self) -> Result<u64, String> {
        let bytes = self.get([0x03])?.ok_or("Missing admission counter")?;
        if bytes.len() != 8 {
            return Err("Invalid admission counter encoding".into());
        }
        Ok(u64::from_be_bytes(
            bytes.try_into().map_err(|_| "Invalid admission counter")?,
        ))
    }

    /// One pending reservation per sender. All inputs come from this same
    /// published snapshot; this does not expose a speculative pending state.
    pub fn pending_nonce(&self, address: Address) -> Result<u64, String> {
        let nonce = self.account(address)?.map_or(0, |account| account.nonce);
        let mut count = 0usize;
        for entry in self.snapshot.prefix(&self.items, [0x23]) {
            count += 1;
            if count > self.capacity().max_pending {
                return Err("Pending queue exceeds bound".into());
            }
            let (key, bytes) = entry.into_inner().map_err(super::engine_error)?;
            if key.len() != 9 {
                return Err("Invalid pending order key".into());
            }
            let mut input = super::encoding::Decoder::new(&bytes)?;
            let hash = input.hash()?;
            let sender = input.address()?;
            input.finish()?;
            if sender != address {
                continue;
            }
            let raw = self
                .raw_transaction(hash)?
                .ok_or("Missing pending envelope")?;
            let info = crate::execution::inspect_for_chain(&raw, self.chain_id())
                .map_err(|_| "Invalid pending envelope")?;
            let status = self.status(hash)?.ok_or("Missing pending status")?;
            if info.sender != address || info.nonce != nonce || status.status != "durably_accepted"
            {
                return Err("Pending nonce reservation is inconsistent".into());
            }
            return nonce
                .checked_add(1)
                .ok_or("Nonce reservation overflow".into());
        }
        Ok(nonce)
    }

    pub(super) fn get(&self, key: impl AsRef<[u8]>) -> Result<Option<Vec<u8>>, String> {
        if self.terminal.load(Ordering::Acquire) {
            return Err("storage is terminal; recovery required".into());
        }
        self.snapshot
            .get(&self.items, key)
            .map(|value| value.map(|bytes| bytes.to_vec()))
            .map_err(super::engine_error)
    }

    pub(super) fn account_record(
        &self,
        address: Address,
    ) -> Result<Option<(Account, bool)>, String> {
        self.get(key(0x10, address.as_slice()))?
            .map(|bytes| records::decode_account(&bytes))
            .transpose()
    }

    pub fn account(&self, address: Address) -> Result<Option<Account>, String> {
        Ok(self
            .account_record(address)?
            .and_then(|(account, deleted)| (!deleted).then_some(account)))
    }

    pub fn code(&self, hash: B256) -> Result<Vec<u8>, String> {
        if hash == B256::ZERO || hash == keccak256([]) {
            return Ok(Vec::new());
        }
        let code = self
            .get(key(0x12, hash.as_slice()))?
            .ok_or("missing referenced code")?;
        records::verify_code(hash, &code)?;
        Ok(code)
    }

    pub fn slot(&self, address: Address, slot: U256) -> Result<U256, String> {
        let Some(account) = self.account(address)? else {
            return Ok(U256::ZERO);
        };
        let Some(bytes) = self.get(slot_key(address, account.storage_epoch, slot))? else {
            return Ok(U256::ZERO);
        };
        if bytes.len() != 32 {
            return Err("invalid stored slot length".into());
        }
        let value = U256::from_be_slice(&bytes);
        if value.is_zero() {
            return Err("noncanonical zero storage record".into());
        }
        Ok(value)
    }

    pub fn block_hash(&self, height: u64) -> Result<B256, String> {
        if height == 0 {
            return Ok(records::genesis_head(
                &self.get([0x01])?.ok_or("missing genesis identity")?,
            )
            .commit_id);
        }
        let Some(bytes) = self.get(key(0x30, &height.to_be_bytes()))? else {
            return Ok(B256::ZERO);
        };
        let block = block::decode_with_capacity(&bytes, self.capacity())?;
        if block.head.height != height || height > self.head.height {
            return Err("inconsistent block identity".into());
        }
        Ok(block.head.commit_id)
    }

    pub fn status(&self, hash: B256) -> Result<Option<TransactionStatus>, String> {
        let status = self
            .get(key(0x21, hash.as_slice()))?
            .map(|bytes| records::decode_status(&bytes))
            .transpose()?;
        if status.as_ref().is_some_and(|status| status.hash != hash) {
            return Err("status identity mismatch".into());
        }
        Ok(status)
    }

    pub fn receipt(&self, hash: B256) -> Result<Option<Receipt>, String> {
        let receipt = self
            .get(key(0x22, hash.as_slice()))?
            .map(|bytes| records::decode_receipt(&bytes, None))
            .transpose()?;
        if receipt
            .as_ref()
            .is_some_and(|receipt| receipt.hash != hash || receipt.block_height > self.head.height)
        {
            return Err("receipt identity mismatch".into());
        }
        Ok(receipt)
    }

    pub fn raw_transaction(&self, hash: B256) -> Result<Option<Vec<u8>>, String> {
        let raw = self.get(key(0x20, hash.as_slice()))?;
        if raw
            .as_ref()
            .is_some_and(|bytes| bytes.len() > MAX_TRANSACTION_BYTES || keccak256(bytes) != hash)
        {
            return Err("stored transaction identity mismatch".into());
        }
        Ok(raw)
    }

    /// Canonical EVM logical state, independent of internal storage epochs/orphan code.
    /// Full scan for bounded offline verification; never a block/state root claim.
    pub fn state_digest(&self) -> Result<B256, String> {
        if self.terminal.load(Ordering::Acquire) {
            return Err("storage is terminal; recovery required".into());
        }
        let mut accounts = Vec::new();
        for item in self.snapshot.prefix(&self.items, [0x10]) {
            let (key, bytes) = item.into_inner().map_err(super::engine_error)?;
            if key.len() != 21 {
                return Err("invalid account key".into());
            }
            let (account, deleted) = records::decode_account(&bytes)?;
            if !deleted {
                accounts.push((Address::from_slice(&key[1..]), account));
            }
        }
        let mut digest = Sha256::new();
        digest.update(b"alephium-l2-development/logical-state/v1");
        digest.update((accounts.len() as u64).to_be_bytes());
        let mut code_hashes = BTreeSet::new();
        for (address, account) in accounts {
            digest.update(address);
            digest.update(account.balance.to_be_bytes::<32>());
            digest.update(account.nonce.to_be_bytes());
            digest.update(account.code_hash);
            let mut prefix = key(0x11, address.as_slice());
            prefix.extend(account.storage_epoch.to_be_bytes());
            let mut slots = Vec::new();
            for item in self.snapshot.prefix(&self.items, &prefix) {
                let (slot_key, value) = item.into_inner().map_err(super::engine_error)?;
                if slot_key.len() != 61
                    || value.len() != 32
                    || U256::from_be_slice(&value).is_zero()
                {
                    return Err("invalid logical storage record".into());
                }
                slots.push((slot_key[29..].to_vec(), value));
            }
            digest.update((slots.len() as u64).to_be_bytes());
            for (slot, value) in slots {
                digest.update(slot);
                digest.update(value);
            }
            if account.code_hash != B256::ZERO && account.code_hash != keccak256([]) {
                code_hashes.insert(account.code_hash);
            }
        }
        digest.update((code_hashes.len() as u64).to_be_bytes());
        for hash in code_hashes {
            let code = self.code(hash)?;
            digest.update(hash);
            digest.update((code.len() as u64).to_be_bytes());
            digest.update(code);
        }
        Ok(B256::from_slice(&digest.finalize()))
    }
}
