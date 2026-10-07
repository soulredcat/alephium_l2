//! Canonical complete execution checkpoint, independent of database layout.
mod codec;
mod decode;
mod reader;

use super::hash::{Digest, Sha256};
use super::proof_transport::ProofLimits;
use super::{Capacity, Head, validate_chain_id};
use alloy_primitives::{Address, B256, U256, keccak256};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const CHECKPOINT_SCHEMA: u32 = 1;
/// Legacy checkpoint/proof ceiling. Expanded development runtime bounds are
/// derived from its identity-bound Capacity; proof transport stays unchanged.
pub const MAX_CHECKPOINT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_CHECKPOINT_ACCOUNTS: usize = MAX_CHECKPOINT_BYTES / 105;
pub const MAX_CHECKPOINT_SLOTS: usize = MAX_CHECKPOINT_BYTES / 64;
pub const MAX_CHECKPOINT_CODES: usize = MAX_CHECKPOINT_BYTES / 36;
pub const MAX_CHECKPOINT_CODE_BYTES: usize = 24_576;
const DOMAIN: &[u8] = b"alephium-l2/execution-checkpoint/v1";

/// All state required to continue the unchanged EVM and local commit encoding.
/// A checkpoint is authenticated only when its root matches an accepted parent.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionCheckpoint {
    pub schema: u32,
    pub chain_id: u64,
    #[serde(default, skip_serializing_if = "Capacity::is_default")]
    pub capacity: Capacity,
    pub genesis_id: B256,
    pub head: Head,
    pub accounts: Vec<CheckpointAccount>,
    pub codes: Vec<CheckpointCode>,
    pub block_hashes: Vec<CheckpointBlockHash>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CheckpointAccount {
    pub address: Address,
    pub balance: U256,
    pub nonce: u64,
    pub code_hash: B256,
    pub storage_epoch: u64,
    pub deleted: bool,
    pub slots: Vec<CheckpointSlot>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CheckpointSlot {
    pub key: U256,
    pub value: U256,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CheckpointCode {
    pub hash: B256,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CheckpointBlockHash {
    pub height: u64,
    pub hash: B256,
}

impl ExecutionCheckpoint {
    pub fn validate(&self) -> Result<(), String> {
        self.encoded_len().map(|_| ())
    }

    /// Validate and meter the exact canonical encoding before allocation.
    pub fn encoded_len(&self) -> Result<usize, String> {
        validate_chain_id(self.chain_id)?;
        self.capacity.validate()?;
        let limit = self.capacity.runtime_checkpoint_bytes()?;
        if self.schema != self.capacity.checkpoint_schema()
            || self.head.genesis_id != self.genesis_id
            || self.accounts.len() > limit / 105
            || self.codes.len() > limit / 36
            || self
                .accounts
                .windows(2)
                .any(|pair| pair[0].address >= pair[1].address)
            || self
                .codes
                .windows(2)
                .any(|pair| pair[0].hash >= pair[1].hash)
        {
            return Err("invalid checkpoint identity, count or canonical ordering".into());
        }
        let mut size = DOMAIN.len() + 136 + if self.capacity.is_default() { 0 } else { 24 };
        let mut slot_count = 0usize;
        let mut referenced = BTreeSet::new();
        let empty_code = keccak256([]);
        for account in &self.accounts {
            add_size(&mut size, 105, limit)?;
            slot_count = slot_count
                .checked_add(account.slots.len())
                .ok_or("checkpoint slot overflow")?;
            if slot_count > limit / 64
                || account
                    .slots
                    .windows(2)
                    .any(|pair| pair[0].key >= pair[1].key)
                || account.slots.iter().any(|slot| slot.value.is_zero())
                || account.deleted
                    && (!account.balance.is_zero()
                        || account.nonce != 0
                        || account.code_hash != B256::ZERO
                        || account.storage_epoch == 0
                        || !account.slots.is_empty())
            {
                return Err("invalid checkpoint account lifecycle or storage".into());
            }
            add_size(
                &mut size,
                account
                    .slots
                    .len()
                    .checked_mul(64)
                    .ok_or("checkpoint slot size overflow")?,
                limit,
            )?;
            if !account.deleted
                && account.code_hash != B256::ZERO
                && account.code_hash != empty_code
            {
                referenced.insert(account.code_hash);
            }
        }
        if referenced.len() != self.codes.len()
            || !referenced
                .iter()
                .copied()
                .eq(self.codes.iter().map(|code| code.hash))
        {
            return Err("checkpoint code set differs from exact live references".into());
        }
        for code in &self.codes {
            if code.bytes.is_empty()
                || code.bytes.len() > MAX_CHECKPOINT_CODE_BYTES
                || keccak256(&code.bytes) != code.hash
            {
                return Err("invalid checkpoint code identity or size".into());
            }
            add_size(&mut size, 36 + code.bytes.len(), limit)?;
        }
        let start = self.head.height.saturating_sub(255);
        if self.block_hashes.len() as u64 != self.head.height - start + 1 {
            return Err("checkpoint historical block window is incomplete".into());
        }
        for (index, block) in self.block_hashes.iter().enumerate() {
            if block.height != start + index as u64
                || block.hash == B256::ZERO
                || block.height == 0 && block.hash != genesis_commit(self.genesis_id)
            {
                return Err("invalid checkpoint historical block identity".into());
            }
        }
        if self.block_hashes.last().map(|block| block.hash) != Some(self.head.commit_id)
            || self.head.height == 0 && self.head.timestamp != 0
        {
            return Err("checkpoint head differs from its canonical history".into());
        }
        add_size(&mut size, self.block_hashes.len() * 40, limit)?;
        Ok(size)
    }

    /// Canonical binary transport: fixed big-endian integers, ordered records,
    /// explicit counts/lengths, strict booleans and no trailing bytes.
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let size = self.encoded_len()?;
        codec::encode(self, size)
    }

    /// Emit the same full canonical state, without an intermediate binary Vec.
    /// This streams encoding only; account/code collections remain bounded full state.
    pub fn write_encoded(
        &self,
        sink: &mut impl FnMut(&[u8]) -> Result<(), String>,
    ) -> Result<(), String> {
        self.validate()?;
        codec::write(self, sink)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        decode::from_slice(bytes, None)
    }

    pub fn capacity_from_prefix(bytes: &[u8]) -> Result<Capacity, String> {
        decode::capacity_from_prefix(bytes)
    }

    pub fn decode_for_capacity(bytes: &[u8], expected: Capacity) -> Result<Self, String> {
        decode::from_slice(bytes, Some(expected))
    }

    /// Decode a declared canonical payload without retaining its wire bytes.
    /// The source must fill each requested slice exactly or return an error.
    /// Only the declared payload is consumed; framing and physical EOF belong
    /// to its caller. Capacity is authenticated before allocating collections.
    pub fn read_encoded_for_capacity(
        source: &mut impl FnMut(&mut [u8]) -> Result<(), String>,
        total_len: usize,
        expected: Capacity,
    ) -> Result<Self, String> {
        decode::read(source, total_len, Some(expected))
    }

    /// The guest supplies its pinned profile; settlement checks this domain and
    /// compares the resulting old root with its accepted parent root.
    pub fn root(
        &self,
        profile: B256,
        l1_network: u8,
        l1_genesis: B256,
        settlement_contract: B256,
    ) -> Result<B256, String> {
        self.capacity.ensure_proof_transport()?;
        if profile == B256::ZERO || l1_genesis == B256::ZERO || settlement_contract == B256::ZERO {
            return Err("checkpoint root requires explicit profile and settlement domain".into());
        }
        self.validate()?;
        let mut digest = Sha256::new();
        digest.update(b"alephium-l2/continuation-root/v1");
        digest.update(profile);
        digest.update([l1_network]);
        digest.update(l1_genesis);
        digest.update(settlement_contract);
        codec::write(self, &mut |bytes| {
            digest.update(bytes);
            Ok(())
        })?;
        Ok(B256::from_slice(&digest.finalize()))
    }

    /// Schema-four root namespace binds its exact transport limits and full
    /// canonical state. Native encoding support is not guest/proof acceptance.
    pub fn root_for_transport(
        &self,
        profile: B256,
        l1_network: u8,
        l1_genesis: B256,
        settlement_contract: B256,
        limits: ProofLimits,
    ) -> Result<B256, String> {
        limits.validate_for_capacity(self.capacity)?;
        if profile == B256::ZERO || l1_genesis == B256::ZERO || settlement_contract == B256::ZERO {
            return Err("checkpoint root requires explicit profile and settlement domain".into());
        }
        if self.encoded_len()? > limits.checkpoint_bytes {
            return Err("checkpoint exceeds the selected proof transport bound".into());
        }
        let mut digest = Sha256::new();
        digest.update(b"alephium-l2/continuation-root/v2");
        digest.update(profile);
        digest.update([l1_network]);
        digest.update(l1_genesis);
        digest.update(settlement_contract);
        digest.update(limits.binding_bytes()?);
        codec::write(self, &mut |bytes| {
            digest.update(bytes);
            Ok(())
        })?;
        Ok(B256::from_slice(&digest.finalize()))
    }
}

fn add_size(size: &mut usize, additional: usize, limit: usize) -> Result<(), String> {
    *size = size
        .checked_add(additional)
        .ok_or("checkpoint byte size overflow")?;
    if *size > limit {
        return Err("checkpoint exceeds canonical byte bound".into());
    }
    Ok(())
}

pub(crate) fn genesis_commit(genesis_id: B256) -> B256 {
    let mut digest = Sha256::new();
    digest.update(b"alephium-l2-development/genesis-commit/v1");
    digest.update(genesis_id);
    B256::from_slice(&digest.finalize())
}
