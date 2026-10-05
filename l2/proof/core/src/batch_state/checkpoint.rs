use super::FullState;
use crate::protocol::{Account, Head, checkpoint::*};
use alloy_primitives::{B256, keccak256};
use std::collections::{BTreeMap, BTreeSet};

impl FullState {
    /// Validation alone is not authentication. Orchestration must commit the
    /// imported checkpoint's canonical root and settlement must match its parent.
    pub(crate) fn from_checkpoint(checkpoint: &ExecutionCheckpoint) -> Result<Self, String> {
        checkpoint.validate()?;
        let mut accounts = BTreeMap::new();
        let mut slots = BTreeMap::new();
        for account in &checkpoint.accounts {
            accounts.insert(
                account.address,
                (
                    Account {
                        balance: account.balance,
                        nonce: account.nonce,
                        code_hash: account.code_hash,
                        storage_epoch: account.storage_epoch,
                    },
                    account.deleted,
                ),
            );
            if !account.slots.is_empty() {
                slots.insert(
                    account.address,
                    account
                        .slots
                        .iter()
                        .map(|slot| (slot.key, slot.value))
                        .collect(),
                );
            }
        }
        Ok(Self {
            chain_id: checkpoint.chain_id,
            genesis_id: checkpoint.genesis_id,
            head: Some(checkpoint.head.clone()),
            accounts,
            slots,
            codes: checkpoint
                .codes
                .iter()
                .map(|code| (code.hash, code.bytes.clone()))
                .collect(),
            blocks: checkpoint
                .block_hashes
                .iter()
                .map(|block| (block.height, block.hash))
                .collect(),
        })
    }

    pub(crate) fn checkpoint(
        &self,
        chain_id: u64,
        genesis_id: B256,
        head: &Head,
    ) -> Result<ExecutionCheckpoint, String> {
        if chain_id != self.chain_id
            || genesis_id != self.genesis_id
            || self.head.as_ref() != Some(head)
        {
            return Err("checkpoint identity differs from executed state".into());
        }
        let mut referenced = BTreeSet::new();
        let accounts = self
            .accounts
            .iter()
            .map(|(address, (account, deleted))| {
                if !deleted && account.code_hash != B256::ZERO && account.code_hash != keccak256([])
                {
                    referenced.insert(account.code_hash);
                }
                CheckpointAccount {
                    address: *address,
                    balance: account.balance,
                    nonce: account.nonce,
                    code_hash: account.code_hash,
                    storage_epoch: account.storage_epoch,
                    deleted: *deleted,
                    slots: self
                        .slots
                        .get(address)
                        .into_iter()
                        .flat_map(|slots| slots.iter())
                        .map(|(key, value)| CheckpointSlot {
                            key: *key,
                            value: *value,
                        })
                        .collect(),
                }
            })
            .collect();
        let codes = referenced
            .into_iter()
            .map(|hash| {
                self.code(hash).map(|bytes| CheckpointCode {
                    hash,
                    bytes: bytes.to_vec(),
                })
            })
            .collect::<Result<_, _>>()?;
        let checkpoint = ExecutionCheckpoint {
            schema: CHECKPOINT_SCHEMA,
            chain_id,
            genesis_id,
            head: head.clone(),
            accounts,
            codes,
            block_hashes: self
                .blocks
                .iter()
                .map(|(height, hash)| CheckpointBlockHash {
                    height: *height,
                    hash: *hash,
                })
                .collect(),
        };
        checkpoint.validate()?;
        Ok(checkpoint)
    }
}
