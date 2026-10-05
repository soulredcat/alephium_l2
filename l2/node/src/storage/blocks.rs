use super::{ReadView, block, encoding::key};
use crate::protocol::{BLOCK_BYTES, BLOCK_GAS, BlockContext, BlockInfo};
use alloy_primitives::B256;

impl ReadView {
    /// Ordered inputs and expected results for offline reexecution. Recorded
    /// state deltas are intentionally not exposed to the replay executor.
    pub fn replay_block(
        &self,
        height: u64,
    ) -> Result<Option<crate::protocol::ReplayBlock>, String> {
        if height == 0 || height > self.head.height {
            return Ok(None);
        }
        let bytes = self
            .get(key(0x30, &height.to_be_bytes()))?
            .ok_or("Missing replay block")?;
        let stored = block::decode(&bytes)?;
        if stored.head.height != height {
            return Err("Replay block height mismatch".into());
        }
        Ok(Some(crate::protocol::ReplayBlock {
            head: stored.head,
            parent: stored.parent,
            context: stored.context,
            transactions: stored.transactions,
            receipts: stored.receipts,
            rejected: stored.rejected,
        }))
    }

    pub fn block(&self, height: u64) -> Result<Option<BlockInfo>, String> {
        if height > self.head.height {
            return Ok(None);
        }
        if height == 0 {
            let head =
                super::records::genesis_head(&self.get([0x01])?.ok_or("Missing genesis identity")?);
            return Ok(Some(BlockInfo {
                parent: head.clone(),
                context: BlockContext {
                    number: 0,
                    timestamp: 0,
                    gas_limit: BLOCK_GAS,
                },
                head,
                transactions: vec![],
                gas_used: 0,
                encoded_bytes: 148,
            }));
        }
        let bytes = self
            .get(key(0x30, &height.to_be_bytes()))?
            .ok_or("Missing committed block")?;
        let stored = block::decode(&bytes)?;
        if stored.head.height != height {
            return Err("Block height identity mismatch".into());
        }
        let mut encoded_bytes = 148usize;
        for hash in &stored.transactions {
            let raw = self
                .raw_transaction(*hash)?
                .ok_or("Missing block transaction")?;
            encoded_bytes = encoded_bytes
                .checked_add(4 + raw.len())
                .ok_or("Block byte overflow")?;
        }
        if encoded_bytes > BLOCK_BYTES {
            return Err("Block payload exceeds protocol limit".into());
        }
        let gas_used = stored
            .receipts
            .last()
            .map_or(0, |receipt| receipt.cumulative_gas);
        Ok(Some(BlockInfo {
            head: stored.head,
            parent: stored.parent,
            context: stored.context,
            transactions: stored.transactions,
            gas_used,
            encoded_bytes,
        }))
    }

    pub fn block_by_hash(&self, hash: B256) -> Result<Option<BlockInfo>, String> {
        let genesis = self.block(0)?.ok_or("Missing genesis block")?;
        if hash == genesis.head.commit_id {
            return Ok(Some(genesis));
        }
        if let Some(height) = self.get(key(0x31, hash.as_slice()))? {
            if height.len() != 8 {
                return Err("Invalid block hash index".into());
            }
            let number = u64::from_be_bytes(height.try_into().map_err(|_| "Invalid block height")?);
            let block = self.block(number)?.ok_or("Indexed block is absent")?;
            if block.head.commit_id != hash {
                return Err("Indexed block hash mismatch".into());
            }
            return Ok(Some(block));
        }
        // Every commit writes the index, so a chain whose first block is indexed
        // has no unindexed records and an index miss is simply an unknown hash.
        let Some(first) = self.block(1)? else {
            return Ok(None);
        };
        if self
            .get(key(0x31, first.head.commit_id.as_slice()))?
            .is_some()
        {
            return Ok(None);
        }
        // Old records have no derived index. Bound lookup without changing their
        // authoritative commit chain or scanning unlimited history.
        let lower = self.head.height.saturating_sub(255).max(1);
        for number in (lower..=self.head.height).rev() {
            if let Some(block) = self.block(number)?
                && block.head.commit_id == hash
            {
                return Ok(Some(block));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Store, encoding::key};
    use crate::{development, execution, protocol::*};
    use alloy_primitives::{Address, B256, U256};

    fn commit(store: &mut Store, nonce: u64) {
        let to = Some(Address::repeat_byte(0x77));
        let raw = development::sign(nonce, to, U256::from(1), vec![], 21_000).unwrap();
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
        store
            .commit(BlockCommit {
                parent: view.head.clone(),
                context,
                transactions: result.receipts.iter().map(|r| r.hash).collect(),
                changes: result.changes,
                receipts: result.receipts,
                rejected: result.rejected,
            })
            .unwrap();
    }

    #[test]
    fn hash_lookup_uses_the_index_and_keeps_the_legacy_scan() {
        let directory = tempfile::tempdir().unwrap();
        let mut store =
            Store::open(&directory.path().join("data"), &development::genesis()).unwrap();
        let unknown = B256::repeat_byte(0x42);
        assert!(
            store
                .view()
                .unwrap()
                .block_by_hash(unknown)
                .unwrap()
                .is_none()
        );
        for nonce in 0..3 {
            commit(&mut store, nonce);
        }
        let view = store.view().unwrap();
        let hashes: Vec<_> = (0..=3)
            .map(|height| view.block(height).unwrap().unwrap().head.commit_id)
            .collect();
        let found = |view: &super::ReadView| -> Vec<Option<u64>> {
            hashes
                .iter()
                .map(|hash| {
                    view.block_by_hash(*hash)
                        .unwrap()
                        .map(|block| block.head.height)
                })
                .collect()
        };
        assert_eq!(found(&view), [Some(0), Some(1), Some(2), Some(3)]);
        assert!(view.block_by_hash(unknown).unwrap().is_none());
        // A chain from before the derived index still resolves by bounded scan.
        for hash in &hashes[1..] {
            store.items.remove(key(0x31, hash.as_slice())).unwrap();
        }
        let legacy = store.view().unwrap();
        assert_eq!(found(&legacy), [Some(0), Some(1), Some(2), Some(3)]);
        assert!(legacy.block_by_hash(unknown).unwrap().is_none());
    }
}
