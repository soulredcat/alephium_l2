//! Intents resolved as rejected without entering a block. A rejected intent
//! changes no state, and the proof witness has no representation for one, so
//! the producer resolves it here instead of committing it with a block.
use super::{ReadView, Store, encoding::key, records};
use crate::protocol::TransactionStatus;
use alloy_primitives::B256;
use fjall::Readable;
use std::collections::{BTreeMap, BTreeSet};

/// Same bound as a block's rejection reason.
const MAX_REASON_BYTES: usize = 4096;

fn status(hash: B256, reason: &str) -> TransactionStatus {
    TransactionStatus {
        hash,
        status: "rejected".into(),
        block_height: None,
        error: Some(reason.into()),
    }
}

impl Store {
    /// Durably resolve one pending intent as rejected outside any block.
    pub fn discard(&mut self, hash: B256, reason: &str) -> Result<TransactionStatus, String> {
        self.check()?;
        if reason.is_empty() || reason.len() > MAX_REASON_BYTES {
            return Err("invalid discarded intent reason".into());
        }
        let (ordinal, _) = self
            .pending_records()?
            .into_iter()
            .find(|(_, pending)| pending.hash == hash)
            .ok_or("discarded intent is not pending")?;
        let status = status(hash, reason);
        let mut batch = self.batch()?;
        batch.insert(
            &self.items,
            key(0x21, hash.as_slice()),
            records::encode_status(&status)?,
        );
        batch.insert(
            &self.items,
            key(0x24, hash.as_slice()),
            reason.as_bytes().to_vec(),
        );
        batch.remove(&self.items, key(0x23, &ordinal.to_be_bytes()));
        self.finish(batch)?;
        Ok(status)
    }

    /// Every intent resolved outside a block, with its reason.
    pub fn discarded(&self) -> Result<Vec<(B256, String)>, String> {
        let view = self.view()?;
        let mut discarded = Vec::new();
        for entry in view.snapshot.prefix(&view.items, [0x24]) {
            let (record_key, reason) = entry.into_inner().map_err(super::engine_error)?;
            discarded.push(decode(&record_key, &reason)?);
        }
        Ok(discarded)
    }
}

fn decode(record_key: &[u8], reason: &[u8]) -> Result<(B256, String), String> {
    if record_key.len() != 33 || reason.is_empty() || reason.len() > MAX_REASON_BYTES {
        return Err("invalid discarded intent record".into());
    }
    let reason = String::from_utf8(reason.to_vec()).map_err(|_| "invalid discarded reason")?;
    Ok((B256::from_slice(&record_key[1..]), reason))
}

/// Recovery: each discarded intent explains its envelope and rejected status,
/// and can be neither resolved in a block nor still pending.
pub(super) fn validate(
    view: &ReadView,
    expected: &mut BTreeMap<Vec<u8>, Vec<u8>>,
    resolved: &mut BTreeSet<B256>,
) -> Result<(), String> {
    for entry in view.snapshot.prefix(&view.items, [0x24]) {
        let (record_key, reason) = entry.into_inner().map_err(super::engine_error)?;
        let (hash, reason) = decode(&record_key, &reason)?;
        if !resolved.insert(hash) {
            return Err("discarded intent is also resolved in a block".into());
        }
        let raw = view
            .raw_transaction(hash)?
            .ok_or("missing discarded transaction envelope")?;
        let info = crate::execution::inspect_for_chain(&raw, view.chain_id())
            .map_err(|_| "invalid discarded signed envelope")?;
        if info.hash != hash {
            return Err("discarded transaction identity mismatch".into());
        }
        expected.insert(key(0x20, hash.as_slice()), raw);
        expected.insert(
            key(0x21, hash.as_slice()),
            records::encode_status(&status(hash, &reason))?,
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::{Store, encoding::key};
    use crate::{development, execution, protocol::*};
    use alloy_primitives::{Address, U256};

    #[test]
    fn recovery_rejects_inconsistent_discard_records() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("data");
        let genesis = development::genesis();
        let mut store = Store::open(&path, &genesis).unwrap();
        let to = Some(Address::repeat_byte(0x63));
        let raw = development::sign(0, to, U256::from(1), vec![], 21_000).unwrap();
        let info = execution::inspect(&raw).unwrap();
        let hash = info.hash;
        store
            .admit(Pending {
                hash,
                sender: info.sender,
                raw,
            })
            .unwrap();
        assert!(store.discard(hash, "").is_err());
        let status = store.discard(hash, "invalid transaction: test").unwrap();
        assert_eq!(
            (status.status.as_str(), status.block_height),
            ("rejected", None)
        );
        assert!(store.discard(hash, "again").is_err(), "no longer pending");
        drop(store);
        let store = Store::open(&path, &genesis).unwrap();
        assert_eq!(store.discarded().unwrap().len(), 1);
        // A discard record for an envelope the store never admitted.
        let unknown = key(0x24, &[0x77; 32]);
        store
            .items
            .insert(unknown.clone(), b"forged".to_vec())
            .unwrap();
        drop(store);
        let error = Store::open(&path, &genesis).err().unwrap();
        assert!(
            error.contains("missing discarded transaction envelope"),
            "{error}"
        );
    }
}
