//! One MVCC snapshot validates every purpose and its exact retained indices.
use super::{codec, validation};
use crate::{
    funding_preparation::{FundingPreparationError as Error, FundingPreparationRecord},
    storage::Store,
};
use alloy_primitives::B256;
use fjall::Readable;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub(super) const MAX_PREPARATIONS: usize = 64;
pub(super) const HEADER_KEY: &[u8] = &[0];
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Header {
    pub schema: u32,
    pub node_chain_id: u64,
    pub node_genesis: B256,
    pub capacity: crate::protocol::Capacity,
    pub records: u32,
    pub total_revision: u64,
}
pub(super) fn key(tag: u8, identity: B256) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(33);
    bytes.push(tag);
    bytes.extend_from_slice(identity.as_slice());
    bytes
}

pub(super) fn load(store: &Store) -> Result<Vec<FundingPreparationRecord>, Error> {
    store.check().map_err(|_| Error::Storage)?;
    let snapshot = store.database.snapshot();
    let genesis = store.view().map_err(|_| Error::Storage)?.head.genesis_id;
    let mut records = BTreeMap::new();
    let mut indices = BTreeMap::new();
    let mut header = None;
    let mut entries = 0;
    for entry in snapshot.iter(&store.funding_items) {
        entries += 1;
        if entries > MAX_PREPARATIONS * 3 + 1 {
            return Err(Error::CorruptState);
        }
        let (key, value) = entry.into_inner().map_err(|_| Error::Storage)?;
        if key.as_ref() == HEADER_KEY {
            if header.is_some() {
                return Err(Error::CorruptState);
            }
            header = Some(codec::decode::<Header>(&value)?);
            continue;
        }
        if key.len() != 33 {
            return Err(Error::CorruptState);
        }
        let identity = B256::from_slice(&key[1..]);
        match key[0] {
            1 => {
                let stored: codec::Stored = codec::decode(&value)?;
                if stored.schema != 1
                    || stored.node_chain_id != store.chain_id
                    || stored.node_genesis != genesis
                    || stored.capacity != store.profile_capacity
                    || stored.record.immutable.purpose_id != identity
                {
                    return Err(Error::CorruptState);
                }
                validation::record(&stored.record).map_err(|_| Error::CorruptState)?;
                if records.insert(identity, stored.record).is_some() {
                    return Err(Error::CorruptState);
                }
            }
            2 | 3 if value.len() == 32 => {
                if indices
                    .insert(key.to_vec(), B256::from_slice(&value))
                    .is_some()
                {
                    return Err(Error::CorruptState);
                }
            }
            _ => return Err(Error::CorruptState),
        }
    }
    let Some(header) = header else {
        return if entries == 0 {
            Ok(Vec::new())
        } else {
            Err(Error::CorruptState)
        };
    };
    if records.len() > MAX_PREPARATIONS {
        return Err(Error::CorruptState);
    }
    let total_revision = records.values().try_fold(0_u64, |sum, record| {
        sum.checked_add(record.revision).ok_or(Error::CorruptState)
    })?;
    if header.schema != 1
        || header.node_chain_id != store.chain_id
        || header.node_genesis != genesis
        || header.capacity != store.profile_capacity
        || records.is_empty()
        || header.records as usize != records.len()
        || header.total_revision != total_revision
    {
        return Err(Error::CorruptState);
    }
    let mut expected = BTreeMap::new();
    for record in records.values() {
        let purpose = record.immutable.purpose_id;
        if expected
            .insert(key(2, record.immutable.transaction_id), purpose)
            .is_some()
        {
            return Err(Error::CorruptState);
        }
        for input in &record.immutable.input_refs {
            if expected.insert(key(3, input.key), purpose).is_some() {
                return Err(Error::CorruptState);
            }
        }
    }
    if indices != expected {
        return Err(Error::CorruptState);
    }
    Ok(records.into_values().collect())
}
