//! Bounded recovery of same-database publisher state and retained lineage.
use super::{Store, records};
use crate::{
    protocol::Capacity,
    publisher::{
        codec::{scope_id, validate_snapshot},
        types::{PublisherError, PublisherSnapshot},
    },
};
use alloy_primitives::B256;
use fjall::Readable;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub(super) const HEADER_KEY: &[u8] = &[0x01];
pub(super) const SNAPSHOT_KEY: &[u8] = &[0x02];

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Header {
    pub schema: u32,
    pub chain_id: u64,
    pub genesis_id: B256,
    pub capacity: Capacity,
    pub scope_sha256: [u8; 32],
    pub revision: u64,
    pub fencing_epoch: u64,
    pub snapshot_sha256: [u8; 32],
}

/// All rows come from one MVCC snapshot. Empty means never initialized; a
/// partial namespace, unknown key or corrupt record is never treated as empty.
pub(super) fn load(store: &Store) -> Result<Option<PublisherSnapshot>, PublisherError> {
    store.check().map_err(|_| PublisherError::Storage)?;
    let snapshot = store.database.snapshot();
    let mut header_bytes = None;
    let mut state_bytes = None;
    for entry in snapshot.iter(&store.publisher_items) {
        let (key, value) = entry.into_inner().map_err(|_| PublisherError::Storage)?;
        if value.len() > records::MAX_RECORD_BYTES {
            return Err(PublisherError::CorruptState);
        }
        if key.as_ref() == HEADER_KEY && header_bytes.is_none() {
            header_bytes = Some(value);
        } else if key.as_ref() == SNAPSHOT_KEY && state_bytes.is_none() {
            state_bytes = Some(value);
        } else {
            return Err(PublisherError::CorruptState);
        }
    }
    let (header_bytes, state_bytes) = match (header_bytes, state_bytes) {
        (None, None) => return Ok(None),
        (Some(header), Some(state)) => (header, state),
        _ => return Err(PublisherError::CorruptState),
    };
    let header: Header =
        records::decode(&header_bytes).map_err(|_| PublisherError::CorruptState)?;
    let state: PublisherSnapshot =
        records::decode(&state_bytes).map_err(|_| PublisherError::CorruptState)?;
    validate_snapshot(&state).map_err(|_| PublisherError::CorruptState)?;
    let genesis = store
        .view()
        .map_err(|_| PublisherError::Storage)?
        .head
        .genesis_id;
    let scope_hash: [u8; 32] = scope_id(&state.scope)
        .map_err(|_| PublisherError::CorruptState)?
        .into();
    let state_hash: [u8; 32] = Sha256::digest(&state_bytes).into();
    if header.schema != 2
        || header.chain_id != store.chain_id
        || header.genesis_id != genesis
        || header.capacity != store.profile_capacity
        || state.scope.l2_chain_id != store.chain_id
        || state.scope.l2_genesis != genesis
        || header.scope_sha256 != scope_hash
        || header.snapshot_sha256 != state_hash
        || header.revision != state.revision
        || header.fencing_epoch != state.fencing_epoch
        || state.revision == 0
    {
        return Err(PublisherError::CorruptState);
    }
    validate_lineage(&state).map_err(|_| PublisherError::CorruptState)?;
    Ok(Some(state))
}

/// Independently retain every operation, input quarantine and historical event.
pub(super) fn validate_append(
    previous: &PublisherSnapshot,
    next: &PublisherSnapshot,
) -> Result<(), PublisherError> {
    if next.revision
        != previous
            .revision
            .checked_add(1)
            .ok_or(PublisherError::ResourceLimit)?
        || next.history.len() != previous.history.len() + 1
        || !next.history.starts_with(&previous.history)
        || next.fencing_epoch < previous.fencing_epoch
    {
        return Err(PublisherError::InvalidTransition);
    }
    for old in &previous.records {
        let new = next
            .records
            .iter()
            .find(|row| row.intent.id == old.intent.id)
            .ok_or(PublisherError::InvalidTransition)?;
        if new.intent != old.intent
            || new.sign_attempts < old.sign_attempts
            || new.submit_attempts < old.submit_attempts
            || old
                .signature
                .as_ref()
                .is_some_and(|signature| new.signature.as_ref() != Some(signature))
        {
            return Err(PublisherError::InvalidTransition);
        }
    }
    validate_lineage(next)
}

fn validate_lineage(state: &PublisherSnapshot) -> Result<(), PublisherError> {
    let mut intents = BTreeSet::new();
    let mut operations = BTreeSet::new();
    let mut transactions = BTreeSet::new();
    let mut reserved = BTreeSet::new();
    for row in &state.records {
        if !intents.insert(row.intent.id)
            || !operations.insert(row.intent.operation_id)
            || !transactions.insert(row.intent.tx_id)
        {
            return Err(PublisherError::CorruptState);
        }
        if row.reservations_retained {
            for input in &row.intent.inputs {
                // The key alone conflicts, so a different hint cannot alias a
                // still-quarantined input into another publication operation.
                if !reserved.insert(input.key) {
                    return Err(PublisherError::Conflict);
                }
            }
        }
    }
    for row in &state.records {
        let mut parent = row.intent.parent;
        let mut seen = BTreeSet::new();
        while let Some(id) = parent {
            if id == row.intent.id || !seen.insert(id) {
                return Err(PublisherError::CorruptState);
            }
            parent = state
                .records
                .iter()
                .find(|row| row.intent.id == id)
                .ok_or(PublisherError::CorruptState)?
                .intent
                .parent;
        }
    }
    let mut revision = 0_u64;
    let mut fence = 0_u64;
    for event in &state.history {
        revision = revision
            .checked_add(1)
            .ok_or(PublisherError::CorruptState)?;
        if event.revision != revision
            || event.fencing_epoch < fence
            || event.intent_id.is_some_and(|id| !intents.contains(&id))
        {
            return Err(PublisherError::CorruptState);
        }
        fence = event.fencing_epoch;
    }
    if revision != state.revision || fence != state.fencing_epoch {
        return Err(PublisherError::CorruptState);
    }
    Ok(())
}
