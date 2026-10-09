//! Durable publisher repository in a separate keyspace of the same database.
//! The whole snapshot atomically includes immutable intents, operations, input
//! quarantine and append-only history. No signer or submission runs here.
mod records;
mod recovery;

use super::Store;
use crate::publisher::{
    codec::{scope_id, validate_snapshot, validate_transition},
    types::{PublisherError, PublisherSnapshot, Repository, Scope},
};
use sha2::{Digest, Sha256};
use std::sync::atomic::Ordering;

impl Store {
    pub fn publisher_load(
        &self,
        scope: &Scope,
    ) -> Result<Option<PublisherSnapshot>, PublisherError> {
        self.check().map_err(|_| PublisherError::Storage)?;
        self.publisher_check_scope(scope)?;
        let snapshot = self.publisher_read()?;
        if snapshot.as_ref().is_some_and(|state| state.scope != *scope) {
            return Err(PublisherError::Conflict);
        }
        Ok(snapshot)
    }

    /// Sole &mut Store ownership plus exact durable revision/epoch comparison
    /// fences stale service caches before any new external operation is allowed.
    pub fn publisher_cas(
        &mut self,
        expected_revision: u64,
        expected_fence: u64,
        next: &PublisherSnapshot,
    ) -> Result<PublisherSnapshot, PublisherError> {
        self.check().map_err(|_| PublisherError::Storage)?;
        self.publisher_check_scope(&next.scope)?;
        validate_snapshot(next)?;
        let stored = self.publisher_read()?;
        let empty = PublisherSnapshot::empty(next.scope.clone());
        let previous = stored.as_ref().unwrap_or(&empty);
        if previous.scope != next.scope || previous.revision != expected_revision {
            return Err(PublisherError::Conflict);
        }
        if previous.fencing_epoch != expected_fence {
            return Err(PublisherError::StaleFence);
        }
        validate_transition(stored.as_ref(), next)?;
        recovery::validate_append(previous, next)?;
        let preparation_inputs = self
            .funding_preparation_reserved_inputs()
            .map_err(|_| PublisherError::Storage)?;
        if next
            .records
            .iter()
            .filter(|row| row.reservations_retained)
            .any(|row| {
                row.intent
                    .inputs
                    .iter()
                    .any(|input| preparation_inputs.contains(&input.key))
            })
        {
            return Err(PublisherError::Conflict);
        }
        let encoded = records::encode(next).map_err(|_| PublisherError::ResourceLimit)?;
        let header = recovery::Header {
            schema: 2,
            chain_id: self.chain_id,
            genesis_id: self
                .view()
                .map_err(|_| PublisherError::Storage)?
                .head
                .genesis_id,
            capacity: self.profile_capacity,
            scope_sha256: scope_id(&next.scope)?.into(),
            revision: next.revision,
            fencing_epoch: next.fencing_epoch,
            snapshot_sha256: Sha256::digest(&encoded).into(),
        };
        let header = records::encode(&header).map_err(|_| PublisherError::ResourceLimit)?;
        let mut batch = self.batch().map_err(|_| PublisherError::Storage)?;
        batch.insert(
            &self.publisher_items,
            recovery::SNAPSHOT_KEY.to_vec(),
            encoded,
        );
        batch.insert(&self.publisher_items, recovery::HEADER_KEY.to_vec(), header);
        self.finish(batch).map_err(|_| PublisherError::Storage)?;
        Ok(next.clone())
    }

    fn publisher_check_scope(&self, scope: &Scope) -> Result<(), PublisherError> {
        let head = self.view().map_err(|_| PublisherError::Storage)?.head;
        if scope.l2_chain_id != self.chain_id || scope.l2_genesis != head.genesis_id {
            return Err(PublisherError::InvalidInput);
        }
        Ok(())
    }

    pub(super) fn publisher_read(&self) -> Result<Option<PublisherSnapshot>, PublisherError> {
        let result = recovery::load(self);
        if matches!(
            result,
            Err(PublisherError::CorruptState | PublisherError::Storage)
        ) {
            self.terminal.store(true, Ordering::Release);
        }
        result
    }
}

impl Repository for Store {
    fn publisher_load(&self, scope: &Scope) -> Result<Option<PublisherSnapshot>, PublisherError> {
        Store::publisher_load(self, scope)
    }

    fn publisher_cas(
        &mut self,
        expected_revision: u64,
        expected_fence: u64,
        next: &PublisherSnapshot,
    ) -> Result<PublisherSnapshot, PublisherError> {
        Store::publisher_cas(self, expected_revision, expected_fence, next)
    }
}

/// Common open_profile hook, including closed-backup validation. Corruption
/// refuses startup; no missing/uncertain intent becomes an automatic fresh job.
pub(super) fn validate_open(store: &Store) -> Result<(), String> {
    store
        .publisher_read()
        .map(|_| ())
        .map_err(|error| error.to_string())
}
