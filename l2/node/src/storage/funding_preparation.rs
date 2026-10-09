//! Funding-preparation CAS and retained reservations in the SAME Fjall database.
mod codec;
mod recovery;
mod validation;
use super::Store;
use crate::funding_preparation::{FundingPreparationError as Error, FundingPreparationRecord};
use alloy_primitives::B256;
use std::sync::atomic::Ordering;

impl Store {
    pub fn load_funding_preparation(
        &self,
        purpose: B256,
    ) -> Result<Option<FundingPreparationRecord>, Error> {
        if purpose == B256::ZERO {
            return Err(Error::InvalidData);
        }
        let records = self.funding_preparation_records()?;
        Ok(records
            .into_iter()
            .find(|record| record.immutable.purpose_id == purpose))
    }

    /// The root controller validates a sealed SDK capability before Planned.
    /// This repository enforces durable DATA invariants, never signs or submits.
    pub fn cas_funding_preparation(
        &mut self,
        expected_revision: u64,
        next: &FundingPreparationRecord,
    ) -> Result<FundingPreparationRecord, Error> {
        self.check().map_err(|_| Error::Storage)?;
        validation::record(next)?;
        let records = self.funding_preparation_records()?;
        let previous = records
            .iter()
            .find(|record| record.immutable.purpose_id == next.immutable.purpose_id);
        if previous.map_or(0, |record| record.revision) != expected_revision {
            return Err(Error::Conflict);
        }
        validation::transition(previous, next)?;
        if previous.is_none() && records.len() >= recovery::MAX_PREPARATIONS {
            return Err(Error::ResourceLimit);
        }
        for record in &records {
            if record.immutable.purpose_id != next.immutable.purpose_id
                && (record.immutable.transaction_id == next.immutable.transaction_id
                    || record.immutable.input_refs.iter().any(|reference| {
                        next.immutable
                            .input_refs
                            .iter()
                            .any(|input| input.key == reference.key)
                    }))
            {
                return Err(Error::Conflict);
            }
        }
        let publisher = self.publisher_read().map_err(|_| Error::Storage)?;
        if publisher.as_ref().is_some_and(|snapshot| {
            snapshot
                .records
                .iter()
                .filter(|row| row.reservations_retained)
                .any(|row| {
                    row.intent.inputs.iter().any(|reference| {
                        next.immutable
                            .input_refs
                            .iter()
                            .any(|input| input.key == reference.key)
                    })
                })
        }) {
            return Err(Error::Conflict);
        }
        let genesis = self.view().map_err(|_| Error::Storage)?.head.genesis_id;
        let encoded = codec::encode(&codec::Stored {
            schema: 1,
            node_chain_id: self.chain_id,
            node_genesis: genesis,
            capacity: self.profile_capacity,
            record: next.clone(),
        })?;
        let total_revision = records
            .iter()
            .try_fold(0_u64, |sum, record| {
                sum.checked_add(record.revision).ok_or(Error::ResourceLimit)
            })?
            .checked_sub(previous.map_or(0, |record| record.revision))
            .and_then(|sum| sum.checked_add(next.revision))
            .ok_or(Error::ResourceLimit)?;
        let header = codec::encode(&recovery::Header {
            schema: 1,
            node_chain_id: self.chain_id,
            node_genesis: genesis,
            capacity: self.profile_capacity,
            records: (records.len() + usize::from(previous.is_none())) as u32,
            total_revision,
        })?;
        let mut batch = self.batch().map_err(|_| Error::Storage)?;
        batch.insert(&self.funding_items, recovery::HEADER_KEY.to_vec(), header);
        batch.insert(
            &self.funding_items,
            recovery::key(1, next.immutable.purpose_id),
            encoded,
        );
        batch.insert(
            &self.funding_items,
            recovery::key(2, next.immutable.transaction_id),
            next.immutable.purpose_id.as_slice().to_vec(),
        );
        for input in &next.immutable.input_refs {
            batch.insert(
                &self.funding_items,
                recovery::key(3, input.key),
                next.immutable.purpose_id.as_slice().to_vec(),
            );
        }
        self.finish(batch).map_err(|_| Error::Storage)?;
        Ok(next.clone())
    }

    /// Retained even after confirmation; a stored historical result cannot
    /// authorize spending, callback repetition or input reuse after a reorg.
    pub(super) fn funding_preparation_reserved_inputs(&self) -> Result<Vec<B256>, Error> {
        Ok(self
            .funding_preparation_records()?
            .iter()
            .flat_map(|record| record.immutable.input_refs.iter().map(|input| input.key))
            .collect())
    }

    fn funding_preparation_records(&self) -> Result<Vec<FundingPreparationRecord>, Error> {
        let result = recovery::load(self);
        if matches!(result, Err(Error::CorruptState | Error::Storage)) {
            self.terminal.store(true, Ordering::Release);
        }
        result
    }
}

pub(super) fn validate_open(store: &Store) -> Result<(), String> {
    store
        .funding_preparation_records()
        .map(|_| ())
        .map_err(|error| error.to_string())
}

#[cfg(test)]
#[path = "../../../../test/publisher/funding_preparation_store_checks.rs"]
pub(crate) mod tests;
