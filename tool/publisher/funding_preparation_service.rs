//! Sealed outer boundary; durable attempts precede every external callback.
use crate::{
    funding_preparation::{
        FundingPreparationError as StoreError, FundingPreparationImmutable,
        FundingPreparationPhase as Phase, FundingPreparationRecord as Record,
    },
    storage::Store,
};
use alephium_l2_sdk::alephium::{
    FundingModel,
    funding_preparation::{
        FundingPreparationSpec, ValidatedFundingPreparation,
        verify_funding_preparation_signature_wire,
    },
};
use alloy_primitives::B256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreparationExternalError {
    Disabled,
    Rejected,
    Unavailable,
    Consumed,
    InvalidSignature,
}

pub trait PreparationSigner {
    fn sign(
        &mut self,
        durable: &Record,
        cap: &ValidatedFundingPreparation,
    ) -> Result<Vec<u8>, PreparationExternalError>;
}
pub trait PreparationSubmitter {
    fn submit(
        &mut self,
        durable: &Record,
        cap: &ValidatedFundingPreparation,
        signature: &[u8],
    ) -> Result<B256, PreparationExternalError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreparationServiceError {
    Stopped,
    Mismatch,
    WrongPhase,
    SignAmbiguous(PreparationExternalError),
    SubmitAmbiguous(PreparationExternalError),
    Durability(StoreError),
}
impl std::fmt::Display for PreparationServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Funding preparation STOP: {self:?}")
    }
}
impl std::error::Error for PreparationServiceError {}
type Error = PreparationServiceError;

/// Caller supplies a freshly sealed capability immediately before each public
/// operation. This controller neither discovers funding nor applies a timer.
pub struct FundingPreparationController<'a> {
    store: &'a mut Store,
    expected: FundingPreparationSpec,
    cache: Option<Record>,
    stopped: bool,
}

impl<'a> FundingPreparationController<'a> {
    pub fn new(store: &'a mut Store, expected: FundingPreparationSpec) -> Self {
        Self {
            store,
            expected,
            cache: None,
            stopped: false,
        }
    }
    pub fn stopped(&self) -> bool {
        self.stopped
    }

    pub fn plan(&mut self, cap: &ValidatedFundingPreparation) -> Result<Record, Error> {
        let planned = self.capture(cap)?;
        self.plan_inner(planned)
    }

    pub fn sign(
        &mut self,
        cap: &ValidatedFundingPreparation,
        signer: &mut impl PreparationSigner,
    ) -> Result<Record, Error> {
        let identity = self.capture(cap)?.immutable;
        self.sign_inner(&identity, |record, _| signer.sign(record, cap))
    }

    pub fn submit(
        &mut self,
        cap: &ValidatedFundingPreparation,
        submitter: &mut impl PreparationSubmitter,
    ) -> Result<Record, Error> {
        let identity = self.capture(cap)?.immutable;
        self.submit_inner(&identity, |record, _| {
            let signature = record
                .signature
                .as_deref()
                .ok_or(PreparationExternalError::InvalidSignature)?;
            submitter.submit(record, cap, signature)
        })
    }

    fn capture(&mut self, cap: &ValidatedFundingPreparation) -> Result<Record, Error> {
        if self.stopped {
            return Err(Error::Stopped);
        }
        if !same_spec(&self.expected, cap.spec())
            || cap.pin().model != FundingModel::CanonicalFixedCurrentV1
            || cap.pin().network_id != 1
            || cap.pin().group != 0
            || cap.pin().group_count != 4
            || cap.pin().source_id != self.expected.funding_source_id
            || cap.pin().network_genesis_id != self.expected.network_genesis_id
        {
            return self.stop(Error::Mismatch);
        }
        Record::planned(cap, [6; 3]).map_err(|error| {
            self.stopped = true;
            Error::Durability(error)
        })
    }

    fn plan_inner(&mut self, planned: Record) -> Result<Record, Error> {
        if self.stopped {
            return Err(Error::Stopped);
        }
        match self
            .store
            .load_funding_preparation(planned.immutable.purpose_id)
        {
            Ok(None) => self.persist(0, &planned),
            Ok(Some(_)) => self.stop(Error::WrongPhase),
            Err(error) => self.stop(Error::Durability(error)),
        }
    }

    fn current(
        &mut self,
        identity: &FundingPreparationImmutable,
        phase: Phase,
    ) -> Result<Record, Error> {
        if self.stopped {
            return Err(Error::Stopped);
        }
        let record = if let Some(record) = &self.cache {
            record.clone()
        } else {
            match self.store.load_funding_preparation(identity.purpose_id) {
                Ok(Some(record)) => record,
                Ok(None) => return self.stop(Error::WrongPhase),
                Err(error) => return self.stop(Error::Durability(error)),
            }
        };
        if &record.immutable != identity {
            return self.stop(Error::Mismatch);
        }
        if record.phase != phase {
            return self.stop(Error::WrongPhase);
        }
        Ok(record)
    }

    /// Private closure seam tests real Store ordering without fabricating an SDK cap.
    fn sign_inner(
        &mut self,
        identity: &FundingPreparationImmutable,
        callback: impl FnOnce(&Record, &Store) -> Result<Vec<u8>, PreparationExternalError>,
    ) -> Result<Record, Error> {
        let current = self.current(identity, Phase::Planned)?;
        let mut attempt = self.next(&current, Phase::SignAttempted)?;
        attempt.sign_attempts = 1;
        let attempt = self.persist(current.revision, &attempt)?;
        let signature = match callback(&attempt, self.store) {
            Ok(signature) if verify_record_signature(&attempt, &signature).is_ok() => signature,
            Ok(_) => {
                return self.sign_ambiguous(&attempt, PreparationExternalError::InvalidSignature);
            }
            Err(error) => return self.sign_ambiguous(&attempt, error),
        };
        let mut signed = self.next(&attempt, Phase::Signed)?;
        signed.signature = Some(signature);
        self.persist(attempt.revision, &signed)
    }

    fn submit_inner(
        &mut self,
        identity: &FundingPreparationImmutable,
        callback: impl FnOnce(&Record, &Store) -> Result<B256, PreparationExternalError>,
    ) -> Result<Record, Error> {
        let current = self.current(identity, Phase::Signed)?;
        if current
            .signature
            .as_deref()
            .is_none_or(|signature| verify_record_signature(&current, signature).is_err())
        {
            return self.stop(Error::Mismatch);
        }
        let mut attempt = self.next(&current, Phase::SubmitAttempted)?;
        attempt.submit_attempts = 1;
        let attempt = self.persist(current.revision, &attempt)?;
        match callback(&attempt, self.store) {
            Ok(id) if id == attempt.immutable.transaction_id => {
                let submitted = self.next(&attempt, Phase::Submitted)?;
                let stored = self.persist(attempt.revision, &submitted)?;
                self.stopped = true;
                Ok(stored) // ACK only; no inclusion or confirmation is attached.
            }
            Ok(_) => self.submit_ambiguous(&attempt, PreparationExternalError::Rejected),
            Err(error) => self.submit_ambiguous(&attempt, error),
        }
    }

    fn sign_ambiguous(
        &mut self,
        attempt: &Record,
        cause: PreparationExternalError,
    ) -> Result<Record, Error> {
        let ambiguous = self.next(attempt, Phase::SignAmbiguous)?;
        self.persist(attempt.revision, &ambiguous)?;
        self.stop(Error::SignAmbiguous(cause))
    }
    fn submit_ambiguous(
        &mut self,
        attempt: &Record,
        cause: PreparationExternalError,
    ) -> Result<Record, Error> {
        let ambiguous = self.next(attempt, Phase::SubmitAmbiguous)?;
        self.persist(attempt.revision, &ambiguous)?;
        self.stop(Error::SubmitAmbiguous(cause))
    }
    fn next(&mut self, current: &Record, phase: Phase) -> Result<Record, Error> {
        let Some(revision) = current.revision.checked_add(1) else {
            return self.stop(Error::Durability(StoreError::ResourceLimit));
        };
        let mut next = current.clone();
        next.revision = revision;
        next.phase = phase;
        Ok(next)
    }
    fn persist(&mut self, revision: u64, next: &Record) -> Result<Record, Error> {
        match self.store.cas_funding_preparation(revision, next) {
            Ok(stored) => {
                self.cache = Some(stored.clone());
                Ok(stored)
            }
            Err(error) => self.stop(Error::Durability(error)),
        }
    }
    fn stop<T>(&mut self, error: Error) -> Result<T, Error> {
        self.stopped = true;
        self.cache = None;
        Err(error)
    }
}

pub(crate) fn same_spec(a: &FundingPreparationSpec, b: &FundingPreparationSpec) -> bool {
    a.purpose_id == b.purpose_id
        && a.operator_source == b.operator_source
        && a.caller_public_key == b.caller_public_key
        && a.network_genesis_id == b.network_genesis_id
        && a.funding_source_id == b.funding_source_id
        && a.gas_amount == b.gas_amount
        && a.gas_price == b.gas_price
}
pub(crate) fn matches_cap(record: &Record, cap: &ValidatedFundingPreparation) -> bool {
    Record::planned(cap, [6; 3]).is_ok_and(|planned| planned.immutable == record.immutable)
}
fn verify_record_signature(
    record: &Record,
    signature: &[u8],
) -> Result<(), PreparationExternalError> {
    let value = &record.immutable;
    let key = value
        .caller_public_key
        .as_slice()
        .try_into()
        .map_err(|_| PreparationExternalError::InvalidSignature)?;
    let spec = FundingPreparationSpec {
        purpose_id: value.purpose_id,
        operator_source: value.operator_source,
        caller_public_key: key,
        network_genesis_id: value.network_genesis_id,
        funding_source_id: value.funding_source_id,
        gas_amount: value.gas_amount,
        gas_price: value.gas_price,
    };
    let input = value
        .input_refs
        .first()
        .ok_or(PreparationExternalError::InvalidSignature)?;
    verify_funding_preparation_signature_wire(
        &spec,
        &value.unsigned,
        input.native(),
        value.input_amount,
        signature,
    )
    .map_err(|_| PreparationExternalError::InvalidSignature)
}

#[cfg(test)]
#[path = "../../test/publisher/funding_preparation_service_checks.rs"]
pub(crate) mod tests;
