//! Distinct current-availability evidence; never an exact-head UTXO snapshot.
use crate::alephium::{
    FundingObservation, FundingPin, OutputRef, PreviousOutput,
    read_node::{
        ChainHeader, ConfirmationCounts, HeaderObservation, InclusionStatus, ReadNodeError,
    },
};
use alloy_primitives::B256;

pub const MAX_OWNER_HEAD_ADVANCE: u32 = 32;

/// Which exact native value the latest projection returned. This does not
/// identify its cache/storage origin; Coincident means both values are equal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockTimeProjection {
    Committed,
    Effective,
    Coincident,
}

/// Refusal classification only; no hash, owner or transaction data is exposed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeadChangeReason {
    PinnedHeight,
    PinnedHash,
    PinnedTimestamp,
    HeightRegression,
    TimestampRegression,
    ZeroHeaderHash,
    SameHeightFork,
    SameHeightHeader,
    LineageLength,
    LineageStart,
    LineageEnd,
    LineageDuplicate,
    LineageHeight,
    LineageParent,
    LineageTimestamp,
    FinalCanonicalHeader,
    FinalSourceIdentity,
    StrictHeader,
    StrictUnexpectedLineage,
    HeightOverflow,
}

/// These thresholds are independently selected local policy, not values echoed
/// by a transaction builder. Every confirmation threshold must be nonzero.
#[derive(Clone, PartialEq, Eq)]
pub struct CurrentFundingPolicy {
    pub minimum_confirmations: ConfirmationCounts,
    pub maximum_references: usize,
    pub maximum_creators: usize,
}

/// An independently configured local registry. None approves only a script-free
/// creator. Some must resolve retained, reviewed serialized script bytes, never
/// accept the creator response's own script/hash as authorization.
pub trait CreatorScriptRegistry {
    fn approved_script(
        &self,
        creator_transaction_id: B256,
    ) -> Result<Option<Vec<u8>>, CurrentFundingError>;
}

/// Useful for ordinary script-free funding transfers; no script is authorized.
pub struct ScriptFreeCreators;
impl CreatorScriptRegistry for ScriptFreeCreators {
    fn approved_script(&self, _: B256) -> Result<Option<Vec<u8>>, CurrentFundingError> {
        Ok(None)
    }
}

/// The committed fixed-output body is bound by the creator unsigned hash.
/// Effective maturity also uses its correlated canonical creator timestamp.
/// Inclusion, that timestamp and availability trust the configured node.
#[derive(Clone)]
pub struct FixedOutputProvenance {
    pub reference: OutputRef,
    pub creator_transaction_id: B256,
    pub creator_chain_from: u8,
    pub creator_chain_to: u8,
    pub fixed_output_index: u32,
    pub inclusion: InclusionStatus,
    pub creator_block_height: u64,
    pub committed_lock_time_ms: u64,
    pub creator_block_timestamp_ms: u64,
    pub effective_lock_time_ms: u64,
    pub initial_lock_time_projection: Option<LockTimeProjection>,
    pub final_lock_time_projection: Option<LockTimeProjection>,
}

/// Only the observer constructs this capability. Creator/availability checks
/// are windowed trusted observations, not atomic UTXO state at the AFTER pin.
/// The current-window path repeats them after lineage validation, then rechecks
/// AFTER canonicality; signing/reservation and later races remain separate.
/// It deliberately has no Debug/Serialize or public unchecked constructor.
pub struct CurrentFixedFundingObservation {
    pub(super) funding: FundingObservation,
    pub(super) policy: CurrentFundingPolicy,
    pub(super) provenance: Vec<FixedOutputProvenance>,
    pub(super) before: HeaderObservation,
    pub(super) after: HeaderObservation,
    pub(super) current_window: bool,
    pub(super) head_lineage: Vec<ChainHeader>,
}

impl CurrentFixedFundingObservation {
    pub fn pin(&self) -> &FundingPin {
        self.funding.pin()
    }
    /// Lock times are native effective maturity values. The signed creator's
    /// original lock times remain separately available in provenance().
    pub fn outputs(&self) -> &[PreviousOutput] {
        self.funding.outputs()
    }
    pub fn policy(&self) -> &CurrentFundingPolicy {
        &self.policy
    }
    pub fn provenance(&self) -> &[FixedOutputProvenance] {
        &self.provenance
    }
    pub fn head_before(&self) -> &HeaderObservation {
        &self.before
    }
    pub fn head_after(&self) -> &HeaderObservation {
        &self.after
    }
    pub fn is_current_window(&self) -> bool {
        self.current_window
    }
    /// Inclusive BEFORE..AFTER canonical-header observations in current mode;
    /// empty for the strict caller-pinned path.
    pub fn head_lineage(&self) -> &[ChainHeader] {
        &self.head_lineage
    }
    pub fn head_advance(&self) -> u32 {
        self.head_lineage.len().saturating_sub(1) as u32
    }
    pub(in crate::alephium) fn validate_lock_evidence(&self) -> Result<(), CurrentFundingError> {
        if self.outputs().len() != self.provenance.len() {
            return Err(CurrentFundingError::CreatorMismatch);
        }
        for (output, fact) in self.outputs().iter().zip(&self.provenance) {
            super::lock_time::evidence(output, fact)?;
        }
        Ok(())
    }
    pub(in crate::alephium) fn validate_head_evidence(&self) -> Result<(), CurrentFundingError> {
        super::checks::head(self.funding.pin(), &self.after.header)?;
        if self.current_window {
            super::checks::head_lineage(&self.before.header, &self.after.header, &self.head_lineage)
        } else if self.before.header != self.after.header || !self.head_lineage.is_empty() {
            Err(super::checks::head_error(
                if !self.head_lineage.is_empty() {
                    HeadChangeReason::StrictUnexpectedLineage
                } else {
                    HeadChangeReason::StrictHeader
                },
                &self.before.header,
                &self.after.header,
            ))
        } else {
            Ok(())
        }
    }
}

/// Metadata-only failures; payloads, signatures and RPC bodies are suppressed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CurrentFundingError {
    Bounds,
    InvalidPolicy,
    InvalidPublisher,
    WrongFundingModel,
    IdentityMismatch,
    HeadChanged {
        reason: HeadChangeReason,
        expected_height: u64,
        observed_height: u64,
        expected_timestamp_ms: u64,
        observed_timestamp_ms: u64,
    },
    HeadProgressTooLarge {
        observed: u64,
        maximum: u32,
        before_height: u64,
        after_height: u64,
    },
    CreatorOriginChanged {
        expected_height: u64,
        observed_height: u64,
        expected_timestamp_ms: u64,
        observed_timestamp_ms: u64,
    },
    CreatorTxNotFound,
    CreatorMemPooled,
    CreatorConflicted,
    CreatorScriptFailed,
    CreatorConfirmationsInsufficient {
        observed_chain: u32,
        observed_from_group: u32,
        observed_to_group: u32,
        required_chain: u32,
        required_from_group: u32,
        required_to_group: u32,
    },
    CreatorMismatch,
    MalformedCreator,
    UnsupportedCreator,
    NotFixedOutput,
    AvailabilityMismatch,
    AvailabilityLockTimeMissing,
    AvailabilityLockTimeMismatch,
    AvailabilityImmature,
    Read(ReadNodeError),
}

impl From<ReadNodeError> for CurrentFundingError {
    fn from(error: ReadNodeError) -> Self {
        Self::Read(error)
    }
}
impl std::fmt::Display for CurrentFundingError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "Current fixed-output funding refused: {self:?}")
    }
}
impl std::error::Error for CurrentFundingError {}
