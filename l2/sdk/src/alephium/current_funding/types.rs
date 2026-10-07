//! Distinct current-availability evidence; never an exact-head UTXO snapshot.
use crate::alephium::{
    FundingObservation, FundingPin, OutputRef, PreviousOutput,
    read_node::{ConfirmationCounts, HeaderObservation, InclusionStatus, ReadNodeError},
};
use alloy_primitives::B256;

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

/// The fixed-output contents are authenticated by the creator unsigned hash.
/// Inclusion and availability still trust the configured consensus node.
pub struct FixedOutputProvenance {
    pub reference: OutputRef,
    pub creator_transaction_id: B256,
    pub fixed_output_index: u32,
    pub inclusion: InclusionStatus,
    pub creator_block_height: u64,
}

/// Only the observer constructs this capability. Latest mempool-aware presence
/// plus matching bracketing heads is NOT an atomic or historical UTXO proof.
/// It deliberately has no Debug/Serialize or public unchecked constructor.
pub struct CurrentFixedFundingObservation {
    pub(super) funding: FundingObservation,
    pub(super) policy: CurrentFundingPolicy,
    pub(super) provenance: Vec<FixedOutputProvenance>,
    pub(super) before: HeaderObservation,
    pub(super) after: HeaderObservation,
}

impl CurrentFixedFundingObservation {
    pub fn pin(&self) -> &FundingPin {
        self.funding.pin()
    }
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
}

/// Metadata-only failures; payloads, signatures and RPC bodies are suppressed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CurrentFundingError {
    Bounds,
    InvalidPolicy,
    WrongFundingModel,
    IdentityMismatch,
    HeadChanged,
    CreatorUnconfirmed,
    CreatorMismatch,
    MalformedCreator,
    UnsupportedCreator,
    NotFixedOutput,
    AvailabilityMismatch,
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
