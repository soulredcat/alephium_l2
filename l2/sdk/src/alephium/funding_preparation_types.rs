//! Dedicated self-split facts; no publisher/factory scope or signing authority.
use super::super::{
    AlephiumValidationError, FundingPin, OutputRef, current_funding::CurrentFundingError,
};
use alloy_primitives::{B256, U256};

pub const FUNDING_PREPARATION_PROFILE: &str = "alephium-v4.7.0/p2pkh-alph/fixed-self-split-four/v1";
pub const FUNDING_PREPARATION_GAS: u32 = 100_000;
pub const FUNDING_PREPARATION_GAS_PRICE: u64 = 100_000_000_000;
pub const FUNDING_PREPARATION_MAX_BYTES: usize = 512;

/// Independent operator-purpose metadata, never supplied by a transaction
/// builder. These fields grant no signing/submission permission by themselves.
#[derive(Clone)]
pub struct FundingPreparationSpec {
    pub purpose_id: B256,
    pub operator_source: B256,
    pub caller_public_key: [u8; 33],
    pub network_genesis_id: B256,
    pub funding_source_id: B256,
    pub gas_amount: u32,
    pub gas_price: U256,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FundingPreparationOutput {
    pub(super) reference: OutputRef,
    pub(super) index: u32,
    pub(super) amount: U256,
    pub(super) owner_hash: B256,
}

impl FundingPreparationOutput {
    /// A predicted fixed-output reference, not evidence of creation/unspentness.
    pub fn reference(&self) -> OutputRef {
        self.reference
    }
    pub fn index(&self) -> u32 {
        self.index
    }
    pub fn amount(&self) -> U256 {
        self.amount
    }
    pub fn owner_hash(&self) -> B256 {
        self.owner_hash
    }
}

/// Only this profile's sealed-source validator can construct the capability.
/// No Debug/Serialize, unchecked constructor, factory token or reservation.
pub struct ValidatedFundingPreparation {
    pub(super) spec: FundingPreparationSpec,
    pub(super) pin: FundingPin,
    pub(super) raw: Vec<u8>,
    pub(super) tx_id: B256,
    pub(super) input: [OutputRef; 1],
    pub(super) input_amount: U256,
    pub(super) fee: U256,
    pub(super) outputs: [FundingPreparationOutput; 4],
}

/// Canonical byte/accounting facts only. This is not authenticated funding,
/// eligibility, a reservation, signing authority or an observation capability.
pub struct FundingPreparationWire {
    pub(super) tx_id: B256,
    pub(super) input: [OutputRef; 1],
    pub(super) input_amount: U256,
    pub(super) fee: U256,
    pub(super) outputs: [FundingPreparationOutput; 4],
}

impl FundingPreparationWire {
    pub fn tx_id(&self) -> B256 {
        self.tx_id
    }
    pub fn input_ref(&self) -> OutputRef {
        self.input[0]
    }
    pub fn input_refs(&self) -> &[OutputRef] {
        &self.input
    }
    pub fn input_amount(&self) -> U256 {
        self.input_amount
    }
    pub fn fee(&self) -> U256 {
        self.fee
    }
    pub fn outputs(&self) -> &[FundingPreparationOutput; 4] {
        &self.outputs
    }
}

impl ValidatedFundingPreparation {
    pub fn profile(&self) -> &'static str {
        FUNDING_PREPARATION_PROFILE
    }
    pub fn spec(&self) -> &FundingPreparationSpec {
        &self.spec
    }
    pub fn pin(&self) -> &FundingPin {
        &self.pin
    }
    pub fn unsigned_bytes(&self) -> &[u8] {
        &self.raw
    }
    pub fn tx_id(&self) -> B256 {
        self.tx_id
    }
    pub fn input_ref(&self) -> OutputRef {
        self.input[0]
    }
    pub fn input_refs(&self) -> &[OutputRef] {
        &self.input
    }
    pub fn input_amount(&self) -> U256 {
        self.input_amount
    }
    pub fn fee(&self) -> U256 {
        self.fee
    }
    pub fn outputs(&self) -> &[FundingPreparationOutput; 4] {
        &self.outputs
    }
}

/// Only metadata-safe classifications; no payload/key/amount is formatted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FundingPreparationError {
    InvalidSpec,
    FundingMismatch,
    OwnershipMismatch,
    ImmatureInput,
    InsufficientAmount,
    UnsupportedShape,
    NoncanonicalUnsigned,
    Overflow,
    Bounds,
    Source(CurrentFundingError),
    Wire(AlephiumValidationError),
}

impl From<CurrentFundingError> for FundingPreparationError {
    fn from(value: CurrentFundingError) -> Self {
        Self::Source(value)
    }
}
impl From<AlephiumValidationError> for FundingPreparationError {
    fn from(value: AlephiumValidationError) -> Self {
        Self::Wire(value)
    }
}
impl std::fmt::Display for FundingPreparationError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "Funding preparation refused: {self:?}")
    }
}
impl std::error::Error for FundingPreparationError {}
