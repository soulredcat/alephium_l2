//! Narrow ALPH-only P2PKH policy and explicit external trust boundaries.
use alloy_primitives::{B256, U256};

/// Explicit source guarantee. Latest availability is never a historical
/// snapshot; both paths retain the same exact monetary/ownership checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum FundingModel {
    ExactHeadSnapshotV1 = 1,
    CanonicalFixedCurrentV1 = 2,
}

/// SDK supported-profile bounds, not protocol maximum/capacity claims.
pub const MAX_UNSIGNED_BYTES: usize = 131_072;
pub const MAX_SCRIPT_BYTES: usize = 65_536;
pub const MAX_INPUTS: usize = 64;
/// Alephium v4.7.0 ordinary (non-coinbase), post-Rhone four-group profile.
pub const SUPPORTED_PROFILE: &str = "alephium-v4.7.0/p2pkh-alph/post-rhone/v1";
pub const MIN_GAS_AMOUNT: u32 = 20_000;
pub const MAX_GAS_AMOUNT: u32 = 5_000_000;
pub const MIN_GAS_PRICE: u64 = 100_000_000_000;
pub const MIN_CHANGE_AMOUNT: u64 = 1_000_000_000_000_000;
pub const MAX_ALPH_VALUE: u128 = 1_000_000_000_000_000_000_000_000_000;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct OutputRef {
    pub hint: u32,
    pub key: B256,
}

/// Independently configured trusted-node identity and exact canonical snapshot.
/// These are policy pins, not a cryptographic proof of consensus or spentness.
#[derive(Clone, PartialEq, Eq)]
pub struct FundingPin {
    pub model: FundingModel,
    pub source_id: B256,
    pub network_id: u8,
    pub network_genesis_id: B256,
    pub group: u8,
    /// This initial validator supports the standard four-group profile only.
    pub group_count: u8,
    pub head_hash: B256,
    pub head_height: u64,
    pub timestamp_ms: u64,
}

#[derive(Clone)]
pub struct SpendLimits {
    pub min_gas_amount: u32,
    pub max_gas_amount: u32,
    pub max_gas_price: U256,
    pub max_fee: U256,
    pub contract_deposit: U256,
    pub max_total_debit: U256,
    pub minimum_change: U256,
}

/// Construct from the independently approved local operation record, never
/// from an unsigned-transaction builder's proposed script or policy metadata.
#[derive(Clone)]
pub struct OperationSpec {
    pub intent_id: B256,
    pub operation_id: B256,
    /// Independent publisher scope commitment; the publisher compares its
    /// complete configured scope and the local approval source checks this pin.
    pub publication_scope: B256,
    pub source_artifact_sha256: B256,
    pub script_blake2b256: Option<B256>,
    pub caller_public_key: [u8; 33],
    pub funding: FundingPin,
    pub limits: SpendLimits,
}

/// Trusted local source/compiler adapter. It must resolve the independently
/// approved operation and instantiate canonical StatefulScript bytes. It never
/// receives builder-supplied unsigned bytes as an approval input. None supports
/// only an explicitly approved script-free, zero-contract-deposit transaction.
pub trait LocalScriptApproval {
    fn approved_script(
        &self,
        operation: &OperationSpec,
    ) -> Result<Option<Vec<u8>>, AlephiumValidationError>;
}

/// Facts from the configured source, including the actual previous output form.
/// This is not an authenticated UTXO proof and deliberately has no safe flag.
#[derive(Clone)]
pub struct PreviousOutput {
    pub reference: OutputRef,
    pub amount: U256,
    pub locking_script: Vec<u8>,
    pub lock_time_ms: u64,
    pub tokens: Vec<(B256, U256)>,
    pub additional_data: Vec<u8>,
}

/// The implementation is an explicitly trusted consensus-validating source.
/// It must return only unspent outputs at the exact network/group/head pin,
/// failing on stale/reorged context, a non-post-Rhone chain context, or
/// missing/spent outputs. Implementing this
/// callback is a trust assertion by the integrating application, not SDK crypto.
pub trait CanonicalFundingSource {
    fn source_id(&self) -> B256;
    fn unspent_outputs(
        &self,
        pin: &FundingPin,
        references: &[OutputRef],
    ) -> Result<Vec<PreviousOutput>, AlephiumValidationError>;
}

#[derive(Clone)]
pub struct ApprovedOperation {
    pub(super) spec: OperationSpec,
    pub(super) script: Option<Vec<u8>>,
    pub(super) owner_hash: B256,
}

impl ApprovedOperation {
    pub fn profile(&self) -> &'static str {
        SUPPORTED_PROFILE
    }
    pub fn spec(&self) -> &OperationSpec {
        &self.spec
    }
    pub fn script_bytes(&self) -> Option<&[u8]> {
        self.script.as_deref()
    }
}

pub struct FundingObservation {
    pub(super) pin: FundingPin,
    pub(super) outputs: Vec<PreviousOutput>,
}

impl FundingObservation {
    pub fn pin(&self) -> &FundingPin {
        &self.pin
    }
    pub fn outputs(&self) -> &[PreviousOutput] {
        &self.outputs
    }
}

/// Only the pure validator can construct this capability. No Debug/Serialize
/// exposes its retained unsigned payload or associated public signing identity.
pub struct ValidatedUnsignedAlephium {
    pub(super) raw: Vec<u8>,
    pub(super) tx_id: B256,
    pub(super) operation: ApprovedOperation,
    pub(super) inputs: Vec<OutputRef>,
    pub(super) fee: U256,
    pub(super) input_amount: U256,
    pub(super) change: U256,
    pub(super) fixed_output_count: u32,
}

impl ValidatedUnsignedAlephium {
    pub fn unsigned_bytes(&self) -> &[u8] {
        &self.raw
    }
    pub fn tx_id(&self) -> B256 {
        self.tx_id
    }
    pub fn input_refs(&self) -> &[OutputRef] {
        &self.inputs
    }
    pub fn intent_id(&self) -> B256 {
        self.operation.spec.intent_id
    }
    pub fn operation_id(&self) -> B256 {
        self.operation.spec.operation_id
    }
    pub fn publication_scope(&self) -> B256 {
        self.operation.spec.publication_scope
    }
    pub fn operation(&self) -> &ApprovedOperation {
        &self.operation
    }
    pub fn fee(&self) -> U256 {
        self.fee
    }
    pub fn input_amount(&self) -> U256 {
        self.input_amount
    }
    pub fn change(&self) -> U256 {
        self.change
    }
    /// Exact count from the validated unsigned layout. Controlled contract
    /// deployment outputs follow these fixed outputs; never assume index zero.
    pub fn fixed_output_count(&self) -> u32 {
        self.fixed_output_count
    }
}

pub struct ValidatedSignedAlephium {
    pub(super) unsigned: ValidatedUnsignedAlephium,
    pub(super) signature: [u8; 64],
}

impl ValidatedSignedAlephium {
    pub fn unsigned(&self) -> &ValidatedUnsignedAlephium {
        &self.unsigned
    }
    pub fn unsigned_bytes(&self) -> &[u8] {
        self.unsigned.unsigned_bytes()
    }
    pub fn tx_id(&self) -> B256 {
        self.unsigned.tx_id()
    }
    pub fn signature(&self) -> &[u8; 64] {
        &self.signature
    }
    pub fn intent_id(&self) -> B256 {
        self.unsigned.intent_id()
    }
    pub fn operation_id(&self) -> B256 {
        self.unsigned.operation_id()
    }
    pub fn publication_scope(&self) -> B256 {
        self.unsigned.publication_scope()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlephiumValidationError {
    UnsupportedProfile,
    InvalidApproval,
    MalformedUnsigned,
    NoncanonicalUnsigned,
    Bounds,
    FundingSourceMismatch,
    FundingUnavailable,
    FundingMismatch,
    OwnershipMismatch,
    AmountMismatch,
    FeeExceeded,
    ScriptMismatch,
    InvalidSignature,
    Overflow,
}

impl std::fmt::Display for AlephiumValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "Alephium validation refused: {self:?}")
    }
}

impl std::error::Error for AlephiumValidationError {}
