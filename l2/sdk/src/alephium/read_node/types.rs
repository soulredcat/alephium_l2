use super::address::{ContractAddress, P2pkhAddress};
use crate::alephium::OutputRef;
use alloy_primitives::{B256, I256, U256};

pub const OFFICIAL_TESTNET_ORIGIN: &str = "https://node.testnet.alephium.org";
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
pub const MAX_CANONICAL_CANDIDATES: usize = 64;
pub const MAX_CONTRACT_DATA_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenesisProvenance {
    Independent,
    DiagnosticObserved,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GenesisPin {
    pub hash: B256,
    pub provenance: GenesisProvenance,
}

/// The client never discovers or replaces this pin automatically. A diagnostic
/// observed pin must remain labelled as such in every resulting observation.
#[derive(Clone)]
pub struct ReadNodeConfig {
    pub origin: String,
    pub source_id: B256,
    pub chain_0_0_genesis: GenesisPin,
}

impl ReadNodeConfig {
    pub fn official_testnet(source_id: B256, chain_0_0_genesis: GenesisPin) -> Self {
        Self {
            origin: OFFICIAL_TESTNET_ORIGIN.into(),
            source_id,
            chain_0_0_genesis,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeVersion {
    V4_7_0,
    V4_7_1,
}

#[derive(Clone, PartialEq, Eq)]
pub struct IdentityObservation {
    pub source_id: B256,
    pub origin: String,
    pub version: NodeVersion,
    pub network_id: u8,
    pub groups: u8,
    pub group_num_per_broker: u8,
    pub num_zeros_at_least_in_hash: u32,
    pub chain_0_0_genesis: GenesisPin,
}

/// Source-reported target-group-zero header, not independently verified
/// consensus. Creator provenance supplies its source chain separately.
#[derive(Clone, PartialEq, Eq)]
pub struct ChainHeader {
    pub hash: B256,
    pub height: u64,
    pub timestamp_ms: u64,
    pub dependencies: [B256; 7],
}

impl ChainHeader {
    pub fn parent(&self) -> Option<B256> {
        (self.height != 0).then_some(self.dependencies[3])
    }
}

#[derive(Clone)]
pub struct HeaderObservation {
    pub identity: IdentityObservation,
    pub header: ChainHeader,
}

pub struct HeightObservation {
    pub identity: IdentityObservation,
    pub height: u64,
}

/// Preserve BlockFlow's three independent counters. None is inferred from
/// height distance, and the reader supplies no application finality threshold.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ConfirmationCounts {
    pub chain: u32,
    pub from_group: u32,
    pub to_group: u32,
}

#[derive(Clone, PartialEq, Eq)]
pub struct InclusionStatus {
    pub block_hash: B256,
    pub transaction_index: usize,
    pub confirmations: ConfirmationCounts,
}

#[derive(Clone, PartialEq, Eq)]
pub enum TransactionStatus {
    Confirmed(InclusionStatus),
    Conflicted(InclusionStatus),
    MemPooled,
    TxNotFound,
}

pub enum TransactionOutcome {
    ScriptSucceeded {
        inclusion: InclusionStatus,
        header: ChainHeader,
    },
    ScriptFailed {
        inclusion: InclusionStatus,
        header: ChainHeader,
    },
    Conflicted(InclusionStatus),
    MemPooled,
    TxNotFound,
}

pub struct TransactionObservation {
    pub identity: IdentityObservation,
    pub transaction_id: B256,
    pub outcome: TransactionOutcome,
}

/// Full transaction data is retained only after block/index/status correlation.
/// It can contain signatures and must never be logged or formatted wholesale.
pub struct TransactionDetailsObservation {
    pub(super) observation: TransactionObservation,
    pub(super) retained_details: Option<serde_json::Value>,
}

impl TransactionDetailsObservation {
    pub fn observation(&self) -> &TransactionObservation {
        &self.observation
    }
    pub fn details(&self) -> Option<&serde_json::Value> {
        self.retained_details.as_ref()
    }
    pub fn into_observation(self) -> TransactionObservation {
        self.observation
    }
}

/// Funding creator discovery can identify any 0..3 -> 0 chain. Coordinates
/// remain absent for unconfirmed/conflicted discovery outcomes; no 0_0 default
/// is inferred. The configured 0_0 genesis identifies the selected network,
/// not an independently verified genesis or history for the creator chain.
pub struct Owner0CreatorDetails {
    pub(super) chain_from: Option<u8>,
    pub(super) transaction: TransactionDetailsObservation,
}

impl Owner0CreatorDetails {
    pub fn chain_from(&self) -> Option<u8> {
        self.chain_from
    }
    pub fn chain_to(&self) -> Option<u8> {
        self.chain_from.map(|_| 0)
    }
    pub fn transaction(&self) -> &TransactionDetailsObservation {
        &self.transaction
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct TokenAmount {
    pub id: B256,
    pub amount: U256,
}

#[derive(Clone, PartialEq, Eq)]
pub enum ContractValue {
    Bool(bool),
    I256(I256),
    U256(U256),
    ByteVec(Vec<u8>),
    P2pkhAddress(P2pkhAddress),
    ContractAddress(ContractAddress),
    Array(Vec<ContractValue>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContractView {
    CurrentUnanchored,
}

/// A current GET result. It cannot establish state/effects at transaction
/// inclusion, even if a separately queried head happens to remain unchanged.
pub struct CurrentContractState {
    pub identity: IdentityObservation,
    pub view: ContractView,
    pub address: ContractAddress,
    pub code_hash: B256,
    pub bytecode: Vec<u8>,
    pub initial_state_hash: Option<B256>,
    pub immutable_fields: Vec<ContractValue>,
    pub mutable_fields: Vec<ContractValue>,
    pub atto_alph_amount: U256,
    pub tokens: Vec<TokenAmount>,
    /// Decoded value payload bytes, not an estimate of VM serialized fields.
    pub field_data_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FundingView {
    LatestIncludingMempoolUnanchored,
}

pub struct UnanchoredUtxo {
    pub reference: OutputRef,
    pub amount: U256,
    pub tokens: Vec<TokenAmount>,
    pub lock_time_ms: Option<u64>,
    pub additional_data: Option<Vec<u8>>,
}

/// GET /addresses/{address}/utxos includes mempool data and offers no historical
/// snapshot selector. Deliberately not convertible to FundingObservation and
/// not an implementation of CanonicalFundingSource.
pub struct UnanchoredUtxos {
    pub identity: IdentityObservation,
    pub owner: P2pkhAddress,
    pub view: FundingView,
    pub outputs: Vec<UnanchoredUtxo>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadNodeError {
    InvalidOrigin,
    InvalidConfiguration,
    HandshakeRequired,
    Transport,
    HttpStatus(u16),
    ResponseTooLarge,
    MalformedResponse,
    UnsupportedVersion,
    WrongNetwork,
    NotReady,
    GenesisMismatch,
    HeaderMismatch,
    NoCanonicalBlock,
    AmbiguousCanonicalBlock,
    ObservationChanged,
    UnsupportedAddress,
    ContractMismatch,
    UnsupportedValue,
    TransactionMismatch,
}

impl std::fmt::Display for ReadNodeError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "Alephium read-only observation failed: {self:?}")
    }
}
impl std::error::Error for ReadNodeError {}
