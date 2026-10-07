//! Versioned private file DTOs. Deserializing these never grants SDK authority.
use crate::publisher::{PublisherError, Scope, Token};
use alloy_primitives::{B256, U256};
use serde::{Deserialize, Serialize};

pub const FORMAT_VERSION: u32 = 1;
pub const MAX_DOCUMENT_BYTES: usize = 1_048_576;

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RequestKind {
    Sign,
    Submit,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FundingRecord {
    pub model: alephium_l2_sdk::alephium::FundingModel,
    pub source_id: B256,
    pub network_id: u8,
    pub network_genesis_id: B256,
    pub group: u8,
    pub group_count: u8,
    pub head_hash: B256,
    pub head_height: u64,
    pub timestamp_ms: u64,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SpendRecord {
    pub min_gas_amount: u32,
    pub max_gas_amount: u32,
    pub max_gas_price: U256,
    pub max_fee: U256,
    pub contract_deposit: U256,
    pub max_total_debit: U256,
    pub minimum_change: U256,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperationRecord {
    pub intent_id: B256,
    pub operation_id: B256,
    pub publication_scope: B256,
    pub source_artifact_sha256: B256,
    pub script_blake2b256: Option<B256>,
    pub caller_public_key_hex: String,
    pub funding: FundingRecord,
    pub limits: SpendRecord,
    pub approved_script_hex: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub profile: String,
    pub kind: RequestKind,
    pub attempt: Token,
    pub scope_id: B256,
    pub intent_id: B256,
    pub operation_id: B256,
    pub tx_id: B256,
    pub unsigned_sha256: B256,
    pub authority_key_hex: String,
    pub network_id: u8,
    pub network_genesis_id: B256,
    pub operation_policy_sha256: B256,
    pub signature_sha256: Option<B256>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RequestBody {
    pub binding: Binding,
    pub scope: Scope,
    pub operation: OperationRecord,
    pub unsigned_hex: String,
    pub signature_hex: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RequestDocument {
    pub version: u32,
    pub request_identity: B256,
    pub checksum_sha256: B256,
    pub body: RequestBody,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResponseOutcome {
    Signed { signature_hex: String },
    SubmissionAcknowledged,
    Cancelled,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResponseBody {
    pub request_identity: B256,
    pub request_checksum_sha256: B256,
    pub binding: Binding,
    pub outcome: ResponseOutcome,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResponseDocument {
    pub version: u32,
    pub checksum_sha256: B256,
    pub body: ResponseBody,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportStage {
    Prepared,
    FileCreated,
    FileSynced,
    DirectorySynced,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExportProgress {
    pub request_identity: B256,
    pub stage: ExportStage,
}

/// Metadata only. An ACK never changes inclusion/confirmation or permits replay.
pub struct SubmissionAcknowledgement {
    pub request_identity: B256,
    pub tx_id: B256,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandoffError {
    InvalidPath,
    AlreadyExists,
    Io,
    DirectoryDurabilityUnconfirmed,
    Format,
    Bounds,
    Binding,
    Cancelled,
    SdkValidation,
    Publisher(PublisherError),
}
impl From<PublisherError> for HandoffError {
    fn from(value: PublisherError) -> Self {
        Self::Publisher(value)
    }
}
impl std::fmt::Display for HandoffError {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str(match self {
            Self::InvalidPath => "private handoff path rejected",
            Self::AlreadyExists => "handoff request already exists; no rewrite or redispatch",
            Self::Io => "private handoff IO incomplete; preserve file and reconcile",
            Self::DirectoryDurabilityUnconfirmed => {
                "handoff file synced but directory-entry durability is unconfirmed; no replay"
            }
            Self::Format => "handoff version, canonical fields or checksum rejected",
            Self::Bounds => "handoff document exceeds its fixed bounds",
            Self::Binding => "handoff request, durable intent or response binding rejected",
            Self::Cancelled => "wallet cancelled; durable attempt and input quarantine remain",
            Self::SdkValidation => "handoff SDK approval, funding or signature validation rejected",
            Self::Publisher(_) => "handoff publisher transition refused; no redispatch",
        })
    }
}
impl std::error::Error for HandoffError {}
