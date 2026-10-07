//! Durable publisher records. Secret/signed bytes deliberately have no Debug.
use alloy_primitives::B256;
use serde::{Deserialize, Serialize};

pub const MAX_PUBLICATIONS: usize = 256;
pub const MAX_HISTORY: usize = 4096;
pub const MAX_UNSIGNED_BYTES: usize = 131_072;
pub const MAX_INPUTS: usize = 64;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub l1_network: u8,
    pub l1_genesis: B256,
    pub l2_chain_id: u64,
    pub l2_genesis: B256,
    pub factory: B256,
    pub execution_profile: B256,
    pub publisher_key: Vec<u8>,
    pub canonical_source: B256,
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Token {
    pub revision: u64,
    pub fencing_epoch: u64,
    pub canonical_head: B256,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReservedInput {
    pub hint: u32,
    pub key: B256,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    pub id: B256,
    pub operation_id: B256,
    pub operation_policy_sha256: B256,
    pub parent: Option<B256>,
    pub tx_id: B256,
    pub unsigned: Vec<u8>,
    pub inputs: Vec<ReservedInput>,
    pub network: u8,
    pub l1_genesis: B256,
    pub canonical_source: B256,
    pub artifact_hash: B256,
    pub script_hash: B256,
    pub expected_effect: B256,
    pub authority_key: Vec<u8>,
    pub created_at_ms: u64,
    pub review_after_ms: u64,
    pub confirmations: u64,
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Intent,
    SignAttempted,
    SignAmbiguous,
    Signed,
    SubmitAttempted,
    SubmitAmbiguous,
    Submitted,
    Included,
    Confirmed,
    Orphaned,
    Abandoned,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Inclusion {
    pub block: B256,
    pub height: u64,
    pub canonical_head: B256,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Publication {
    pub intent: Intent,
    pub phase: Phase,
    pub sign_attempts: u8,
    pub submit_attempts: u8,
    pub signature: Option<Vec<u8>>,
    pub inclusion: Option<Inclusion>,
    /// Once signing may have happened, retain/quarantine inputs on abandonment.
    pub reservations_retained: bool,
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditKind {
    Fence,
    Intent,
    SignAttempt,
    SignAmbiguous,
    Signed,
    SubmitAttempt,
    SubmitAmbiguous,
    Submitted,
    CanonicalHead,
    CanonicalObservation,
    Reorg,
    Abandon,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuditEntry {
    pub revision: u64,
    pub fencing_epoch: u64,
    pub intent_id: Option<B256>,
    pub kind: AuditKind,
    pub at_ms: u64,
    pub canonical_head: B256,
    pub inclusion: Option<Inclusion>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublisherSnapshot {
    pub schema: u32,
    pub scope: Scope,
    pub revision: u64,
    pub fencing_epoch: u64,
    pub canonical_head: B256,
    pub records: Vec<Publication>,
    pub history: Vec<AuditEntry>,
}

impl PublisherSnapshot {
    pub fn empty(scope: Scope) -> Self {
        Self {
            schema: 2,
            scope,
            revision: 0,
            fencing_epoch: 0,
            canonical_head: B256::ZERO,
            records: Vec::new(),
            history: Vec::new(),
        }
    }
    pub fn token(&self) -> Token {
        Token {
            revision: self.revision,
            fencing_epoch: self.fencing_epoch,
            canonical_head: self.canonical_head,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublisherError {
    InvalidInput,
    Conflict,
    StaleFence,
    Storage,
    CorruptState,
    InvalidTransition,
    Disabled,
    Ambiguous,
    InvalidSignature,
    InvalidObservation,
    ResourceLimit,
}

impl std::fmt::Display for PublisherError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(match self {
            Self::InvalidInput => "publisher input binding rejected",
            Self::Conflict => "publisher revision or canonical head changed",
            Self::StaleFence => "publisher writer fencing epoch is stale",
            Self::Storage => "publisher durability failed; restart and reconcile",
            Self::CorruptState => "publisher durable state is malformed",
            Self::InvalidTransition => "publisher transition is not permitted",
            Self::Disabled => "publisher external operation is disabled",
            Self::Ambiguous => "publisher external outcome is ambiguous; reconcile only",
            Self::InvalidSignature => "publisher signed response rejected",
            Self::InvalidObservation => "publisher canonical evidence rejected",
            Self::ResourceLimit => "publisher declared local record bound reached",
        })
    }
}
impl std::error::Error for PublisherError {}

/// Implemented only by storage/repository adapters. A failed durable operation
/// grants no permission for a callback or automatic replay of an external effect.
pub trait Repository {
    fn publisher_load(&self, scope: &Scope) -> Result<Option<PublisherSnapshot>, PublisherError>;
    fn publisher_cas(
        &mut self,
        expected_revision: u64,
        expected_fence: u64,
        next: &PublisherSnapshot,
    ) -> Result<PublisherSnapshot, PublisherError>;
}
