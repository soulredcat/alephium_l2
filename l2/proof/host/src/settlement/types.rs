//! Native preparation records, never proof, publication or settlement authority.
use alephium_l2_transition_core::{
    SettlementDomain,
    protocol::{Capacity, Head},
};
use serde::Serialize;

/// The development transport bound is distinct from node/block capacity.
pub const MAX_INLINE_DATA_BYTES: usize = 3_000;
pub const INLINE_DATA_VERSION: u32 = 1;

/// Public metadata excludes envelopes, seals and auxiliary witness bytes.
#[derive(Clone, Serialize)]
pub struct InlineDataMetadata {
    pub version: u32,
    pub bytes: u32,
    pub data_sha256: [u8; 32],
    pub journal_sha256: [u8; 32],
    pub parent_checkpoint_sha256: [u8; 32],
    pub domain: SettlementDomain,
    pub chain_id: u64,
    pub genesis_id: [u8; 32],
    pub execution_profile: [u8; 32],
    pub capacity: Capacity,
    pub parent: Head,
    pub head: Head,
    pub old_state_root: [u8; 32],
    pub new_state_root: [u8; 32],
    pub blocks: u64,
    pub executed_transactions: u64,
}

/// Opaque checked inline bytes. This deliberately has no Debug/Serialize,
/// unchecked public constructor, proof flag or availability/eligibility flag.
pub struct PreparedInlineData {
    pub(crate) metadata: InlineDataMetadata,
    pub(crate) data: Vec<u8>,
    pub(crate) parent_checkpoint: Vec<u8>,
}

impl PreparedInlineData {
    pub fn metadata(&self) -> &InlineDataMetadata {
        &self.metadata
    }

    /// Explicit access for an owned future ByteVec request; never log this slice.
    pub fn private_data_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Original parent state only; never confuse this with the final checkpoint.
    pub fn private_parent_checkpoint_bytes(&self) -> &[u8] {
        &self.parent_checkpoint
    }
}

#[derive(Clone, Serialize)]
pub struct ParentCheckpointMetadata {
    pub bytes: u32,
    pub sha256: [u8; 32],
    pub schema: u32,
    pub chain_id: u64,
    pub genesis_id: [u8; 32],
    pub capacity: Capacity,
    pub head: Head,
}

/// Extracted and integrity-pinned state; no native execution/acceptance is implied.
pub struct OriginalParentCheckpoint {
    pub(crate) metadata: ParentCheckpointMetadata,
    pub(crate) bytes: Vec<u8>,
}

impl OriginalParentCheckpoint {
    pub fn metadata(&self) -> &ParentCheckpointMetadata {
        &self.metadata
    }

    pub fn private_checkpoint_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Borrowed private claim bytes. This deliberately has no Debug/Serialize.
pub struct StagedClaim<'a> {
    pub image_id: &'a [u8],
    pub journal_sha256: &'a [u8],
    pub seal: &'a [u8],
    pub auxiliary: &'a [u8],
}

/// Exact existing staged-claim codec; no cryptographic validity is implied.
#[derive(Clone, Serialize)]
pub struct StagedClaimBinding {
    pub image_id: [u8; 32],
    pub journal_sha256: [u8; 32],
    pub seal_sha256: [u8; 32],
    pub auxiliary_sha256: [u8; 32],
    pub payload_id: [u8; 32],
}

#[derive(Clone, Serialize)]
pub struct SessionCandidateMetadata {
    pub factory_id: [u8; 32],
    pub candidate_key: [u8; 32],
    pub proof_path: Vec<u8>,
    pub data_path: Vec<u8>,
    pub claim: StagedClaimBinding,
}

/// A checked native plan, not a canonical creation result or settlement right.
pub struct SessionCandidate {
    pub(crate) metadata: SessionCandidateMetadata,
}

impl SessionCandidate {
    pub fn metadata(&self) -> &SessionCandidateMetadata {
        &self.metadata
    }
}

/// Externally derived child identities; canonical origin still requires the
/// target's authenticated factory checks, never this metadata record alone.
#[derive(Clone, Serialize)]
pub struct SessionBinding {
    pub candidate: SessionCandidateMetadata,
    pub proof_child_id: [u8; 32],
    pub data_child_id: [u8; 32],
    pub statement_id: [u8; 32],
}
