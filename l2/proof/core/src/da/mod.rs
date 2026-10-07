//! Native-only DA bytes and reconstruction; no proof/settlement authority.
mod encoding;
mod reader;
mod reconstruction;

pub use encoding::write_checkpoint_da;
pub use reader::read_checkpoint_da;
pub use reconstruction::reconstruct_checkpoint_da;

use crate::protocol::{Capacity, checkpoint::ExecutionCheckpoint};
use crate::{BatchTransitionJournal, SettlementDomain, TransitionContext};
use alloy_primitives::B256;

pub(crate) const NAMESPACE: &[u8] = b"alephium-l2/reconstruction/checkpoint-suffix/v4";

/// Independently pinned local candidate statement/profile. These inputs are
/// never taken from a fetched package manifest as proof/settlement authority.
pub struct ExpectedDa<'a> {
    pub journal: &'a BatchTransitionJournal,
    pub capacity: Capacity,
}

/// Safe counters/digest only; a successful export is not public availability.
pub struct DaEncodingEvidence {
    pub bytes: usize,
    pub commitment: B256,
}

/// Private canonical data: no Debug/Serialize that could disclose envelopes.
pub struct DecodedCheckpointDa {
    pub(crate) domain: SettlementDomain,
    pub(crate) profile: B256,
    pub(crate) checkpoint: ExecutionCheckpoint,
    pub(crate) blocks: Vec<DaBlock>,
    pub(crate) encoding: DaEncodingEvidence,
}

pub(crate) struct DaBlock {
    pub(crate) context: TransitionContext,
    pub(crate) envelopes: Vec<Vec<u8>>,
}

impl DecodedCheckpointDa {
    pub fn encoding(&self) -> &DaEncodingEvidence {
        &self.encoding
    }

    /// Borrowed canonical input only; consumers must authenticate its old root.
    pub fn parent_checkpoint(&self) -> &ExecutionCheckpoint {
        &self.checkpoint
    }
}
