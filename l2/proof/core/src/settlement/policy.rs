//! Independently pinned ancestry/domain/time checks, separate from proof and DA.
use super::journal::validate_journal_v4;
use crate::{
    BatchTransitionJournal, SettlementDomain,
    protocol::{Head, validate_chain_id},
};
use alloy_primitives::B256;

/// Operator/release-pinned settlement domain and drift, never candidate-derived.
#[derive(Clone)]
pub struct SettlementPolicy {
    pub domain: SettlementDomain,
    pub chain_id: u64,
    pub genesis_id: B256,
    pub execution_profile: B256,
    pub max_future_seconds: u64,
}

/// The last canonically accepted head/root, supplied by the settlement owner.
#[derive(Clone)]
pub struct SettlementAnchor {
    pub head: Head,
    pub state_root: B256,
}

impl SettlementPolicy {
    /// Check candidate eligibility against independent pins and an L1 timestamp.
    /// L2 Head timestamps are seconds; the caller supplies canonical L1 time in
    /// milliseconds. Success does not verify a receipt, DA availability or L1
    /// confirmation, and does not mutate or advance the accepted anchor.
    pub fn validate(
        &self,
        anchor: &SettlementAnchor,
        journal: &BatchTransitionJournal,
        l1_timestamp_ms: u64,
    ) -> Result<(), String> {
        self.domain.validate()?;
        validate_chain_id(self.chain_id)?;
        validate_journal_v4(journal)?;
        if self.genesis_id == B256::ZERO
            || self.execution_profile == B256::ZERO
            || anchor.state_root == B256::ZERO
            || anchor.head.genesis_id != self.genesis_id
            || journal.domain != self.domain
            || journal.chain_id != self.chain_id
            || journal.genesis_id != self.genesis_id
            || journal.execution_profile != self.execution_profile
        {
            return Err(
                "Settlement candidate differs from the pinned domain or execution identity".into(),
            );
        }
        if journal.parent != anchor.head
            || journal.old_state_root != anchor.state_root
            || journal.batch_start
                != anchor
                    .head
                    .height
                    .checked_add(1)
                    .ok_or("Settlement anchor height overflow")?
        {
            return Err(
                "Settlement candidate does not extend the accepted head and state root".into(),
            );
        }
        let future_ms = self
            .max_future_seconds
            .checked_mul(1000)
            .ok_or("Settlement timestamp drift overflow")?;
        let maximum_ms = l1_timestamp_ms
            .checked_add(future_ms)
            .ok_or("Settlement L1 timestamp bound overflow")?;
        let candidate_ms = journal
            .head
            .timestamp
            .checked_mul(1000)
            .ok_or("Settlement L2 timestamp overflow")?;
        if candidate_ms > maximum_ms {
            return Err(
                "Settlement candidate timestamp exceeds the pinned L1-relative drift".into(),
            );
        }
        Ok(())
    }
}
