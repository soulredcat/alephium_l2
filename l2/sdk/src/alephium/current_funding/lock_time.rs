//! Native asset lock-time semantics, separate from signed creator bytes.
use super::{
    CurrentFundingError as Error, FixedOutputProvenance, LockTimeProjection, PreviousOutput,
};
use crate::alephium::read_node::ChainHeader;

pub(super) fn evidence(fixed: &PreviousOutput, fact: &FixedOutputProvenance) -> Result<(), Error> {
    if fact.reference != fixed.reference
        || fact.effective_lock_time_ms != fixed.lock_time_ms
        || fact.effective_lock_time_ms
            != fact
                .committed_lock_time_ms
                .max(fact.creator_block_timestamp_ms)
        || fact.effective_lock_time_ms > i64::MAX as u64
    {
        return Err(Error::CreatorMismatch);
    }
    Ok(())
}

/// A final creator read must reproduce the same committed and canonical facts,
/// even when a different timestamp would leave max(committed, timestamp) equal.
pub(super) fn rechecked(
    fact: &FixedOutputProvenance,
    committed: &PreviousOutput,
    header: &ChainHeader,
) -> Result<(), Error> {
    if fact.committed_lock_time_ms != committed.lock_time_ms
        || fact.creator_block_timestamp_ms != header.timestamp_ms
        || fact.creator_block_height != header.height
        || fact.inclusion.block_hash != header.hash
    {
        return Err(Error::CreatorMismatch);
    }
    evidence(&effective_output(committed, header.timestamp_ms)?, fact)
}

/// Call only after authenticating the original unsigned body and correlating
/// its canonical creator header. Never re-encode this derived value into txId.
/// v4.7.0 and v4.7.1 use the same native rule:
/// https://github.com/alephium/alephium/blob/v4.7.1/flow/src/main/scala/org/alephium/flow/core/BlockFlowState.scala#L932
pub(super) fn effective_output(
    committed: &PreviousOutput,
    creator_timestamp_ms: u64,
) -> Result<PreviousOutput, Error> {
    if committed.lock_time_ms > i64::MAX as u64 || creator_timestamp_ms > i64::MAX as u64 {
        return Err(Error::CreatorMismatch);
    }
    let mut effective = committed.clone();
    effective.lock_time_ms = committed.lock_time_ms.max(creator_timestamp_ms);
    Ok(effective)
}

/// Block cache copies original output objects, while persisted state stamps
/// max(committed, creator timestamp). The REST view erases that origin tag:
/// https://github.com/alephium/alephium/blob/v4.7.1/flow/src/main/scala/org/alephium/flow/core/BlockFlowGroupView.scala#L183
/// Both exact representations require maturity of the derived effective value.
pub(super) fn projection(
    committed: u64,
    effective: u64,
    observed: Option<u64>,
    maturity_at: u64,
) -> Result<LockTimeProjection, Error> {
    if committed > effective || effective > i64::MAX as u64 {
        return Err(Error::CreatorMismatch);
    }
    let observed = observed.ok_or(Error::AvailabilityLockTimeMissing)?;
    let projection = match (observed == committed, observed == effective) {
        (true, true) => LockTimeProjection::Coincident,
        (true, false) => LockTimeProjection::Committed,
        (false, true) => LockTimeProjection::Effective,
        (false, false) => return Err(Error::AvailabilityLockTimeMismatch),
    };
    if effective > maturity_at {
        return Err(Error::AvailabilityImmature);
    }
    Ok(projection)
}
