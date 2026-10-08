use super::{CurrentFundingError as Error, CurrentFundingPolicy};
use crate::alephium::{
    FundingModel, FundingPin, MAX_INPUTS, OutputRef, PreviousOutput,
    read_node::{
        ChainHeader, ConfirmationCounts, GenesisProvenance, IdentityObservation, InclusionStatus,
        TransactionOutcome, UnanchoredUtxo,
    },
};
use std::collections::BTreeSet;

pub(super) fn request(
    pin: &FundingPin,
    references: &[OutputRef],
    policy: &CurrentFundingPolicy,
) -> Result<(), Error> {
    if pin.model != FundingModel::CanonicalFixedCurrentV1 {
        return Err(Error::WrongFundingModel);
    }
    let minimum = policy.minimum_confirmations;
    if minimum.chain == 0
        || minimum.from_group == 0
        || minimum.to_group == 0
        || policy.maximum_references == 0
        || policy.maximum_references > MAX_INPUTS
        || policy.maximum_creators == 0
        || policy.maximum_creators > MAX_INPUTS
        || pin.network_id != 1
        || pin.group != 0
        || pin.group_count != 4
    {
        return Err(Error::InvalidPolicy);
    }
    if references.is_empty() || references.len() > policy.maximum_references {
        return Err(Error::Bounds);
    }
    if references.iter().copied().collect::<BTreeSet<_>>().len() != references.len() {
        return Err(Error::AvailabilityMismatch);
    }
    Ok(())
}

pub(super) fn identity(
    pin: &FundingPin,
    observed: &IdentityObservation,
    policy: &CurrentFundingPolicy,
) -> Result<(), Error> {
    let committed_source = policy.source_id(&observed.origin, observed.chain_0_0_genesis)?;
    if pin.source_id != committed_source
        || observed.source_id != committed_source
        || !super::policy::allows_version(observed.version)
        || pin.network_id != observed.network_id
        || pin.group_count != observed.groups
        || pin.network_genesis_id != observed.chain_0_0_genesis.hash
        || observed.chain_0_0_genesis.provenance != GenesisProvenance::Independent
    {
        return Err(Error::IdentityMismatch);
    }
    Ok(())
}

pub(super) fn head(pin: &FundingPin, observed: &ChainHeader) -> Result<(), Error> {
    if pin.head_hash != observed.hash
        || pin.head_height != observed.height
        || pin.timestamp_ms != observed.timestamp_ms
    {
        return Err(Error::HeadChanged);
    }
    Ok(())
}

pub(super) fn confirmations(
    observed: ConfirmationCounts,
    minimum: ConfirmationCounts,
) -> Result<(), Error> {
    if observed.chain < minimum.chain
        || observed.from_group < minimum.from_group
        || observed.to_group < minimum.to_group
    {
        return Err(Error::CreatorConfirmationsInsufficient {
            observed_chain: observed.chain,
            observed_from_group: observed.from_group,
            observed_to_group: observed.to_group,
            required_chain: minimum.chain,
            required_from_group: minimum.from_group,
            required_to_group: minimum.to_group,
        });
    }
    Ok(())
}

/// Report only status metadata. Failed, conflicted, pending and missing creators
/// remain ineligible regardless of any other returned transaction fields.
pub(super) fn creator_execution(
    outcome: &TransactionOutcome,
) -> Result<(&InclusionStatus, &ChainHeader), Error> {
    match outcome {
        TransactionOutcome::ScriptSucceeded { inclusion, header } => Ok((inclusion, header)),
        TransactionOutcome::ScriptFailed { .. } => Err(Error::CreatorScriptFailed),
        TransactionOutcome::Conflicted(_) => Err(Error::CreatorConflicted),
        TransactionOutcome::MemPooled => Err(Error::CreatorMemPooled),
        TransactionOutcome::TxNotFound => Err(Error::CreatorTxNotFound),
    }
}

pub(super) fn creator_inclusion(
    chain_from: u8,
    chain_to: u8,
    inclusion: &InclusionStatus,
    header: &ChainHeader,
) -> Result<(), Error> {
    if !super::policy::allows_creator_chain(chain_from, chain_to) {
        return Err(Error::UnsupportedCreator);
    }
    // No owner0_0 height parameter: distinct chains' heights are incomparable.
    if inclusion.block_hash != header.hash {
        return Err(Error::CreatorMismatch);
    }
    Ok(())
}

pub(super) fn fixed_output<'a>(
    outputs: &'a [PreviousOutput],
    reference: &OutputRef,
) -> Result<(u32, &'a PreviousOutput), Error> {
    outputs
        .iter()
        .enumerate()
        .find(|(_, output)| output.reference == *reference)
        .map(|(index, output)| (index as u32, output))
        .ok_or(Error::NotFixedOutput)
}

pub(super) fn latest(
    fixed: &PreviousOutput,
    observed: &UnanchoredUtxo,
    provenance: &super::FixedOutputProvenance,
    owner_hash: alloy_primitives::B256,
    timestamp_ms: u64,
) -> Result<super::LockTimeProjection, Error> {
    super::lock_time::evidence(fixed, provenance)?;
    if fixed.reference != observed.reference
        || fixed.amount != observed.amount
        || !fixed.tokens.is_empty()
        || !observed.tokens.is_empty()
        || !fixed.additional_data.is_empty()
        || observed.additional_data.as_deref() != Some(&[][..])
        || fixed.locking_script.len() != 33
        || fixed.locking_script[0] != 0
        || &fixed.locking_script[1..] != owner_hash.as_slice()
    {
        return Err(Error::AvailabilityMismatch);
    }
    super::lock_time::projection(
        provenance.committed_lock_time_ms,
        fixed.lock_time_ms,
        observed.lock_time_ms,
        timestamp_ms,
    )
}

/// Bound progress on the same owner 0_0 chain. Equal heights require the exact
/// typed header; these checks do not authenticate source-reported header hashes.
pub(super) fn head_advance(before: &ChainHeader, after: &ChainHeader) -> Result<u32, Error> {
    let advance = after
        .height
        .checked_sub(before.height)
        .ok_or(Error::HeadChanged)?;
    if before.hash == alloy_primitives::B256::ZERO
        || after.hash == alloy_primitives::B256::ZERO
        || after.timestamp_ms < before.timestamp_ms
        || advance == 0 && before != after
    {
        return Err(Error::HeadChanged);
    }
    if advance > u64::from(super::MAX_OWNER_HEAD_ADVANCE) {
        return Err(Error::HeadProgressTooLarge {
            observed: advance,
            maximum: super::MAX_OWNER_HEAD_ADVANCE,
        });
    }
    Ok(advance as u32)
}

/// Validate the bounded inclusive before-to-after lineage. The other six DAG
/// dependencies may change between heights; only this chain's parent is linked.
pub(super) fn head_lineage(
    before: &ChainHeader,
    after: &ChainHeader,
    lineage: &[ChainHeader],
) -> Result<(), Error> {
    let advance = head_advance(before, after)?;
    if lineage.len() != advance as usize + 1
        || lineage.first() != Some(before)
        || lineage.last() != Some(after)
    {
        return Err(Error::HeadChanged);
    }
    let mut seen = BTreeSet::new();
    for header in lineage {
        if header.hash == alloy_primitives::B256::ZERO || !seen.insert(header.hash) {
            return Err(Error::HeadChanged);
        }
    }
    for pair in lineage.windows(2) {
        let previous = &pair[0];
        let next = &pair[1];
        if previous.height.checked_add(1) != Some(next.height)
            || next.parent() != Some(previous.hash)
            || next.timestamp_ms < previous.timestamp_ms
        {
            return Err(Error::HeadChanged);
        }
    }
    Ok(())
}
