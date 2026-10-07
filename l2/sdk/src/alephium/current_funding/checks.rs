use super::{CurrentFundingError as Error, CurrentFundingPolicy};
use crate::alephium::{
    FundingModel, FundingPin, MAX_INPUTS, OutputRef, PreviousOutput,
    read_node::{
        ChainHeader, ConfirmationCounts, GenesisProvenance, IdentityObservation, UnanchoredUtxo,
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
        return Err(Error::CreatorUnconfirmed);
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
    owner_hash: alloy_primitives::B256,
    timestamp_ms: u64,
) -> Result<(), Error> {
    if fixed.reference != observed.reference
        || fixed.amount != observed.amount
        || !fixed.tokens.is_empty()
        || !observed.tokens.is_empty()
        || !fixed.additional_data.is_empty()
        || observed.additional_data.as_deref() != Some(&[][..])
        || observed.lock_time_ms != Some(fixed.lock_time_ms)
        || fixed.lock_time_ms > timestamp_ms
        || fixed.locking_script.len() != 33
        || fixed.locking_script[0] != 0
        || &fixed.locking_script[1..] != owner_hash.as_slice()
    {
        return Err(Error::AvailabilityMismatch);
    }
    Ok(())
}
