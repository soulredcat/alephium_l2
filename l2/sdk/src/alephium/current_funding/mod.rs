//! Windowed trusted funding observations, never atomic historical UTXO proofs.
//! No signing, reservation, submission, retry or automatic renewal of an intent.
mod availability;
mod checks;
mod creator;
mod lock_time;
mod materialize;
mod policy;
mod types;
mod wire;

#[cfg(test)]
pub(crate) mod tests;

pub use materialize::materialize_current_unsigned;
pub use types::*;

use super::{
    AlephiumValidationError, ApprovedOperation, FundingModel, FundingObservation, FundingPin,
    OutputRef, PreviousOutput, ValidatedUnsignedAlephium, publisher_address_from_public_key,
    read_node::{
        ChainHeader, HeaderObservation, IdentityObservation, InclusionStatus, P2pkhAddress,
        ReadNode,
    },
};
use alloy_primitives::B256;
use std::collections::BTreeMap;

struct Creator {
    outputs: Vec<PreviousOutput>,
    inclusion: InclusionStatus,
    header: ChainHeader,
    chain_from: u8,
    chain_to: u8,
}

struct Context {
    pin: FundingPin,
    before: HeaderObservation,
    owner: P2pkhAddress,
    current_window: bool,
}

/// A previously approved operation never adopts a different head automatically.
pub fn observe_current_fixed_funding(
    operation: &ApprovedOperation,
    references: &[OutputRef],
    node: &ReadNode,
    policy: &CurrentFundingPolicy,
    registry: &impl CreatorScriptRegistry,
) -> Result<CurrentFixedFundingObservation, CurrentFundingError> {
    observe_current_fixed_funding_context(
        &operation.spec().funding,
        &operation.spec().caller_public_key,
        references,
        node,
        policy,
        registry,
    )
}

/// Strict caller-pinned observation: BEFORE, AFTER and the returned pin match.
pub fn observe_current_fixed_funding_context(
    pin: &FundingPin,
    key: &[u8; 33],
    references: &[OutputRef],
    node: &ReadNode,
    policy: &CurrentFundingPolicy,
    registry: &impl CreatorScriptRegistry,
) -> Result<CurrentFixedFundingObservation, CurrentFundingError> {
    checks::request(pin, references, policy)?;
    let owner = context_owner(pin, key)?;
    let before = node.head()?;
    checks::identity(pin, &before.identity, policy)?;
    checks::head(pin, &before.header)?;
    observe(
        Context {
            pin: pin.clone(),
            before,
            owner,
            current_window: false,
        },
        references,
        node,
        policy,
        registry,
    )
}

/// Build one fresh read context internally. Only canonical owner0_0 forward
/// progress of at most32 blocks may update the returned pin to captured AFTER.
/// This result requires a fresh local approval; it cannot renew an old intent.
/// Final creator/UTXO checks follow lineage, then AFTER canonicality is rechecked.
/// They do not prove an atomic UTXO state exactly at AFTER.
pub fn observe_current_fixed_funding_current(
    key: &[u8; 33],
    references: &[OutputRef],
    node: &ReadNode,
    policy: &CurrentFundingPolicy,
    registry: &impl CreatorScriptRegistry,
) -> Result<CurrentFixedFundingObservation, CurrentFundingError> {
    let owner = publisher_owner(key)?;
    let before = node.head()?;
    let pin = FundingPin {
        model: FundingModel::CanonicalFixedCurrentV1,
        source_id: before.identity.source_id,
        network_id: before.identity.network_id,
        network_genesis_id: before.identity.chain_0_0_genesis.hash,
        group: 0,
        group_count: before.identity.groups,
        head_hash: before.header.hash,
        head_height: before.header.height,
        timestamp_ms: before.header.timestamp_ms,
    };
    checks::request(&pin, references, policy)?;
    checks::identity(&pin, &before.identity, policy)?;
    context_owner(&pin, key)?;
    observe(
        Context {
            pin,
            before,
            owner,
            current_window: true,
        },
        references,
        node,
        policy,
        registry,
    )
}

fn observe(
    context: Context,
    references: &[OutputRef],
    node: &ReadNode,
    policy: &CurrentFundingPolicy,
    registry: &impl CreatorScriptRegistry,
) -> Result<CurrentFixedFundingObservation, CurrentFundingError> {
    use CurrentFundingError as Error;
    let pin = &context.pin;
    let mut creators = BTreeMap::<B256, Creator>::new();
    let mut outputs = Vec::with_capacity(references.len());
    let mut provenance = Vec::with_capacity(references.len());
    for reference in references {
        let id = node.resolve_output_creator(*reference)?;
        if !creators.contains_key(&id) {
            if creators.len() >= policy.maximum_creators {
                return Err(Error::Bounds);
            }
            creators.insert(
                id,
                read_creator(node, id, pin, &context.before.identity, policy, registry)?,
            );
        }
        let creator = creators.get(&id).ok_or(Error::CreatorMismatch)?;
        let (index, fixed) = checks::fixed_output(&creator.outputs, reference)?;
        let effective = lock_time::effective_output(fixed, creator.header.timestamp_ms)?;
        provenance.push(FixedOutputProvenance {
            reference: *reference,
            creator_transaction_id: id,
            creator_chain_from: creator.chain_from,
            creator_chain_to: creator.chain_to,
            fixed_output_index: index,
            inclusion: creator.inclusion.clone(),
            creator_block_height: creator.header.height,
            committed_lock_time_ms: fixed.lock_time_ms,
            creator_block_timestamp_ms: creator.header.timestamp_ms,
            effective_lock_time_ms: effective.lock_time_ms,
            initial_lock_time_projection: None,
            final_lock_time_projection: None,
        });
        outputs.push(effective);
    }
    let initial_forms = availability::latest(
        node,
        pin,
        &context.before.identity,
        &context.owner,
        &outputs,
        &provenance,
        policy,
    )?;
    for (fact, form) in provenance.iter_mut().zip(initial_forms) {
        fact.initial_lock_time_projection = Some(form);
    }
    let after = node.head()?;
    checks::identity(pin, &after.identity, policy)?;
    if after.identity != context.before.identity {
        return Err(Error::IdentityMismatch);
    }
    let mut final_pin = pin.clone();
    let head_lineage = if context.current_window {
        let lineage = read_lineage(node, pin, &context.before, &after, policy)?;
        final_pin.head_hash = after.header.hash;
        final_pin.head_height = after.header.height;
        final_pin.timestamp_ms = after.header.timestamp_ms;
        // Owner ancestry alone says nothing about canonical creator X->0 origin.
        for (id, original) in &creators {
            let current = read_creator(node, *id, &final_pin, &after.identity, policy, registry)?;
            if original.header != current.header
                || original.chain_from != current.chain_from
                || original.chain_to != current.chain_to
                || original.inclusion.block_hash != current.inclusion.block_hash
                || original.inclusion.transaction_index != current.inclusion.transaction_index
            {
                return Err(Error::CreatorMismatch);
            }
            for fact in provenance
                .iter_mut()
                .filter(|fact| fact.creator_transaction_id == *id)
            {
                let (index, committed) = checks::fixed_output(&current.outputs, &fact.reference)?;
                if index != fact.fixed_output_index {
                    return Err(Error::CreatorMismatch);
                }
                lock_time::rechecked(fact, committed, &current.header)?;
                fact.inclusion = current.inclusion.clone();
            }
        }
        let final_forms = availability::latest(
            node,
            &final_pin,
            &after.identity,
            &context.owner,
            &outputs,
            &provenance,
            policy,
        )?;
        for (fact, form) in provenance.iter_mut().zip(final_forms) {
            fact.final_lock_time_projection = Some(form);
        }
        let last = node.canonical_header(after.header.height)?;
        checks::identity(&final_pin, &last.identity, policy)?;
        if last.identity != after.identity || last.header != after.header {
            return Err(Error::HeadChanged);
        }
        lineage
    } else {
        checks::head(pin, &after.header)?;
        if after.header != context.before.header {
            return Err(Error::HeadChanged);
        }
        Vec::new()
    };
    Ok(CurrentFixedFundingObservation {
        funding: FundingObservation {
            pin: final_pin,
            outputs,
        },
        policy: policy.clone(),
        provenance,
        before: context.before,
        after,
        current_window: context.current_window,
        head_lineage,
    })
}

fn read_creator(
    node: &ReadNode,
    id: B256,
    pin: &FundingPin,
    identity: &IdentityObservation,
    policy: &CurrentFundingPolicy,
    registry: &impl CreatorScriptRegistry,
) -> Result<Creator, CurrentFundingError> {
    use CurrentFundingError as Error;
    let result = node.funding_creator_details(id)?;
    let details = result.transaction();
    let observation = details.observation();
    checks::identity(pin, &observation.identity, policy)?;
    if &observation.identity != identity || observation.transaction_id != id {
        return Err(Error::IdentityMismatch);
    }
    let (inclusion, header) = checks::creator_execution(&observation.outcome)?;
    let chain_from = result.chain_from().ok_or(Error::CreatorMismatch)?;
    let chain_to = result.chain_to().ok_or(Error::CreatorMismatch)?;
    checks::creator_inclusion(chain_from, chain_to, inclusion, header)?;
    checks::confirmations(inclusion.confirmations, policy.minimum_confirmations)?;
    let script = registry.approved_script(id)?;
    if script
        .as_ref()
        .is_some_and(|s| s.is_empty() || s.len() > 32_768)
    {
        return Err(Error::Bounds);
    }
    Ok(Creator {
        outputs: creator::fixed_outputs(
            details.details().ok_or(Error::MalformedCreator)?,
            id,
            script.as_deref(),
        )?,
        inclusion: inclusion.clone(),
        header: header.clone(),
        chain_from,
        chain_to,
    })
}

fn read_lineage(
    node: &ReadNode,
    pin: &FundingPin,
    before: &HeaderObservation,
    after: &HeaderObservation,
    policy: &CurrentFundingPolicy,
) -> Result<Vec<ChainHeader>, CurrentFundingError> {
    let advance = checks::head_advance(&before.header, &after.header)?;
    let mut lineage = Vec::with_capacity(advance as usize + 1);
    for step in 0..=advance {
        let height = before
            .header
            .height
            .checked_add(u64::from(step))
            .ok_or(CurrentFundingError::HeadChanged)?;
        let observed = node.canonical_header(height)?;
        checks::identity(pin, &observed.identity, policy)?;
        if observed.identity != before.identity {
            return Err(CurrentFundingError::IdentityMismatch);
        }
        lineage.push(observed.header);
    }
    checks::head_lineage(&before.header, &after.header, &lineage)?;
    Ok(lineage)
}

fn publisher_owner(key: &[u8; 33]) -> Result<P2pkhAddress, CurrentFundingError> {
    let owner = publisher_address_from_public_key(key)
        .map_err(|_| CurrentFundingError::InvalidPublisher)?;
    if owner.group() != 0 {
        return Err(CurrentFundingError::InvalidPublisher);
    }
    Ok(owner)
}

fn context_owner(pin: &FundingPin, key: &[u8; 33]) -> Result<P2pkhAddress, CurrentFundingError> {
    if [pin.source_id, pin.network_genesis_id, pin.head_hash].contains(&B256::ZERO)
        || pin.timestamp_ms > i64::MAX as u64
    {
        return Err(CurrentFundingError::InvalidPolicy);
    }
    let owner = publisher_owner(key)?;
    if owner.group() != pin.group {
        return Err(CurrentFundingError::InvalidPublisher);
    }
    Ok(owner)
}

/// A new AFTER-pinned observation cannot validate an old operation's pin.
pub fn validate_current_unsigned(
    operation: &ApprovedOperation,
    observation: &CurrentFixedFundingObservation,
    raw: &[u8],
) -> Result<ValidatedUnsignedAlephium, AlephiumValidationError> {
    if operation.spec().funding.model != FundingModel::CanonicalFixedCurrentV1
        || observation.funding.pin().model != FundingModel::CanonicalFixedCurrentV1
        || observation.funding.pin() != &operation.spec().funding
    {
        return Err(AlephiumValidationError::FundingMismatch);
    }
    for identity in [&observation.before.identity, &observation.after.identity] {
        checks::identity(observation.funding.pin(), identity, &observation.policy)
            .map_err(|_| AlephiumValidationError::FundingSourceMismatch)?;
    }
    observation
        .validate_head_evidence()
        .map_err(|_| AlephiumValidationError::FundingMismatch)?;
    observation
        .validate_lock_evidence()
        .map_err(|_| AlephiumValidationError::FundingMismatch)?;
    super::validation::validate_unsigned_observation(operation, &observation.funding, raw)
}
