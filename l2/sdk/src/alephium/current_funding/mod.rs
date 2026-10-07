//! Confirmed canonical fixed outputs plus trusted latest availability.
//! This separate profile never implements CanonicalFundingSource or promises an
//! atomic historical snapshot. No signing, reservation, submission or retry.
mod checks;
mod creator;
mod policy;
mod types;
mod wire;

#[cfg(test)]
pub(crate) mod tests;

pub use types::*;

use super::{
    AlephiumValidationError, ApprovedOperation, FundingModel, FundingObservation, OutputRef,
    PreviousOutput, ValidatedUnsignedAlephium, alephium_hash,
    read_node::{
        ChainHeader, FundingView, InclusionStatus, P2pkhAddress, ReadNode, TransactionOutcome,
    },
};
use alloy_primitives::B256;
use std::collections::BTreeMap;

struct Creator {
    outputs: Vec<PreviousOutput>,
    inclusion: InclusionStatus,
    header: ChainHeader,
}

/// Query each selected reference's creator, authenticate its canonical unsigned
/// fixed output, then compare with the same owner's latest UTXO view. Every GET
/// remains an observation from the configured trusted node. Bracketing heads
/// detect changes; they cannot eliminate races or make this a snapshot proof.
pub fn observe_current_fixed_funding(
    operation: &ApprovedOperation,
    references: &[OutputRef],
    node: &ReadNode,
    policy: &CurrentFundingPolicy,
    registry: &impl CreatorScriptRegistry,
) -> Result<CurrentFixedFundingObservation, CurrentFundingError> {
    use CurrentFundingError as Error;
    let pin = &operation.spec().funding;
    checks::request(pin, references, policy)?;
    let before = node.head()?;
    checks::identity(pin, &before.identity, policy)?;
    checks::head(pin, &before.header)?;
    let owner_hash = alephium_hash(&operation.spec().caller_public_key);
    let owner = P2pkhAddress::from_hash(owner_hash);
    if owner.group() != 0 {
        return Err(Error::InvalidPolicy);
    }
    let mut creators = BTreeMap::<B256, Creator>::new();
    let mut outputs = Vec::with_capacity(references.len());
    let mut provenance = Vec::with_capacity(references.len());
    for reference in references {
        let creator_id = node.resolve_output_creator(*reference)?;
        if !creators.contains_key(&creator_id) {
            if creators.len() >= policy.maximum_creators {
                return Err(Error::Bounds);
            }
            let details = node.transaction_details(creator_id)?;
            let observation = details.observation();
            checks::identity(pin, &observation.identity, policy)?;
            if observation.identity != before.identity || observation.transaction_id != creator_id {
                return Err(Error::IdentityMismatch);
            }
            let (inclusion, header) = match &observation.outcome {
                TransactionOutcome::ScriptSucceeded { inclusion, header } => (inclusion, header),
                _ => return Err(Error::CreatorUnconfirmed),
            };
            if header.height > pin.head_height || inclusion.block_hash != header.hash {
                return Err(Error::CreatorMismatch);
            }
            checks::confirmations(inclusion.confirmations, policy.minimum_confirmations)?;
            let approved_script = registry.approved_script(creator_id)?;
            if approved_script
                .as_ref()
                .is_some_and(|script| script.is_empty() || script.len() > 32_768)
            {
                return Err(Error::Bounds);
            }
            let fixed = creator::fixed_outputs(
                details.details().ok_or(Error::MalformedCreator)?,
                creator_id,
                approved_script.as_deref(),
            )?;
            creators.insert(
                creator_id,
                Creator {
                    outputs: fixed,
                    inclusion: inclusion.clone(),
                    header: header.clone(),
                },
            );
        }
        let creator = creators.get(&creator_id).ok_or(Error::CreatorMismatch)?;
        let (index, fixed) = checks::fixed_output(&creator.outputs, reference)?;
        outputs.push(fixed.clone());
        provenance.push(FixedOutputProvenance {
            reference: *reference,
            creator_transaction_id: creator_id,
            fixed_output_index: index,
            inclusion: creator.inclusion.clone(),
            creator_block_height: creator.header.height,
        });
    }
    let current = node.unanchored_utxos(&owner)?;
    checks::identity(pin, &current.identity, policy)?;
    if current.identity != before.identity
        || current.owner != owner
        || current.view != FundingView::LatestIncludingMempoolUnanchored
    {
        return Err(Error::IdentityMismatch);
    }
    for fixed in &outputs {
        let observed = current
            .outputs
            .iter()
            .find(|output| output.reference == fixed.reference)
            .ok_or(Error::AvailabilityMismatch)?;
        checks::latest(fixed, observed, owner_hash, pin.timestamp_ms)?;
    }
    let after = node.head()?;
    checks::identity(pin, &after.identity, policy)?;
    checks::head(pin, &after.header)?;
    if after.identity != before.identity || after.header != before.header {
        return Err(Error::HeadChanged);
    }
    Ok(CurrentFixedFundingObservation {
        funding: FundingObservation {
            pin: pin.clone(),
            outputs,
        },
        policy: policy.clone(),
        provenance,
        before,
        after,
    })
}

/// Reuse all existing canonical spend, ownership, fee, deposit and change
/// validation. The internal common record never escapes as an exact snapshot.
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
    super::validation::validate_unsigned_observation(operation, &observation.funding, raw)
}
