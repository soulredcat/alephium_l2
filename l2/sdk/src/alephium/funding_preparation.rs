//! One sealed current input into four same-owner fixed outputs; no effects.
#[path = "funding_preparation_types.rs"]
mod types;
#[path = "funding_preparation_wire.rs"]
mod wire;
pub use types::*;

use super::{
    FundingModel, MAX_ALPH_VALUE, MIN_CHANGE_AMOUNT, OutputRef, PreviousOutput, alephium_hash,
    codec, current_funding::CurrentFixedFundingObservation, publisher_address_from_public_key,
};
use alloy_primitives::{B256, U256};

struct Checked<'a> {
    input: &'a PreviousOutput,
    owner: B256,
    fee: U256,
    amounts: [U256; 4],
}

/// No script, contract deposit, output lock, token, data or arbitrary recipient
/// exists in this profile. Source freshness and durable effect ownership remain
/// the controller's responsibility; a selected observation is not a reservation.
pub fn prepare_funding_split(
    spec: &FundingPreparationSpec,
    selected: &CurrentFixedFundingObservation,
) -> Result<ValidatedFundingPreparation, FundingPreparationError> {
    let checked = check(spec, selected)?;
    let raw = wire::encode(
        spec,
        checked.input.reference,
        checked.owner,
        &checked.amounts,
    )?;
    finish(spec, selected, checked, raw)
}

/// Restore no capability from JSON: exact bytes must again match a sealed
/// current input, static purpose policy, and the deterministic four-way split.
pub fn validate_funding_split(
    spec: &FundingPreparationSpec,
    selected: &CurrentFixedFundingObservation,
    raw: &[u8],
) -> Result<ValidatedFundingPreparation, FundingPreparationError> {
    if raw.is_empty() || raw.len() > FUNDING_PREPARATION_MAX_BYTES {
        return Err(FundingPreparationError::Bounds);
    }
    let checked = check(spec, selected)?;
    finish(spec, selected, checked, raw.to_vec())
}

fn check<'a>(
    spec: &FundingPreparationSpec,
    selected: &'a CurrentFixedFundingObservation,
) -> Result<Checked<'a>, FundingPreparationError> {
    use FundingPreparationError as Error;
    let pin = selected.pin();
    let owner = check_spec(spec)?;
    if pin.model != FundingModel::CanonicalFixedCurrentV1
        || pin.network_id != 1
        || pin.group != 0
        || pin.group_count != 4
        || pin.network_genesis_id != spec.network_genesis_id
        || pin.source_id != spec.funding_source_id
        || selected.outputs().len() != 1
        || selected.provenance().len() != 1
    {
        return Err(Error::FundingMismatch);
    }
    selected.validate_head_evidence()?;
    selected.validate_lock_evidence()?;
    for identity in [
        &selected.head_before().identity,
        &selected.head_after().identity,
    ] {
        if selected
            .policy()
            .source_id(&identity.origin, identity.chain_0_0_genesis)?
            != spec.funding_source_id
            || identity.source_id != spec.funding_source_id
            || identity.network_id != 1
            || identity.groups != 4
            || identity.chain_0_0_genesis.hash != spec.network_genesis_id
        {
            return Err(Error::FundingMismatch);
        }
    }
    let input = &selected.outputs()[0];
    if input.reference.key == B256::ZERO
        || input.reference.hint != codec::owner_hint(owner)
        || !codec::is_owner_lock(&input.locking_script, owner)
        || !input.tokens.is_empty()
        || !input.additional_data.is_empty()
    {
        return Err(Error::OwnershipMismatch);
    }
    if input.lock_time_ms > pin.timestamp_ms {
        return Err(Error::ImmatureInput);
    }
    let (fee, amounts) = partition(spec, input.amount)?;
    Ok(Checked {
        input,
        owner,
        fee,
        amounts,
    })
}

fn check_spec(spec: &FundingPreparationSpec) -> Result<B256, FundingPreparationError> {
    use FundingPreparationError as Error;
    if [
        spec.purpose_id,
        spec.operator_source,
        spec.network_genesis_id,
        spec.funding_source_id,
    ]
    .contains(&B256::ZERO)
        || spec.gas_amount != FUNDING_PREPARATION_GAS
        || spec.gas_price != U256::from(FUNDING_PREPARATION_GAS_PRICE)
    {
        return Err(Error::InvalidSpec);
    }
    let address = publisher_address_from_public_key(&spec.caller_public_key)?;
    if address.group() != 0 {
        return Err(Error::OwnershipMismatch);
    }
    Ok(alephium_hash(&spec.caller_public_key))
}

fn partition(
    spec: &FundingPreparationSpec,
    input_amount: U256,
) -> Result<(U256, [U256; 4]), FundingPreparationError> {
    use FundingPreparationError as Error;
    if input_amount.is_zero() || input_amount >= U256::from(MAX_ALPH_VALUE) {
        return Err(Error::Bounds);
    }
    let fee = U256::from(spec.gas_amount)
        .checked_mul(spec.gas_price)
        .ok_or(Error::Overflow)?;
    let remaining = input_amount
        .checked_sub(fee)
        .ok_or(Error::InsufficientAmount)?;
    let quarter = remaining / U256::from(4);
    let last = remaining
        .checked_sub(quarter.checked_mul(U256::from(3)).ok_or(Error::Overflow)?)
        .ok_or(Error::Overflow)?;
    if quarter < U256::from(MIN_CHANGE_AMOUNT) || last < U256::from(MIN_CHANGE_AMOUNT) {
        return Err(Error::InsufficientAmount);
    }
    let amounts = [quarter, quarter, quarter, last];
    let sum = amounts.iter().try_fold(fee, |sum, amount| {
        sum.checked_add(*amount).ok_or(Error::Overflow)
    })?;
    if sum != input_amount {
        return Err(Error::FundingMismatch);
    }
    Ok((fee, amounts))
}

fn finish(
    spec: &FundingPreparationSpec,
    selected: &CurrentFixedFundingObservation,
    checked: Checked<'_>,
    raw: Vec<u8>,
) -> Result<ValidatedFundingPreparation, FundingPreparationError> {
    wire::validate(
        &raw,
        spec,
        checked.input.reference,
        checked.owner,
        &checked.amounts,
    )?;
    let tx_id = alephium_hash(&raw);
    let outputs = output_facts(tx_id, checked.owner, &checked.amounts);
    Ok(ValidatedFundingPreparation {
        spec: spec.clone(),
        pin: selected.pin().clone(),
        raw,
        tx_id,
        input: [checked.input.reference],
        input_amount: checked.input.amount,
        fee: checked.fee,
        outputs,
    })
}

fn output_facts(tx_id: B256, owner: B256, amounts: &[U256; 4]) -> [FundingPreparationOutput; 4] {
    std::array::from_fn(|index| {
        let mut preimage = [0_u8; 36];
        preimage[..32].copy_from_slice(tx_id.as_slice());
        preimage[32..].copy_from_slice(&(index as u32).to_be_bytes());
        FundingPreparationOutput {
            reference: OutputRef {
                hint: codec::owner_hint(owner),
                key: alephium_hash(&preimage),
            },
            index: index as u32,
            amount: amounts[index],
            owner_hash: owner,
        }
    })
}

/// Recovery audit of declared facts and exact bytes only; never creates a
/// current-funding or validated-preparation capability from persisted data.
pub fn inspect_funding_preparation_wire(
    spec: &FundingPreparationSpec,
    raw: &[u8],
    expected_input: OutputRef,
    expected_input_amount: U256,
) -> Result<FundingPreparationWire, FundingPreparationError> {
    if raw.is_empty() || raw.len() > FUNDING_PREPARATION_MAX_BYTES {
        return Err(FundingPreparationError::Bounds);
    }
    let owner = check_spec(spec)?;
    if expected_input.key == B256::ZERO || expected_input.hint != codec::owner_hint(owner) {
        return Err(FundingPreparationError::OwnershipMismatch);
    }
    let (fee, amounts) = partition(spec, expected_input_amount)?;
    wire::validate(raw, spec, expected_input, owner, &amounts)?;
    let tx_id = alephium_hash(raw);
    Ok(FundingPreparationWire {
        tx_id,
        input: [expected_input],
        input_amount: expected_input_amount,
        fee,
        outputs: output_facts(tx_id, owner, &amounts),
    })
}

pub fn verify_funding_preparation_signature(
    cap: &ValidatedFundingPreparation,
    signature: &[u8],
) -> Result<(), FundingPreparationError> {
    super::validation::verify_prehash(cap.tx_id(), &cap.spec().caller_public_key, signature)?;
    Ok(())
}

/// Stored-record signature integrity only; this does not renew funding or
/// permit another sign/submit attempt. The signed digest is always derived here.
pub fn verify_funding_preparation_signature_wire(
    spec: &FundingPreparationSpec,
    raw: &[u8],
    expected_input: OutputRef,
    expected_input_amount: U256,
    signature: &[u8],
) -> Result<(), FundingPreparationError> {
    let facts = inspect_funding_preparation_wire(spec, raw, expected_input, expected_input_amount)?;
    super::validation::verify_prehash(facts.tx_id(), &spec.caller_public_key, signature)?;
    Ok(())
}

#[cfg(test)]
#[path = "../../../../test/sdk/funding_preparation_checks.rs"]
pub(crate) mod tests;
