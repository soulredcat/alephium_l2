//! Immutable native shape and monotone data transitions; no external effects.
use crate::funding_preparation::*;
use alephium_l2_sdk::alephium::funding_preparation::{
    FundingPreparationSpec, inspect_funding_preparation_wire,
    verify_funding_preparation_signature_wire,
};
use alloy_primitives::{B256, U256};

type Error = FundingPreparationError;

pub(super) fn record(record: &FundingPreparationRecord) -> Result<(), Error> {
    let identity = &record.immutable;
    if record.schema != 1
        || record.revision == 0
        || identity.network != 1
        || identity.input_refs.len() != 1
        || identity.outputs.len() != 4
        || identity
            .minimum_confirmations
            .iter()
            .any(|minimum| *minimum < 6)
        || identity.gas_amount != 100_000
        || identity.gas_price != U256::from(100_000_000_000_u64)
        || identity.fee != U256::from(10_000_000_000_000_000_u64)
    {
        return Err(Error::InvalidData);
    }
    let key: [u8; 33] = identity
        .caller_public_key
        .as_slice()
        .try_into()
        .map_err(|_| Error::InvalidData)?;
    let spec = FundingPreparationSpec {
        purpose_id: identity.purpose_id,
        operator_source: identity.operator_source,
        caller_public_key: key,
        network_genesis_id: identity.network_genesis_id,
        funding_source_id: identity.funding_source_id,
        gas_amount: identity.gas_amount,
        gas_price: identity.gas_price,
    };
    let input = identity.input_refs[0].native();
    let wire =
        inspect_funding_preparation_wire(&spec, &identity.unsigned, input, identity.input_amount)
            .map_err(|_| Error::InvalidData)?;
    if wire.tx_id() != identity.transaction_id
        || wire.input_refs() != [input]
        || wire.input_amount() != identity.input_amount
        || wire.fee() != identity.fee
    {
        return Err(Error::InvalidData);
    }
    for (actual, expected) in wire.outputs().iter().zip(&identity.outputs) {
        if actual.reference() != expected.reference.native()
            || actual.index() != expected.index
            || actual.amount() != expected.amount
            || actual.owner_hash() != expected.owner_hash
            || expected.lock_time_ms != 0
        {
            return Err(Error::InvalidData);
        }
    }
    if let Some(signature) = &record.signature {
        if signature.len() != 64 {
            return Err(Error::InvalidSignature);
        }
        verify_funding_preparation_signature_wire(
            &spec,
            &identity.unsigned,
            input,
            identity.input_amount,
            signature,
        )
        .map_err(|_| Error::InvalidSignature)?;
    }
    if record.sign_attempts > 1 || record.submit_attempts > record.sign_attempts {
        return Err(Error::InvalidData);
    }
    let (signs, submits, signed, included, minimum_revision) = match record.phase {
        FundingPreparationPhase::Planned => (0, 0, false, false, 1),
        FundingPreparationPhase::SignAttempted => (1, 0, false, false, 2),
        FundingPreparationPhase::SignAmbiguous => (1, 0, false, false, 3),
        FundingPreparationPhase::Signed => (1, 0, true, false, 3),
        FundingPreparationPhase::SubmitAttempted => (1, 1, true, false, 4),
        FundingPreparationPhase::SubmitAmbiguous | FundingPreparationPhase::Submitted => {
            (1, 1, true, false, 5)
        }
        FundingPreparationPhase::Confirmed => (1, 1, true, true, 5),
    };
    if record.sign_attempts != signs
        || record.submit_attempts != submits
        || record.signature.is_some() != signed
        || record.inclusion.is_some() != included
        || record.revision < minimum_revision
        || record.phase == FundingPreparationPhase::Planned && record.revision != 1
    {
        return Err(Error::InvalidData);
    }
    if let Some(inclusion) = &record.inclusion
        && (inclusion.transaction_id != identity.transaction_id
            || inclusion.block_hash == B256::ZERO
            || inclusion.canonical_head == B256::ZERO
            || inclusion.observed_at_ms > i64::MAX as u64
            || inclusion
                .confirmations
                .iter()
                .zip(identity.minimum_confirmations)
                .any(|(seen, minimum)| *seen < minimum))
    {
        return Err(Error::InvalidData);
    }
    Ok(())
}

pub(super) fn transition(
    previous: Option<&FundingPreparationRecord>,
    next: &FundingPreparationRecord,
) -> Result<(), Error> {
    record(next)?;
    let Some(previous) = previous else {
        return if next.phase == FundingPreparationPhase::Planned && next.revision == 1 {
            Ok(())
        } else {
            Err(Error::InvalidTransition)
        };
    };
    if previous.immutable != next.immutable
        || previous.revision.checked_add(1) != Some(next.revision)
        || previous.signature.is_some() && previous.signature != next.signature
    {
        return Err(Error::InvalidTransition);
    }
    use FundingPreparationPhase as Phase;
    let valid = matches!(
        (previous.phase, next.phase),
        (Phase::Planned, Phase::SignAttempted)
            | (Phase::SignAttempted, Phase::Signed | Phase::SignAmbiguous)
            | (Phase::SignAmbiguous, Phase::Signed)
            | (Phase::Signed, Phase::SubmitAttempted)
            | (
                Phase::SubmitAttempted,
                Phase::Submitted | Phase::SubmitAmbiguous | Phase::Confirmed
            )
            | (Phase::Submitted | Phase::SubmitAmbiguous, Phase::Confirmed)
    );
    if !valid {
        return Err(Error::InvalidTransition);
    }
    Ok(())
}
