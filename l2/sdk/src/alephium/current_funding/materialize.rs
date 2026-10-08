//! Narrow local unsigned construction from independently approved script/policy.
//! No builder RPC, signing, reservation, broadcast or future-funding capability.
use super::{CurrentFixedFundingObservation, CurrentFundingError, validate_current_unsigned};
use crate::alephium::{
    AlephiumValidationError as Error, ApprovedOperation, FundingModel, FundingObservation,
    MAX_ALPH_VALUE, MAX_GAS_AMOUNT, MAX_INPUTS, MAX_SCRIPT_BYTES, MIN_CHANGE_AMOUNT,
    MIN_GAS_AMOUNT, MIN_GAS_PRICE, OutputRef, ValidatedUnsignedAlephium, codec,
    publisher_address_from_public_key,
};
use alloy_primitives::U256;
use std::collections::BTreeSet;

impl CurrentFixedFundingObservation {
    /// Select only already verified outputs. This preserves the original
    /// observer-time evidence and does not claim renewed unspentness or create
    /// a capability for predicted change, a new head or a different owner.
    pub fn select_references(&self, references: &[OutputRef]) -> Result<Self, CurrentFundingError> {
        if references.is_empty()
            || references.len() > MAX_INPUTS
            || references.len() > self.policy.maximum_references
        {
            return Err(CurrentFundingError::Bounds);
        }
        if self.funding.outputs.len() != self.provenance.len() {
            return Err(CurrentFundingError::CreatorMismatch);
        }
        let mut seen = BTreeSet::new();
        let mut outputs = Vec::with_capacity(references.len());
        let mut provenance = Vec::with_capacity(references.len());
        for reference in references {
            if !seen.insert(reference.key) {
                return Err(CurrentFundingError::AvailabilityMismatch);
            }
            let index = self
                .funding
                .outputs
                .iter()
                .position(|output| output.reference == *reference)
                .ok_or(CurrentFundingError::AvailabilityMismatch)?;
            let source = &self.provenance[index];
            if source.reference != *reference {
                return Err(CurrentFundingError::CreatorMismatch);
            }
            outputs.push(self.funding.outputs[index].clone());
            provenance.push(source.clone());
        }
        Ok(Self {
            funding: FundingObservation {
                pin: self.funding.pin.clone(),
                outputs,
            },
            policy: self.policy.clone(),
            provenance,
            before: self.before.clone(),
            after: self.after.clone(),
            current_window: self.current_window,
            head_lineage: self.head_lineage.clone(),
        })
    }
}

/// Emits exactly one same-owner P2PKH change output. An exhausted/dust balance
/// is refused even where the lower-level script validator permits zero outputs.
/// The sealed evidence remains a non-atomic current observation; callers must
/// refresh funding and persist intent/reservations before any external effect.
pub fn materialize_current_unsigned(
    operation: &ApprovedOperation,
    observed: &CurrentFixedFundingObservation,
    gas_amount: u32,
    gas_price: U256,
) -> Result<ValidatedUnsignedAlephium, Error> {
    let spec = operation.spec();
    let pin = observed.pin();
    if spec.funding.model != FundingModel::CanonicalFixedCurrentV1
        || pin.model != FundingModel::CanonicalFixedCurrentV1
        || pin.network_id != 1
        || pin.group != 0
        || pin.group_count != 4
    {
        return Err(Error::UnsupportedProfile);
    }
    if spec.funding != *pin {
        return Err(Error::FundingMismatch);
    }
    let owner = publisher_address_from_public_key(&spec.caller_public_key)
        .map_err(|_| Error::OwnershipMismatch)?;
    if owner.group() != 0 {
        return Err(Error::OwnershipMismatch);
    }
    if operation
        .script_bytes()
        .is_some_and(|script| script.is_empty() || script.len() > MAX_SCRIPT_BYTES)
    {
        return Err(Error::Bounds);
    }
    let limits = &spec.limits;
    if !(MIN_GAS_AMOUNT..=MAX_GAS_AMOUNT).contains(&gas_amount)
        || gas_amount < limits.min_gas_amount
        || gas_amount > limits.max_gas_amount
        || gas_price < U256::from(MIN_GAS_PRICE)
        || gas_price >= U256::from(MAX_ALPH_VALUE)
        || gas_price > limits.max_gas_price
    {
        return Err(Error::FeeExceeded);
    }
    let fee = U256::from(gas_amount)
        .checked_mul(gas_price)
        .ok_or(Error::Overflow)?;
    let debit = fee
        .checked_add(limits.contract_deposit)
        .ok_or(Error::Overflow)?;
    if fee > limits.max_fee || debit > limits.max_total_debit {
        return Err(Error::FeeExceeded);
    }
    let outputs = observed.outputs();
    if outputs.is_empty() || outputs.len() > MAX_INPUTS {
        return Err(Error::Bounds);
    }
    let owner_hash = owner.hash();
    let mut seen = BTreeSet::new();
    let mut total = U256::ZERO;
    let mut inputs = Vec::with_capacity(outputs.len());
    for output in outputs {
        if output.amount.is_zero()
            || !output.tokens.is_empty()
            || !output.additional_data.is_empty()
            || output.lock_time_ms > i64::MAX as u64
            || output.lock_time_ms > pin.timestamp_ms
        {
            return Err(Error::UnsupportedProfile);
        }
        if !seen.insert(output.reference.key)
            || output.reference.key.is_zero()
            || output.reference.hint != codec::owner_hint(owner_hash)
            || !codec::is_owner_lock(&output.locking_script, owner_hash)
        {
            return Err(Error::OwnershipMismatch);
        }
        total = total.checked_add(output.amount).ok_or(Error::Overflow)?;
        inputs.push(codec::Input {
            reference: output.reference,
            public_key: spec.caller_public_key,
        });
    }
    let change = total.checked_sub(debit).ok_or(Error::AmountMismatch)?;
    if change < limits.minimum_change || change < U256::from(MIN_CHANGE_AMOUNT) {
        return Err(Error::AmountMismatch);
    }
    let unsigned = codec::Unsigned {
        network_id: 1,
        gas_amount,
        gas_price,
        inputs,
        outputs: vec![codec::Output {
            amount: change,
            owner_hash,
            lock_time_ms: 0,
        }],
    };
    let raw = codec::encode(&unsigned, operation)?;
    // One existing validator checks canonical encoding, exact approved script,
    // same source/head observation, monetary allocation and all ownership rules.
    validate_current_unsigned(operation, observed, &raw)
}
