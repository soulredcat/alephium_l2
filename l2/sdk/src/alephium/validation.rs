//! Pure spending/signature checks over explicit local approval and funding pins.
use super::{codec, types::*};
use alloy_primitives::{B256, U256};
use blake2::{Blake2b, Digest, digest::consts::U32};
use secp256k1::{Message, PublicKey, Secp256k1, ecdsa::Signature};
use std::collections::BTreeSet;

/// Protocol Blake2b with a 256-bit output parameter, not truncated Blake2b-512.
pub fn alephium_hash(bytes: &[u8]) -> B256 {
    B256::from_slice(&Blake2b::<U32>::digest(bytes))
}

/// Pure public identity validation; no key custody, signing or network access.
pub fn publisher_address_from_public_key(
    bytes: &[u8],
) -> Result<super::read_node::P2pkhAddress, AlephiumValidationError> {
    let key =
        PublicKey::from_slice(bytes).map_err(|_| AlephiumValidationError::UnsupportedProfile)?;
    if bytes.len() != 33 || key.serialize().as_slice() != bytes {
        return Err(AlephiumValidationError::UnsupportedProfile);
    }
    Ok(super::read_node::P2pkhAddress::from_hash(alephium_hash(
        bytes,
    )))
}

pub fn approve_operation(
    spec: OperationSpec,
    source: &impl LocalScriptApproval,
) -> Result<ApprovedOperation, AlephiumValidationError> {
    use AlephiumValidationError as Error;
    let limits = &spec.limits;
    if [
        spec.intent_id,
        spec.operation_id,
        spec.publication_scope,
        spec.source_artifact_sha256,
        spec.funding.source_id,
        spec.funding.network_genesis_id,
        spec.funding.head_hash,
    ]
    .contains(&B256::ZERO)
        || spec.funding.group_count != 4
        || spec.funding.group >= spec.funding.group_count
        || spec.funding.timestamp_ms > i64::MAX as u64
        || limits.min_gas_amount < MIN_GAS_AMOUNT
        || limits.max_gas_amount < limits.min_gas_amount
        || limits.max_gas_amount > MAX_GAS_AMOUNT
        || limits.max_gas_price < U256::from(MIN_GAS_PRICE)
        || limits.max_gas_price >= U256::from(MAX_ALPH_VALUE)
        || limits.max_fee.is_zero()
        || limits.max_total_debit.is_zero()
        || limits.contract_deposit > limits.max_total_debit
        || limits.minimum_change < U256::from(MIN_CHANGE_AMOUNT)
    {
        return Err(Error::InvalidApproval);
    }
    let key =
        PublicKey::from_slice(&spec.caller_public_key).map_err(|_| Error::UnsupportedProfile)?;
    if key.serialize() != spec.caller_public_key {
        return Err(Error::UnsupportedProfile);
    }
    let owner_hash = alephium_hash(&spec.caller_public_key);
    if codec::owner_group(owner_hash, spec.funding.group_count)? != spec.funding.group {
        return Err(Error::OwnershipMismatch);
    }
    let script = source.approved_script(&spec)?;
    match (&script, spec.script_blake2b256) {
        (Some(bytes), Some(expected))
            if !bytes.is_empty()
                && bytes.len() <= MAX_SCRIPT_BYTES
                && expected != B256::ZERO
                && alephium_hash(bytes) == expected => {}
        (None, None) if limits.contract_deposit.is_zero() => {}
        _ => return Err(Error::InvalidApproval),
    }
    Ok(ApprovedOperation {
        spec,
        script,
        owner_hash,
    })
}

/// Invoke only the independently configured canonical funding source. There is
/// no network client or cryptographic prevout-authentication claim in this API.
pub fn observe_funding(
    operation: &ApprovedOperation,
    references: &[OutputRef],
    source: &impl CanonicalFundingSource,
) -> Result<FundingObservation, AlephiumValidationError> {
    use AlephiumValidationError as Error;
    if operation.spec.funding.model != FundingModel::ExactHeadSnapshotV1 {
        return Err(Error::UnsupportedProfile);
    }
    if references.is_empty() || references.len() > MAX_INPUTS {
        return Err(Error::Bounds);
    }
    if references.iter().copied().collect::<BTreeSet<_>>().len() != references.len() {
        return Err(Error::FundingMismatch);
    }
    if source.source_id() != operation.spec.funding.source_id {
        return Err(Error::FundingSourceMismatch);
    }
    let outputs = source.unspent_outputs(&operation.spec.funding, references)?;
    if outputs.len() != references.len()
        || !outputs
            .iter()
            .map(|output| output.reference)
            .eq(references.iter().copied())
    {
        return Err(Error::FundingMismatch);
    }
    for output in &outputs {
        if output.locking_script.len() != 33
            || !output.tokens.is_empty()
            || !output.additional_data.is_empty()
            || output.amount.is_zero()
            || output.lock_time_ms > i64::MAX as u64
            || output.lock_time_ms > operation.spec.funding.timestamp_ms
        {
            return Err(Error::UnsupportedProfile);
        }
    }
    Ok(FundingObservation {
        pin: operation.spec.funding.clone(),
        outputs,
    })
}

/// Extract the exact references to query/reserve, without granting spend safety.
pub fn unsigned_input_refs(
    operation: &ApprovedOperation,
    raw: &[u8],
) -> Result<Vec<OutputRef>, AlephiumValidationError> {
    let tx = codec::decode(raw, operation)?;
    if tx.inputs.is_empty() {
        return Err(AlephiumValidationError::FundingMismatch);
    }
    Ok(tx.inputs.iter().map(|input| input.reference).collect())
}

/// Validate canonical bytes and allocation of ALPH to fee, controlled script
/// deposit and optional same-owner change. Input reservation and freshness at
/// dispatch belong to the durable publisher; this call performs no signing.
pub fn validate_unsigned(
    operation: &ApprovedOperation,
    funding: &FundingObservation,
    raw: &[u8],
) -> Result<ValidatedUnsignedAlephium, AlephiumValidationError> {
    if operation.spec.funding.model != FundingModel::ExactHeadSnapshotV1
        || funding.pin.model != FundingModel::ExactHeadSnapshotV1
    {
        return Err(AlephiumValidationError::UnsupportedProfile);
    }
    validate_unsigned_observation(operation, funding, raw)
}

// Both sealed observation paths retain one exact monetary/ownership validator.
// Source semantics stay explicit in the operation pin and private constructors.
pub(super) fn validate_unsigned_observation(
    operation: &ApprovedOperation,
    funding: &FundingObservation,
    raw: &[u8],
) -> Result<ValidatedUnsignedAlephium, AlephiumValidationError> {
    use AlephiumValidationError as Error;
    let tx = codec::decode(raw, operation)?;
    if tx.inputs.is_empty() {
        return Err(Error::FundingMismatch);
    }
    let spec = &operation.spec;
    let limits = &spec.limits;
    if tx.network_id != spec.funding.network_id || funding.pin != spec.funding {
        return Err(Error::FundingMismatch);
    }
    if tx.gas_amount < limits.min_gas_amount
        || tx.gas_amount > limits.max_gas_amount
        || tx.gas_price < U256::from(MIN_GAS_PRICE)
        || tx.gas_price >= U256::from(MAX_ALPH_VALUE)
        || tx.gas_price > limits.max_gas_price
    {
        return Err(Error::FeeExceeded);
    }
    let fee = U256::from(tx.gas_amount)
        .checked_mul(tx.gas_price)
        .ok_or(Error::Overflow)?;
    let debit = fee
        .checked_add(limits.contract_deposit)
        .ok_or(Error::Overflow)?;
    if fee > limits.max_fee || debit > limits.max_total_debit {
        return Err(Error::FeeExceeded);
    }
    if funding.outputs.len() != tx.inputs.len() {
        return Err(Error::FundingMismatch);
    }
    let mut seen = BTreeSet::new();
    let mut input_amount = U256::ZERO;
    for (input, previous) in tx.inputs.iter().zip(&funding.outputs) {
        if previous.locking_script.len() != 33
            || !previous.tokens.is_empty()
            || !previous.additional_data.is_empty()
            || previous.amount.is_zero()
            || previous.lock_time_ms > i64::MAX as u64
            || previous.lock_time_ms > spec.funding.timestamp_ms
        {
            return Err(Error::UnsupportedProfile);
        }
        if !seen.insert(input.reference) || input.reference != previous.reference {
            return Err(Error::FundingMismatch);
        }
        if input.public_key != spec.caller_public_key
            || input.reference.hint != codec::owner_hint(operation.owner_hash)
            || !codec::is_owner_lock(&previous.locking_script, operation.owner_hash)
        {
            return Err(Error::OwnershipMismatch);
        }
        input_amount = input_amount
            .checked_add(previous.amount)
            .ok_or(Error::Overflow)?;
    }
    let change = input_amount
        .checked_sub(debit)
        .ok_or(Error::AmountMismatch)?;
    match tx.outputs.as_slice() {
        // A script-free transaction cannot supply the protocol-required output
        // through generated outputs. A script's effects remain locally approved.
        [] if change.is_zero() && operation.script.is_some() => {}
        [output]
            if !change.is_zero()
                && output.amount == change
                && change >= limits.minimum_change
                && output.owner_hash == operation.owner_hash
                && output.lock_time_ms == 0 => {}
        _ => return Err(Error::AmountMismatch),
    }
    let fixed_output_count = u32::try_from(tx.outputs.len()).map_err(|_| Error::Bounds)?;
    let inputs = tx.inputs.into_iter().map(|input| input.reference).collect();
    Ok(ValidatedUnsignedAlephium {
        raw: raw.to_vec(),
        tx_id: alephium_hash(raw),
        operation: operation.clone(),
        inputs,
        fee,
        input_amount,
        change,
        fixed_output_count,
    })
}

/// Verify one detached 64-byte low-S r||s signature over the transaction ID.
/// The ID is the ECDSA prehash: no Ethereum prefix, recovery byte or extra hash.
pub fn validate_detached_signature(
    unsigned: ValidatedUnsignedAlephium,
    signature: &[u8],
) -> Result<ValidatedSignedAlephium, AlephiumValidationError> {
    let signature = verify_prehash(
        unsigned.tx_id,
        &unsigned.operation.spec.caller_public_key,
        signature,
    )?;
    Ok(ValidatedSignedAlephium {
        unsigned,
        signature,
    })
}

pub(super) fn verify_prehash(
    tx_id: B256,
    public_key: &[u8; 33],
    signature: &[u8],
) -> Result<[u8; 64], AlephiumValidationError> {
    use AlephiumValidationError as Error;
    let signature: [u8; 64] = signature.try_into().map_err(|_| Error::InvalidSignature)?;
    let mut parsed = Signature::from_compact(&signature).map_err(|_| Error::InvalidSignature)?;
    parsed.normalize_s();
    if parsed.serialize_compact() != signature {
        return Err(Error::InvalidSignature);
    }
    let key = PublicKey::from_slice(public_key).map_err(|_| Error::InvalidSignature)?;
    Secp256k1::verification_only()
        .verify_ecdsa(Message::from_digest(tx_id.0), &parsed, &key)
        .map_err(|_| Error::InvalidSignature)?;
    Ok(signature)
}
