//! Reconstruct unsigned creator commitments; generated outputs are not covered.
use super::super::{
    MAX_ALPH_VALUE, MAX_GAS_AMOUNT, MIN_CHANGE_AMOUNT, MIN_GAS_AMOUNT, MIN_GAS_PRICE, OutputRef,
    PreviousOutput, alephium_hash, codec, read_node::P2pkhAddress,
};
use super::{CurrentFundingError as Error, wire};
use alloy_primitives::{B256, U256};
use secp256k1::PublicKey;
use serde_json::{Map, Value};
use std::collections::BTreeSet;

/// The caller separately establishes canonical inclusion and current unspentness.
/// Only fixed outputs are committed by this re-derived unsigned transaction ID.
pub(super) fn fixed_outputs(
    details: &Value,
    claimed_id: B256,
    approved_script: Option<&[u8]>,
) -> Result<Vec<PreviousOutput>, Error> {
    execution_unsigned(details, claimed_id, approved_script).map(|(_, outputs)| outputs)
}

/// Reuse the exact native creator encoder for correlated execution evidence.
/// No signature, funding or execution authority is created by these bytes.
pub(crate) fn execution_unsigned(
    details: &Value,
    claimed_id: B256,
    approved_script: Option<&[u8]>,
) -> Result<(Vec<u8>, Vec<PreviousOutput>), Error> {
    let unsigned = details.get("unsigned").ok_or(Error::MalformedCreator)?;
    let unsigned = wire::object(
        unsigned,
        &[
            "txId",
            "version",
            "networkId",
            "gasAmount",
            "gasPrice",
            "inputs",
            "fixedOutputs",
        ],
        &["scriptOpt"],
    )?;
    if wire::hash(wire::field(unsigned, "txId")?)? != claimed_id {
        return Err(Error::CreatorMismatch);
    }
    if wire::number(wire::field(unsigned, "version")?, u8::MAX.into())? != 0
        || wire::number(wire::field(unsigned, "networkId")?, u8::MAX.into())? != 1
    {
        return Err(Error::UnsupportedCreator);
    }
    let mut encoded = wire::Writer::new();
    encoded.bytes(&[0, 1])?;
    encode_script(unsigned.get("scriptOpt"), approved_script, &mut encoded)?;
    let gas = wire::number(wire::field(unsigned, "gasAmount")?, i32::MAX as u64)? as u32;
    let price = wire::amount(wire::field(unsigned, "gasPrice")?)?;
    if !(MIN_GAS_AMOUNT..=MAX_GAS_AMOUNT).contains(&gas)
        || price < U256::from(MIN_GAS_PRICE)
        || price >= U256::from(MAX_ALPH_VALUE)
    {
        return Err(Error::UnsupportedCreator);
    }
    encoded.int(gas)?;
    encoded.amount(price)?;
    encode_inputs(wire::field(unsigned, "inputs")?, &mut encoded)?;
    let outputs = wire::list(wire::field(unsigned, "fixedOutputs")?)?;
    if outputs.is_empty() {
        return Err(Error::UnsupportedCreator);
    }
    encoded.int(outputs.len() as u32)?;
    let mut previous = Vec::with_capacity(outputs.len());
    for (index, output) in outputs.iter().enumerate() {
        previous.push(encode_output(
            output,
            claimed_id,
            index as u32,
            &mut encoded,
        )?);
    }
    if alephium_hash(encoded.as_bytes()) != claimed_id {
        return Err(Error::CreatorMismatch);
    }
    Ok((encoded.as_bytes().to_vec(), previous))
}

fn encode_script(
    value: Option<&Value>,
    approved: Option<&[u8]>,
    encoded: &mut wire::Writer,
) -> Result<(), Error> {
    if approved.is_some_and(|bytes| bytes.len() > wire::MAX_SCRIPT_BYTES) {
        return Err(Error::Bounds);
    }
    match (value.filter(|value| !value.is_null()), approved) {
        (None, None) => encoded.bytes(&[0]),
        (Some(value), Some(approved)) => {
            let script = wire::hex_bytes(value, wire::MAX_SCRIPT_BYTES)?;
            if approved.is_empty() || script != approved {
                return Err(Error::CreatorMismatch);
            }
            encoded.bytes(&[1])?;
            encoded.bytes(&script)
        }
        _ => Err(Error::CreatorMismatch),
    }
}

fn encode_inputs(value: &Value, encoded: &mut wire::Writer) -> Result<(), Error> {
    let inputs = wire::list(value)?;
    if inputs.is_empty() {
        return Err(Error::UnsupportedCreator);
    }
    encoded.int(inputs.len() as u32)?;
    let mut seen = BTreeSet::new();
    let mut previous_hint = None;
    for input in inputs {
        let input = wire::object(input, &["outputRef", "unlockScript"], &[])?;
        let reference = wire::object(wire::field(input, "outputRef")?, &["hint", "key"], &[])?;
        let hint = wire::hint(wire::field(reference, "hint")?)?;
        let key = wire::hash(wire::field(reference, "key")?)?;
        if !seen.insert(key) {
            return Err(Error::MalformedCreator);
        }
        let unlock = wire::hex_bytes(wire::field(input, "unlockScript")?, 34)?;
        match unlock.as_slice() {
            [0, public_key @ ..] if public_key.len() == 33 => {
                let parsed =
                    PublicKey::from_slice(public_key).map_err(|_| Error::UnsupportedCreator)?;
                if parsed.serialize().as_slice() != public_key
                    || hint != codec::owner_hint(alephium_hash(public_key))
                {
                    return Err(Error::CreatorMismatch);
                }
                previous_hint = Some(hint);
            }
            [3] => {
                // A chain of SameAsPrevious must originate at a validated full
                // P2PKH unlock and retain its owner hint. Preserve the one byte.
                let expected = previous_hint.ok_or(Error::UnsupportedCreator)?;
                if hint != expected {
                    return Err(Error::CreatorMismatch);
                }
            }
            _ => return Err(Error::UnsupportedCreator),
        }
        encoded.bytes(&hint.to_be_bytes())?;
        encoded.bytes(key.as_slice())?;
        encoded.bytes(&unlock)?;
    }
    Ok(())
}

fn encode_output(
    value: &Value,
    tx_id: B256,
    index: u32,
    encoded: &mut wire::Writer,
) -> Result<PreviousOutput, Error> {
    let output = wire::object(
        value,
        &[
            "hint",
            "key",
            "attoAlphAmount",
            "address",
            "tokens",
            "lockTime",
            "message",
        ],
        &[],
    )?;
    require_plain_output(output)?;
    let address = P2pkhAddress::parse(wire::text(wire::field(output, "address")?)?)
        .map_err(|_| Error::UnsupportedCreator)?;
    let amount = wire::amount(wire::field(output, "attoAlphAmount")?)?;
    if amount < U256::from(MIN_CHANGE_AMOUNT) || amount >= U256::from(MAX_ALPH_VALUE) {
        return Err(Error::UnsupportedCreator);
    }
    let lock_time_ms = wire::number(wire::field(output, "lockTime")?, i64::MAX as u64)?;
    let hint = codec::owner_hint(address.hash());
    // v4.7.0 TxInput.scala: Hash.hash(txId.bytes ++ Bytes.from(outputIndex)).
    // Bytes.from(Int) is four-byte BE; this is not a 32-byte integer suffix.
    let mut preimage = [0; 36];
    preimage[..32].copy_from_slice(tx_id.as_slice());
    preimage[32..].copy_from_slice(&index.to_be_bytes());
    let key = alephium_hash(&preimage);
    if wire::hint(wire::field(output, "hint")?)? != hint
        || wire::hash(wire::field(output, "key")?)? != key
    {
        return Err(Error::CreatorMismatch);
    }
    let mut locking_script = Vec::with_capacity(33);
    locking_script.push(0);
    locking_script.extend_from_slice(address.hash().as_slice());
    encoded.amount(amount)?;
    encoded.bytes(&locking_script)?;
    encoded.bytes(&lock_time_ms.to_be_bytes())?;
    encoded.bytes(&[0, 0])?; // Empty token vector and empty additional data.
    Ok(PreviousOutput {
        reference: OutputRef { hint, key },
        amount,
        locking_script,
        lock_time_ms,
        tokens: Vec::new(),
        additional_data: Vec::new(),
    })
}

fn require_plain_output(output: &Map<String, Value>) -> Result<(), Error> {
    if !wire::list(wire::field(output, "tokens")?)?.is_empty()
        || !wire::text(wire::field(output, "message")?)?.is_empty()
    {
        return Err(Error::UnsupportedCreator);
    }
    Ok(())
}
