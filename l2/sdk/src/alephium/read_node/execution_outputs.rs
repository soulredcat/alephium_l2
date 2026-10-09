//! Bounded native API output shapes. Output references and contract IDs differ.
use super::{ContractAddress, P2pkhAddress, execution_types::*, wire};
use crate::alephium::{MAX_ALPH_VALUE, OutputRef, alephium_hash, codec};
use alloy_primitives::{B256, U256};
use serde_json::{Map, Value};
use std::collections::BTreeSet;

type Error = ExecutedTransactionError;
pub(super) const MAX_EXECUTED_ITEMS: usize = 64;

pub(super) fn object<'a>(
    value: &'a Value,
    required: &[&str],
) -> Result<&'a Map<String, Value>, Error> {
    let value = value.as_object().ok_or(Error::Format)?;
    if value.len() != required.len() || required.iter().any(|name| !value.contains_key(*name)) {
        return Err(Error::Format);
    }
    Ok(value)
}

pub(super) fn list(value: &Value, maximum: usize) -> Result<&[Value], Error> {
    let values = value.as_array().ok_or(Error::Format)?;
    if values.len() > maximum {
        return Err(Error::Bounds);
    }
    Ok(values)
}

pub(super) fn text(value: &Value) -> Result<&str, Error> {
    value.as_str().ok_or(Error::Format)
}

pub(super) fn hint(value: &Value) -> Result<u32, Error> {
    let value = value.as_i64().ok_or(Error::Format)?;
    Ok(i32::try_from(value).map_err(|_| Error::Format)? as u32)
}

pub(super) fn bytes(value: &Value, maximum: usize) -> Result<Vec<u8>, Error> {
    wire::hex_bytes(text(value)?, maximum).map_err(|_| Error::Format)
}

fn hash(value: &Value) -> Result<B256, Error> {
    wire::hash(text(value)?).map_err(|_| Error::Format)
}

pub(super) fn contract_inputs(value: &Value) -> Result<Vec<OutputRef>, Error> {
    let mut seen = BTreeSet::new();
    list(value, MAX_EXECUTED_ITEMS)?
        .iter()
        .map(|value| {
            let value = object(value, &["hint", "key"])?;
            let reference = OutputRef {
                hint: hint(&value["hint"])?,
                key: hash(&value["key"])?,
            };
            if reference.hint & 1 != 0 || reference.key == B256::ZERO || !seen.insert(reference.key)
            {
                return Err(Error::ContractInputs);
            }
            // A contract input key is a previous native output reference, not CID.
            Ok(reference)
        })
        .collect()
}

pub(super) fn generated_outputs(
    value: &Value,
    tx_id: B256,
    fixed: u32,
) -> Result<Vec<ExecutedOutput>, Error> {
    list(value, MAX_EXECUTED_ITEMS)?
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let index = u32::try_from(index).map_err(|_| Error::Bounds)?;
            let global_index = fixed.checked_add(index).ok_or(Error::Bounds)?;
            output(value, tx_id, global_index)
        })
        .collect()
}

fn output(value: &Value, tx_id: B256, global_index: u32) -> Result<ExecutedOutput, Error> {
    let kind = text(value.get("type").ok_or(Error::Format)?)?;
    let asset = match kind {
        "AssetOutput" => true,
        "ContractOutput" => false,
        _ => return Err(Error::Profile),
    };
    let fields = if asset {
        &[
            "type",
            "hint",
            "key",
            "attoAlphAmount",
            "address",
            "tokens",
            "lockTime",
            "message",
        ][..]
    } else {
        &["type", "hint", "key", "attoAlphAmount", "address", "tokens"][..]
    };
    let value = object(value, fields)?;
    let hint = hint(&value["hint"])?;
    let key = hash(&value["key"])?;
    let index = i32::try_from(global_index).map_err(|_| Error::Bounds)?;
    let mut preimage = [0_u8; 36];
    preimage[..32].copy_from_slice(tx_id.as_slice());
    preimage[32..].copy_from_slice(&index.to_be_bytes());
    if key != alephium_hash(&preimage) {
        return Err(Error::Generated);
    }
    let (address, expected_hint, lock_time_ms, additional_data) = if asset {
        let address = P2pkhAddress::parse(text(&value["address"])?).map_err(|_| Error::Profile)?;
        let expected_hint = codec::owner_hint(address.hash());
        let lock = value["lockTime"]
            .as_u64()
            .filter(|time| *time <= i64::MAX as u64)
            .ok_or(Error::Format)?;
        let data = bytes(&value["message"], 16_384)?;
        (
            ExecutedOutputAddress::Asset(address),
            expected_hint,
            Some(lock),
            Some(data),
        )
    } else {
        let address =
            ContractAddress::parse(text(&value["address"])?).map_err(|_| Error::Profile)?;
        let expected_hint = codec::owner_hint(address.id()) & !1;
        (
            ExecutedOutputAddress::Contract(address),
            expected_hint,
            None,
            None,
        )
    };
    if hint != expected_hint {
        return Err(Error::Generated);
    }
    let amount = wire::amount(text(&value["attoAlphAmount"])?).map_err(|_| Error::Format)?;
    if amount == U256::ZERO || amount >= U256::from(MAX_ALPH_VALUE) {
        return Err(Error::Profile);
    }
    let tokens = list(&value["tokens"], MAX_EXECUTED_ITEMS)?
        .iter()
        .map(|token| {
            object(token, &["id", "amount"])?;
            serde_json::from_value::<wire::Token>(token.clone()).map_err(|_| Error::Format)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let tokens = wire::tokens(tokens).map_err(|_| Error::Generated)?;
    Ok(ExecutedOutput {
        global_index,
        reference: OutputRef { hint, key },
        address,
        amount,
        tokens,
        lock_time_ms,
        additional_data,
    })
}
