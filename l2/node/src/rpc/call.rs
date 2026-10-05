use super::{
    RpcError, bytes, latest, parameters, quantity,
    read::{address, hash},
};
use crate::{execution, protocol::*, storage::ReadView};
use alloy_eips::eip2930::{AccessList, AccessListItem};
use alloy_primitives::{Address, U256};
use serde_json::{Map, Value, json};
use std::sync::Arc;

/// The fee cap is retained for estimator affordability; simulation GASPRICE
/// uses the effective fee at this development profile's fixed zero base fee.
pub(super) struct ParsedCall {
    pub request: CallRequest,
    pub fee_cap: u128,
}

pub(super) fn parse(input: &Value, block_gas: u64) -> Result<ParsedCall, RpcError> {
    let params = parameters(input, 1, 2)?;
    latest(params, 1)?;
    let object = params[0].as_object().ok_or("Expected call object")?;
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "from"
                | "to"
                | "data"
                | "input"
                | "value"
                | "gas"
                | "gasPrice"
                | "maxFeePerGas"
                | "maxPriorityFeePerGas"
                | "accessList"
        )
    }) {
        return Err("Unsupported call field or override".into());
    }
    if object.contains_key("data") && object.contains_key("input") {
        return Err("Use data or input, not both".into());
    }
    let data = object
        .get("data")
        .or_else(|| object.get("input"))
        .map(|value| {
            bytes(
                value.as_str().ok_or("Expected call data")?,
                MAX_TRANSACTION_BYTES,
            )
        })
        .transpose()?
        .unwrap_or_default();
    let gas_limit = number(object, "gas")?.unwrap_or(U256::from(block_gas));
    if gas_limit.is_zero() || gas_limit > U256::from(block_gas) {
        return Err("Call gas out of bounds".into());
    }
    let (gas_price, fee_cap) = fees(object)?;
    let access_list = access_list(object.get("accessList"), data.len())?;
    Ok(ParsedCall {
        request: CallRequest {
            from: object
                .get("from")
                .map(address)
                .transpose()?
                .unwrap_or(Address::ZERO),
            to: object.get("to").map(address).transpose()?,
            data,
            value: number(object, "value")?.unwrap_or(U256::ZERO),
            gas_limit: gas_limit.to::<u64>(),
            gas_price,
            access_list,
        },
        fee_cap,
    })
}

fn number(object: &Map<String, Value>, key: &str) -> Result<Option<U256>, RpcError> {
    object
        .get(key)
        .map(|value| quantity(value.as_str().ok_or("Expected hexadecimal quantity")?))
        .transpose()
}

fn fee(object: &Map<String, Value>, key: &str) -> Result<Option<u128>, RpcError> {
    number(object, key)?
        .map(|value| {
            if value > U256::from(u128::MAX) {
                return Err("Fee exceeds supported range".into());
            }
            Ok(value.to::<u128>())
        })
        .transpose()
}

fn fees(object: &Map<String, Value>) -> Result<(u128, u128), RpcError> {
    let legacy = fee(object, "gasPrice")?;
    let cap = fee(object, "maxFeePerGas")?;
    let priority = fee(object, "maxPriorityFeePerGas")?;
    match (legacy, cap, priority) {
        (Some(price), None, None) => Ok((price, price)),
        (None, Some(cap), Some(priority)) if priority <= cap => Ok((priority, cap)),
        (None, None, None) => Ok((0, 0)),
        _ => Err("Use gasPrice or a valid maxFeePerGas/maxPriorityFeePerGas pair".into()),
    }
}

fn access_list(value: Option<&Value>, data_bytes: usize) -> Result<AccessList, RpcError> {
    let Some(value) = value else {
        return Ok(AccessList::default());
    };
    let entries = value.as_array().ok_or("Expected accessList array")?;
    if entries.len() > 1024 {
        return Err("Access list exceeds address limit".into());
    }
    let mut total_bytes = data_bytes;
    let mut total_slots = 0usize;
    let mut list = Vec::with_capacity(entries.len());
    for entry in entries {
        let object = entry.as_object().ok_or("Expected access list item")?;
        if object.len() != 2
            || !object.contains_key("address")
            || !object.contains_key("storageKeys")
        {
            return Err("Expected access list address/storageKeys only".into());
        }
        let slots = object["storageKeys"]
            .as_array()
            .ok_or("Expected storageKeys array")?;
        total_slots = total_slots.saturating_add(slots.len());
        total_bytes = total_bytes.saturating_add(20 + slots.len().saturating_mul(32));
        if total_slots > 4096 || total_bytes > MAX_TRANSACTION_BYTES {
            return Err("Access list/data exceeds supported limit".into());
        }
        list.push(AccessListItem {
            address: address(&object["address"])?,
            storage_keys: slots.iter().map(hash).collect::<Result<_, _>>()?,
        });
    }
    // Duplicate entries remain present: EIP-2930 charges them individually.
    Ok(AccessList(list))
}

pub(super) fn context(view: &ReadView) -> BlockContext {
    BlockContext {
        number: view.head.height,
        timestamp: view.head.timestamp,
        gas_limit: view.capacity().block_gas,
    }
}

pub(super) fn failure(result: &CallResult, block_bytes: usize) -> RpcError {
    if result.output.len() > block_bytes / 2 {
        return "Call result exceeds RPC response bound".into();
    }
    RpcError {
        code: 3,
        message: if result.halted {
            "EVM call halted"
        } else {
            "EVM call reverted"
        }
        .into(),
        data: (!result.halted).then(|| json!(format!("0x{}", hex::encode(&result.output)))),
    }
}

pub(super) fn query(view: Arc<ReadView>, input: &Value) -> Result<Value, RpcError> {
    let capacity = view.capacity();
    let request = parse(input, capacity.block_gas)?.request;
    let result = execution::simulate((*view).clone(), request, context(&view))?;
    if !result.success {
        return Err(failure(&result, capacity.block_bytes));
    }
    if result.output.len() > capacity.block_bytes / 2 {
        return Err("Call result exceeds RPC response bound".into());
    }
    Ok(json!(format!("0x{}", hex::encode(result.output))))
}
