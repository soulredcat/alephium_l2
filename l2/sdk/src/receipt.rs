use crate::{ClientError, Receipt};
use alloy_primitives::{Address, B256};
use serde_json::{Map, Value};

const BLOCK_GAS_LIMIT: u64 = 30_000_000;
const MAX_BLOCK_TRANSACTIONS: u64 = 256;

/// Parse only the receipt metadata exposed by this SDK. The node's local block
/// identity is not an authenticated state root or evidence of L1 settlement.
pub(crate) fn parse(value: &Value, expected_hash: B256) -> Result<Receipt, ClientError> {
    let object = value.as_object().ok_or(ClientError::MalformedResponse)?;
    let hash = B256::from(fixed_bytes::<32>(field(object, "transactionHash")?)?);
    let block_hash = B256::from(fixed_bytes::<32>(field(object, "blockHash")?)?);
    let block_height = quantity_u64(field(object, "blockNumber")?)?;
    let transaction_index = quantity_u64(field(object, "transactionIndex")?)?;
    let gas_used = quantity_u64(field(object, "gasUsed")?)?;
    let cumulative_gas = quantity_u64(field(object, "cumulativeGasUsed")?)?;
    let effective_gas_price = quantity(field(object, "effectiveGasPrice")?, 32)?;
    let success = match quantity(field(object, "status")?, 2)? {
        0 => false,
        1 => true,
        _ => return Err(ClientError::MalformedResponse),
    };
    let transaction_type = match quantity(field(object, "type")?, 2)? {
        0 => 0,
        2 => 2,
        _ => return Err(ClientError::MalformedResponse),
    };
    let from = Address::from(fixed_bytes::<20>(field(object, "from")?)?);
    let to = optional_address(field(object, "to")?)?;
    let contract = optional_address(field(object, "contractAddress")?)?;
    if hash != expected_hash
        || block_height == 0
        || transaction_index >= MAX_BLOCK_TRANSACTIONS
        || gas_used == 0
        || gas_used > cumulative_gas
        || transaction_index == 0 && cumulative_gas != gas_used
        || cumulative_gas > BLOCK_GAS_LIMIT
        || contract.is_some() != (to.is_none() && success)
    {
        return Err(ClientError::MalformedResponse);
    }
    Ok(Receipt {
        hash,
        block_hash,
        block_height,
        success,
        from,
        to,
        contract,
        gas_used,
        effective_gas_price,
        transaction_type,
    })
}

fn field<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a Value, ClientError> {
    object.get(name).ok_or(ClientError::MalformedResponse)
}

fn quantity(value: &Value, max_digits: usize) -> Result<u128, ClientError> {
    let digits = value
        .as_str()
        .and_then(|value| value.strip_prefix("0x"))
        .ok_or(ClientError::MalformedResponse)?;
    if digits.is_empty()
        || digits.len() > max_digits
        || (digits.len() > 1 && digits.starts_with('0'))
        || !digits
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ClientError::MalformedResponse);
    }
    u128::from_str_radix(digits, 16).map_err(|_| ClientError::MalformedResponse)
}

fn quantity_u64(value: &Value) -> Result<u64, ClientError> {
    u64::try_from(quantity(value, 16)?).map_err(|_| ClientError::MalformedResponse)
}

fn fixed_bytes<const N: usize>(value: &Value) -> Result<[u8; N], ClientError> {
    let digits = value
        .as_str()
        .and_then(|value| value.strip_prefix("0x"))
        .ok_or(ClientError::MalformedResponse)?;
    if digits.len() != N * 2 || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ClientError::MalformedResponse);
    }
    let mut bytes = [0; N];
    hex::decode_to_slice(digits, &mut bytes).map_err(|_| ClientError::MalformedResponse)?;
    Ok(bytes)
}

fn optional_address(value: &Value) -> Result<Option<Address>, ClientError> {
    if value.is_null() {
        Ok(None)
    } else {
        fixed_bytes::<20>(value).map(|bytes| Some(Address::from(bytes)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> (B256, Value) {
        let hash = B256::repeat_byte(1);
        let value = json!({
            "transactionHash": hash, "blockHash": B256::repeat_byte(2),
            "blockNumber": "0x1", "transactionIndex": "0x0",
            "gasUsed": "0x5208", "cumulativeGasUsed": "0x5208",
            "effectiveGasPrice": "0xffffffffffffffffffffffffffffffff",
            "status": "0x1", "type": "0x2", "from": Address::repeat_byte(3),
            "to": Address::repeat_byte(4), "contractAddress": null
        });
        (hash, value)
    }

    #[test]
    fn receipt_identity_bounds_and_creation_semantics() {
        let (hash, valid) = fixture();
        assert!(parse(&valid, hash).unwrap().success);
        assert!(parse(&valid, B256::ZERO).is_err());
        for (name, invalid) in [
            ("blockNumber", json!("0x0")),
            ("blockNumber", json!("0x10000000000000000")),
            ("transactionIndex", json!("0x100")),
            ("gasUsed", json!("0x05208")),
            ("gasUsed", json!("0x0")),
            ("cumulativeGasUsed", json!("0x1")),
            ("cumulativeGasUsed", json!("0x5209")),
            ("cumulativeGasUsed", json!("0x1c9c381")),
            (
                "effectiveGasPrice",
                json!("0x100000000000000000000000000000000"),
            ),
            ("status", json!("0x2")),
            ("type", json!("0x1")),
            ("from", json!("0x03")),
            ("contractAddress", json!(Address::repeat_byte(5))),
        ] {
            let mut value = valid.clone();
            value[name] = invalid;
            assert!(parse(&value, hash).is_err(), "invalid receipt field {name}");
        }
        let mut creation = valid;
        creation["to"] = Value::Null;
        assert!(parse(&creation, hash).is_err());
        creation["contractAddress"] = json!(Address::repeat_byte(5));
        assert!(parse(&creation, hash).unwrap().contract.is_some());
        creation["status"] = json!("0x0");
        assert!(parse(&creation, hash).is_err());
        creation["contractAddress"] = Value::Null;
        assert!(!parse(&creation, hash).unwrap().success);
        creation.as_object_mut().unwrap().remove("to");
        assert!(parse(&creation, hash).is_err());
    }
}
