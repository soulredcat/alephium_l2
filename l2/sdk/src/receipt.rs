use crate::{ClientError, Receipt};
use alloy_primitives::{Address, B256};
use serde_json::{Map, Value};

const LEGACY_BLOCK_GAS_LIMIT: u64 = 30_000_000;
const LEGACY_MAX_BLOCK_TRANSACTIONS: u64 = 256;

/// Larger configured profiles require the containing block, rather than trusting
/// a raised receipt limit or an unbound health response. Legacy calls stay unchanged.
pub(crate) fn required_block(value: &Value) -> Result<Option<B256>, ClientError> {
    let object = value.as_object().ok_or(ClientError::MalformedResponse)?;
    let index = quantity_u64(field(object, "transactionIndex")?)?;
    let cumulative = quantity_u64(field(object, "cumulativeGasUsed")?)?;
    if exceeds_legacy(index, cumulative) {
        Ok(Some(B256::from(fixed_bytes::<32>(field(
            object,
            "blockHash",
        )?)?)))
    } else {
        Ok(None)
    }
}

/// Parse only the receipt metadata exposed by this SDK. The node's local block
/// identity is not an authenticated state root or evidence of L1 settlement.
pub(crate) fn parse(
    value: &Value,
    expected_hash: B256,
    block: Option<&Value>,
) -> Result<Receipt, ClientError> {
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
        || gas_used == 0
        || gas_used > cumulative_gas
        || transaction_index == 0 && cumulative_gas != gas_used
        || contract.is_some() != (to.is_none() && success)
    {
        return Err(ClientError::MalformedResponse);
    }
    if let Some(block) = block {
        validate_block(
            block,
            hash,
            block_hash,
            block_height,
            transaction_index,
            cumulative_gas,
        )?;
    } else if exceeds_legacy(transaction_index, cumulative_gas) {
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

fn exceeds_legacy(index: u64, cumulative_gas: u64) -> bool {
    index >= LEGACY_MAX_BLOCK_TRANSACTIONS || cumulative_gas > LEGACY_BLOCK_GAS_LIMIT
}

fn validate_block(
    value: &Value,
    hash: B256,
    block_hash: B256,
    height: u64,
    index: u64,
    cumulative_gas: u64,
) -> Result<(), ClientError> {
    let object = value.as_object().ok_or(ClientError::MalformedResponse)?;
    let actual_hash = B256::from(fixed_bytes::<32>(field(object, "hash")?)?);
    let number = quantity_u64(field(object, "number")?)?;
    let gas_limit = quantity_u64(field(object, "gasLimit")?)?;
    let gas_used = quantity_u64(field(object, "gasUsed")?)?;
    let transactions = field(object, "transactions")?
        .as_array()
        .ok_or(ClientError::MalformedResponse)?;
    let index = usize::try_from(index).map_err(|_| ClientError::MalformedResponse)?;
    let included = transactions
        .get(index)
        .ok_or(ClientError::MalformedResponse)?;
    if actual_hash != block_hash
        || number != height
        || gas_used > gas_limit
        || cumulative_gas > gas_used
        || index == transactions.len() - 1 && cumulative_gas != gas_used
        || B256::from(fixed_bytes::<32>(included)?) != hash
    {
        return Err(ClientError::MalformedResponse);
    }
    Ok(())
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
        assert_eq!(required_block(&valid).unwrap(), None);
        assert!(parse(&valid, hash, None).unwrap().success);
        assert!(parse(&valid, B256::ZERO, None).is_err());
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
            assert!(
                parse(&value, hash, None).is_err(),
                "invalid receipt field {name}"
            );
        }
        let mut creation = valid;
        creation["to"] = Value::Null;
        assert!(parse(&creation, hash, None).is_err());
        creation["contractAddress"] = json!(Address::repeat_byte(5));
        assert!(parse(&creation, hash, None).unwrap().contract.is_some());
        creation["status"] = json!("0x0");
        assert!(parse(&creation, hash, None).is_err());
        creation["contractAddress"] = Value::Null;
        assert!(!parse(&creation, hash, None).unwrap().success);
        creation.as_object_mut().unwrap().remove("to");
        assert!(parse(&creation, hash, None).is_err());
    }

    #[test]
    fn configured_capacity_requires_matching_block_membership_and_gas() {
        let (hash, mut receipt) = fixture();
        receipt["gasUsed"] = json!("0x2625a00"); // 40 million, index zero.
        receipt["cumulativeGasUsed"] = receipt["gasUsed"].clone();
        let mut block = json!({
            "hash":receipt["blockHash"], "number":"0x1",
            "gasLimit":"0x11e1a300", "gasUsed":receipt["gasUsed"],
            "transactions":[hash]
        });
        assert_eq!(
            required_block(&receipt).unwrap(),
            Some(B256::repeat_byte(2))
        );
        assert!(parse(&receipt, hash, None).is_err());
        assert!(parse(&receipt, hash, Some(&block)).is_ok());
        for (name, invalid) in [
            ("hash", json!(B256::ZERO)),
            ("number", json!("0x2")),
            ("gasLimit", json!("0x1c9c380")),
            ("gasUsed", json!("0x26259ff")),
            ("gasUsed", json!("0x2625a01")),
            ("gasLimit", json!("0x10000000000000000")),
            ("gasUsed", json!("0x02625a00")),
            ("transactions", json!([])),
            ("transactions", json!([B256::ZERO])),
        ] {
            let mut invalid_block = block.clone();
            invalid_block[name] = invalid;
            assert!(
                parse(&receipt, hash, Some(&invalid_block)).is_err(),
                "invalid block field {name}"
            );
        }
        // The configured pending capacity may also produce more than 256 entries.
        receipt["gasUsed"] = json!("0x5208");
        receipt["transactionIndex"] = json!("0x100");
        receipt["cumulativeGasUsed"] = json!(format!("0x{:x}", 257 * 21_000));
        block["gasUsed"] = receipt["cumulativeGasUsed"].clone();
        let mut transactions = vec![json!(B256::repeat_byte(3)); 257];
        transactions[256] = json!(hash);
        block["transactions"] = json!(transactions);
        assert!(required_block(&receipt).unwrap().is_some());
        assert!(parse(&receipt, hash, None).is_err());
        assert!(parse(&receipt, hash, Some(&block)).is_ok());
        receipt["transactionIndex"] = json!("0x101");
        assert!(parse(&receipt, hash, Some(&block)).is_err());
        receipt["transactionIndex"] = json!("0xffffffffffffffff");
        assert!(parse(&receipt, hash, Some(&block)).is_err());
    }
}
