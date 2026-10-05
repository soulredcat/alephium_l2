use super::{RpcError, latest, parameters, quantity};
use crate::storage::ReadView;
use alloy_primitives::{Address, B256, U256};
use serde_json::{Value, json};
use std::sync::Arc;

pub(super) fn address(value: &Value) -> Result<Address, RpcError> {
    value
        .as_str()
        .ok_or("Expected address")?
        .parse()
        .map_err(|_| "Invalid address".into())
}

pub(super) fn hash(value: &Value) -> Result<B256, RpcError> {
    value
        .as_str()
        .ok_or("Expected hash")?
        .parse()
        .map_err(|_| "Invalid hash".into())
}

pub(super) fn storage_error(value: String) -> RpcError {
    RpcError::from(format!("Storage read failed: {value}"))
}

pub(super) fn dispatch(view: Arc<ReadView>, input: &Value) -> Result<Value, RpcError> {
    match input["method"].as_str().unwrap_or("") {
        "eth_chainId" => {
            parameters(input, 0, 0)?;
            Ok(json!(format!("0x{:x}", view.chain_id())))
        }
        "eth_blockNumber" => {
            parameters(input, 0, 0)?;
            Ok(json!(format!("0x{:x}", view.head.height)))
        }
        "net_version" => {
            parameters(input, 0, 0)?;
            Ok(json!(view.chain_id().to_string()))
        }
        "eth_gasPrice" | "eth_maxPriorityFeePerGas" => {
            parameters(input, 0, 0)?;
            Ok(json!("0x1"))
        }
        "eth_getBalance"
        | "eth_getTransactionCount"
        | "l2_getBalance"
        | "l2_getTransactionCount" => {
            let method = input["method"].as_str().ok_or("Expected method")?;
            let pinned = method.starts_with("l2_");
            let params = if pinned {
                parameters(input, 3, 3)?
            } else {
                parameters(input, 1, 2)?
            };
            if pinned {
                super::genesis_pin(&view, &params[2])?;
            }
            let nonce_query = method.ends_with("TransactionCount");
            if nonce_query && params.get(1).and_then(Value::as_str) == Some("pending") {
                let nonce = view
                    .pending_nonce(address(&params[0])?)
                    .map_err(storage_error)?;
                return Ok(json!(format!("0x{nonce:x}")));
            }
            latest(params, 1)?;
            let account = view.account(address(&params[0])?).map_err(storage_error)?;
            if !nonce_query {
                Ok(json!(format!(
                    "{:#x}",
                    account.map(|a| a.balance).unwrap_or(U256::ZERO)
                )))
            } else {
                Ok(json!(format!(
                    "0x{:x}",
                    account.map(|a| a.nonce).unwrap_or(0)
                )))
            }
        }
        "eth_getTransactionReceipt" | "l2_getTransactionReceipt" => {
            let pinned = input["method"] == "l2_getTransactionReceipt";
            let params = if pinned {
                parameters(input, 2, 2)?
            } else {
                parameters(input, 1, 1)?
            };
            if pinned {
                super::genesis_pin(&view, &params[1])?;
            }
            view.receipt(hash(&params[0])?)
                .map_err(storage_error)?
                .map(|r| super::receipt::encode(&view, &r))
                .transpose()
                .map(|r| r.unwrap_or(Value::Null))
        }
        "l2_getTransactionStatus" => {
            let params = parameters(input, 1, 2)?;
            if let Some(expected) = params.get(1) {
                super::genesis_pin(&view, expected)?;
            }
            Ok(json!(
                view.status(hash(&params[0])?).map_err(storage_error)?
            ))
        }
        "eth_getCode" => {
            let params = parameters(input, 1, 2)?;
            latest(params, 1)?;
            let account = view.account(address(&params[0])?).map_err(storage_error)?;
            let code = match account {
                Some(account) => view.code(account.code_hash).map_err(storage_error)?,
                None => vec![],
            };
            Ok(json!(format!("0x{}", hex::encode(code))))
        }
        "eth_getStorageAt" => {
            let params = parameters(input, 2, 3)?;
            latest(params, 2)?;
            let slot = quantity(params[1].as_str().ok_or("Expected slot")?)?;
            let value = view
                .slot(address(&params[0])?, slot)
                .map_err(storage_error)?;
            Ok(json!(format!(
                "0x{}",
                hex::encode(value.to_be_bytes::<32>())
            )))
        }
        "web3_clientVersion" => {
            parameters(input, 0, 0)?;
            Ok(json!(concat!(
                "alephium-l2-node/v",
                env!("CARGO_PKG_VERSION"),
                "/development"
            )))
        }
        "eth_syncing" => {
            // The sole sequencer's committed head is always current.
            parameters(input, 0, 0)?;
            Ok(json!(false))
        }
        "eth_accounts" => {
            // The node holds no signing keys.
            parameters(input, 0, 0)?;
            Ok(json!([]))
        }
        "net_listening" => {
            parameters(input, 0, 0)?;
            Ok(json!(true))
        }
        "eth_feeHistory" => super::fee_history::query(view, input),
        "eth_call" => super::call::query(view, input),
        "eth_estimateGas" => super::estimate::query(view, input),
        "eth_getTransactionByHash" => super::transaction::query(view, input),
        "eth_getBlockByNumber" | "eth_getBlockByHash" => super::block::query(view, input),
        "eth_getLogs" => super::logs::query(view, input),
        _ => Err(RpcError {
            code: -32601,
            message: "Unsupported method".into(),
            data: None,
        }),
    }
}
