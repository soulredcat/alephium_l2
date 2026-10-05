use super::{
    RpcError, parameters, quantity,
    read::{hash, storage_error},
    transaction,
};
use crate::{
    protocol::{BLOCK_BYTES, BlockInfo},
    storage::ReadView,
};
use serde_json::{Value, json};
use std::sync::Arc;

pub(super) fn height(value: &Value, view: &ReadView) -> Result<u64, RpcError> {
    match value.as_str().ok_or("Expected block number")? {
        "latest" => Ok(view.head.height),
        "earliest" => Ok(0),
        value => {
            let number = quantity(value)?;
            number
                .try_into()
                .map_err(|_| "Block number exceeds supported range".into())
        }
    }
}

fn encode(view: &ReadView, block: &BlockInfo, full: bool) -> Result<Value, RpcError> {
    let mut transactions = Vec::with_capacity(block.transactions.len());
    // Bound before accumulating full transaction JSON. Stored blocks already
    // satisfy the binary block limit; JSON expansion has its own response bound.
    let mut response_bytes = 2048usize;
    for hash in &block.transactions {
        let value = if full {
            transaction::encode(view, *hash)?
                .ok_or_else(|| storage_error("missing block transaction".into()))?
        } else {
            json!(hash)
        };
        response_bytes = response_bytes.saturating_add(
            serde_json::to_vec(&value)
                .map_err(|_| RpcError::from("Cannot encode block transaction"))?
                .len()
                + 1,
        );
        if response_bytes > BLOCK_BYTES {
            return Err("Block exceeds RPC response bound".into());
        }
        transactions.push(value);
    }
    // These SHA-256 local commit identities are not Ethereum RLP header hashes.
    // Unsupported authenticated roots are explicit null values.
    let result = json!({
        "hash":block.head.commit_id,"parentHash":block.parent.commit_id,
        "number":format!("0x{:x}",block.head.height),
        "timestamp":format!("0x{:x}",block.context.timestamp),
        "gasLimit":format!("0x{:x}",block.context.gas_limit),
        "gasUsed":format!("0x{:x}",block.gas_used),
        "size":format!("0x{:x}",block.encoded_bytes),
        "baseFeePerGas":"0x0","transactions":transactions,"uncles":[],
        "stateRoot":null,"transactionsRoot":null,"receiptsRoot":null,
        "l2Commitment":"local-sha256-v1"
    });
    if serde_json::to_vec(&result)
        .map_err(|_| RpcError::from("Cannot encode block"))?
        .len()
        > BLOCK_BYTES
    {
        return Err("Block exceeds RPC response bound".into());
    }
    Ok(result)
}

pub(super) fn query(view: Arc<ReadView>, input: &Value) -> Result<Value, RpcError> {
    let params = parameters(input, 2, 2)?;
    let full = params[1]
        .as_bool()
        .ok_or("Expected full transactions flag")?;
    let block = if input["method"] == "eth_getBlockByHash" {
        view.block_by_hash(hash(&params[0])?)
            .map_err(storage_error)?
    } else {
        view.block(height(&params[0], &view)?)
            .map_err(storage_error)?
    };
    block
        .map(|block| encode(&view, &block, full))
        .transpose()
        .map(|block| block.unwrap_or(Value::Null))
}
