use super::RpcError;
use crate::{
    protocol::{BLOCK_BYTES, Receipt},
    storage::ReadView,
};
use alloy_primitives::Bloom;
use serde_json::{Value, json};

pub(super) fn log_value(receipt: &Receipt, index: usize) -> Result<Value, RpcError> {
    let log = receipt.logs.get(index).ok_or("Invalid receipt log index")?;
    let log_index = receipt
        .first_log_index
        .checked_add(index as u64)
        .ok_or_else(|| super::read::storage_error("receipt log index overflow".into()))?;
    Ok(json!({"address":log.address,"topics":log.topics,
        "data":format!("0x{}",hex::encode(&log.data)),
        "blockNumber":format!("0x{:x}",receipt.block_height),"blockHash":receipt.block_hash,
        "transactionHash":receipt.hash,"transactionIndex":format!("0x{:x}",receipt.transaction_index),
        "logIndex":format!("0x{log_index:x}"),"removed":false}))
}

pub(super) fn encode(view: &ReadView, receipt: &Receipt) -> Result<Value, RpcError> {
    let transaction = super::transaction::envelope(view, receipt.hash)?
        .ok_or_else(|| super::read::storage_error("missing receipt transaction".into()))?;
    super::transaction::verify_receipt(view, &transaction, receipt)?;
    let mut bloom = Bloom::ZERO;
    let mut logs = Vec::with_capacity(receipt.logs.len());
    let mut result_bytes = 0usize;
    for (index, log) in receipt.logs.iter().enumerate() {
        result_bytes =
            result_bytes.saturating_add(log.data.len() * 2 + log.topics.len() * 66 + 512);
        if result_bytes > BLOCK_BYTES {
            return Err("Receipt logs exceed RPC response bound".into());
        }
        bloom.accrue_raw_log(log.address, &log.topics);
        logs.push(log_value(receipt, index)?);
    }
    let result = json!({"transactionHash":receipt.hash,"transactionIndex":format!("0x{:x}",receipt.transaction_index),
        "blockHash":receipt.block_hash,"blockNumber":format!("0x{:x}",receipt.block_height),
        "from":receipt.from,"to":receipt.to,"contractAddress":receipt.contract,
        "gasUsed":format!("0x{:x}",receipt.gas_used),"cumulativeGasUsed":format!("0x{:x}",receipt.cumulative_gas),
        "effectiveGasPrice":format!("0x{:x}",receipt.gas_price),"status":if receipt.success {"0x1"} else {"0x0"},
        "logs":logs,"logsBloom":format!("{bloom:#x}"),"type":format!("0x{:x}",super::transaction::kind(&transaction))});
    if serde_json::to_vec(&result)
        .map_err(|_| RpcError::from("Cannot encode receipt"))?
        .len()
        > BLOCK_BYTES
    {
        return Err("Receipt exceeds RPC response bound".into());
    }
    Ok(result)
}
