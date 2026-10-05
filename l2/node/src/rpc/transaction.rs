use super::{
    RpcError, parameters,
    read::{hash, storage_error},
};
use crate::{
    protocol::{BLOCK_BYTES, Receipt},
    storage::ReadView,
};
use alloy_consensus::{Transaction, TxEnvelope, transaction::SignerRecoverable};
use alloy_eips::eip2718::{Decodable2718, Encodable2718};
use alloy_primitives::B256;
use serde_json::{Value, json};
use std::sync::Arc;

pub(super) fn envelope(view: &ReadView, hash: B256) -> Result<Option<TxEnvelope>, RpcError> {
    let Some(raw) = view.raw_transaction(hash).map_err(storage_error)? else {
        return Ok(None);
    };
    let mut remaining = raw.as_slice();
    let transaction = TxEnvelope::decode_2718(&mut remaining)
        .map_err(|_| storage_error("invalid stored transaction envelope".into()))?;
    if !remaining.is_empty()
        || transaction.encoded_2718() != raw
        || transaction.tx_hash() != &hash
        || transaction.chain_id() != Some(view.chain_id())
        || !matches!(transaction, TxEnvelope::Legacy(_) | TxEnvelope::Eip1559(_))
    {
        return Err(storage_error(
            "inconsistent stored transaction envelope".into(),
        ));
    }
    Ok(Some(transaction))
}

pub(super) fn kind(transaction: &TxEnvelope) -> u8 {
    match transaction {
        TxEnvelope::Legacy(_) => 0,
        TxEnvelope::Eip1559(_) => 2,
        _ => unreachable!(),
    }
}

pub(super) fn verify_receipt(
    view: &ReadView,
    transaction: &TxEnvelope,
    receipt: &Receipt,
) -> Result<(), RpcError> {
    let sender = transaction
        .recover_signer()
        .map_err(|_| storage_error("invalid stored signer".into()))?;
    if receipt.hash != *transaction.tx_hash()
        || receipt.from != sender
        || receipt.to != transaction.to()
        || receipt.gas_used > transaction.gas_limit()
        || receipt.gas_price != transaction.effective_gas_price(Some(0))
    {
        return Err(storage_error(
            "receipt differs from stored transaction".into(),
        ));
    }
    let block = view
        .block(receipt.block_height)
        .map_err(storage_error)?
        .ok_or_else(|| storage_error("missing receipt block".into()))?;
    let index = usize::try_from(receipt.transaction_index)
        .map_err(|_| storage_error("receipt transaction index overflow".into()))?;
    if block.head.commit_id != receipt.block_hash
        || block.transactions.get(index) != Some(&receipt.hash)
    {
        return Err(storage_error("receipt differs from committed block".into()));
    }
    Ok(())
}

/// RPC metadata intentionally omits signed-envelope bytes and signature fields.
pub(super) fn encode(view: &ReadView, hash: B256) -> Result<Option<Value>, RpcError> {
    let Some(transaction) = envelope(view, hash)? else {
        return Ok(None);
    };
    let status = view
        .status(hash)
        .map_err(storage_error)?
        .ok_or_else(|| storage_error("missing transaction status".into()))?;
    if status.status == "rejected" {
        return Ok(None);
    }
    let receipt = view.receipt(hash).map_err(storage_error)?;
    if let Some(receipt) = &receipt {
        verify_receipt(view, &transaction, receipt)?;
        if !matches!(status.status.as_str(), "committed" | "reverted")
            || status.block_height != Some(receipt.block_height)
        {
            return Err(storage_error(
                "transaction status differs from receipt".into(),
            ));
        }
    } else if status.status != "durably_accepted" || status.block_height.is_some() {
        return Err(storage_error(
            "transaction status has no matching receipt".into(),
        ));
    }
    let sender = transaction
        .recover_signer()
        .map_err(|_| storage_error("invalid stored signer".into()))?;
    let mut result = json!({
        "hash": hash, "from": sender, "to": transaction.to(),
        "nonce": format!("0x{:x}", transaction.nonce()),
        "value": format!("{:#x}", transaction.value()),
        "gas": format!("0x{:x}", transaction.gas_limit()),
        "gasPrice": format!("0x{:x}", transaction.effective_gas_price(Some(0))),
        "input": format!("0x{}", hex::encode(transaction.input())),
        "type": format!("0x{:x}", kind(&transaction)),
        "chainId": format!("0x{:x}", view.chain_id()),
        "blockHash": receipt.as_ref().map(|receipt| receipt.block_hash),
        "blockNumber": receipt.as_ref().map(|receipt| format!("0x{:x}", receipt.block_height)),
        "transactionIndex": receipt.as_ref().map(|receipt| format!("0x{:x}", receipt.transaction_index)),
    });
    if let Some(priority) = transaction.max_priority_fee_per_gas() {
        result["maxFeePerGas"] = json!(format!("0x{:x}", transaction.max_fee_per_gas()));
        result["maxPriorityFeePerGas"] = json!(format!("0x{priority:x}"));
        result["accessList"] = json!(transaction.access_list().map(|list| {
            list.iter()
                .map(|item| json!({"address":item.address,"storageKeys":item.storage_keys}))
                .collect::<Vec<_>>()
        }));
    }
    if serde_json::to_vec(&result)
        .map_err(|_| RpcError::from("Cannot encode transaction"))?
        .len()
        > BLOCK_BYTES
    {
        return Err("Transaction exceeds RPC response bound".into());
    }
    Ok(Some(result))
}

pub(super) fn query(view: Arc<ReadView>, input: &Value) -> Result<Value, RpcError> {
    let params = parameters(input, 1, 1)?;
    Ok(encode(&view, hash(&params[0])?)?.unwrap_or(Value::Null))
}
