use super::{
    RpcError, parameters, quantity,
    read::{hash, storage_error},
    transaction,
};
use crate::{protocol::BlockInfo, storage::ReadView};
use alloy_consensus::{
    EMPTY_OMMER_ROOT_HASH, Eip658Value, Receipt, ReceiptEnvelope, TxEnvelope,
    proofs::{calculate_receipt_root, calculate_transaction_root},
};
use alloy_primitives::{B256, Bloom, Log};
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

/// Ethereum transaction/receipt trie roots and bloom derived from the stored
/// envelopes and receipts. They are not authenticated by L1 settlement.
fn derived_roots(view: &ReadView, block: &BlockInfo) -> Result<(B256, B256, Bloom), RpcError> {
    let mut envelopes = Vec::with_capacity(block.transactions.len());
    let mut receipts = Vec::with_capacity(block.transactions.len());
    let mut bloom = Bloom::ZERO;
    for hash in &block.transactions {
        let envelope = transaction::envelope(view, *hash)?
            .ok_or_else(|| storage_error("missing block transaction".into()))?;
        let stored = view
            .receipt(*hash)
            .map_err(storage_error)?
            .ok_or_else(|| storage_error("missing block receipt".into()))?;
        if stored.block_height != block.head.height || stored.block_hash != block.head.commit_id {
            return Err(storage_error("receipt differs from committed block".into()));
        }
        let logs = stored
            .logs
            .iter()
            .map(|log| Log::new_unchecked(log.address, log.topics.clone(), log.data.clone().into()))
            .collect();
        let receipt = Receipt {
            status: Eip658Value::Eip658(stored.success),
            cumulative_gas_used: stored.cumulative_gas,
            logs,
        }
        .with_bloom();
        bloom.accrue_bloom(&receipt.logs_bloom);
        receipts.push(match envelope {
            TxEnvelope::Legacy(_) => ReceiptEnvelope::Legacy(receipt),
            _ => ReceiptEnvelope::Eip1559(receipt),
        });
        envelopes.push(envelope);
    }
    Ok((
        calculate_transaction_root(&envelopes),
        calculate_receipt_root(&receipts),
        bloom,
    ))
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
        if response_bytes > view.capacity().block_bytes {
            return Err("Block exceeds RPC response bound".into());
        }
        transactions.push(value);
    }
    let (transactions_root, receipts_root, logs_bloom) = derived_roots(view, block)?;
    // These SHA-256 local commit identities are not Ethereum RLP header hashes.
    // Standard clients require every header field. There is no Ethereum state
    // trie, so stateRoot is zero; miner and mixHash are the profile's zero
    // beneficiary and PREVRANDAO. l2Commitment names the actual commitment.
    let result = json!({
        "hash":block.head.commit_id,"parentHash":block.parent.commit_id,
        "number":format!("0x{:x}",block.head.height),
        "timestamp":format!("0x{:x}",block.context.timestamp),
        "gasLimit":format!("0x{:x}",block.context.gas_limit),
        "gasUsed":format!("0x{:x}",block.gas_used),
        "size":format!("0x{:x}",block.encoded_bytes),
        "baseFeePerGas":"0x0","transactions":transactions,"uncles":[],
        "sha3Uncles":EMPTY_OMMER_ROOT_HASH,"miner":alloy_primitives::Address::ZERO,
        "stateRoot":B256::ZERO,"transactionsRoot":transactions_root,"receiptsRoot":receipts_root,
        "logsBloom":logs_bloom,"difficulty":"0x0","extraData":"0x",
        "mixHash":B256::ZERO,"nonce":"0x0000000000000000",
        "l2Commitment":"local-sha256-v1"
    });
    if serde_json::to_vec(&result)
        .map_err(|_| RpcError::from("Cannot encode block"))?
        .len()
        > view.capacity().block_bytes
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
