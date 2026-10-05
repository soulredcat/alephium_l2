//! eth_feeHistory over committed blocks. The base fee is fixed at zero, so a
//! transaction's effective gas price is its whole priority reward.
use super::{RpcError, block, parameters, quantity, read::storage_error};
use crate::storage::ReadView;
use serde_json::{Value, json};
use std::sync::Arc;

const MAX_BLOCKS: u64 = 256;
const MAX_PERCENTILES: usize = 100;

fn block_count(value: &Value) -> Result<u64, RpcError> {
    let count = match value {
        Value::Number(number) => number.as_u64().ok_or("Invalid block count")?,
        Value::String(text) => quantity(text)?
            .try_into()
            .map_err(|_| RpcError::from("Invalid block count"))?,
        _ => return Err("Invalid block count".into()),
    };
    if count == 0 || count > MAX_BLOCKS {
        return Err("Fee history must contain between one and 256 blocks".into());
    }
    Ok(count)
}

fn percentiles(value: Option<&Value>) -> Result<Option<Vec<f64>>, RpcError> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let values = value
        .as_array()
        .filter(|values| values.len() <= MAX_PERCENTILES)
        .ok_or("Expected at most 100 reward percentiles")?
        .iter()
        .map(|value| value.as_f64().filter(|p| (0.0..=100.0).contains(p)))
        .collect::<Option<Vec<_>>>()
        .ok_or("Reward percentiles must be between 0 and 100")?;
    if values.windows(2).any(|pair| pair[0] > pair[1]) {
        return Err("Reward percentiles must be non-decreasing".into());
    }
    Ok(Some(values))
}

/// Gas-weighted percentiles of effective prices, as Ethereum clients define them.
fn rewards(
    view: &ReadView,
    hashes: &[alloy_primitives::B256],
    wanted: &[f64],
) -> Result<Vec<Value>, RpcError> {
    let mut paid = Vec::with_capacity(hashes.len());
    for hash in hashes {
        let receipt = view
            .receipt(*hash)
            .map_err(storage_error)?
            .ok_or_else(|| storage_error("missing block receipt".into()))?;
        paid.push((receipt.gas_price, receipt.gas_used));
    }
    paid.sort_unstable();
    let total: u64 = paid.iter().map(|(_, gas)| gas).sum();
    Ok(wanted
        .iter()
        .map(|percentile| {
            let threshold = total as f64 * percentile / 100.0;
            let mut cumulative = 0u64;
            let price = paid
                .iter()
                .find(|(_, gas)| {
                    cumulative += gas;
                    cumulative as f64 >= threshold
                })
                .or(paid.last())
                .map_or(0, |(price, _)| *price);
            json!(format!("0x{price:x}"))
        })
        .collect())
}

pub(super) fn query(view: Arc<ReadView>, input: &Value) -> Result<Value, RpcError> {
    let params = parameters(input, 2, 3)?;
    let count = block_count(&params[0])?;
    let newest = if params[1].as_str() == Some("pending") {
        view.head.height
    } else {
        block::height(&params[1], &view)?
    };
    if newest > view.head.height {
        return Err("Future fee history block is unsupported".into());
    }
    let wanted = percentiles(params.get(2))?;
    let oldest = newest.saturating_sub(count - 1);
    let mut ratios = Vec::new();
    let mut reward = Vec::new();
    for height in oldest..=newest {
        let block = view
            .block(height)
            .map_err(storage_error)?
            .ok_or_else(|| storage_error("missing committed block".into()))?;
        ratios.push(json!(
            block.gas_used as f64 / block.context.gas_limit as f64
        ));
        if let Some(wanted) = &wanted {
            reward.push(Value::Array(rewards(&view, &block.transactions, wanted)?));
        }
    }
    let blocks = ratios.len();
    let mut result = json!({
        "oldestBlock": format!("0x{oldest:x}"),
        "baseFeePerGas": vec!["0x0"; blocks + 1],
        "gasUsedRatio": ratios,
        "baseFeePerBlobGas": vec!["0x0"; blocks + 1],
        "blobGasUsedRatio": vec![0.0; blocks],
    });
    if wanted.is_some() {
        result["reward"] = Value::Array(reward);
    }
    Ok(result)
}
