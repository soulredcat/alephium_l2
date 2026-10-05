use super::{
    RpcError, parameters, quantity,
    read::{address, hash, storage_error},
    receipt::log_value,
};
use crate::{
    protocol::{BlockInfo, EventLog},
    storage::ReadView,
};
use alloy_primitives::{Address, B256, U256};
use serde_json::{Map, Value};
use std::sync::Arc;

const MAX_BLOCKS: u64 = 256;
const MAX_LOGS: usize = 1024;
const MAX_ALTERNATIVES: usize = 64;

struct Filter {
    addresses: Option<Vec<Address>>,
    topics: Vec<Option<Vec<B256>>>,
}

impl Filter {
    fn parse(object: &Map<String, Value>) -> Result<Self, RpcError> {
        if object.keys().any(|key| {
            !matches!(
                key.as_str(),
                "fromBlock" | "toBlock" | "address" | "topics" | "blockHash"
            )
        }) {
            return Err("Unsupported log filter field".into());
        }
        let addresses = object
            .get("address")
            .map(|value| alternatives(value, address))
            .transpose()?
            .filter(|values| !values.is_empty());
        let topics = match object.get("topics") {
            None => Vec::new(),
            Some(Value::Array(values)) if values.len() <= 4 => values
                .iter()
                .map(|value| {
                    if value.is_null() {
                        Ok(None)
                    } else {
                        alternatives(value, hash)
                            .map(|values| (!values.is_empty()).then_some(values))
                    }
                })
                .collect::<Result<Vec<_>, RpcError>>()?,
            _ => return Err("Expected at most four topic filters".into()),
        };
        Ok(Self { addresses, topics })
    }

    fn matches(&self, log: &EventLog) -> bool {
        if self
            .addresses
            .as_ref()
            .is_some_and(|values| !values.contains(&log.address))
        {
            return false;
        }
        self.topics.iter().enumerate().all(|(index, values)| {
            // A positional wildcard still requires that the log has that topic.
            log.topics
                .get(index)
                .is_some_and(|topic| values.as_ref().is_none_or(|values| values.contains(topic)))
        })
    }
}

fn alternatives<T>(
    value: &Value,
    parse: fn(&Value) -> Result<T, RpcError>,
) -> Result<Vec<T>, RpcError> {
    if let Value::Array(values) = value {
        if values.len() > MAX_ALTERNATIVES {
            return Err("Too many log filter alternatives".into());
        }
        values.iter().map(parse).collect()
    } else {
        Ok(vec![parse(value)?])
    }
}

fn height(value: Option<&Value>, head: u64) -> Result<u64, RpcError> {
    let height = match value
        .map(|value| value.as_str().ok_or("Expected block bound"))
        .transpose()?
    {
        None | Some("latest") => head,
        Some("earliest") => 0,
        Some(value) => {
            let number = quantity(value)?;
            if number > U256::from(u64::MAX) {
                return Err("Block bound exceeds supported range".into());
            }
            number.to::<u64>()
        }
    };
    if height > head {
        return Err("Future log block bound is unsupported".into());
    }
    Ok(height)
}

struct Results {
    logs: Vec<Value>,
    bytes: usize,
    limit: usize,
}

impl Results {
    fn append(&mut self, receipt: &crate::protocol::Receipt, index: usize) -> Result<(), RpcError> {
        if self.logs.len() >= MAX_LOGS || receipt.logs[index].data.len() > self.limit / 2 {
            return Err("Log result exceeds response bound; narrow the filter".into());
        }
        let value = log_value(receipt, index)?;
        let length = serde_json::to_vec(&value)
            .map_err(|_| RpcError::from("Failed to encode log result".to_string()))?
            .len();
        self.bytes = self
            .bytes
            .saturating_add(length + usize::from(!self.logs.is_empty()));
        if self.bytes > self.limit {
            return Err("Log result exceeds response bound; narrow the filter".into());
        }
        self.logs.push(value);
        Ok(())
    }

    fn block(
        &mut self,
        view: &ReadView,
        block: &BlockInfo,
        filter: &Filter,
    ) -> Result<(), RpcError> {
        let mut first_log = 0u64;
        let mut cumulative_gas = 0u64;
        for (transaction_index, hash) in block.transactions.iter().enumerate() {
            let receipt = view
                .receipt(*hash)
                .map_err(storage_error)?
                .ok_or_else(|| storage_error("missing block receipt".into()))?;
            cumulative_gas = cumulative_gas
                .checked_add(receipt.gas_used)
                .ok_or_else(|| storage_error("receipt gas overflow".into()))?;
            if receipt.block_height != block.head.height
                || receipt.block_hash != block.head.commit_id
                || receipt.transaction_index != transaction_index as u64
                || receipt.first_log_index != first_log
                || receipt.cumulative_gas != cumulative_gas
                || cumulative_gas > block.context.gas_limit
                || !receipt.success && !receipt.logs.is_empty()
                || receipt.logs.iter().any(|log| log.topics.len() > 4)
            {
                return Err(storage_error("inconsistent block receipt".into()));
            }
            first_log = first_log
                .checked_add(receipt.logs.len() as u64)
                .ok_or_else(|| storage_error("receipt log index overflow".into()))?;
            for (index, log) in receipt.logs.iter().enumerate() {
                if filter.matches(log) {
                    self.append(&receipt, index)?;
                }
            }
        }
        if cumulative_gas != block.gas_used {
            return Err(storage_error("block gas total mismatch".into()));
        }
        Ok(())
    }
}

/// Scan committed receipts over one pinned view. Limits return errors, never partial data.
pub(super) fn query(view: Arc<ReadView>, input: &Value) -> Result<Value, RpcError> {
    let params = parameters(input, 1, 1)?;
    let object = params[0].as_object().ok_or("Expected log filter object")?;
    let filter = Filter::parse(object)?;
    let mut result = Results {
        logs: Vec::new(),
        bytes: 2,
        limit: view.capacity().block_bytes,
    };
    if let Some(block_hash) = object.get("blockHash") {
        if object.contains_key("fromBlock") || object.contains_key("toBlock") {
            return Err("blockHash cannot be combined with block ranges".into());
        }
        let block_hash = hash(block_hash)?;
        if let Some(block) = view.block_by_hash(block_hash).map_err(storage_error)? {
            if block.head.commit_id != block_hash || block.head.height > view.head.height {
                return Err(storage_error("inconsistent block hash lookup".into()));
            }
            result.block(&view, &block, &filter)?;
        }
    } else {
        let from = height(object.get("fromBlock"), view.head.height)?;
        let to = height(object.get("toBlock"), view.head.height)?;
        if from > to || to - from >= MAX_BLOCKS {
            return Err("Log range must contain between one and 256 blocks".into());
        }
        let mut previous_hash = None;
        for height in from..=to {
            let block = view
                .block(height)
                .map_err(storage_error)?
                .ok_or_else(|| storage_error("missing committed block".into()))?;
            if block.head.height != height
                || previous_hash.is_some_and(|hash| block.parent.commit_id != hash)
            {
                return Err(storage_error("inconsistent committed block range".into()));
            }
            result.block(&view, &block, &filter)?;
            previous_hash = Some(block.head.commit_id);
        }
    }
    Ok(Value::Array(result.logs))
}
