use super::{RpcError, call, read::storage_error};
use crate::{execution, protocol::CallRequest, storage::ReadView};
use alloy_primitives::U256;
use serde_json::{Value, json};
use std::sync::Arc;

const MAX_PROBES: usize = 16;
const MAX_DECLARED_GAS: u64 = 90_000_000;

/// Returns a gas limit which succeeded on this one committed view, not the gas
/// consumed or a promise for future state. The bounded search may overestimate.
pub(super) fn query(view: Arc<ReadView>, input: &Value) -> Result<Value, RpcError> {
    let mut parsed = call::parse(input)?;
    let balance = view
        .account(parsed.request.from)
        .map_err(storage_error)?
        .map_or(U256::ZERO, |account| account.balance);
    if parsed.request.value > balance {
        return Err("Insufficient balance for call value".into());
    }
    if parsed.fee_cap != 0 {
        let allowance = (balance - parsed.request.value) / U256::from(parsed.fee_cap);
        if allowance < U256::from(parsed.request.gas_limit) {
            parsed.request.gas_limit = allowance.to::<u64>();
        }
    }
    if parsed.request.gas_limit == 0 {
        return Err("Insufficient balance for gas".into());
    }
    let context = call::context(&view);
    let upper = execution::simulate((*view).clone(), parsed.request.clone(), context)?;
    if !upper.success {
        return Err(call::failure(&upper));
    }
    let mut high = parsed.request.gas_limit;
    let mut low = 20_999u64.min(high.saturating_sub(1));
    let mut consumed_budget = high;
    for _ in 1..MAX_PROBES {
        if high - low <= 1 {
            break;
        }
        let probe = low + (high - low) / 2;
        if consumed_budget.saturating_add(probe) > MAX_DECLARED_GAS {
            break;
        }
        consumed_budget += probe;
        let request = CallRequest {
            gas_limit: probe,
            ..parsed.request.clone()
        };
        match execution::simulate((*view).clone(), request, context) {
            Ok(result) if result.success => high = probe,
            Ok(_) => low = probe,
            Err(error) if error.starts_with("invalid transaction:") => low = probe,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(json!(format!("0x{high:x}")))
}
