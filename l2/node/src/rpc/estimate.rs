use super::{RpcError, call, read::storage_error};
use crate::{execution, protocol::CallRequest, storage::ReadView};
use alloy_primitives::U256;
use serde_json::{Value, json};
use std::sync::Arc;

const MAX_PROBES: usize = 16;
const MAX_DECLARED_GAS: u64 = 90_000_000;
const CALL_STIPEND: u64 = 2_300;

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
    // A limit below the post-refund gas used always fails, so it is a valid
    // failing lower bound and keeps the search near the actual requirement.
    let mut low = upper
        .gas_used
        .saturating_sub(1)
        .max(20_999)
        .min(high.saturating_sub(1));
    // Probe the exact consumption first, then a limit that covers refunds and
    // the 63/64 call-gas retention, before falling back to bisection.
    let hints = [
        upper.gas_spent,
        upper
            .gas_spent
            .saturating_add(CALL_STIPEND)
            .saturating_mul(64)
            / 63,
    ];
    let mut consumed_budget = high;
    for attempt in 1..MAX_PROBES {
        if high - low <= 1 {
            break;
        }
        let probe = hints
            .get(attempt - 1)
            .copied()
            .filter(|hint| *hint > low && *hint < high)
            .unwrap_or(low + (high - low) / 2);
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

#[cfg(test)]
mod tests {
    use super::query;
    use crate::{development, execution, protocol::*, storage::Store};
    use alloy_primitives::{Address, U256};
    use serde_json::{Value, json};
    use std::sync::Arc;

    fn deploy(store: &mut Store, nonce: u64, init: Vec<u8>) -> Address {
        let raw = development::sign(nonce, None, U256::ZERO, init, 1_000_000).unwrap();
        let info = execution::inspect(&raw).unwrap();
        store
            .admit(Pending {
                hash: info.hash,
                sender: info.sender,
                raw: raw.clone(),
            })
            .unwrap();
        let view = store.view().unwrap();
        let context = BlockContext {
            number: view.head.height + 1,
            timestamp: view.head.timestamp,
            gas_limit: BLOCK_GAS,
        };
        let result = execution::execute_block(view.clone(), &[raw], context).unwrap();
        let contract = result.receipts[0].contract.unwrap();
        store
            .commit(BlockCommit {
                parent: view.head.clone(),
                context,
                transactions: result.receipts.iter().map(|r| r.hash).collect(),
                changes: result.changes,
                receipts: result.receipts,
                rejected: result.rejected,
            })
            .unwrap();
        contract
    }

    fn estimate(store: &Store, call: &Value) -> u64 {
        let input = json!({"jsonrpc":"2.0","id":1,"method":"eth_estimateGas","params":[call]});
        let value = query(Arc::new(store.view().unwrap()), &input).unwrap();
        u64::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
    }

    fn succeeds(store: &Store, call: &Value, gas: u64) -> bool {
        let mut call = call.clone();
        call["gas"] = json!(format!("0x{gas:x}"));
        let input = json!({"jsonrpc":"2.0","id":1,"method":"eth_call","params":[call]});
        crate::rpc::call::query(Arc::new(store.view().unwrap()), &input).is_ok()
    }

    #[test]
    fn estimates_are_the_minimal_successful_limit() {
        let directory = tempfile::tempdir().unwrap();
        let mut store =
            Store::open(&directory.path().join("data"), &development::genesis()).unwrap();
        let from = format!("{:#x}", development::address());
        let fixture = deploy(&mut store, 0, development::contract_init());
        // Constructor stores 1 in slot 0; runtime clears it, earning a refund.
        let clearing = deploy(
            &mut store,
            1,
            hex::decode("60016000556006601160003960066000f3600060005500").unwrap(),
        );
        let transfer =
            json!({"from":from,"to":format!("{:#x}", Address::repeat_byte(0x42)),"value":"0x1"});
        assert_eq!(estimate(&store, &transfer), 21_000);
        let calls = [
            json!({"from":from,"to":format!("{fixture:#x}"),
                "data":format!("0x{}", hex::encode(development::contract_input(1, None)))}),
            json!({"from":from,"to":format!("{clearing:#x}")}),
        ];
        for call in calls {
            let gas = estimate(&store, &call);
            assert!(succeeds(&store, &call, gas), "estimate {gas} must succeed");
            assert!(
                !succeeds(&store, &call, gas - 1),
                "estimate {gas} must be minimal"
            );
        }
    }
}
