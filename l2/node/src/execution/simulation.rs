use super::batch::{describe_error, engine};
use crate::protocol::{BlockContext, CallRequest, CallResult, MAX_TRANSACTION_BYTES};
use crate::storage::ReadView;
use revm::ExecuteEvm;
use revm::context::TxEnv;
use revm::primitives::TxKind;

/// Simulates latest committed state on a private overlay. The service bounds
/// concurrency and retains its permit/read view until this work actually ends.
/// Initial profile keeps normal EOA caller/value affordability checks enabled.
pub fn simulate(
    view: ReadView,
    request: CallRequest,
    context: BlockContext,
) -> Result<CallResult, String> {
    if request.gas_limit == 0 || request.gas_limit > context.gas_limit {
        return Err("simulation gas exceeds the supported limit".into());
    }
    if request.data.len() > MAX_TRANSACTION_BYTES {
        return Err("simulation data exceeds the supported limit".into());
    }
    let nonce = view
        .account(request.from)
        .map_err(|error| format!("committed state read failed: {error}"))?
        .map_or(0, |account| account.nonce);
    let tx = TxEnv::builder()
        .caller(request.from)
        .chain_id(Some(view.chain_id()))
        .nonce(nonce)
        .gas_limit(request.gas_limit)
        .gas_price(request.gas_price)
        .access_list(request.access_list)
        .kind(request.to.map_or(TxKind::Create, TxKind::Call))
        .value(request.value)
        .data(request.data.into())
        .build()
        .map_err(|_| "invalid simulation environment".to_owned())?;
    let mut evm = engine(view, context)?;
    let outcome = evm.transact(tx).map_err(describe_error)?;
    Ok(CallResult {
        success: outcome.result.is_success(),
        output: outcome
            .result
            .output()
            .map(|output| output.to_vec())
            .unwrap_or_default(),
        gas_used: outcome.result.tx_gas_used(),
        halted: outcome.result.is_halt(),
    })
}
