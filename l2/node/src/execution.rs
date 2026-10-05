//! Sequential development EVM execution; disk commitment belongs to Store.

mod batch;
mod changes;
mod database;
mod simulation;
mod transaction;

#[cfg(test)]
mod reference_tests;
#[cfg(test)]
mod touch_tests;

pub use batch::{ExecutionBatch, execute_block};
pub use simulation::simulate;
pub use transaction::{inspect, inspect_for_chain};

use crate::protocol::{BlockContext, TransactionInfo};
use crate::storage::ReadView;
use revm::context::{ContextSetters, JournalTr};
use revm::handler::{Handler, MainnetHandler};

/// Fatal host/read failures must halt admission instead of becoming client rejects.
pub fn is_infrastructure_error(error: &str) -> bool {
    error.starts_with("committed state read failed:")
        || error == "fatal EVM host failure"
        || error == "invalid recorded block context"
        || error == "block gas limit is outside the development profile"
}

/// Validate admission without running contract code or changing committed state.
/// Ordering reservations and duplicate reconciliation belong to the owning service.
pub fn validate(
    view: ReadView,
    raw: &[u8],
    context: BlockContext,
) -> Result<TransactionInfo, String> {
    let (tx, info) = transaction::decode(raw, view.chain_id())?;
    let mut evm = batch::engine(view, context)?;
    evm.ctx.set_tx(tx);
    let result = MainnetHandler::default().validate(&mut evm);
    // Validation changes the private journal's nonce/upfront balance. Discard it,
    // including on rejection; admission never mutates the read view or store.
    evm.ctx.journaled_state.clear();
    result.map_err(batch::describe_error)?;
    Ok(info)
}
