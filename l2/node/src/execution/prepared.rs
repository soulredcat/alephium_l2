//! Immutable canonical-envelope/signature results, never mutable state validation.

use super::{ExecutionBatch, batch, transaction, validate_transaction};
use crate::protocol::{BlockContext, TransactionInfo};
use crate::storage::ReadView;
use revm::context::TxEnv;
use std::sync::Arc;

struct VerifiedTransaction {
    raw: Arc<[u8]>,
    chain_id: u64,
    tx: TxEnv,
    info: TransactionInfo,
}

/// Only canonical decoding/signature recovery can construct this node-local value.
/// Cloning shares immutable results; account nonce/balance are checked separately.
#[derive(Clone)]
pub(crate) struct PreparedTransaction(Arc<VerifiedTransaction>);

impl PreparedTransaction {
    pub(crate) fn info(&self) -> &TransactionInfo {
        &self.0.info
    }

    pub(crate) fn matches(&self, raw: &[u8], chain_id: u64) -> bool {
        self.0.chain_id == chain_id && self.0.raw.as_ref() == raw
    }
}

pub(crate) fn prepare_for_chain(raw: &[u8], chain_id: u64) -> Result<PreparedTransaction, String> {
    let (tx, info) = transaction::decode(raw, chain_id)?;
    Ok(PreparedTransaction(Arc::new(VerifiedTransaction {
        raw: Arc::from(raw),
        chain_id,
        tx,
        info,
    })))
}

/// The read view is authoritative even when signature recovery was cached.
pub(crate) fn validate_prepared(
    view: ReadView,
    prepared: &PreparedTransaction,
    context: BlockContext,
) -> Result<TransactionInfo, String> {
    check_chain(prepared, view.chain_id())?;
    validate_transaction(
        view,
        prepared.0.tx.clone(),
        prepared.0.info.clone(),
        context,
    )
}

/// Execute in input order with the same state checks, charges and receipt logic.
pub(crate) fn execute_prepared_block(
    view: ReadView,
    inputs: &[PreparedTransaction],
    context: BlockContext,
) -> Result<ExecutionBatch, String> {
    for prepared in inputs {
        check_chain(prepared, view.chain_id())?;
    }
    batch::execute_decoded(
        view,
        inputs
            .iter()
            .map(|prepared| Ok((prepared.0.tx.clone(), prepared.0.info.clone()))),
        inputs.len(),
        context,
    )
}

fn check_chain(prepared: &PreparedTransaction, chain_id: u64) -> Result<(), String> {
    if prepared.0.chain_id != chain_id {
        return Err("prepared transaction belongs to a different chain".into());
    }
    Ok(())
}
