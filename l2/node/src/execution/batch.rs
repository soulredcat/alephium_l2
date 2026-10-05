use super::{changes::Changes, database::ReadError, database::ViewDatabase, transaction};
use crate::protocol::{AccountChange, BlockContext, EventLog, Receipt, TransactionInfo};
use crate::storage::ReadView;
use alloy_primitives::{B256, U256, keccak256};
use revm::context::{BlockEnv, TxEnv, result::EVMError};
use revm::context_interface::transaction::Transaction;
use revm::database::CacheDB;
use revm::handler::MainnetContext;
use revm::primitives::{TxKind, hardfork::SpecId};
use revm::{Context, ExecuteCommitEvm, ExecuteEvm, MainBuilder, MainContext, MainnetEvm};

type Engine = MainnetEvm<MainnetContext<CacheDB<ViewDatabase>>>;

pub struct ExecutionBatch {
    pub changes: Vec<AccountChange>,
    pub receipts: Vec<Receipt>,
    pub rejected: Vec<(B256, String)>,
}

pub(super) fn engine(view: ReadView, context: BlockContext) -> Result<Engine, String> {
    if context.gas_limit == 0 || context.gas_limit > view.capacity().block_gas {
        return Err("block gas limit is outside the development profile".into());
    }
    let chain_id = view.chain_id();
    Ok(Context::mainnet()
        .with_db(CacheDB::new(ViewDatabase(view)))
        .modify_cfg_chained(|cfg| {
            cfg.chain_id = chain_id;
            cfg.set_spec_and_mainnet_gas_params(SpecId::CANCUN);
        })
        .with_block(BlockEnv {
            number: U256::from(context.number),
            timestamp: U256::from(context.timestamp),
            gas_limit: context.gas_limit,
            basefee: 0,
            ..Default::default()
        })
        .build_mainnet())
}

pub(super) fn describe_error(error: EVMError<ReadError>) -> String {
    match error {
        EVMError::Transaction(error) => format!("invalid transaction: {error}"),
        EVMError::Database(error) => format!("committed state read failed: {error}"),
        EVMError::Header(_) => "invalid recorded block context".into(),
        EVMError::Custom(_) | EVMError::CustomAny(_) => "fatal EVM host failure".into(),
    }
}

/// Execute accepted intents in order over one private, cache-first overlay.
/// Any infrastructure error aborts the block: it is never a transaction rejection.
pub fn execute_block(
    view: ReadView,
    inputs: &[Vec<u8>],
    context: BlockContext,
) -> Result<ExecutionBatch, String> {
    let chain_id = view.chain_id();
    execute_decoded(
        view,
        inputs
            .iter()
            .map(|raw| transaction::decode(raw, chain_id).map_err(|error| (keccak256(raw), error))),
        inputs.len(),
        context,
    )
}

pub(super) fn execute_decoded(
    view: ReadView,
    inputs: impl Iterator<Item = Result<(TxEnv, TransactionInfo), (B256, String)>>,
    count: usize,
    context: BlockContext,
) -> Result<ExecutionBatch, String> {
    let mut evm = engine(view, context)?;
    let mut changes = Changes::default();
    let mut receipts = Vec::with_capacity(count);
    let mut rejected = Vec::new();
    let mut cumulative_gas = 0_u64;
    let mut first_log_index = 0_u64;
    for input in inputs {
        let (tx, info) = match input {
            Ok(decoded) => decoded,
            Err(error) => {
                rejected.push(error);
                continue;
            }
        };
        if tx.gas_limit > context.gas_limit.saturating_sub(cumulative_gas) {
            return Err("selected transactions exceed remaining block gas".into());
        }
        let to = match tx.kind {
            TxKind::Call(address) => Some(address),
            TxKind::Create => None,
        };
        // Cancun development profile fixes base fee at zero. The receipt must
        // reflect the effective charge, not the EIP-1559 affordability cap.
        let gas_price = tx.effective_gas_price(0);
        let mut outcome = match evm.transact(tx) {
            Ok(outcome) => outcome,
            Err(error @ EVMError::Transaction(_)) => {
                rejected.push((info.hash, describe_error(error)));
                continue;
            }
            Err(error) => return Err(describe_error(error)),
        };
        changes.absorb(&mut outcome.state);
        evm.commit(outcome.state);
        let result = outcome.result;
        cumulative_gas = cumulative_gas
            .checked_add(result.tx_gas_used())
            .ok_or_else(|| "block gas accounting overflow".to_owned())?;
        let logs: Vec<_> = result
            .logs()
            .iter()
            .map(|log| EventLog {
                address: log.address,
                topics: log.data.topics().to_vec(),
                data: log.data.data.to_vec(),
            })
            .collect();
        let log_count = logs.len() as u64;
        // Ethereum-style receipts retain status/gas/logs, not transaction return
        // data. RETURN memory is not priced for repeated durable serialization;
        // eth_call supplies transient output, and traces need a later API policy.
        receipts.push(Receipt {
            hash: info.hash,
            from: info.sender,
            to,
            contract: result.created_address(),
            success: result.is_success(),
            gas_used: result.tx_gas_used(),
            gas_price,
            logs,
            block_height: context.number,
            block_hash: B256::ZERO,
            transaction_index: receipts.len() as u64,
            cumulative_gas,
            first_log_index,
        });
        first_log_index += log_count;
    }
    Ok(ExecutionBatch {
        changes: changes.finish(),
        receipts,
        rejected,
    })
}
