use crate::{
    batch_state::FullState,
    changes::Changes,
    protocol::{AccountChange, BLOCK_GAS, BlockContext, EventLog, MAX_PENDING, Receipt},
    transaction,
};
use alloy_primitives::{B256, U256};
use revm::context::BlockEnv;
use revm::context_interface::transaction::Transaction;
use revm::database::CacheDB;
use revm::primitives::{TxKind, hardfork::SpecId};
use revm::{Context, ExecuteCommitEvm, ExecuteEvm, MainBuilder, MainContext};

pub(crate) struct ExecutedBlock {
    pub changes: Vec<AccountChange>,
    pub receipts: Vec<Receipt>,
}

/// Reexecute the producer's accepted envelopes over a private cache overlay.
/// The same decoder, REVM version, Cancun configuration and Changes accumulator
/// are used for transfers, creation, nested calls, storage, logs and reverts.
/// Rejected intents are outside this witness schema and cannot become receipts.
pub(crate) fn execute_block(
    state: &FullState,
    inputs: &[Vec<u8>],
    chain_id: u64,
    context: BlockContext,
) -> Result<ExecutedBlock, String> {
    if context.gas_limit != BLOCK_GAS || inputs.is_empty() || inputs.len() > MAX_PENDING {
        return Err("unsupported executed block gas or transaction count".into());
    }
    // Keep default Cancun precompiles enabled, including nested invocations.
    // REVM's guest k256 ecrecover backend differs from the producer's native
    // secp256k1 backend. Their parity is a release verification requirement;
    // changing a backend must not change this execution or receipt profile.
    let mut evm = Context::mainnet()
        .with_db(CacheDB::new(state))
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
        .build_mainnet();
    let mut changes = Changes::default();
    let mut receipts = Vec::with_capacity(inputs.len());
    let mut cumulative_gas = 0_u64;
    let mut first_log_index = 0_u64;
    for raw in inputs {
        let (tx, info) = transaction::decode(raw, chain_id)?;
        if tx.gas_limit > context.gas_limit.saturating_sub(cumulative_gas) {
            return Err("selected transactions exceed remaining block gas".into());
        }
        let to = match tx.kind {
            TxKind::Call(address) => Some(address),
            TxKind::Create => None,
        };
        let gas_price = tx.effective_gas_price(0);
        // Do not expose decoded transaction data or backend error internals.
        let mut outcome = evm
            .transact(tx)
            .map_err(|_| "pinned REVM rejected a claimed committed transaction".to_owned())?;
        changes.absorb(&mut outcome.state);
        evm.commit(outcome.state);
        let result = outcome.result;
        let gas_used = result.tx_gas_used();
        cumulative_gas = cumulative_gas
            .checked_add(gas_used)
            .ok_or("block gas overflow")?;
        if cumulative_gas > context.gas_limit || gas_used > info.gas_limit {
            return Err("executed transaction exceeds block gas bounds".into());
        }
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
        receipts.push(Receipt {
            hash: info.hash,
            from: info.sender,
            to,
            contract: result.created_address(),
            success: result.is_success(),
            gas_used,
            gas_price,
            logs,
            block_height: context.number,
            block_hash: B256::ZERO,
            transaction_index: receipts.len() as u64,
            cumulative_gas,
            first_log_index,
        });
        first_log_index = first_log_index
            .checked_add(log_count)
            .ok_or("log index overflow")?;
    }
    Ok(ExecutedBlock {
        changes: changes.finish(),
        receipts,
    })
}
