use crate::{
    changes::Changes,
    protocol::{AccountChange, BlockContext, MAX_TRANSACTION_BYTES, Receipt},
    state::NativeState,
    transaction,
};
use alloy_primitives::{Address, B256, U256};
use revm::context::BlockEnv;
use revm::database::{CacheDB, EmptyDB};
use revm::primitives::{TxKind, hardfork::SpecId};
use revm::state::AccountInfo;
use revm::{Context, ExecuteCommitEvm, ExecuteEvm, MainBuilder, MainContext};

pub(crate) struct ExecutedTransfer {
    pub changes: Vec<AccountChange>,
    pub receipt: Receipt,
    pub value: U256,
    pub beneficiary: Address,
}

/// Do not log the argument, decoded bytes, signatures or underlying parse error.
pub(crate) fn private_envelope(value: &str) -> Result<Vec<u8>, String> {
    let value = value
        .strip_prefix("0x")
        .ok_or("missing envelope hex prefix")?;
    if value.is_empty() || value.len() > MAX_TRANSACTION_BYTES * 2 || value.len() % 2 != 0 {
        return Err("private envelope exceeds the supported byte bound".into());
    }
    hex::decode(value).map_err(|_| "invalid private envelope hex".into())
}

pub(crate) fn execute(
    state: &NativeState,
    raw: &[u8],
    chain_id: u64,
    context: BlockContext,
) -> Result<ExecutedTransfer, String> {
    // Production decoder performs canonical RLP, EIP-155 and EIP-2 checked
    // signer recovery. The additional restrictions define this guest's scope.
    let (tx, info) = transaction::decode(raw, chain_id)?;
    let TxKind::Call(recipient) = tx.kind else {
        return Err("native transfer proof excludes contract creation".into());
    };
    if tx.tx_type != 0
        || tx.nonce != 0
        || !tx.data.is_empty()
        || !tx.access_list.0.is_empty()
        || tx.gas_priority_fee.is_some()
        || !tx.blob_hashes.is_empty()
        || !tx.authorization_list.is_empty()
        || tx.value.is_zero()
        || tx.gas_limit > context.gas_limit
    {
        return Err("unsupported transaction in native genesis-first proof".into());
    }
    // Cancun precompiles occupy addresses 1..=10. Excluding them guarantees
    // this guest does not silently claim parity for its different crypto backend.
    if recipient.as_slice()[..19].iter().all(|byte| *byte == 0)
        && (1..=10).contains(&recipient.as_slice()[19])
    {
        return Err("native transfer proof excludes precompile execution".into());
    }
    let value = tx.value;
    let gas_price = tx.gas_price;
    let mut database = CacheDB::new(EmptyDB::default());
    for (address, account) in state.accounts() {
        database.insert_account_info(
            *address,
            AccountInfo {
                balance: account.balance,
                nonce: account.nonce,
                code_hash: account.code_hash,
                code: None,
                ..Default::default()
            },
        );
    }
    let block = BlockEnv {
        number: U256::from(context.number),
        timestamp: U256::from(context.timestamp),
        gas_limit: context.gas_limit,
        basefee: 0,
        ..Default::default()
    };
    let beneficiary = block.beneficiary;
    let mut evm = Context::mainnet()
        .with_db(database)
        .modify_cfg_chained(|cfg| {
            cfg.chain_id = chain_id;
            cfg.set_spec_and_mainnet_gas_params(SpecId::CANCUN);
        })
        .with_block(block)
        .build_mainnet();
    let mut outcome = evm
        .transact(tx)
        .map_err(|_| "pinned REVM rejected the native transition".to_owned())?;
    let mut changes = Changes::default();
    changes.absorb(&mut outcome.state);
    evm.commit(outcome.state);
    let result = outcome.result;
    if !result.is_success() || result.created_address().is_some() || !result.logs().is_empty() {
        return Err("native transfer produced an unsupported execution outcome".into());
    }
    let gas_used = result.tx_gas_used();
    if gas_used != 21_000 || gas_used > info.gas_limit {
        return Err("native transfer differs from pinned Cancun intrinsic gas".into());
    }
    Ok(ExecutedTransfer {
        changes: changes.finish(),
        receipt: Receipt {
            hash: info.hash,
            from: info.sender,
            to: Some(recipient),
            contract: None,
            success: true,
            gas_used,
            gas_price,
            logs: Vec::new(),
            block_height: context.number,
            block_hash: B256::ZERO,
            transaction_index: 0,
            cumulative_gas: gas_used,
            first_log_index: 0,
        },
        value,
        beneficiary,
    })
}
