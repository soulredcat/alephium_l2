use crate::protocol::hash::{Digest, Sha256};
use crate::{
    encoding::Encoder,
    journal::TransitionJournal,
    protocol::{Account, BLOCK_BYTES, BLOCK_GAS, BLOCK_INTERVAL_MS, SCHEMA},
    records,
};
use alloy_primitives::{Address, B256, keccak256};
use std::collections::BTreeMap;

/// Exactly the native-state subset of ReadView::state_digest: canonical address
/// order, account fields, zero storage count per account and zero code count.
/// Storage/code cannot enter this state type or the accepted guest execution.
pub(crate) fn native_state_digest(accounts: &BTreeMap<Address, Account>) -> Result<B256, String> {
    let mut digest = Sha256::new();
    digest.update(b"alephium-l2-development/logical-state/v1");
    digest.update((accounts.len() as u64).to_be_bytes());
    for (address, account) in accounts {
        if account.code_hash != B256::ZERO && account.code_hash != keccak256([]) {
            return Err("native logical state contains nonempty code".into());
        }
        digest.update(address);
        digest.update(account.balance.to_be_bytes::<32>());
        digest.update(account.nonce.to_be_bytes());
        digest.update(account.code_hash);
        digest.update(0_u64.to_be_bytes());
    }
    digest.update(0_u64.to_be_bytes());
    Ok(B256::from_slice(&digest.finalize()))
}

pub(crate) fn journal_bytes(journal: &TransitionJournal) -> Result<Vec<u8>, String> {
    let mut out = Encoder::default();
    out.bytes(b"alephium-l2-transition-proof/journal/v1")?;
    out.u32(journal.schema);
    out.bytes(journal.proof_scope.as_bytes())?;
    out.bytes(journal.rpc_profile.as_bytes())?;
    out.bytes(journal.execution_engine.as_bytes())?;
    out.bytes(b"logical-state/v1/full-native-state")?;
    out.u32(SCHEMA);
    out.u64(BLOCK_GAS);
    out.u64(BLOCK_BYTES as u64);
    out.u64(BLOCK_INTERVAL_MS);
    out.u64(journal.chain_id);
    out.hash(journal.genesis_id);
    out.0.extend(records::encode_head(&journal.parent));
    out.0.extend(records::encode_head(&journal.head));
    out.u64(journal.context.number);
    out.u64(journal.context.timestamp);
    out.u64(journal.context.gas_limit);
    out.hash(journal.transaction_hash);
    out.hash(journal.before_state_digest);
    out.hash(journal.after_state_digest);
    out.u32(journal.before_account_count);
    out.u32(journal.after_account_count);
    out.amount(journal.before_total_balance);
    out.amount(journal.after_total_balance);
    out.bytes(&records::encode_receipt(&journal.receipt, true)?)?;
    let accounting = &journal.accounting;
    out.address(accounting.sender);
    out.address(accounting.recipient);
    out.address(accounting.beneficiary);
    out.amount(accounting.value);
    out.amount(accounting.gas_fee);
    out.u64(accounting.base_fee);
    out.amount(accounting.burned_fee);
    out.amount(accounting.sender_balance_before);
    out.amount(accounting.sender_balance_after);
    out.amount(accounting.recipient_balance_before);
    out.amount(accounting.recipient_balance_after);
    out.amount(accounting.beneficiary_balance_before);
    out.amount(accounting.beneficiary_balance_after);
    out.finish()
}
