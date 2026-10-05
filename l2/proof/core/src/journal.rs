use crate::{canonical, protocol::{Head, Receipt}, TransitionContext};
use alloy_primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransferAccounting {
    pub sender: Address,
    pub recipient: Address,
    pub beneficiary: Address,
    pub value: U256,
    pub gas_fee: U256,
    pub base_fee: u64,
    pub burned_fee: U256,
    pub sender_balance_before: U256,
    pub sender_balance_after: U256,
    pub recipient_balance_before: U256,
    pub recipient_balance_after: U256,
    pub beneficiary_balance_before: U256,
    pub beneficiary_balance_after: U256,
}

/// Every field is derived in the guest from full genesis and actual execution.
/// Logical-state digests commit the complete bounded native state; they are not
/// Merkle roots and do not establish generic sparse-witness EVM soundness.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionJournal {
    pub schema: u32,
    pub proof_scope: String,
    pub rpc_profile: String,
    pub execution_engine: String,
    pub chain_id: u64,
    pub genesis_id: B256,
    pub parent: Head,
    pub head: Head,
    pub context: TransitionContext,
    pub transaction_hash: B256,
    pub before_state_digest: B256,
    pub after_state_digest: B256,
    pub before_account_count: u32,
    pub after_account_count: u32,
    pub before_total_balance: U256,
    pub after_total_balance: U256,
    pub receipt: Receipt,
    pub accounting: TransferAccounting,
}

impl TransitionJournal {
    /// Domain-separated canonical bytes for env::commit_slice. JSON rendering
    /// is a safe report only, never the settlement statement's canonical form.
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        canonical::journal_bytes(self)
    }
}
