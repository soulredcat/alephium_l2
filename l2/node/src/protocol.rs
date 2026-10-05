use alloy_primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};

mod capacity;
pub mod checkpoint;
pub use capacity::Capacity;
#[allow(dead_code)]
pub(crate) mod encoding;
pub(crate) mod head_codec;
pub(crate) mod receipt_codec;

pub const CHAIN_ID: u64 = 424243;
/// Schema 2 excludes absent-to-absent account removals from block changes.
/// This is a fresh development chain profile, not an upgrade of schema 1 data.
pub const SCHEMA: u32 = 2;
pub const BLOCK_INTERVAL_MS: u64 = 200;
pub const BLOCK_GAS: u64 = 30_000_000;
pub const BLOCK_BYTES: usize = 1_048_576;
pub const MAX_PENDING: usize = 256;
pub const MAX_TRANSACTION_BYTES: usize = 131_072;

/// All configured development identities must be replay-protected and nonzero.
pub fn validate_chain_id(chain_id: u64) -> Result<(), String> {
    if chain_id == 0 {
        return Err("Development chain identity must be nonzero".into());
    }
    Ok(())
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Account {
    pub balance: U256,
    pub nonce: u64,
    pub code_hash: B256,
    pub storage_epoch: u64,
}

#[derive(Clone, Debug, Default)]
pub struct AccountChange {
    pub address: Address,
    pub balance: U256,
    pub nonce: u64,
    pub code_hash: B256,
    pub code: Option<Vec<u8>>,
    pub deleted: bool,
    pub storage_reset: bool,
    pub slots: Vec<(U256, U256)>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventLog {
    pub address: Address,
    pub topics: Vec<B256>,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Receipt {
    pub hash: B256,
    pub from: Address,
    pub to: Option<Address>,
    pub contract: Option<Address>,
    pub success: bool,
    pub gas_used: u64,
    pub gas_price: u128,
    pub logs: Vec<EventLog>,
    pub block_height: u64,
    pub block_hash: B256,
    pub transaction_index: u64,
    pub cumulative_gas: u64,
    pub first_log_index: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Head {
    pub height: u64,
    pub timestamp: u64,
    pub commit_id: B256,
    pub genesis_id: B256,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Genesis {
    pub chain_id: u64,
    #[serde(default, skip_serializing_if = "Capacity::is_default")]
    pub capacity: Capacity,
    pub accounts: Vec<GenesisAccount>,
}

impl Genesis {
    pub fn validate(&self) -> Result<(), String> {
        validate_chain_id(self.chain_id)?;
        self.capacity.validate()?;
        if self.accounts.len() > 4096 {
            return Err("genesis account count exceeds development limit".into());
        }
        let mut addresses = std::collections::BTreeSet::new();
        if self
            .accounts
            .iter()
            .any(|account| !addresses.insert(account.address))
        {
            return Err("duplicate genesis account".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GenesisAccount {
    pub address: Address,
    pub balance: U256,
}

#[derive(Clone, Debug)]
pub struct Pending {
    pub hash: B256,
    pub sender: Address,
    pub raw: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransactionStatus {
    pub hash: B256,
    pub status: String,
    pub block_height: Option<u64>,
    pub error: Option<String>,
}

#[derive(Clone, Copy, Debug)]
pub struct BlockContext {
    pub number: u64,
    pub timestamp: u64,
    pub gas_limit: u64,
}

#[derive(Clone, Debug)]
pub struct BlockCommit {
    pub parent: Head,
    pub context: BlockContext,
    pub transactions: Vec<B256>,
    pub changes: Vec<AccountChange>,
    pub receipts: Vec<Receipt>,
    pub rejected: Vec<(B256, String)>,
}

#[derive(Clone, Debug)]
pub struct TransactionInfo {
    pub hash: B256,
    pub sender: Address,
    pub nonce: u64,
    pub gas_limit: u64,
    /// Effective price per gas at this profile's fixed zero base fee.
    pub gas_price: u128,
}

#[derive(Clone, Debug)]
pub struct CallRequest {
    pub from: Address,
    pub to: Option<Address>,
    pub data: Vec<u8>,
    pub value: U256,
    pub gas_limit: u64,
    pub gas_price: u128,
    pub access_list: alloy_eips::eip2930::AccessList,
}

#[derive(Clone, Debug)]
pub struct CallResult {
    pub success: bool,
    pub output: Vec<u8>,
    pub gas_used: u64,
    /// Gas consumed before refunds; a successful limit is at least this value.
    pub gas_spent: u64,
    pub halted: bool,
}

#[derive(Clone, Debug)]
pub struct BlockInfo {
    pub head: Head,
    pub parent: Head,
    pub context: BlockContext,
    pub transactions: Vec<B256>,
    pub gas_used: u64,
    pub encoded_bytes: usize,
}

#[derive(Clone, Debug)]
pub struct ReplayBlock {
    pub head: Head,
    pub parent: Head,
    pub context: BlockContext,
    pub transactions: Vec<B256>,
    pub receipts: Vec<Receipt>,
    pub rejected: Vec<(B256, String)>,
}
