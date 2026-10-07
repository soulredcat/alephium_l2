//! Versioned external-signing DTOs. Private request/response bytes omit Debug.
use crate::PreparedTransaction;
use alloy_primitives::{Address, B256, Bytes, U256};
use serde::{Deserialize, Serialize};
use std::fmt;

pub const WALLET_ADAPTER_VERSION: u32 = 1;
pub const MAX_WALLET_PAYLOAD_BYTES: usize = 131_072;
pub const WALLET_INTENT_KECCAK256_DOMAIN: &[u8] = b"ALPH/L2/wallet-adapter-intent/keccak256/v1";

/// Genesis is a caller/RPC identity pin, not an Ethereum signature field.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "namespace", rename_all = "snake_case", deny_unknown_fields)]
pub enum WalletNetwork {
    AlephiumL1 { network_id: u8, genesis_id: B256 },
    EvmL2 { chain_id: u64, genesis_id: B256 },
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "namespace", rename_all = "snake_case", deny_unknown_fields)]
pub enum WalletAccount {
    AlephiumL1 { address: String },
    EvmL2 { address: Address },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvmFees {
    Legacy {
        gas_price: u128,
    },
    Eip1559 {
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
    },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletAccessListItem {
    pub address: Address,
    pub storage_keys: Vec<B256>,
}

/// All supported signed transaction fields, including the ordered access list.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvmTransactionIntent {
    pub chain_id: u64,
    pub nonce: u64,
    pub gas_limit: u64,
    pub to: Option<Address>,
    pub value: U256,
    pub input: Bytes,
    pub fees: EvmFees,
    pub access_list: Vec<WalletAccessListItem>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "namespace", rename_all = "snake_case", deny_unknown_fields)]
pub enum WalletPayload {
    AlephiumL1 { unsigned_encoded_tx: Bytes },
    EvmL2 { transaction: EvmTransactionIntent },
}

/// Adapter Keccak digests are NOT Alephium tx IDs or settlement SHA digests.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletRequestBinding {
    pub protocol_version: u32,
    /// Caller-allocated nonzero ID, unique per request; persist before signing.
    pub request_id: B256,
    /// Caller-selected durable intent reference, not an authorization token.
    pub intent_id: B256,
    pub network: WalletNetwork,
    pub from: WalletAccount,
    pub payload_keccak256: B256,
    pub intent_keccak256: B256,
}

/// Caller persists exact intent before handing this to an external adapter.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletRequest {
    pub binding: WalletRequestBinding,
    pub payload: WalletPayload,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletCapability {
    AlephiumL1Transaction,
    EvmL2Transaction,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilitySupport {
    Unsupported,
    ImplementedByExternalAdapter,
}

/// A declaration, never evidence that a wallet is installed or connected.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletCapabilities {
    pub protocol_version: u32,
    pub alephium_l1: CapabilitySupport,
    pub evm_l2: CapabilitySupport,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum WalletResponseOutcome {
    Unsupported {
        capability: WalletCapability,
    },
    Rejected,
    SignedEvm {
        signed_transaction: Bytes,
    },
    /// Opaque L1 signing is not accepted until a full spend/signature checker exists.
    SignedAlephium {
        signed_transaction: Bytes,
    },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletResponse {
    pub binding: WalletRequestBinding,
    pub result: WalletResponseOutcome,
}

/// EVM success validates an exact signed body only; no submission occurred.
pub enum ValidatedWalletResponse {
    Unsupported(WalletCapability),
    Rejected,
    Evm(PreparedTransaction),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalletAdapterError {
    UnsupportedVersion,
    InvalidRequest,
    BindingMismatch,
    InvalidSignedTransaction,
    UnsupportedL1Validation,
}

impl fmt::Display for WalletAdapterError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str(match self {
            Self::UnsupportedVersion => "Unsupported wallet adapter protocol version",
            Self::InvalidRequest => "Invalid or unsupported caller-selected wallet intent",
            Self::BindingMismatch => "Wallet response differs from the caller's exact intent",
            Self::InvalidSignedTransaction => {
                "Wallet returned a noncanonical or different transaction"
            }
            Self::UnsupportedL1Validation => "Alephium signed spend validation is not implemented",
        })
    }
}
impl std::error::Error for WalletAdapterError {}

/// External implementation owns key custody and explicit user authorization.
/// This interface performs no automatic connect, sign retry or broadcast.
pub trait WalletAdapter {
    fn capabilities(&self) -> WalletCapabilities;
    fn request_signature(
        &mut self,
        request: &WalletRequest,
    ) -> Result<WalletResponse, WalletAdapterError>;
}
