use alloy_primitives::{Address, B256};
use serde::Serialize;
use std::fmt;

#[derive(Clone, Debug)]
pub struct ExpectedNetwork {
    pub chain_id: u64,
    pub genesis_id: B256,
    pub rpc_profile: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct NodeInfo {
    pub chain_id: u64,
    pub genesis_id: B256,
    pub height: u64,
    pub local_commit_id: B256,
    pub rpc_profile: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lifecycle {
    Unknown,
    DurablyAccepted,
    Committed,
    Reverted,
    Rejected,
}

#[derive(Clone)]
pub struct Receipt {
    pub hash: B256,
    pub block_hash: B256,
    pub block_height: u64,
    pub success: bool,
    pub from: Address,
    pub to: Option<Address>,
    pub contract: Option<Address>,
    pub gas_used: u64,
    pub effective_gas_price: u128,
    pub transaction_type: u8,
}

impl fmt::Debug for Receipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Receipt")
            .field("hash", &self.hash)
            .field("block_height", &self.block_height)
            .field("success", &self.success)
            .field("gas_used", &self.gas_used)
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct Submission {
    pub hash: B256,
    pub lifecycle: Lifecycle,
    pub receipt: Option<Receipt>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientError {
    InvalidEndpoint,
    IdentityMismatch,
    UnsupportedProfile,
    NodeUnhealthy,
    InvalidTransaction,
    MalformedResponse,
    Transport,
    Rpc(i64),
    Ambiguous(B256),
    Timeout(B256),
}

impl fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ambiguous(hash) => write!(
                formatter,
                "Submission outcome ambiguous; reconcile {hash:#x}"
            ),
            Self::Timeout(hash) => write!(
                formatter,
                "Outcome not resolved within deadline; reconcile {hash:#x}"
            ),
            Self::Rpc(code) => write!(formatter, "RPC request failed with code {code}"),
            _ => formatter.write_str(match self {
                Self::InvalidEndpoint => {
                    "Use an explicit loopback HTTP endpoint without credentials/query/fragment"
                }
                Self::IdentityMismatch => {
                    "Node chain/genesis identity differs from the pinned network"
                }
                Self::UnsupportedProfile => {
                    "Node does not support the expected development protocol"
                }
                Self::NodeUnhealthy => "Node requires recovery",
                Self::InvalidTransaction => "Unsupported, noncanonical or wrong-chain transaction",
                Self::MalformedResponse => "Node returned an inconsistent or malformed response",
                Self::Transport => "Node transport failed",
                _ => unreachable!(),
            }),
        }
    }
}
impl std::error::Error for ClientError {}
