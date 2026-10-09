//! GET-only testnet settlement reads on 0 -> 0, and owner-zero funding creators.
//! No light-client/PoW proof, signing, submission, historical contract effects,
//! or canonical funding snapshot is implemented by this module.
mod address;
mod blocks;
mod client;
mod contract;
mod creator_transactions;
mod execution;
mod execution_outputs;
mod execution_types;
mod identity;
mod transactions;
mod transport;
mod types;
mod utxos;
mod wire;

pub use address::{ContractAddress, P2pkhAddress};
pub use client::ReadNode;
pub use execution::decode_executed_transaction;
pub use execution_types::{
    ExecutedOutcome, ExecutedOutput, ExecutedOutputAddress, ExecutedTransactionError,
    ExecutedTransactionEvidence,
};
pub(crate) use transport::canonical_origin;
pub use types::*;

#[cfg(test)]
pub(crate) mod tests;

#[cfg(test)]
#[path = "../../../../../test/sdk/execution.rs"]
pub(crate) mod execution_tests;
