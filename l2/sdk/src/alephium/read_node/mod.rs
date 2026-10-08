//! GET-only testnet settlement reads on 0 -> 0, and owner-zero funding creators.
//! No light-client/PoW proof, signing, submission, historical contract effects,
//! or canonical funding snapshot is implemented by this module.
mod address;
mod blocks;
mod client;
mod contract;
mod creator_transactions;
mod identity;
mod transactions;
mod transport;
mod types;
mod utxos;
mod wire;

pub use address::{ContractAddress, P2pkhAddress};
pub use client::ReadNode;
pub(crate) use transport::canonical_origin;
pub use types::*;

#[cfg(test)]
pub(crate) mod tests;
