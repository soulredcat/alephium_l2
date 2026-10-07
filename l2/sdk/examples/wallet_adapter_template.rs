//! External wallet integration contract; this example does not connect or sign.
//!
//! 1. Keep Alephium L1 accounts separate from EVM L2 addresses, chain and genesis.
//! 2. Persist the caller-selected version/request ID/intent and exact transaction.
//! 3. The external wallet owns keys and explicit user approval. Implement
//!    WalletAdapter there and echo the unchanged binding for that request only.
//! 4. Validate the response against the retained request, then use the existing
//!    Client/ExpectedNetwork and explicit submit-once/reconcile interfaces.
//! 5. Ethereum signatures do not cover genesis or adapter request IDs. Those
//!    stay independently selected RPC/context pins; never invent custom signing.
//! 6. L1 signed results remain unsupported until canonical signature/unsigned
//!    transaction identity, authority and full spending-limit checks exist.
//!
//! Capability changes alone must never produce signing success. The shipped
//! template always returns Unsupported; it proves no installed/connected wallet.
use alephium_l2_sdk::wallet::{ExternalWalletAdapterTemplate, WalletAdapter};

fn main() {
    let adapter = ExternalWalletAdapterTemplate;
    // Safe declaration only; never print requests, signed bytes or key material.
    println!("{:?}", adapter.capabilities());
}
