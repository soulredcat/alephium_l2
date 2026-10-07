//! The same SHA-256 bytes on the native node and the pinned proof guest.
//! Guest compression uses the existing SDK circuit; native builds keep sha2.
#[cfg(target_os = "zkvm")]
pub(crate) use risc0_zkvm::sha::rust_crypto::{Digest, Sha256};
#[cfg(not(target_os = "zkvm"))]
pub(crate) use sha2::{Digest, Sha256};
