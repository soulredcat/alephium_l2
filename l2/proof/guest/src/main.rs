//! Pinned transition guest; no host output or pass flag authorizes a claim.
#![no_main]

use alephium_l2_transition_core::{decode_input, prove_input};
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

const MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;

fn main() {
    let mut length = [0_u8; 4];
    env::read_slice(&mut length);
    let length = u32::from_le_bytes(length) as usize;
    assert!(
        length > 0 && length <= MAX_INPUT_BYTES,
        "transition input size rejected"
    );
    let mut bytes = vec![0_u8; length];
    env::read_slice(&mut bytes);
    let bundle =
        decode_input(&bytes).unwrap_or_else(|_| panic!("transition input schema rejected"));
    let journal = prove_input(&bundle).unwrap_or_else(|_| panic!("transition execution rejected"));
    let encoded = journal
        .encode()
        .unwrap_or_else(|_| panic!("transition journal encoding rejected"));
    env::commit_slice(&encoded);
}
