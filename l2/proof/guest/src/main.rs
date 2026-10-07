//! Pinned transition guest; no host output or pass flag authorizes a claim.
#![no_main]

use alephium_l2_transition_core::{decode_input_reader, prove_input};
use risc0_zkvm::guest::env;
use std::io::{BufReader, Read};

risc0_zkvm::guest::entry!(main);

fn main() {
    // FdReader otherwise makes a guest syscall for every small wire field.
    // Reuse one fixed-size buffer for framing and the bounded shared decoder.
    let mut input = BufReader::with_capacity(8 * 1024, env::stdin());
    let mut length = [0_u8; 4];
    input
        .read_exact(&mut length)
        .unwrap_or_else(|_| panic!("transition length framing rejected"));
    let length = u32::from_le_bytes(length) as usize;
    // The shared dispatcher probes the schema-four capacity/limit header before
    // its bounded frame reader allocates. Older inputs retain the 16 MiB guard.
    // No complete schema-four wire Vec is allocated here; decoded state and
    // transaction envelopes still occupy bounded resident memory.
    let bundle = decode_input_reader(&mut input, length)
        .unwrap_or_else(|_| panic!("transition input schema rejected"));
    let journal = prove_input(&bundle).unwrap_or_else(|_| panic!("transition execution rejected"));
    drop(bundle);
    let encoded = journal
        .encode()
        .unwrap_or_else(|_| panic!("transition journal encoding rejected"));
    env::commit_slice(&encoded);
}
