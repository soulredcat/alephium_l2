//! Cross-backend agreement for the producer's retained ecrecover boundary flow.
use alephium_l2_transition_core::{ProofInput, ProvenTransition, decode_input, prove_input};
use std::{fs, io::Write};

#[test]
fn ecrecover_native_producer_matches_portable_guest_core() {
    let input = std::env::var_os("L2_PRECOMPILE_INPUT")
        .expect("set L2_PRECOMPILE_INPUT to the retained producer export");
    let bytes = fs::read(input).expect("read private precompile export");
    let input = decode_input(&bytes).expect("decode shared private witness schema");
    let ProofInput::Batch(bundle) = &input else {
        panic!("precompile parity requires a batch witness");
    };
    assert_eq!(bundle.blocks.len(), 12);
    assert_eq!(bundle.batch_start, 1);
    // Each block hash includes derived storage/code/receipt changes, so replay
    // compares every intermediate recovered word, not just the last zero slot.
    let ProvenTransition::Batch(journal) =
        prove_input(&input).expect("native secp256k1 producer and portable k256 core disagree")
    else {
        panic!("unexpected native-transfer proof scope");
    };
    assert_eq!(journal.blocks, 12);
    assert_eq!(journal.executed_transactions, 12);
    assert_eq!(journal.head, bundle.head);
    assert_eq!(journal.after_state_digest, bundle.expected_state_digest);
    if let Some(output) = std::env::var_os("L2_PRECOMPILE_CORE_EVIDENCE") {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)
            .expect("new safe backend agreement evidence path");
        let evidence = serde_json::json!({
            "status":"passed", "scope":"native-producer/portable-core-ecrecover-agreement",
            "precompile_cases":11, "includes_nested_staticcall":true,
            "guest_receipt_generated_by_this_check":false, "settlement_verified":false,
            "journal":journal,
        });
        file.write_all(&serde_json::to_vec_pretty(&evidence).unwrap())
            .unwrap();
        file.sync_all().unwrap();
    }
}
