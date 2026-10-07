//! One cross-engine boundary flow consumes the node's retained private export.
use alephium_l2_transition_core::{
    BatchTransitionBundle, RawEnvelope, batch_data, decode_input, prove_batch_transition,
    prove_input,
};
use alloy_primitives::{B256, U256};
use std::{fs, path::PathBuf};

#[test]
fn actual_batch_execution_statement_and_mutation_boundaries() {
    let path = PathBuf::from(
        std::env::var_os("L2_TRANSITION_INPUT")
            .expect("set L2_TRANSITION_INPUT to the retained node export"),
    );
    let bytes = fs::read(path).expect("read private exported witness");
    let input: BatchTransitionBundle =
        serde_json::from_slice(&bytes).unwrap_or_else(|_| panic!("invalid private witness schema"));
    let journal = prove_batch_transition(&input).expect("node/guest execution disagreement");
    let decoded = decode_input(&bytes).expect("shared host/guest schema decode");
    assert_eq!(
        prove_input(&decoded).unwrap().encode().unwrap(),
        journal.encode().unwrap()
    );
    assert!(decode_input(br#"{"schema":3}"#).is_err());
    assert!(decode_input(br#"{"schema":1,"schema":2}"#).is_err());
    assert_eq!(journal.blocks, 4);
    assert_eq!(journal.executed_transactions, 4);
    assert_eq!(journal.parent.height, 0);
    assert_eq!(journal.head, input.head);
    assert_eq!(journal.after_state_digest, input.expected_state_digest);
    assert_eq!(journal.inbox_count, 0);
    assert_eq!(journal.outbox_count, 0);
    assert_ne!(journal.old_state_root, journal.new_state_root);
    assert_ne!(journal.da_commitment, B256::ZERO);

    let mut first = input.clone();
    first.blocks.truncate(2);
    first.head = first.blocks[1].head.clone();
    // The prefix oracle is independently produced below by replay's suffix
    // boundary; no host-provided digest can bypass the normal oracle comparison.
    let mut suffix = input.clone();
    suffix.batch_start = 3;
    let suffix_journal = prove_batch_transition(&suffix).unwrap();
    first.expected_state_digest = suffix_journal.before_state_digest;
    let first_journal = prove_batch_transition(&first).unwrap();
    assert_eq!(suffix_journal.parent, first_journal.head);
    assert_eq!(suffix_journal.old_state_root, first_journal.new_state_root);
    assert_eq!(suffix_journal.new_state_root, journal.new_state_root);
    assert_eq!(suffix_journal.blocks, 2);
    assert_eq!(suffix_journal.executed_transactions, 2);
    assert_ne!(suffix_journal.encode().unwrap(), journal.encode().unwrap());

    let mut wrong = input.clone();
    wrong.expected_state_digest = B256::ZERO;
    assert!(prove_batch_transition(&wrong).is_err());
    wrong = input.clone();
    wrong.blocks[2].parent.commit_id = B256::ZERO;
    assert!(prove_batch_transition(&wrong).is_err());
    wrong = input.clone();
    wrong.blocks[1].transactions[0].expected_receipt.gas_used += 1;
    assert!(prove_batch_transition(&wrong).is_err());
    wrong = input.clone();
    wrong.blocks[0].transactions[0].raw_envelope_hex = RawEnvelope::from_bytes(vec![0xff]).unwrap();
    assert!(prove_batch_transition(&wrong).is_err());
    wrong = input.clone();
    wrong.genesis.accounts[0].balance += U256::from(1);
    assert!(prove_batch_transition(&wrong).is_err());
    wrong = input.clone();
    wrong.chain_id += 1;
    assert!(prove_batch_transition(&wrong).is_err());

    let encoded = journal.encode().unwrap();
    let mut changed_report = journal.clone();
    changed_report.after_account_count += 1;
    assert_ne!(changed_report.encode().unwrap(), encoded);
    changed_report = journal.clone();
    changed_report.after_total_balance += U256::from(1);
    assert_ne!(changed_report.encode().unwrap(), encoded);
    let data = batch_data(&input).unwrap();
    wrong = input.clone();
    wrong.domain.settlement_contract_id = B256::from([0x33; 32]);
    let other = prove_batch_transition(&wrong).unwrap();
    assert_ne!(other.encode().unwrap(), encoded);
    assert_ne!(batch_data(&wrong).unwrap(), data);
    wrong = input.clone();
    wrong.semantic_replay_verified = false;
    wrong.guest_proof_generated = true;
    wrong.settlement_verified = true;
    assert_eq!(
        prove_batch_transition(&wrong).unwrap().encode().unwrap(),
        encoded
    );
    if let Some(output) = std::env::var_os("L2_TRANSITION_CORE_EVIDENCE") {
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)
            .expect("new safe core evidence path");
        file.write_all(&serde_json::to_vec_pretty(&journal).unwrap())
            .unwrap();
        file.sync_all().unwrap();
    }
}
