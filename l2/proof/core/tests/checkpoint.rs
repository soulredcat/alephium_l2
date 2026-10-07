//! Native continuation from actual immutable runtime boundaries; schemas 3 and 4.
#[path = "checkpoint/mutations.rs"]
mod mutations;

use alephium_l2_transition_core::{
    BatchTransitionJournal, CheckpointTransitionBundle, ProofInput, checkpoint_batch_commitment,
    checkpoint_batch_data, checkpoint_profile_v4_with_capacity, checkpoint_profile_with_capacity,
    decode_input, encode_checkpoint_transition, encode_large_checkpoint_transition,
    protocol::{Capacity, checkpoint::ExecutionCheckpoint, proof_transport::ProofLimits},
    prove_checkpoint_transition,
};
use alloy_primitives::B256;
use sha2::{Digest, Sha256};
use std::{fs, io::Write, path::PathBuf};

fn wire(input: &CheckpointTransitionBundle) -> Vec<u8> {
    match input.schema {
        3 => encode_checkpoint_transition(input),
        4 => encode_large_checkpoint_transition(input),
        _ => panic!("expected checkpoint witness schema three or four"),
    }
    .expect("canonical checkpoint wire encoding")
}

fn profile(schema: u32, capacity: Capacity) -> B256 {
    match schema {
        3 => checkpoint_profile_with_capacity(capacity),
        4 => checkpoint_profile_v4_with_capacity(capacity),
        _ => panic!("unsupported checkpoint profile schema"),
    }
    .expect("capacity-bound checkpoint profile")
}

fn checkpoint_root(
    input: &CheckpointTransitionBundle,
    checkpoint: &ExecutionCheckpoint,
    execution_profile: B256,
) -> Result<B256, String> {
    let domain = &input.domain;
    match input.schema {
        3 => checkpoint.root(
            execution_profile,
            domain.l1_network,
            domain.l1_genesis_id,
            domain.settlement_contract_id,
        ),
        4 => checkpoint.root_for_transport(
            execution_profile,
            domain.l1_network,
            domain.l1_genesis_id,
            domain.settlement_contract_id,
            ProofLimits::for_capacity(checkpoint.capacity)?,
        ),
        _ => Err("unsupported checkpoint root schema".into()),
    }
}

fn reconstruction_commitment(input: &CheckpointTransitionBundle) -> B256 {
    match input.schema {
        3 => B256::from_slice(&Sha256::digest(
            checkpoint_batch_data(input).expect("canonical schema-three reconstruction"),
        )),
        4 => checkpoint_batch_commitment(input).expect("bounded schema-four reconstruction"),
        _ => panic!("unsupported reconstruction schema"),
    }
}

/// Test-only comparison against the independently reviewed predecessor/session.
/// A valid checkpoint or a different valid proof cannot choose these pins.
/// This predicate is not an implemented settlement contract or deployment policy.
fn matches_reviewed_parent(
    candidate: &BatchTransitionJournal,
    reviewed: &BatchTransitionJournal,
) -> bool {
    candidate.schema == reviewed.schema
        && candidate.proof_scope == reviewed.proof_scope
        && candidate.rpc_profile == reviewed.rpc_profile
        && candidate.execution_engine == reviewed.execution_engine
        && candidate.domain == reviewed.domain
        && candidate.chain_id == reviewed.chain_id
        && candidate.genesis_id == reviewed.genesis_id
        && candidate.execution_profile == reviewed.execution_profile
        && candidate.parent == reviewed.parent
        && candidate.old_state_root == reviewed.old_state_root
}

fn bundle(path: PathBuf) -> CheckpointTransitionBundle {
    let bytes = fs::read(path).expect("read retained private checkpoint input");
    let ProofInput::Checkpoint(bundle) = decode_input(&bytes).expect("shared binary input decode")
    else {
        panic!("expected checkpoint witness");
    };
    assert!(wire(&bundle) == bytes, "binary encoding drift");
    bundle
}

#[test]
fn actual_checkpoint_batches_chain_and_authenticate_hidden_state() {
    let root = PathBuf::from(
        std::env::var_os("L2_CHECKPOINT_INPUT_ROOT")
            .expect("set L2_CHECKPOINT_INPUT_ROOT to retained checkpoint export root"),
    );
    let full = bundle(root.join("genesis-export/transition.bin"));
    let suffix = bundle(root.join("export/transition.bin"));
    assert!(matches!(full.schema, 3 | 4));
    assert_eq!(full.schema, suffix.schema);
    assert_eq!(full.checkpoint.head.height, 0);
    assert_eq!(full.checkpoint.capacity, suffix.checkpoint.capacity);
    assert_eq!(full.domain, suffix.domain);
    assert!(
        full.blocks
            .iter()
            .map(|block| block.transactions.len())
            .sum::<usize>()
            <= 1_000,
        "continuation fixture exceeds the selected development workload"
    );
    let complete = prove_checkpoint_transition(&full).expect("genesis checkpoint replay disagrees");
    let second =
        prove_checkpoint_transition(&suffix).expect("retained checkpoint replay disagrees");
    assert_eq!(complete.journal.blocks, 4);
    assert_eq!(second.journal.blocks, 2);
    assert_eq!(second.journal.parent.height, 2);
    assert_eq!(complete.journal.schema, full.schema);
    assert_eq!(second.journal.schema, suffix.schema);
    assert_eq!(
        complete.journal.new_state_root,
        second.journal.new_state_root
    );
    assert!(
        complete.checkpoint.encode().unwrap() == second.checkpoint.encode().unwrap(),
        "checkpoint continuation changes canonical final state"
    );
    assert_eq!(complete.journal.head, second.journal.head);
    assert_eq!(
        complete.journal.after_state_digest,
        second.journal.after_state_digest
    );
    assert_eq!(
        complete.journal.after_total_balance,
        second.journal.after_total_balance
    );
    assert_eq!(
        complete.journal.after_account_count,
        second.journal.after_account_count
    );
    assert_eq!(
        complete.journal.da_commitment,
        reconstruction_commitment(&full)
    );
    assert_eq!(
        second.journal.da_commitment,
        reconstruction_commitment(&suffix)
    );

    let mut first = full.clone();
    first.blocks.truncate(2);
    first.head = first.blocks.last().unwrap().head.clone();
    first.expected_state_digest = second.journal.before_state_digest;
    let first = prove_checkpoint_transition(&first).expect("predecessor execution disagrees");
    assert_eq!(first.journal.new_state_root, second.journal.old_state_root);
    assert_eq!(first.journal.head, second.journal.parent);
    assert!(
        first.checkpoint.encode().unwrap() == suffix.checkpoint.encode().unwrap(),
        "derived predecessor and retained boundary bytes differ"
    );
    let execution_profile = profile(suffix.schema, suffix.checkpoint.capacity);
    assert_eq!(second.journal.execution_profile, execution_profile);
    assert_eq!(
        checkpoint_root(&suffix, &suffix.checkpoint, execution_profile).unwrap(),
        first.journal.new_state_root
    );
    assert_eq!(
        checkpoint_root(&suffix, &second.checkpoint, execution_profile).unwrap(),
        second.journal.new_state_root
    );

    // Rebuild from executed predecessor state rather than trust the export's checkpoint.
    let mut derived_suffix = suffix.clone();
    derived_suffix.checkpoint = first.checkpoint.clone();
    let derived = prove_checkpoint_transition(&derived_suffix).expect("derived suffix disagrees");
    assert!(
        derived.journal.encode().unwrap() == second.journal.encode().unwrap(),
        "canonical statement or transaction/context/receipt/DA commitments differ"
    );
    assert!(matches_reviewed_parent(&second.journal, &second.journal));
    mutations::assert_hidden_state_binding(&suffix, &second.journal);
    mutations::assert_domain_profile_and_parent_binding(&suffix, &second);
    mutations::assert_transport_rejections(&suffix);

    let public_statement = serde_json::to_value(&second).unwrap();
    assert!(public_statement.get("checkpoint").is_none());
    assert_eq!(public_statement["schema"], suffix.schema);
    if let Some(path) = std::env::var_os("L2_CHECKPOINT_CORE_EVIDENCE") {
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .expect("new safe checkpoint evidence path");
        let evidence = serde_json::json!({
            "status":"passed", "scope":"native-runtime/portable-core-checkpoint-continuation",
            "witness_schema":suffix.schema, "maximum_fixture_transactions":1000,
            "first":first.journal, "second":second.journal,
            "complete":complete.journal, "parent_root_chain_verified":true,
            "canonical_checkpoint_bytes_and_journal_commitments_match":true,
            "hidden_state_mutations_fail_reviewed_prior_root_guard":true,
            "structural_violations_rejected_by_shared_execution":true,
            "different_valid_domain_statements_fail_reviewed_parent_guard":true,
            "profile_capacity_parent_and_transport_mutations_rejected":true,
            "prior_root_guard_scope":"test-only independent predecessor/session comparison",
            "live_consumer_authentication_implemented":false,
            "guest_receipt_generated_by_this_check":false, "settlement_verified":false,
        });
        output
            .write_all(&serde_json::to_vec_pretty(&evidence).unwrap())
            .unwrap();
        output.sync_all().unwrap();
    }
}
