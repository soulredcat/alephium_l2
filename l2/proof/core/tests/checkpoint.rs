//! Authenticated continuation from two actual immutable runtime boundaries.
use alephium_l2_transition_core::{
    CheckpointTransitionBundle, ProofInput, checkpoint_profile, decode_input,
    encode_checkpoint_transition, prove_checkpoint_transition,
};
use alloy_primitives::B256;
use std::{fs, io::Write, path::PathBuf};

fn bundle(path: PathBuf) -> CheckpointTransitionBundle {
    let bytes = fs::read(path).expect("read retained private checkpoint input");
    let ProofInput::Checkpoint(bundle) = decode_input(&bytes).expect("shared binary input decode")
    else {
        panic!("expected checkpoint witness");
    };
    assert!(
        encode_checkpoint_transition(&bundle).unwrap() == bytes,
        "binary encoding drift"
    );
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
    let complete = prove_checkpoint_transition(&full).expect("genesis checkpoint replay disagrees");
    let second =
        prove_checkpoint_transition(&suffix).expect("retained checkpoint replay disagrees");
    assert_eq!(complete.journal.blocks, 4);
    assert_eq!(second.journal.blocks, 2);
    assert_eq!(second.journal.parent.height, 2);
    assert_eq!(
        complete.journal.new_state_root,
        second.journal.new_state_root
    );
    assert!(
        complete.checkpoint == second.checkpoint,
        "checkpoint continuation changes final state"
    );

    let mut first = full.clone();
    first.blocks.truncate(2);
    first.head = first.blocks.last().unwrap().head.clone();
    first.expected_state_digest = second.journal.before_state_digest;
    let first = prove_checkpoint_transition(&first).unwrap();
    assert_eq!(first.journal.new_state_root, second.journal.old_state_root);
    assert_eq!(first.journal.head, second.journal.parent);
    assert!(
        first.checkpoint == suffix.checkpoint,
        "guest/native boundary checkpoint differs"
    );
    let root_of =
        |checkpoint: &alephium_l2_transition_core::protocol::checkpoint::ExecutionCheckpoint| {
            checkpoint.root(
                checkpoint_profile().unwrap(),
                suffix.domain.l1_network,
                suffix.domain.l1_genesis_id,
                suffix.domain.settlement_contract_id,
            )
        };
    let accepted = first.journal.new_state_root;
    let mut changed = suffix.checkpoint.clone();
    changed.accounts[0].storage_epoch += 1;
    assert_ne!(
        root_of(&changed).unwrap(),
        accepted,
        "unbound storage epoch"
    );
    changed = suffix.checkpoint.clone();
    changed.block_hashes[1].hash = B256::from([0x55; 32]);
    assert_ne!(
        root_of(&changed).unwrap(),
        accepted,
        "unbound BLOCKHASH history"
    );
    changed = suffix.checkpoint.clone();
    changed.block_hashes.remove(0);
    assert!(changed.validate().is_err());
    changed = suffix.checkpoint.clone();
    changed.accounts.insert(0, changed.accounts[0].clone());
    assert!(changed.validate().is_err());
    changed = suffix.checkpoint.clone();
    changed.codes[0].bytes[0] ^= 1;
    assert!(changed.validate().is_err());

    let mut wrong = suffix.clone();
    wrong.blocks[0].parent.commit_id = B256::ZERO;
    assert!(prove_checkpoint_transition(&wrong).is_err());
    wrong = suffix.clone();
    wrong.expected_state_digest = B256::ZERO;
    assert!(prove_checkpoint_transition(&wrong).is_err());
    let public_statement = serde_json::to_value(&second).unwrap();
    assert!(public_statement.get("checkpoint").is_none());
    assert_eq!(public_statement["schema"], 3);
    if let Some(path) = std::env::var_os("L2_CHECKPOINT_CORE_EVIDENCE") {
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .expect("new safe checkpoint evidence path");
        let evidence = serde_json::json!({
            "status":"passed", "scope":"native-runtime/portable-core-checkpoint-continuation",
            "first":first.journal, "second":second.journal,
            "complete":complete.journal, "parent_root_chain_verified":true,
            "epochs_and_blockhash_authenticated":true,
            "guest_receipt_generated_by_this_check":false, "settlement_verified":false,
        });
        output
            .write_all(&serde_json::to_vec_pretty(&evidence).unwrap())
            .unwrap();
        output.sync_all().unwrap();
    }
}
