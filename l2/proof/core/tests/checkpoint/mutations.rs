//! Separate structural rejection from binding to the independently reviewed prior root.
use super::{
    BatchTransitionJournal, CheckpointTransitionBundle, checkpoint_root, decode_input,
    matches_reviewed_parent, profile, prove_checkpoint_transition, reconstruction_commitment, wire,
};
use alephium_l2_transition_core::{
    CheckpointTransitionOutput, protocol::checkpoint::ExecutionCheckpoint,
};
use alloy_primitives::{B256, U256, keccak256};

fn assert_bound(
    input: &CheckpointTransitionBundle,
    changed: &ExecutionCheckpoint,
    reviewed: &BatchTransitionJournal,
) {
    assert!(
        changed.validate().is_ok(),
        "binding mutation must remain structurally valid"
    );
    let root = checkpoint_root(input, changed, profile(input.schema, changed.capacity))
        .expect("valid changed checkpoint root");
    assert_ne!(
        root, reviewed.old_state_root,
        "checkpoint mutation is not root-bound"
    );
    // Compare with the reviewed root, never a caller-provided replacement pin.
    let mut candidate = reviewed.clone();
    candidate.old_state_root = root;
    candidate.parent = changed.head.clone();
    assert!(!matches_reviewed_parent(&candidate, reviewed));
}

fn assert_structural_rejection(input: &CheckpointTransitionBundle, changed: ExecutionCheckpoint) {
    assert!(
        changed.validate().is_err(),
        "expected a checkpoint structural violation"
    );
    let mut invalid = input.clone();
    invalid.checkpoint = changed;
    assert!(prove_checkpoint_transition(&invalid).is_err());
}

pub(super) fn assert_hidden_state_binding(
    input: &CheckpointTransitionBundle,
    reviewed: &BatchTransitionJournal,
) {
    let plain = input
        .checkpoint
        .accounts
        .iter()
        .position(|account| {
            !account.deleted
                && (account.code_hash == B256::ZERO || account.code_hash == keccak256([]))
        })
        .expect("fixture needs a live account without referenced code");
    for field in 0..3 {
        let mut changed = input.checkpoint.clone();
        match field {
            0 => changed.accounts[plain].balance += U256::from(1),
            1 => changed.accounts[plain].nonce += 1,
            _ => changed.accounts[plain].storage_epoch += 1,
        }
        assert_bound(input, &changed, reviewed);
    }
    let mut changed = input.checkpoint.clone();
    changed.block_hashes[1].hash = B256::from([0x55; 32]);
    assert_bound(input, &changed, reviewed);
    changed = input.checkpoint.clone();
    let account = &mut changed.accounts[plain];
    account.deleted = true;
    account.balance = U256::ZERO;
    account.nonce = 0;
    account.code_hash = B256::ZERO;
    account.storage_epoch = 1;
    account.slots.clear();
    assert_bound(input, &changed, reviewed);
    changed.accounts[plain].balance = U256::from(1);
    assert_structural_rejection(input, changed);

    let mut changed = input.checkpoint.clone();
    changed.codes[0].bytes[0] ^= 1;
    assert_structural_rejection(input, changed);
    // Rebinding code and every reference is structurally valid, but not the reviewed state.
    let mut changed = input.checkpoint.clone();
    let previous_hash = changed.codes[0].hash;
    changed.codes[0].bytes[0] ^= 1;
    let replacement_hash = keccak256(&changed.codes[0].bytes);
    changed.codes[0].hash = replacement_hash;
    for account in &mut changed.accounts {
        if account.code_hash == previous_hash {
            account.code_hash = replacement_hash;
        }
    }
    changed.codes.sort_by_key(|code| code.hash);
    assert_bound(input, &changed, reviewed);
    changed = input.checkpoint.clone();
    changed.block_hashes.remove(0);
    assert_structural_rejection(input, changed);
    changed = input.checkpoint.clone();
    changed.accounts.insert(0, changed.accounts[0].clone());
    assert_structural_rejection(input, changed);

    // Self-consistent new capacity is valid metadata, but a different prior root.
    let mut changed = input.checkpoint.clone();
    changed.capacity.block_gas += 1;
    changed.schema = changed.capacity.checkpoint_schema();
    assert_bound(input, &changed, reviewed);
    let mut invalid = input.clone();
    invalid.checkpoint = changed;
    assert!(
        prove_checkpoint_transition(&invalid).is_err(),
        "context uses another gas capacity"
    );
}

pub(super) fn assert_domain_profile_and_parent_binding(
    input: &CheckpointTransitionBundle,
    output: &CheckpointTransitionOutput,
) {
    let journal = &output.journal;
    assert_eq!((journal.inbox_count, journal.outbox_count), (0, 0));
    assert_ne!(journal.inbox_commitment, journal.outbox_commitment);
    let encoded = journal.encode().unwrap();
    let data = reconstruction_commitment(input);
    for field in 0..3 {
        let mut other = input.clone();
        match field {
            0 => other.domain.l1_network ^= 1,
            1 => other.domain.l1_genesis_id.as_mut_slice()[0] ^= 1,
            _ => other.domain.settlement_contract_id.as_mut_slice()[0] ^= 1,
        }
        // Different nonzero domains are valid guest statements, not accepted ancestry.
        let changed = prove_checkpoint_transition(&other).unwrap();
        assert!(
            changed.checkpoint == output.checkpoint,
            "domain changed EVM execution"
        );
        assert_eq!(
            changed.journal.before_state_digest,
            journal.before_state_digest
        );
        assert_ne!(changed.journal.old_state_root, journal.old_state_root);
        assert_ne!(changed.journal.new_state_root, journal.new_state_root);
        assert_ne!(changed.journal.inbox_commitment, journal.inbox_commitment);
        assert_ne!(changed.journal.outbox_commitment, journal.outbox_commitment);
        assert_ne!(changed.journal.da_commitment, journal.da_commitment);
        assert!(changed.journal.encode().unwrap() != encoded);
        assert_ne!(reconstruction_commitment(&other), data);
        assert!(!matches_reviewed_parent(&changed.journal, journal));
    }
    let changed_profile = B256::from([0x44; 32]);
    assert_ne!(
        checkpoint_root(input, &input.checkpoint, changed_profile).unwrap(),
        journal.old_state_root
    );
    let mut changed = journal.clone();
    changed.execution_profile = changed_profile;
    assert!(!matches_reviewed_parent(&changed, journal));
    changed = journal.clone();
    changed.parent.commit_id = B256::ZERO;
    assert!(!matches_reviewed_parent(&changed, journal));
    assert!(checkpoint_root(input, &input.checkpoint, B256::ZERO).is_err());

    for field in 0..2 {
        let mut invalid = input.clone();
        if field == 0 {
            invalid.domain.l1_genesis_id = B256::ZERO;
        } else {
            invalid.domain.settlement_contract_id = B256::ZERO;
        }
        assert!(prove_checkpoint_transition(&invalid).is_err());
    }
    let mut invalid = input.clone();
    invalid.blocks[0].parent.commit_id = B256::ZERO;
    assert!(prove_checkpoint_transition(&invalid).is_err());
    invalid = input.clone();
    invalid.expected_state_digest = B256::ZERO;
    assert!(prove_checkpoint_transition(&invalid).is_err());
    invalid = input.clone();
    invalid.rpc_profile.push_str("/unapproved");
    assert!(prove_checkpoint_transition(&invalid).is_err());
    invalid = input.clone();
    invalid.execution_engine.push_str("/unapproved");
    assert!(prove_checkpoint_transition(&invalid).is_err());
}

pub(super) fn assert_transport_rejections(input: &CheckpointTransitionBundle) {
    let mut noncanonical = input.checkpoint.encode().unwrap();
    let capacity_bytes = if input.checkpoint.capacity.is_default() {
        0
    } else {
        24
    };
    // First account's deleted marker follows the fixed checkpoint header and address.
    let deleted_offset = b"alephium-l2/execution-checkpoint/v1".len() + 128 + capacity_bytes + 20;
    noncanonical[deleted_offset] = 2;
    assert!(ExecutionCheckpoint::decode(&noncanonical).is_err());
    let mut trailing = wire(input);
    trailing.push(0);
    assert!(decode_input(&trailing).is_err());
    trailing.truncate(trailing.len() - 2);
    assert!(decode_input(&trailing).is_err());
    // Schema four has binary-only guest transport. Its private serde type still
    // rejects added bridge fields; do not mistake unsupported JSON for that guard.
    let baseline_json = serde_json::to_vec(input).unwrap();
    assert!(serde_json::from_slice::<CheckpointTransitionBundle>(&baseline_json).is_ok());
    let mut fake_inbox = serde_json::to_value(input).unwrap();
    fake_inbox["inbox_commitment"] = serde_json::json!(B256::from([0x77; 32]));
    let changed_json = serde_json::to_vec(&fake_inbox).unwrap();
    assert!(
        serde_json::from_slice::<CheckpointTransitionBundle>(&changed_json).is_err(),
        "private checkpoint type must reject host-supplied bridge fields"
    );
    if input.schema == 3 {
        assert!(
            decode_input(&baseline_json).is_ok(),
            "schema-three JSON baseline"
        );
        assert!(decode_input(&changed_json).is_err());
    }
}
