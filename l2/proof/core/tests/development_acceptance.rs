//! Independent native agreement for the retained 1000-TX GPU development fixture.
#[path = "development_acceptance/artifacts.rs"]
mod artifacts;
#[path = "development_acceptance/ledger.rs"]
mod ledger;

use alephium_l2_transition_core::{
    CheckpointTransitionReport, ProofInput, ProvenTransition, checkpoint_batch_commitment,
    checkpoint_profile_v4_with_capacity, decode_input, encode_large_checkpoint_transition,
    protocol::{
        BLOCK_BYTES, BLOCK_GAS, BLOCK_INTERVAL_MS, Capacity, Genesis, Head, SCHEMA,
        checkpoint::{CheckpointAccount, CheckpointBlockHash, ExecutionCheckpoint},
        proof_transport::ProofLimits,
    },
    prove_input,
};
use alloy_primitives::{B256, U256, keccak256};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const TOTAL: usize = 1_000;
const TRANSFERS: usize = 996;
const CAPACITY: Capacity = Capacity {
    block_gas: 3_000_000_000,
    block_bytes: 32 * 1024 * 1024,
    max_pending: TOTAL,
};

fn hash(bytes: &[u8]) -> B256 {
    B256::from_slice(&Sha256::digest(bytes))
}

fn field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Independent canonical genesis oracle; it consumes immutable allocations, not guest data.
/// The field order follows storage/records.rs, without invoking its private encoder.
fn genesis_checkpoint(genesis: &Genesis) -> ExecutionCheckpoint {
    genesis.validate().expect("declared genesis validation");
    let mut allocations: Vec<_> = genesis.accounts.iter().collect();
    allocations.sort_by_key(|account| account.address);
    assert!(allocations.iter().all(|account| !account.balance.is_zero()));
    let mut bytes = Vec::new();
    field(&mut bytes, b"alephium-l2-development/genesis");
    bytes.extend_from_slice(&SCHEMA.to_be_bytes());
    bytes.extend_from_slice(&genesis.chain_id.to_be_bytes());
    field(&mut bytes, b"Cancun");
    for value in [BLOCK_GAS, BLOCK_BYTES as u64, BLOCK_INTERVAL_MS] {
        bytes.extend_from_slice(&value.to_be_bytes());
    }
    bytes.extend_from_slice(&(allocations.len() as u32).to_be_bytes());
    for account in &allocations {
        bytes.extend_from_slice(account.address.as_slice());
        bytes.extend_from_slice(&account.balance.to_be_bytes::<32>());
    }
    if !genesis.capacity.is_default() {
        field(&mut bytes, b"alephium-l2-development/capacity/v1");
        bytes.extend_from_slice(&1_u32.to_be_bytes());
        for value in [
            genesis.capacity.block_gas,
            genesis.capacity.block_bytes as u64,
            genesis.capacity.max_pending as u64,
        ] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
    }
    if genesis.capacity.uses_extended_runtime_codec() {
        field(&mut bytes, b"alephium-l2-development/runtime-codec/v1");
        bytes.extend_from_slice(&1_u32.to_be_bytes());
        bytes.extend_from_slice(
            &(genesis.capacity.runtime_record_bytes().unwrap() as u64).to_be_bytes(),
        );
        bytes.extend_from_slice(
            &(genesis.capacity.runtime_checkpoint_bytes().unwrap() as u64).to_be_bytes(),
        );
    }
    let genesis_id = hash(&bytes);
    let mut commit = b"alephium-l2-development/genesis-commit/v1".to_vec();
    commit.extend_from_slice(genesis_id.as_slice());
    let head = Head {
        height: 0,
        timestamp: 0,
        commit_id: hash(&commit),
        genesis_id,
    };
    ExecutionCheckpoint {
        schema: genesis.capacity.checkpoint_schema(),
        chain_id: genesis.chain_id,
        capacity: genesis.capacity,
        genesis_id,
        head: head.clone(),
        accounts: allocations
            .into_iter()
            .map(|account| CheckpointAccount {
                address: account.address,
                balance: account.balance,
                nonce: 0,
                code_hash: keccak256([]),
                storage_epoch: 0,
                deleted: false,
                slots: Vec::new(),
            })
            .collect(),
        codes: Vec::new(),
        block_hashes: vec![CheckpointBlockHash {
            height: 0,
            hash: head.commit_id,
        }],
    }
}

fn total_balance(checkpoint: &ExecutionCheckpoint) -> U256 {
    checkpoint
        .accounts
        .iter()
        .try_fold(U256::ZERO, |total, account| {
            total.checked_add(account.balance)
        })
        .expect("exact checkpoint balance sum")
}

#[test]
#[ignore = "Requires retained 1000-TX fixture and a new project-drive output; primary coordinates"]
fn gpu_development_fixture_matches_independent_portable_native_execution() {
    let (root, output) = artifacts::directories();
    let genesis: Genesis = artifacts::json(&root, "genesis.json");
    let plan: ledger::UnsignedPlan = artifacts::json(&root, "unsigned-intents.json");
    let node: Value = artifacts::json(&root, "report.json");
    let exported: CheckpointTransitionReport = artifacts::json(&root, "export-report.json");
    let actual_final: ExecutionCheckpoint = artifacts::json(&root, "final-checkpoint.json");
    assert!(genesis.capacity == CAPACITY && genesis.accounts.len() == TRANSFERS + 1);
    assert!(
        genesis_checkpoint(&plan.genesis).encode().unwrap()
            == genesis_checkpoint(&genesis).encode().unwrap()
    );
    for flag in [
        "passed",
        "development_only",
        "exact_accounting_verified",
        "actual_reopen_verified",
        "ordered_ancestry_and_membership_verified",
        "witness_from_genesis",
    ] {
        assert!(
            node[flag] == true,
            "required recorded node invariant missing"
        );
    }
    assert!(node["setup_transactions"] == 0 && node["pending"] == 0);
    assert!(node["total_transactions"] == TOTAL && node["committed_receipts"] == TOTAL);
    assert!(node["durable_acks"] == TOTAL && node["genesis_accounts"] == genesis.accounts.len());
    assert!(node["gpu"]["selected"] == "cuda" && node["gpu"]["active"] == true);
    assert!(node["gpu"]["verified_delta"] == TOTAL && node["gpu"]["full_cpu_oracle"] == true);
    assert!(node["gpu"]["failures"] == 0);
    let input_bytes = artifacts::read(&root, "export/transition.bin", 128 * 1024 * 1024);
    assert!(
        input_bytes.len() == exported.bundle_bytes && hash(&input_bytes) == exported.bundle_sha256
    );
    let input = decode_input(&input_bytes).expect("bounded current witness decode");
    let ProofInput::Checkpoint(bundle) = &input else {
        panic!("expected checkpoint witness");
    };
    assert!(bundle.schema == 4 && bundle.checkpoint.capacity == CAPACITY);
    assert!(encode_large_checkpoint_transition(bundle).unwrap() == input_bytes);
    assert!(
        bundle.blocks.len() == 8
            && bundle
                .blocks
                .iter()
                .map(|b| b.transactions.len())
                .sum::<usize>()
                == TOTAL
    );
    let ordered_ids: Vec<_> = bundle
        .blocks
        .iter()
        .flat_map(|block| {
            block
                .transactions
                .iter()
                .map(|transaction| transaction.transaction_hash)
        })
        .collect();
    assert!(
        ordered_ids == exported.transaction_hashes,
        "exported ordered membership differs"
    );
    assert!(bundle.domain == exported.domain && bundle.head == exported.head);
    assert!(bundle.expected_state_digest == exported.expected_state_digest);
    assert!(exported.schema == 4 && exported.executed_transactions == TOTAL as u64);
    assert!(exported.blocks == 8 && exported.replayed_blocks == 8);
    assert!(
        exported.semantic_replay_verified
            && !exported.guest_proof_generated
            && !exported.settlement_verified
    );
    let initial = genesis_checkpoint(&genesis);
    let initial_bytes = initial
        .encode()
        .expect("independent genesis checkpoint bytes");
    assert!(
        bundle.checkpoint.encode().unwrap() == initial_bytes,
        "input differs from immutable genesis"
    );
    assert!(hash(&initial_bytes) == exported.checkpoint_sha256);
    assert!(
        bundle.checkpoint.genesis_id == exported.genesis_id
            && bundle.checkpoint.chain_id == exported.chain_id
    );
    assert!(bundle.checkpoint.head == exported.parent && exported.parent.height == 0);
    let limits = ProofLimits::for_capacity(CAPACITY).unwrap();
    assert!(
        node["proof_limits"]
            == json!({
                "checkpoint_bytes":limits.checkpoint_bytes,"transcript_bytes":limits.transcript_bytes,
                "input_bytes":limits.input_bytes,"frame_bytes":limits.frame_bytes
            })
    );
    assert!(node["witness_schema"] == 4 && node["guest_proof_generated"] == false);
    assert!(node["settlement_verified"] == false);
    let profile = checkpoint_profile_v4_with_capacity(CAPACITY).unwrap();
    let initial_root = initial
        .root_for_transport(
            profile,
            bundle.domain.l1_network,
            bundle.domain.l1_genesis_id,
            bundle.domain.settlement_contract_id,
            limits,
        )
        .unwrap();
    let ProvenTransition::Checkpoint(proven) =
        prove_input(&input).expect("portable native execution")
    else {
        panic!("expected current checkpoint result");
    };
    let journal = &proven.journal;
    assert!(journal.schema == 4 && journal.execution_profile == profile);
    assert!(journal.parent == initial.head && journal.old_state_root == initial_root);
    assert!(journal.chain_id == genesis.chain_id && journal.genesis_id == initial.genesis_id);
    assert!(journal.head == actual_final.head && journal.head == exported.head);
    assert!(journal.executed_transactions == TOTAL as u64 && journal.blocks == 8);
    assert!(journal.after_state_digest == exported.expected_state_digest);
    assert!(serde_json::to_value(&journal.head).unwrap() == node["head"]);
    assert!(serde_json::to_value(journal.after_state_digest).unwrap() == node["state_digest"]);
    assert!(serde_json::to_value(CAPACITY).unwrap() == node["capacity"]);
    let checkpoint_bytes = proven
        .checkpoint
        .encode()
        .expect("canonical final checkpoint bytes");
    assert!(
        checkpoint_bytes == actual_final.encode().unwrap(),
        "native and actual final state differ"
    );
    assert!(
        checkpoint_bytes.len() == 210_346 && node["checkpoint_bytes"] == checkpoint_bytes.len()
    );
    assert!(proven.checkpoint.accounts.len() == 1_996 && node["final_accounts"] == 1_996);
    assert!(node["final_contract_codes"] == proven.checkpoint.codes.len());
    assert!(node["producer_checkpoint_limit"] == 8 * 1024 * 1024);
    assert!(journal.before_account_count == 997 && journal.after_account_count == 1_996);
    let (gas, fees) = ledger::verify(&plan, bundle, &proven.checkpoint);
    assert!(gas == 21_085_496 && node["executed_gas"] == gas);
    assert!(journal.before_total_balance == total_balance(&initial));
    assert!(journal.after_total_balance == journal.before_total_balance);
    assert!(total_balance(&proven.checkpoint) == journal.before_total_balance);
    assert!(journal.da_commitment == checkpoint_batch_commitment(bundle).unwrap());
    assert!(journal.inbox_count == 0 && journal.outbox_count == 0);
    let final_root = proven
        .checkpoint
        .root_for_transport(
            profile,
            bundle.domain.l1_network,
            bundle.domain.l1_genesis_id,
            bundle.domain.settlement_contract_id,
            limits,
        )
        .unwrap();
    assert!(journal.new_state_root == final_root);
    let journal_bytes = journal
        .encode()
        .expect("canonical independently derived journal");
    artifacts::write(&output.join("journal.bin"), &journal_bytes);
    artifacts::write(&output.join("checkpoint.bin"), &checkpoint_bytes);
    let evidence = json!({
        "schema":1,"status":"passed","scope":"independent-native/current-1000-TX-GPU-development-fixture",
        "input_bytes":input_bytes.len(),"input_sha256":hash(&input_bytes),
        "genesis_json_sha256":hash(&artifacts::read(&root,"genesis.json",16*1024*1024)),
        "node_report_sha256":hash(&artifacts::read(&root,"report.json",16*1024*1024)),
        "witness_schema":4,"capacity":CAPACITY,"qualified_fixture_transactions":TOTAL,
        "blocks":journal.blocks,"executed_gas":gas,"exact_fees":fees,
        "before_accounts":journal.before_account_count,"after_accounts":journal.after_account_count,
        "canonical_genesis_checkpoint_matches":true,"immutable_genesis_root_derived":true,
        "all_retained_heads_receipts_and_final_state_match":true,
        "exact_ledger_code_storage_and_reopen_record_match":true,
        "canonical_final_checkpoint_bytes_match":true,"checkpoint_bytes":checkpoint_bytes.len(),
        "checkpoint_sha256":hash(&checkpoint_bytes),"journal_bytes":journal_bytes.len(),
        "journal_sha256":hash(&journal_bytes),"journal":journal,
        "native_journal_derived_without_guest_report":true,"node_report_is_cryptographic_authority":false,
        "cuda_executed_by_this_check":false,"guest_receipt_generated":false,
        "proof_authority_established":false,"settlement_verified":false,"mainnet_qualified":false,
        "arbitrary_numeric_capacity_workloads_qualified":false,
        "artifact_access":artifacts::access(&output)
    });
    artifacts::write(
        &output.join("report.json"),
        &serde_json::to_vec_pretty(&evidence).unwrap(),
    );
}
