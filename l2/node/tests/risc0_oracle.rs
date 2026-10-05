//! Canonical historical receipt compatibility in the local Cancun EVM only.
//! This is neither an Alphred verifier nor proof of an L2 state transition.
#[path = "support/risc0_fixture.rs"]
mod fixture;

use alephium_l2_node::{development, protocol::CallResult, storage::Store};
use alloy_primitives::keccak256;
use fixture::{
    Artifact, RECEIPT_SELECTOR, SELECTOR_MISMATCH, VERIFICATION_FAILED, VERIFY_SELECTOR, call,
    decode, deploy, digest, verify_input, word,
};
use serde_json::{Value, json};

#[test]
fn canonical_risc0_receipt_executes_and_rejects_altered_statements() -> Result<(), String> {
    let artifact = Artifact::load()?;
    let seal = decode(&artifact.fixture.seal)?;
    let image_id = word(&artifact.fixture.image_id)?;
    let journal = decode(&artifact.fixture.journal)?;
    let journal_digest = digest(&journal);
    let control_root = word(&artifact.fixture.control_root)?;
    let control_id = word(&artifact.fixture.bn254_control_id)?;
    assert!(seal.len() == 260, "official seal length changed");
    assert!(
        seal.starts_with(&RECEIPT_SELECTOR),
        "official selector changed"
    );
    assert!(journal.len() == 21, "official journal length changed");
    assert!(
        journal_digest == word(&artifact.fixture.journal_digest)?,
        "fixture SHA-256 mismatch"
    );
    assert!(keccak256(b"verify(bytes,bytes32,bytes32)")[..4] == VERIFY_SELECTOR);

    let owned = tempfile::Builder::new()
        .prefix("l2-c7-risc0-oracle-")
        .tempdir()
        .map_err(|error| error.to_string())?;
    let source = owned.path().join("source");
    let genesis = development::genesis();
    let mut store = Store::open(&source, &genesis)?;
    let creation = decode(&artifact.creation_bytecode)?;
    let runtime_template = decode(&artifact.runtime_template)?;
    let mut init = creation.clone();
    init.extend(control_root);
    init.extend(control_id);
    let deployment = deploy(&mut store, init)?;
    let contract = deployment
        .contract
        .ok_or("missing verifier deployment address")?;
    let view = store.view()?;
    let account = view.account(contract)?.ok_or("missing verifier account")?;
    let runtime = view.code(account.code_hash)?;
    assert!(
        runtime.len() == runtime_template.len(),
        "deployed runtime length mismatch"
    );
    assert!(
        keccak256(&runtime) == account.code_hash,
        "deployed code hash mismatch"
    );
    let head = view.head.clone();
    let state_digest = view.state_digest()?;

    let getter = call(&view, contract, keccak256(b"SELECTOR()")[..4].to_vec())?;
    let mut expected_selector = [0u8; 32];
    expected_selector[..4].copy_from_slice(&RECEIPT_SELECTOR);
    assert!(getter.success && !getter.halted, "SELECTOR getter failed");
    assert!(
        getter.output == expected_selector,
        "deployed selector mismatch"
    );

    let calldata = verify_input(&seal, image_id, journal_digest);
    assert!(
        calldata.len() == 420,
        "official ABI calldata length mismatch"
    );
    let valid = call(&view, contract, calldata)?;
    expect_success(&valid, "official_receipt");
    let mut cases = vec![case("official_receipt", &valid, 420, Some(true))];

    let mut altered_seal = seal.clone();
    altered_seal[4] ^= 1;
    let mut wrong_image = image_id;
    wrong_image[0] ^= 1;
    let mut changed_journal = journal.clone();
    changed_journal[0] ^= 1;
    let changed_digest = digest(&changed_journal);
    assert!(
        changed_digest != journal_digest,
        "journal mutation did not alter SHA-256"
    );
    let mut wrong_selector = seal.clone();
    wrong_selector[0] ^= 1;
    for (name, proof, image, journal_hash, error) in [
        (
            "altered_seal",
            altered_seal,
            image_id,
            journal_digest,
            VERIFICATION_FAILED,
        ),
        (
            "wrong_image",
            seal.clone(),
            wrong_image,
            journal_digest,
            VERIFICATION_FAILED,
        ),
        (
            "changed_journal",
            seal.clone(),
            image_id,
            changed_digest,
            VERIFICATION_FAILED,
        ),
        (
            "wrong_selector",
            wrong_selector,
            image_id,
            journal_digest,
            SELECTOR_MISMATCH,
        ),
    ] {
        let input = verify_input(&proof, image, journal_hash);
        let bytes = input.len();
        let outcome = call(&view, contract, input)?;
        expect_revert(&outcome, &error, name);
        cases.push(case(name, &outcome, bytes, Some(false)));
    }

    // Canonical Solidity decodes eight coordinates without a strict trailing-byte guard.
    // Observe the actual behavior instead of asserting an invented length restriction.
    let mut trailing_seal = seal.clone();
    trailing_seal.push(0);
    let trailing_input = verify_input(&trailing_seal, image_id, journal_digest);
    let trailing_bytes = trailing_input.len();
    let trailing = call(&view, contract, trailing_input)?;
    assert!(
        !trailing.halted && trailing.gas_used > 0,
        "trailing-byte call halted"
    );
    cases.push(case(
        "trailing_seal_byte_observation",
        &trailing,
        trailing_bytes,
        None,
    ));

    assert!(
        store.view()?.head == head,
        "simulation changed committed head"
    );
    assert!(
        store.state_digest()? == state_digest,
        "simulation changed committed state"
    );
    drop(view);
    drop(store);
    let reopened = Store::open_existing(&source, &genesis)?;
    let restarted = reopened.view()?;
    assert!(restarted.head == head, "restart head changed");
    assert!(
        restarted.state_digest()? == state_digest,
        "restart state changed"
    );
    assert!(
        restarted.receipt(deployment.hash)?.as_ref() == Some(&deployment),
        "restart receipt changed"
    );
    assert!(
        restarted.code(account.code_hash)? == runtime,
        "restart code changed"
    );
    let repeated = call(
        &restarted,
        contract,
        verify_input(&seal, image_id, journal_digest),
    )?;
    expect_success(&repeated, "official_receipt_after_restart");
    assert!(
        repeated.gas_used == valid.gas_used,
        "restart verifier gas changed"
    );
    cases.push(case(
        "official_receipt_after_restart",
        &repeated,
        420,
        Some(true),
    ));

    // Never log proof bytes, signed envelopes, signatures, or fixture signing material.
    println!(
        "RISC0_ORACLE {}",
        json!({
            "scope": "isolated-development-cancun-evm-reference-only",
            "compiler": artifact.compiler,
            "creation_bytecode_bytes": creation.len(),
            "creation_bytecode_keccak256": keccak256(&creation),
            "runtime_template_bytes": runtime_template.len(),
            "deployed_runtime_bytes": runtime.len(),
            "deployed_runtime_keccak256": account.code_hash,
            "constructor_argument_bytes": 64,
            "seal_bytes": seal.len(),
            "journal_bytes": journal.len(),
            "deployment_gas": deployment.gas_used,
            "selector_getter_gas": getter.gas_used,
            "state_unchanged_by_calls": true,
            "restart_equal": true,
            "cases": cases,
            "alephium_verifier_accepted": false,
            "evm_transition_proof_accepted": false,
            "historical_guest_authorized_for_settlement": false
        })
    );
    Ok(())
}

fn expect_success(outcome: &CallResult, name: &str) {
    assert!(
        outcome.success && !outcome.halted,
        "{name}: verification did not succeed"
    );
    assert!(
        outcome.output.is_empty(),
        "{name}: unexpected verifier output"
    );
    assert!(outcome.gas_used > 0, "{name}: gas was not charged");
}

fn expect_revert(outcome: &CallResult, selector: &[u8; 4], name: &str) {
    assert!(
        !outcome.success && !outcome.halted,
        "{name}: expected EVM revert"
    );
    assert!(
        outcome.output.starts_with(selector),
        "{name}: unexpected revert selector"
    );
    assert!(outcome.gas_used > 0, "{name}: gas was not charged");
}

fn case(name: &str, outcome: &CallResult, input_bytes: usize, expected: Option<bool>) -> Value {
    json!({
        "name": name, "expected_success": expected, "success": outcome.success,
        "halted": outcome.halted, "gas_used": outcome.gas_used,
        "calldata_bytes": input_bytes, "output_bytes": outcome.output.len(),
        "revert_selector": (!outcome.success && outcome.output.len() >= 4)
            .then(|| hex::encode(&outcome.output[..4])),
    })
}
