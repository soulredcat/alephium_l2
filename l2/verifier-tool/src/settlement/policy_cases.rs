//! New outer-policy rejections; no repeat of the historical 69-case math suite.
use super::{
    Prepared,
    cases::changed_byte,
    journal::sha,
    layout::Templates,
    service::{FUTURE_SECONDS, candidate_args, finalize_args},
    state::{self, Run, bytes, word},
};
use crate::{compiler::Compiled, factory_state, staged_cases};
use serde_json::{Value, json};

pub(super) fn before_creation(
    run: &mut Run<'_>,
    _proof: &Compiled,
    data: &Compiled,
    templates: &Templates,
    p: &Prepared,
) -> Result<(), String> {
    let initial_root_snapshot = run.root.clone();
    run.success(
        "uninitialized-anchor-view",
        run.request("getAnchor", vec![], &[], false)?,
        std::slice::from_ref(&initial_root_snapshot),
        vec![word(0), bytes(&[0; 80]), bytes(&[0; 32])],
        &[],
    )?;
    run.reject(
        "finalize-before-initialization",
        run.request("finalize", finalize_args(p, &p.auxiliary_hash), &[], false)?,
        1613,
    )?;
    run.reject(
        "changed-original-genesis-checkpoint",
        run.request(
            "initializeGenesis",
            vec![bytes(&changed_byte(&p.bootstrap.checkpoint, 0))],
            &[],
            false,
        )?,
        1614,
    )?;
    let mut initialized = run.root.clone();
    initialized["mutFields"] = json!([
        word(1),
        bytes(&p.journal.parent.bytes),
        bytes(&p.journal.old_root)
    ]);
    run.success(
        "initialize-approved-genesis-root",
        run.request(
            "initializeGenesis",
            vec![bytes(&p.bootstrap.checkpoint)],
            &[],
            false,
        )?,
        &[initialized],
        vec![bytes(&p.journal.old_root)],
        &[],
    )?;
    run.reject(
        "genesis-reinitialization-refused",
        run.request(
            "initializeGenesis",
            vec![bytes(&p.bootstrap.checkpoint)],
            &[],
            false,
        )?,
        1612,
    )?;
    let existing = vec![templates.proof.clone(), templates.data.clone()];
    let full = &p.bootstrap.data;
    for (name, raw) in [
        ("missing-inline-data", vec![]),
        ("partial-inline-data", full[..full.len() - 1].to_vec()),
        ("altered-inline-data", changed_byte(full, 0)),
        ("oversized-inline-data", vec![0; 3001]),
    ] {
        run.reject(
            name,
            run.request(
                "createCandidate",
                candidate_args(p, &p.auxiliary_hash, &raw),
                &existing,
                true,
            )?,
            1616,
        )?;
    }
    let journal = &p.journal.bytes;
    let mut extended = journal.clone();
    extended.push(0);
    for (name, changed, code) in [
        (
            "truncated-journal",
            journal[..journal.len() - 1].to_vec(),
            1600,
        ),
        ("extended-journal", extended, 1600),
        ("wrong-execution-profile", changed_byte(journal, 266), 1602),
        ("foreign-factory-domain", changed_domain(journal), 1601),
        ("changed-parent-commit", changed_byte(journal, 322), 1603),
        ("changed-old-root", changed_byte(journal, 490), 1603),
        (
            "skipped-head-height",
            changed_u64(
                journal,
                386,
                p.journal
                    .head
                    .height
                    .checked_add(1)
                    .ok_or("Head height overflow")?,
            ),
            1606,
        ),
        (
            "future-timestamp",
            changed_u64(
                journal,
                394,
                p.journal
                    .head
                    .timestamp
                    .checked_add(FUTURE_SECONDS + 1)
                    .ok_or("Timestamp overflow")?,
            ),
            1605,
        ),
        (
            "timestamp-conversion-overflow",
            changed_u64(journal, 394, u64::MAX),
            1605,
        ),
    ] {
        let args = vec![
            bytes(&changed),
            bytes(&p.seal_hash),
            bytes(&p.auxiliary_hash),
            bytes(full),
        ];
        run.reject(
            name,
            run.request("createCandidate", args, &existing, true)?,
            code,
        )?;
    }
    let original_time = run.timestamp_ms;
    run.timestamp_ms = p
        .journal
        .head
        .timestamp
        .checked_sub(FUTURE_SECONDS)
        .and_then(|seconds| seconds.checked_mul(1000))
        .and_then(|millis| millis.checked_sub(1))
        .ok_or("Retained timestamp cannot exercise the declared millisecond boundary")?;
    let request = run.request(
        "createCandidate",
        candidate_args(p, &p.auxiliary_hash, full),
        &existing,
        true,
    )?;
    run.timestamp_ms = original_time;
    run.reject("future-boundary-one-millisecond", request, 1605)?;
    for (name, index) in [("short-seal-digest", 1), ("short-auxiliary-digest", 2)] {
        let mut args = candidate_args(p, &p.auxiliary_hash, full);
        args[index] = bytes(&[0; 31]);
        run.reject(
            name,
            run.request("createCandidate", args, &existing, true)?,
            1618,
        )?;
    }
    let wrong_template = state::contract(
        data,
        &templates.proof_id,
        vec![bytes(b"wrong executable")],
        vec![],
    )?;
    run.reject(
        "wrong-proof-template-executable",
        run.request(
            "createCandidate",
            candidate_args(p, &p.auxiliary_hash, full),
            &[wrong_template, templates.data.clone()],
            true,
        )?,
        1615,
    )?;
    let mut clone_id = p.journal.factory;
    clone_id[0] ^= 1;
    let mut clone_request = run.request(
        "createCandidate",
        candidate_args(p, &p.auxiliary_hash, full),
        &existing,
        true,
    )?;
    clone_request["address"] = json!(staged_cases::contract_address(&clone_id));
    run.reject("same-code-foreign-factory", clone_request, 1601)?;
    run.reject(
        "finalize-missing-canonical-data-and-proof",
        run.request("finalize", finalize_args(p, &p.auxiliary_hash), &[], false)?,
        1617,
    )?;
    Ok(())
}

pub(super) fn before_finalize(
    run: &mut Run<'_>,
    data: &Compiled,
    p: &Prepared,
    proof_state: &Value,
    data_state: &Value,
) -> Result<(), String> {
    let args = finalize_args(p, &p.auxiliary_hash);
    run.reject(
        "finalize-missing-canonical-proof",
        run.request(
            "finalize",
            args.clone(),
            std::slice::from_ref(data_state),
            false,
        )?,
        1617,
    )?;
    let mut clone_id = p.ids.proof;
    clone_id[0] ^= 1;
    let mut clone = factory_state::state_at(proof_state, &clone_id);
    clone["mutFields"][0] = word(3);
    clone["mutFields"][staged_cases::MUTABLE_WORDS] = staged_cases::bytes(&p.fixture.statement_id);
    run.reject(
        "same-code-forged-accepted-clone",
        run.request(
            "finalize",
            args.clone(),
            &[data_state.clone(), clone],
            false,
        )?,
        1617,
    )?;
    run.reject(
        "canonical-proof-not-finished",
        run.request(
            "finalize",
            args.clone(),
            &[data_state.clone(), proof_state.clone()],
            false,
        )?,
        1619,
    )?;
    let mut changed_data = data_state.clone();
    changed_data["immFields"] = json!([bytes(&changed_byte(&p.bootstrap.data, 0))]);
    run.reject(
        "canonical-data-hash-substitution",
        run.request(
            "finalize",
            args.clone(),
            &[changed_data, proof_state.clone()],
            false,
        )?,
        1616,
    )?;
    let mut changed_proof = proof_state.clone();
    changed_proof["immFields"][1] =
        staged_cases::bytes(&staged_cases::different_id(&p.fixture.payload_id)?);
    run.reject(
        "canonical-proof-binding-substitution",
        run.request(
            "finalize",
            args.clone(),
            &[data_state.clone(), changed_proof],
            false,
        )?,
        1618,
    )?;
    let wrong_code = state::contract(data, &p.ids.proof, vec![bytes(b"wrong executable")], vec![])?;
    run.reject(
        "canonical-proof-executable-substitution",
        run.request("finalize", args, &[data_state.clone(), wrong_code], false)?,
        1615,
    )?;
    Ok(())
}

fn changed_u64(bytes: &[u8], offset: usize, value: u64) -> Vec<u8> {
    let mut changed = bytes.to_vec();
    changed[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
    changed
}

/// Deliberately consistent empty-message commitments on a wrong factory domain.
/// This reaches the domain rejection; it is never submitted as a positive proof.
fn changed_domain(bytes: &[u8]) -> Vec<u8> {
    let mut changed = changed_byte(bytes, 194);
    for (kind, offset) in [(b"inbox".as_slice(), 786), (b"outbox".as_slice(), 826)] {
        let mut preimage = b"alephium-l2/authenticated-messages/v1".to_vec();
        preimage.extend(kind);
        preimage.extend(&changed[161..226]);
        preimage.extend(&changed[234..266]);
        preimage.extend(0_u64.to_be_bytes());
        changed[offset..offset + 32].copy_from_slice(&sha(&preimage));
    }
    changed
}
