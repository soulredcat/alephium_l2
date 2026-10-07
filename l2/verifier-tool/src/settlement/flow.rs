//! One matched-domain candidate trajectory reusing the independently checked receipt.
use super::{
    Prepared,
    journal::sha,
    layout::Templates,
    policy_cases,
    service::{FUTURE_SECONDS, candidate_args, finalize_args},
    state::{self, Run, bytes, word},
};
use crate::{
    compiler::Compiled,
    factory_state,
    staged_canonical::{self, Claim},
    staged_cases,
};
use serde_json::{Value, json};
pub(super) fn execute(
    run: &mut Run<'_>,
    proof: &Compiled,
    data: &Compiled,
    templates: &Templates,
    p: &Prepared,
    report: &mut Value,
) -> Result<(), String> {
    policy_cases::before_creation(run, proof, data, templates, p)?;
    // A stalled distinct hash-keyed proposal coexists without reserving the head.
    let mut stalled_aux = p.auxiliary_hash;
    stalled_aux[0] ^= 1;
    let stalled = state::ids(
        &p.journal.factory,
        &p.image,
        &p.journal.digest,
        &p.seal_hash,
        &stalled_aux,
    );
    // Construct expected immutable payload directly from its exact digest fields.
    let mut payload = staged_cases::PAYLOAD_DOMAIN.to_vec();
    payload.extend([0x73, 0xc4, 0x57, 0xba]);
    payload.extend(p.image);
    payload.extend(p.journal.digest);
    payload.extend(p.seal_hash);
    payload.extend(stalled_aux);
    let stalled_proof = factory_state::child_state(
        proof,
        &stalled.proof,
        staged_cases::initial_fields(),
        &hex::encode(sha(&payload)),
    );
    let stalled_data =
        state::contract(data, &stalled.data, vec![bytes(&p.bootstrap.data)], vec![])?;
    let templates_only = vec![templates.proof.clone(), templates.data.clone()];
    let expected = vec![
        run.root.clone(),
        templates.proof.clone(),
        templates.data.clone(),
        stalled_data.clone(),
        stalled_proof.clone(),
    ];
    let stalled_states = run.success(
        "stalled-candidate-create",
        run.request(
            "createCandidate",
            candidate_args(p, &stalled_aux, &p.bootstrap.data),
            &templates_only,
            true,
        )?,
        &expected,
        vec![
            bytes(&stalled.key),
            bytes(&stalled.proof),
            bytes(&stalled.data),
        ],
        &[stalled.data, stalled.proof],
    )?;
    let stalled_proof = stalled_states
        .iter()
        .find(|state| state["address"] == stalled_proof["address"])
        .cloned()
        .ok_or("Missing VM-created stalled proof child")?;
    let stalled_data = stalled_states
        .iter()
        .find(|state| state["address"] == stalled_data["address"])
        .cloned()
        .ok_or("Missing VM-created stalled data child")?;
    let initial_proof = factory_state::child_state(
        proof,
        &p.ids.proof,
        staged_cases::initial_fields(),
        &p.fixture.payload_id,
    );
    let initial_data = state::contract(data, &p.ids.data, vec![bytes(&p.bootstrap.data)], vec![])?;
    let existing = vec![
        templates.proof.clone(),
        templates.data.clone(),
        stalled_data.clone(),
        stalled_proof.clone(),
    ];
    let mut expected = vec![run.root.clone()];
    expected.extend(existing.clone());
    expected.extend([initial_data.clone(), initial_proof.clone()]);
    run.timestamp_ms = p
        .journal
        .head
        .timestamp
        .checked_sub(FUTURE_SECONDS)
        .and_then(|seconds| seconds.checked_mul(1000))
        .ok_or("Time-boundary conversion overflow")?;
    let states = run.success(
        "valid-candidate-create-at-time-boundary",
        run.request(
            "createCandidate",
            candidate_args(p, &p.auxiliary_hash, &p.bootstrap.data),
            &existing,
            true,
        )?,
        &expected,
        vec![bytes(&p.ids.key), bytes(&p.ids.proof), bytes(&p.ids.data)],
        &[p.ids.data, p.ids.proof],
    )?;
    let created = states
        .iter()
        .find(|state| state["address"] == initial_proof["address"])
        .cloned()
        .ok_or("Missing genuine VM-created proof child")?;
    let initial_data = states
        .iter()
        .find(|state| state["address"] == initial_data["address"])
        .cloned()
        .ok_or("Missing genuine VM-created data child")?;
    let mut all = existing;
    all.extend([initial_data.clone(), created.clone()]);
    let mut expected = vec![run.root.clone()];
    expected.extend(all.clone());
    run.success(
        "identical-candidate-reuses-checked-children",
        run.request(
            "createCandidate",
            candidate_args(p, &p.auxiliary_hash, &p.bootstrap.data),
            &all,
            true,
        )?,
        &expected,
        vec![bytes(&p.ids.key), bytes(&p.ids.proof), bytes(&p.ids.data)],
        &[],
    )?;
    policy_cases::before_finalize(run, data, p, &created, &initial_data)?;
    let mut child_report = json!({"passed": false, "results": []});
    let finished = staged_canonical::execute(
        run.node,
        proof,
        &mut child_report,
        &p.fixture,
        &created,
        Claim {
            label: "settlement",
            id: &p.fixture.statement_id,
            args: &p.fixture.begin_args,
            reject: false,
            check_order: false,
        },
    );
    report["canonicalChildLifecycle"] = child_report;
    let finished = finished?;
    let mut wrong_statement = finished.clone();
    wrong_statement["mutFields"][staged_cases::MUTABLE_WORDS] =
        staged_cases::bytes(&staged_cases::different_id(&p.fixture.statement_id)?);
    run.reject(
        "accepted-child-wrong-statement",
        run.request(
            "finalize",
            finalize_args(p, &p.auxiliary_hash),
            &[initial_data.clone(), wrong_statement],
            false,
        )?,
        1620,
    )?;
    let mut accepted = run.root.clone();
    accepted["mutFields"] = json!([
        word(1),
        bytes(&p.journal.head.bytes),
        bytes(&p.journal.new_root)
    ]);
    run.success(
        "consume-actual-canonical-proof-and-data",
        run.request(
            "finalize",
            finalize_args(p, &p.auxiliary_hash),
            &[initial_data.clone(), finished.clone()],
            false,
        )?,
        &[accepted, initial_data.clone(), finished.clone()],
        vec![bytes(&p.journal.new_root)],
        &[],
    )?;
    let accepted_root_snapshot = run.root.clone();
    run.success(
        "accepted-anchor-view",
        run.request("getAnchor", vec![], &[], false)?,
        std::slice::from_ref(&accepted_root_snapshot),
        vec![
            word(1),
            bytes(&p.journal.head.bytes),
            bytes(&p.journal.new_root),
        ],
        &[],
    )?;
    for (name, method, args) in [
        (
            "semantic-replay-refused",
            "finalize",
            finalize_args(p, &p.auxiliary_hash),
        ),
        (
            "stale-parent-registration-refused",
            "createCandidate",
            candidate_args(p, &p.auxiliary_hash, &p.bootstrap.data),
        ),
        (
            "stalled-parent-refused-after-progress",
            "finalize",
            finalize_args(p, &stalled_aux),
        ),
    ] {
        run.reject(
            name,
            run.request(method, args, &[], method == "createCandidate")?,
            1603,
        )?;
    }
    Ok(())
}
