//! Canonical-child trajectory shared by historical and actual receipt inputs.
use crate::{
    cases::word,
    compiler::Compiled,
    staged_cases::{self, Fixture, INITIAL_CURSOR, bytes},
    staged_state::{self, Run},
    transport::ReadOnlyNode,
};
use serde_json::{Value, json};

pub(crate) struct Claim<'a> {
    pub label: &'static str,
    pub id: &'a str,
    pub args: &'a [Value],
    pub reject: bool,
    pub check_order: bool,
}

/// Always begins at checked VM-created zero state. Rejections never supply
/// reconstructed accepted state; return the last successful target checkpoint.
pub(crate) fn execute(
    node: &ReadOnlyNode,
    compiled: &Compiled,
    report: &mut Value,
    fixture: &Fixture,
    initial_contract_state: &Value,
    claim: Claim<'_>,
) -> Result<Value, String> {
    let method = |name: &str| {
        compiled
            .public_methods
            .get(name)
            .copied()
            .ok_or("Missing compiled staged method")
    };
    let (begin, advance, finish, acceptance) = (
        method("begin")?,
        method("advance")?,
        method("finish")?,
        method("getAcceptance")?,
    );
    if compiled.public_methods.len() != 5 {
        return Err("Canonical child has an unexpected public entry point".into());
    }
    let mut fields =
        staged_state::canonical_child_fields(initial_contract_state, compiled, fixture)?;
    let transitions = if claim.reject { 11 } else { 12 } + if claim.check_order { 5 } else { 0 };
    let (prefix, id) = (claim.label, claim.id);
    report["stagedLifecycle"] = json!({
        "scope": "synthetic VM-created canonical child transition replay",
        "fixtureContractId": hex::encode(fixture.contract_id), "fixtureAddress": fixture.address,
        "expectedPayloadId": fixture.payload_id, "payloadDomain": "ALPH/L2/stagedpayload/v1",
        "payloadPreimageBytes": 156, "instanceStatementPreimageBytes": 188,
        "canonicalZeroOriginValidated": true, "fixedTransitionRequests": transitions,
        "stateSource": "actual VM factory-created child followed by checked VM states",
        "realOnChainContinuityProven": false, "deploymentProven": false,
        "originTrustedCanonicalDeployment": false, "durableStateProven": false,
        "receiptAcceptedBeforeFinish": false, "settlementAccepted": false,
        "actualOrderGuardsExecuted": claim.check_order
    });
    let mut run = Run::new(node, compiled, fixture, report);
    if claim.check_order {
        run.reject(
            "actual-advance-before-begin",
            advance,
            advance_args(id, 65),
            &fields,
            1500,
        )?;
    }
    fields = run.success(
        &format!("{prefix}-begin"),
        begin,
        claim.args.to_vec(),
        &fields,
        1,
        INITIAL_CURSOR,
        id,
        vec![bytes(id)],
    )?;
    if claim.check_order {
        run.reject(
            "actual-premature-finish",
            finish,
            vec![bytes(id)],
            &fields,
            1500,
        )?;
        run.reject(
            "actual-out-of-order-advance",
            advance,
            advance_args(id, 57),
            &fields,
            1502,
        )?;
        let wrong_id = staged_cases::different_id(id)?;
        run.reject(
            "actual-wrong-statement-advance",
            advance,
            advance_args(&wrong_id, 65),
            &fields,
            1501,
        )?;
    }
    let mut cursor = INITIAL_CURSOR;
    for stage in 1..=9 {
        let next = cursor.saturating_sub(8);
        fields = run.success(
            &format!("{prefix}-advance-{stage:02}"),
            advance,
            advance_args(id, cursor),
            &fields,
            if next == 0 { 2 } else { 1 },
            next,
            id,
            vec![word(&next.to_string())],
        )?;
        if claim.check_order && stage == 1 {
            run.reject(
                "actual-duplicate-advance",
                advance,
                advance_args(id, cursor),
                &fields,
                1502,
            )?;
        }
        cursor = next;
    }
    if claim.reject {
        run.reject(
            &format!("{prefix}-final-equation"),
            finish,
            vec![bytes(id)],
            &fields,
            1404,
        )?;
    } else {
        fields = run.success(
            &format!("{prefix}-finish"),
            finish,
            vec![bytes(id)],
            &fields,
            3,
            0,
            id,
            vec![bytes(id)],
        )?;
        run.view(
            &format!("{prefix}-final-acceptance"),
            acceptance,
            &fields,
            3,
            0,
            id,
        )?;
    }
    let final_state = run.last_contract_state()?;
    if final_state["mutFields"] != json!(fields) || run.records.len() != transitions {
        return Err("Canonical child final VM state or transition count differs".into());
    }
    run.report["stagedLifecycle"]["wrongJournalTargetFlowExecuted"] =
        json!(prefix == "wrong-journal");
    run.report["stagedLifecycle"]["receiptAccepted"] = json!(!claim.reject);
    run.report["stagedLifecycle"]["finalStatus"] = json!(if claim.reject { 2 } else { 3 });
    let gas: Vec<_> = run
        .records
        .iter()
        .filter_map(|entry| entry["gasUsed"].as_u64())
        .collect();
    run.report["positiveVmGasSum"] = json!(gas.iter().sum::<u64>());
    run.report["positiveVmGasMax"] = json!(gas.iter().max());
    run.report["executedCases"] = json!(run.records.len());
    run.report["passed"] = json!(true);
    Ok(final_state)
}

fn advance_args(id: &str, cursor: u64) -> Vec<Value> {
    vec![bytes(id), word(&cursor.to_string())]
}
