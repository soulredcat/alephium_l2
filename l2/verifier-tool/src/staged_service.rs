//! Bounded synthetic VM transitions; carries only checked VM-produced fields.
use crate::{
    cases::word,
    compiler::Compiled,
    staged_cases::{self, Fixture, INITIAL_CURSOR, MAX_REQUESTS, MUTABLE_WORDS, bytes},
    staged_state::{Run, fingerprint},
    transport::ReadOnlyNode,
};
use serde_json::{Value, json};

pub fn execute(node: &ReadOnlyNode, compiled: &Compiled, report: &mut Value) -> Result<(), String> {
    let methods = ["begin", "advance", "finish", "getAcceptance"].map(|name| {
        compiled
            .public_methods
            .get(name)
            .copied()
            .ok_or("Missing compiled staged method")
    });
    let [begin, advance, finish, acceptance] = methods;
    let (begin, advance, finish, acceptance) = (begin?, advance?, finish?, acceptance?);
    if compiled.public_methods.len() != 4 {
        return Err("Staged contract has an unexpected public entry point".into());
    }
    let fixture = Fixture::load()?;
    report["stagedLifecycle"] = json!({
        "scope": "mainnet-pinned synthetic read-only target execution",
        "fixtureContractId": hex::encode(fixture.contract_id),
        "fixtureAddress": fixture.address,
        "statementIdentityDomain": "ALPH/L2/stagedreceipt/v1",
        "statementIdentityPreimageBytes": 188,
        "stateSource": "last fully checked successful VM ContractState.mutFields only",
        "maximumRequests": MAX_REQUESTS, "advanceDigitBound": 8,
        "mutableU256Words": MUTABLE_WORDS, "mutableByteVecBytes": 32,
        "initialVirtualAttoAlph": "100000000000000000",
        "realOnChainContinuityProven": false, "deploymentProven": false,
        "originTrustedCanonicalDeployment": false,
        "durableStateProven": false, "receiptAcceptedBeforeFinish": false,
        "settlementAccepted": false, "wrongImageAndJournalIndependentlyFalse": true,
        "wrongJournalTargetFlowExecuted": false,
        "responseSchemaSource": "https://github.com/alephium/alephium/blob/v4.7.0/api/src/main/scala/org/alephium/api/model/TestContractResult.scala"
    });
    let mut run = Run::new(node, compiled, &fixture, report);
    let mut fields = staged_cases::initial_fields();
    let id = &fixture.statement_id;
    let zero_id = "00".repeat(32);
    let mut parameter_request = run.request(begin, fixture.begin_args.clone(), &fields);
    parameter_request["initialImmFields"] = json!([word("0")]);
    run.reject_request("wrong-modulus-begin", parameter_request, &fields, 1002)?;
    run.report["parameterBinding"] = json!({"passed": true, "wrongModulus": "0",
        "expectedAssertionCode": 1002, "beforeArithmeticRequired": true, "requests": 1});
    run.reject(
        "advance-before-begin",
        advance,
        advance_args(&zero_id, 0),
        &fields,
        1500,
    )?;
    run.reject(
        "finish-before-begin",
        finish,
        vec![bytes(&zero_id)],
        &fields,
        1500,
    )?;
    run.reject(
        "zero-root-begin",
        begin,
        fixture.zero_witness_args()?,
        &fields,
        1432,
    )?;
    fields = run.success(
        "official-begin",
        begin,
        fixture.begin_args.clone(),
        &fields,
        1,
        INITIAL_CURSOR,
        id,
        vec![bytes(id)],
    )?;
    run.view("pending-acceptance-view", acceptance, &fields, 1, 65, id)?;
    run.reject(
        "duplicate-begin",
        begin,
        fixture.begin_args.clone(),
        &fields,
        1500,
    )?;
    run.reject("premature-finish", finish, vec![bytes(id)], &fields, 1500)?;
    let wrong_id = staged_cases::different_id(id)?;
    run.reject(
        "wrong-identity-advance",
        advance,
        advance_args(&wrong_id, 65),
        &fields,
        1501,
    )?;
    run.reject(
        "stale-cursor-advance",
        advance,
        advance_args(id, 64),
        &fields,
        1502,
    )?;
    run.reject(
        "out-of-order-advance",
        advance,
        advance_args(id, 57),
        &fields,
        1502,
    )?;
    let mut cursor = INITIAL_CURSOR;
    for stage in 1..=9 {
        let next = cursor.saturating_sub(8);
        let old_fields = fields.clone();
        fields = run.success(
            &format!("official-advance-{stage:02}"),
            advance,
            advance_args(id, cursor),
            &fields,
            if next == 0 { 2 } else { 1 },
            next,
            id,
            vec![word(&next.to_string())],
        )?;
        if stage == 1 {
            run.reject(
                "duplicate-advance",
                advance,
                advance_args(id, cursor),
                &fields,
                1502,
            )?;
            if fingerprint(&old_fields) == fingerprint(&fields) {
                return Err("Successful advance did not change the checked VM checkpoint".into());
            }
        }
        cursor = next;
    }
    run.view("ready-acceptance-view", acceptance, &fields, 2, 0, id)?;
    run.reject(
        "wrong-identity-finish",
        finish,
        vec![bytes(&wrong_id)],
        &fields,
        1501,
    )?;
    fields = run.success(
        "official-finish",
        finish,
        vec![bytes(id)],
        &fields,
        3,
        0,
        id,
        vec![bytes(id)],
    )?;
    run.view("final-acceptance-view", acceptance, &fields, 3, 0, id)?;
    run.reject("duplicate-finish", finish, vec![bytes(id)], &fields, 1500)?;
    run.reject(
        "begin-after-finish",
        begin,
        fixture.begin_args.clone(),
        &fields,
        1500,
    )?;
    run.reject(
        "advance-after-finish",
        advance,
        advance_args(id, 0),
        &fields,
        1500,
    )?;
    run.report["stagedLifecycle"]["officialCompleteFlowPassed"] = json!(true);
    run.report["stagedLifecycle"]["officialAdvanceTransitions"] = json!(9);
    run.report["stagedLifecycle"]["officialFinalStatus"] = json!(3);
    let official_gas: Vec<_> = run
        .records
        .iter()
        .filter(|entry| {
            entry["name"]
                .as_str()
                .is_some_and(|name| name.starts_with("official-"))
        })
        .filter_map(|entry| entry["gasUsed"].as_u64())
        .collect();
    run.report["stagedLifecycle"]["officialVmGasSum"] = json!(official_gas.iter().sum::<u64>());
    run.report["stagedLifecycle"]["officialVmGasMax"] = json!(official_gas.iter().max());
    // A new isolated synthetic instance with the same fixture address is used.
    // The changed image is independently invalid, yet structurally admitted.
    let bad_id = &fixture.wrong_image_id;
    fields = run.success(
        "wrong-image-begin",
        begin,
        fixture.wrong_image_args.clone(),
        &staged_cases::initial_fields(),
        1,
        65,
        bad_id,
        vec![bytes(bad_id)],
    )?;
    cursor = INITIAL_CURSOR;
    for stage in 1..=9 {
        let next = cursor.saturating_sub(8);
        fields = run.success(
            &format!("wrong-image-advance-{stage:02}"),
            advance,
            advance_args(bad_id, cursor),
            &fields,
            if next == 0 { 2 } else { 1 },
            next,
            bad_id,
            vec![word(&next.to_string())],
        )?;
        cursor = next;
    }
    run.reject(
        "wrong-image-final-equation",
        finish,
        vec![bytes(bad_id)],
        &fields,
        1404,
    )?;
    run.report["stagedLifecycle"]["wrongImageTargetFlowExecuted"] = json!(true);
    run.report["stagedLifecycle"]["wrongImageNeverAccepted"] = json!(true);
    let gas: Vec<_> = run
        .records
        .iter()
        .filter_map(|entry| entry["gasUsed"].as_u64())
        .collect();
    run.report["positiveVmGasSum"] = json!(gas.iter().sum::<u64>());
    run.report["positiveVmGasMax"] = json!(gas.iter().max());
    run.report["executedCases"] = json!(run.records.len());
    run.report["passed"] = json!(true);
    Ok(())
}

/// Starts exclusively from the caller's checked VM-created child state.
/// Returned ContractState is the last successful VM result, never reconstructed.
pub fn execute_canonical(
    node: &ReadOnlyNode,
    compiled: &Compiled,
    report: &mut Value,
    contract_id: &[u8; 32],
    initial_contract_state: &Value,
) -> Result<Value, String> {
    let fixture = Fixture::at_id(contract_id)?;
    execute_canonical_fixture(
        node,
        compiled,
        report,
        &fixture,
        initial_contract_state,
        false,
    )
}

/// Historical modes retain their original claim and request inventory.
pub(crate) fn execute_canonical_fixture(
    node: &ReadOnlyNode,
    compiled: &Compiled,
    report: &mut Value,
    fixture: &Fixture,
    initial_contract_state: &Value,
    reject_journal: bool,
) -> Result<Value, String> {
    let (id, args, label) = if reject_journal {
        (
            &fixture.wrong_journal_id,
            &fixture.wrong_journal_args,
            "wrong-journal",
        )
    } else {
        (&fixture.statement_id, &fixture.begin_args, "canonical")
    };
    crate::staged_canonical::execute(
        node,
        compiled,
        report,
        fixture,
        initial_contract_state,
        crate::staged_canonical::Claim {
            label,
            id,
            args,
            reject: reject_journal,
            check_order: false,
        },
    )
}
fn advance_args(id: &str, cursor: u64) -> Vec<Value> {
    vec![bytes(id), word(&cursor.to_string())]
}
