//! Actual-receipt orchestration over the existing checked factory VM adapter.
use crate::{
    cases::{FP_MODULUS, word},
    compiler::Compiled,
    factory_service::{self, Run},
    factory_state::{child_state, fixture_id},
    staged_canonical::{self, Claim},
    staged_cases::{self, Fixture, bytes},
    staged_state::{asset, fingerprint},
    transport::ReadOnlyNode,
};
use serde_json::{Value, json};

pub(crate) fn execute(
    node: &ReadOnlyNode,
    factory: &Compiled,
    child: &Compiled,
    report: &mut Value,
    fixture: &Fixture,
    changed_proof: &Fixture,
) -> Result<(), String> {
    let create = *factory
        .public_methods
        .get("create")
        .ok_or("Missing factory create")?;
    let accepted = *factory
        .public_methods
        .get("accepted")
        .ok_or("Missing factory accepted")?;
    if factory.public_methods.len() != 2 {
        return Err("Unexpected public factory entry point".into());
    }
    let factory_id = fixture_id(b"ALPH/L2/stagedfactory/development-fixture/v1");
    let child_id = factory_service::canonical_child_id()?;
    if fixture.contract_id != child_id
        || fixture.address != staged_cases::contract_address(&child_id)
    {
        return Err("Actual receipt fixture is not bound to the canonical child".into());
    }
    let template_id = fixture_id(b"ALPH/L2/stagedfactory/template-fixture/v1");
    let template = child_state(child, &template_id, staged_cases::initial_fields());
    let immutable = json!([
        bytes(&hex::encode(template_id)),
        child.evidence["productionCodeHash"]
            .as_str()
            .map(bytes)
            .ok_or("Missing native template code hash")?,
        word(FP_MODULUS)
    ]);
    let root_state = json!({"address": staged_cases::contract_address(&factory_id),
        "bytecode": factory.bytecode, "codeHash": factory.evidence["productionCodeHash"],
        "immFields": immutable, "mutFields": [], "asset": asset()});
    report["factoryLifecycle"] = json!({
        "scope": "actual SDK receipt; mainnet-pinned synthetic VM factory and gate",
        "fixtureFactoryId": hex::encode(factory_id), "childPath": "7631",
        "independentlyDerivedChildId": hex::encode(child_id),
        "childDerivation": "Blake2b256(Blake2b256(factoryId || path)), final byte = group 0",
        "factoryImmutableConfigurationPinned": true, "maximumFactoryRequests": 9,
        "maximumCanonicalChildRequests": 17, "maximumWrongJournalRequests": 11,
        "maximumWrongImageRequests": 11, "maximumChangedProofRequests": 11,
        "virtualCallerAttoAlph": "1000000000000000000",
        "virtualChildDepositAttoAlph": "100000000000000000", "signed": false,
        "templateTrust": "synthetically supplied pinned production code, not prover authority",
        "canonicalStateSource": "VM copyCreateSubContract result then checked child transitions",
        "historicalOriginGuardCasesReused": false,
        "syntheticCreationProven": false, "realCanonicalDeploymentProven": false,
        "realOnChainContinuityProven": false, "durableStateProven": false,
        "settlementAccepted": false, "forgedCanonicalOriginUsed": false
    });
    let mut run = Run::new(node, factory, root_state, report);
    // The only positive origin is this checked actual VM creation response.
    let created = run.create(create, child, &template, &child_id)?;
    run.reject(
        "actual-acceptance-before-finish",
        accepted,
        vec![bytes(&fixture.statement_id)],
        std::slice::from_ref(&created),
        1514,
    )?;
    // Attack fixture has the correct executable but forged accepted status at a
    // different address; it must never substitute for the canonical child.
    let clone_id = fixture_id(b"ALPH/L2/stagedfactory/actual-forged-clone/v1");
    let mut forged = staged_cases::initial_fields();
    forged[0] = word("3");
    forged[staged_cases::MUTABLE_WORDS] = bytes(&fixture.statement_id);
    let clone = child_state(child, &clone_id, forged);
    run.reject(
        "actual-forged-clone-without-canonical",
        accepted,
        vec![bytes(&fixture.statement_id)],
        std::slice::from_ref(&clone),
        1513,
    )?;
    run.reject(
        "actual-forged-clone-canonical-pending",
        accepted,
        vec![bytes(&fixture.statement_id)],
        &[created.clone(), clone],
        1514,
    )?;
    let mut child_report = json!({"results": [], "passed": false});
    let final_state = staged_canonical::execute(
        node,
        child,
        &mut child_report,
        fixture,
        &created,
        Claim {
            label: "canonical",
            id: &fixture.statement_id,
            args: &fixture.begin_args,
            reject: false,
            check_order: true,
        },
    );
    run.report["canonicalChildLifecycle"] = child_report;
    let final_state = final_state?;
    if final_state["mutFields"][staged_cases::MUTABLE_WORDS] != bytes(&fixture.statement_id) {
        return Err("Actual canonical child has a different independent statement".into());
    }
    run.reject(
        "actual-accepted-wrong-statement",
        accepted,
        vec![bytes(&staged_cases::different_id(&fixture.statement_id)?)],
        std::slice::from_ref(&final_state),
        1515,
    )?;
    run.accepted(accepted, &fixture.statement_id, &final_state)?;

    // Each isolated negative starts at the same genuine VM-created zero origin.
    // Original auxiliary bytes remain unchanged for all three false equations.
    for (section, label, id, args) in [
        (
            "wrongJournalLifecycle",
            "wrong-journal",
            &fixture.wrong_journal_id,
            &fixture.wrong_journal_args,
        ),
        (
            "wrongImageLifecycle",
            "wrong-image",
            &fixture.wrong_image_id,
            &fixture.wrong_image_args,
        ),
        (
            "changedProofLifecycle",
            "changed-proof",
            &changed_proof.statement_id,
            &changed_proof.begin_args,
        ),
    ] {
        let mut bad_report = json!({"results": [], "passed": false});
        let bad_state = staged_canonical::execute(
            node,
            child,
            &mut bad_report,
            fixture,
            &created,
            Claim {
                label,
                id,
                args,
                reject: true,
                check_order: false,
            },
        );
        run.report[section] = bad_report;
        let bad_state = bad_state?;
        if bad_state["mutFields"][0] != word("2")
            || bad_state["mutFields"][staged_cases::MUTABLE_WORDS] != bytes(id)
        {
            return Err("Rejected actual claim did not retain its checked ready state".into());
        }
        run.reject(
            &format!("{label}-never-factory-accepted"),
            accepted,
            vec![bytes(id)],
            std::slice::from_ref(&bad_state),
            1514,
        )?;
    }
    let count = |section: &str| {
        run.report[section]["executedCases"]
            .as_u64()
            .ok_or("Missing actual receipt child request count")
    };
    if run.records.len() != 9
        || count("canonicalChildLifecycle")? != 17
        || count("wrongJournalLifecycle")? != 11
        || count("wrongImageLifecycle")? != 11
        || count("changedProofLifecycle")? != 11
    {
        return Err("Actual factory flow differs from its fixed request inventory".into());
    }
    let mut gas: Vec<_> = run
        .records
        .iter()
        .filter_map(|entry| entry["gasUsed"].as_u64())
        .collect();
    for section in [
        "canonicalChildLifecycle",
        "wrongJournalLifecycle",
        "wrongImageLifecycle",
        "changedProofLifecycle",
    ] {
        gas.extend(
            run.report[section]["results"]
                .as_array()
                .ok_or("Missing checked actual child results")?
                .iter()
                .filter_map(|entry| entry["gasUsed"].as_u64()),
        );
    }
    run.report["factoryLifecycle"]["syntheticCreationProven"] = json!(true);
    run.report["factoryLifecycle"]["canonicalGenesisFieldsMatched"] = json!(true);
    run.report["factoryLifecycle"]["nativeTemplateCodeHashMatched"] = json!(true);
    run.report["factoryLifecycle"]["canonicalCompleteFlowAndGatePassed"] = json!(true);
    run.report["factoryLifecycle"]["wrongJournalNeverAccepted"] = json!(true);
    run.report["factoryLifecycle"]["wrongImageNeverAccepted"] = json!(true);
    run.report["factoryLifecycle"]["changedProofNeverAccepted"] = json!(true);
    run.report["factoryLifecycle"]["actualForgedOriginGuardsPassed"] = json!(true);
    run.report["factoryLifecycle"]["finalCheckpointSha256"] = json!(fingerprint(
        final_state["mutFields"]
            .as_array()
            .ok_or("Missing final actual fields")?,
    ));
    run.report["positiveVmGasSum"] = json!(gas.iter().sum::<u64>());
    run.report["positiveVmGasMax"] = json!(gas.iter().max());
    run.report["executedCases"] = json!(crate::actual_receipt::MAX_REQUESTS);
    run.report["passed"] = json!(true);
    Ok(())
}
