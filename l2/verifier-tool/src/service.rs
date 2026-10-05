//! Field verification workflow and exact target outcome assessment.
use crate::{
    actual_receipt,
    cases::{self, Case, Expected},
    compiler, curve_cases, diagnostic_cases, factory_service, fixed_pair, folded_msm,
    input::Suite,
    miller_cases, pairing_cases, receipt_cases, residue_cases, staged_service, tower_cases,
    transport, verification_key,
};
use serde_json::{Value, json};
use std::{path::Path, time::Instant};

pub fn execute(
    jar: &Path,
    evidence: &Path,
    deadline: Instant,
    suite: Suite,
    report: &mut Value,
    actual: Option<&actual_receipt::Input>,
) -> Result<(), String> {
    let actual = actual.map(actual_receipt::prepare).transpose()?;
    if matches!(
        suite,
        Suite::StagedReceipt | Suite::StagedFactory | Suite::StagedFactoryFlow
    ) {
        report["verificationKeyCertificate"] = verification_key::certify()?;
        report["foldedMsmCertificate"] = folded_msm::certify()?;
        report["fixedPairCertificate"] = fixed_pair::certify()?;
        let compiled = compiler::compile(jar, evidence, deadline, suite)?;
        report["compiler"] = compiled.evidence.clone();
        let binding = json!({
            "sourceClosureHashesChecked": report["compiler"]["projectSourceHashesMatched"],
            "executableSha256": report["compiler"]["executableSha256"],
            "compilerJarSha256": report["compiler"]["jarSha256"],
            "immutableModulus": cases::word(cases::FP_MODULUS),
            "mutableSchemaChecked": true, "callerAdmissionFlag": false
        });
        for certificate in [
            "verificationKeyCertificate",
            "foldedMsmCertificate",
            "fixedPairCertificate",
        ] {
            report[certificate]["artifactBinding"] = binding.clone();
        }
        if matches!(suite, Suite::StagedFactory) {
            report["passed"] = json!(true);
            report["compilationOnly"] = json!(true);
            report["canonicalCreationExecuted"] = json!(false);
            return Ok(());
        }
        let node = transport::ReadOnlyNode::connect(deadline)?;
        report["reportedVmIdentity"] = node.identity.clone();
        if matches!(suite, Suite::StagedFactoryFlow) {
            let child_dir = evidence.join("child");
            std::fs::create_dir(&child_dir)
                .map_err(|_| "Cannot create fresh child compilation directory")?;
            let child = compiler::compile(jar, &child_dir, deadline, Suite::StagedReceipt)?;
            report["childCompiler"] = child.evidence.clone();
            if let Some(actual) = actual {
                return actual_receipt::execute_actual(&node, &compiled, &child, report, actual);
            }
            return factory_service::execute(&node, &compiled, &child, report);
        }
        return staged_service::execute(&node, &compiled, report);
    }
    if matches!(
        suite,
        Suite::Receipt | Suite::ResidueReceipt | Suite::ResidueDiagnostic
    ) {
        report["verificationKeyCertificate"] = verification_key::certify()?;
        report["foldedMsmCertificate"] = folded_msm::certify()?;
        report["receiptFixture"] = receipt_cases::fixture_evidence()?;
    }
    if matches!(suite, Suite::ResidueReceipt) {
        report["residueWitness"] = residue_cases::evidence()?;
    }
    if matches!(suite, Suite::ResidueReceipt | Suite::ResidueDiagnostic) {
        report["fixedPairCertificate"] = fixed_pair::certify()?;
    }
    if matches!(suite, Suite::ResidueDiagnostic) {
        report["diagnosis"] = diagnostic_cases::evidence();
    }
    let corpus = match suite {
        Suite::Base => cases::corpus()?,
        Suite::Tower => tower_cases::corpus()?,
        Suite::PairingArithmetic => pairing_cases::corpus()?,
        Suite::Curves => curve_cases::corpus()?,
        Suite::Miller => miller_cases::corpus()?,
        Suite::Receipt => receipt_cases::corpus()?,
        Suite::ResidueReceipt => residue_cases::corpus()?,
        Suite::ResidueDiagnostic => diagnostic_cases::corpus()?,
        Suite::StagedReceipt | Suite::StagedFactory | Suite::StagedFactoryFlow => {
            unreachable!("Staged workflow dispatched above")
        }
    };
    if corpus.len() != suite.case_count() {
        return Err("Verification corpus differs from the declared fixed bound".into());
    }
    report["expectationOracle"]["corpusPreparedBeforeCompilation"] = json!(true);
    let compiled = compiler::compile(jar, evidence, deadline, suite)?;
    report["compiler"] = compiled.evidence;
    if matches!(
        suite,
        Suite::Receipt | Suite::ResidueReceipt | Suite::ResidueDiagnostic
    ) {
        report["verificationKeyCertificate"]["artifactBinding"] = json!({
            "sourceClosureHashesChecked": report["compiler"]["projectSourceHashesMatched"],
            "executableSha256": report["compiler"]["executableSha256"],
            "compilerJarSha256": report["compiler"]["jarSha256"],
            "immutableFields": [cases::word(cases::FP_MODULUS)],
            "mutableFields": [], "callerAdmissionFlag": false
        });
        report["foldedMsmCertificate"]["artifactBinding"] =
            report["verificationKeyCertificate"]["artifactBinding"].clone();
    }
    if matches!(suite, Suite::ResidueReceipt | Suite::ResidueDiagnostic) {
        report["fixedPairCertificate"]["artifactBinding"] =
            report["verificationKeyCertificate"]["artifactBinding"].clone();
    }
    let node = transport::ReadOnlyNode::connect(deadline)?;
    report["reportedVmIdentity"] = node.identity.clone();
    let first = corpus.first().ok_or("Empty verification corpus")?;
    let parameter_result = node.test(&request(
        first,
        &compiled.bytecode,
        compiled.method_index,
        suite,
        "0",
    ));
    let parameter_passed = matches!(
        parameter_result,
        Err(transport::ProbeError::VmAssertion(1002))
    );
    report["parameterBinding"] = json!({
        "passed": parameter_passed, "wrongModulus": "0", "expectedAssertionCode": 1002,
        "beforeArithmeticRequired": true, "requests": 1
    });
    if !parameter_passed {
        return Err("Immutable modulus identity was not rejected before arithmetic".into());
    }
    let mut results = Vec::with_capacity(corpus.len());
    for case in corpus {
        let response = node.test(&request(
            &case,
            &compiled.bytecode,
            compiled.method_index,
            suite,
            cases::FP_MODULUS,
        ));
        let result = assess(&case, response);
        let passed = result["passed"] == true;
        results.push(result);
        report["results"] = json!(results);
        if !passed {
            return Err(format!(
                "Field case {} failed its expected VM outcome; response payload suppressed",
                case.name
            ));
        }
    }
    let charged_gas: Vec<_> = results
        .iter()
        .filter_map(|result| result["gasUsed"].as_u64())
        .collect();
    report["positiveVmGasSum"] = json!(charged_gas.iter().sum::<u64>());
    report["positiveVmGasMax"] = json!(charged_gas.iter().max());
    report["executedCases"] = json!(results.len());
    report["passed"] = json!(true);
    Ok(())
}

fn request(case: &Case, code: &str, method: usize, suite: Suite, modulus: &str) -> Value {
    if matches!(suite, Suite::ResidueDiagnostic) {
        let mut request = case.receipt_request(code, method, modulus);
        let mut args: Vec<_> = case
            .args
            .iter()
            .map(|value| json!({"type": "ByteVec", "value": value}))
            .collect();
        args.push(cases::word(&case.op.to_string()));
        request["args"] = json!(args);
        return request;
    }
    if matches!(suite, Suite::Receipt | Suite::ResidueReceipt) {
        case.receipt_request(code, method, modulus)
    } else {
        case.request_with_modulus(code, method, modulus)
    }
}

fn assess(case: &Case, response: Result<Value, transport::ProbeError>) -> Value {
    match (&case.expected, response) {
        (Expected::Returns(expected), Ok(result)) => {
            let gas = result["gasUsed"].as_u64();
            let expected_returns = json!(
                expected
                    .iter()
                    .map(|value| cases::word(value))
                    .collect::<Vec<_>>()
            );
            let passed = gas.is_some_and(|gas| gas > 0 && gas <= 5_000_000)
                && result["returns"] == expected_returns;
            json!({"name": case.name, "operation": case.op, "passed": passed,
                "outcome": "vm-success", "exactArkReturnsMatched": result["returns"] == expected_returns,
                "gasUsed": gas})
        }
        (Expected::Assertion(expected), Err(transport::ProbeError::VmAssertion(actual))) => {
            json!({"name": case.name, "operation": case.op, "passed": actual == *expected,
                "outcome": "vm-assertion", "expectedAssertionCode": expected,
                "assertionCode": actual, "rejectionGasAvailable": false})
        }
        (_, Ok(_)) => json!({"name": case.name, "operation": case.op,
            "passed": false, "outcome": "unexpected-vm-success"}),
        (_, Err(transport::ProbeError::VmAssertion(code))) => {
            json!({"name": case.name, "operation": case.op, "passed": false,
                "outcome": "unexpected-vm-assertion", "assertionCode": code})
        }
        (_, Err(transport::ProbeError::Deadline)) => {
            json!({"name": case.name, "operation": case.op,
                "passed": false, "outcome": "deadline"})
        }
        (_, Err(transport::ProbeError::VmGasExhausted)) => {
            json!({"name": case.name, "operation": case.op,
                "passed": false, "outcome": "vm-gas-exhausted"})
        }
        (_, Err(transport::ProbeError::Transport)) => {
            json!({"name": case.name, "operation": case.op,
                "passed": false, "outcome": "transport-or-response-error"})
        }
    }
}
