//! Offline source-only draft packaging. This mode never freezes a signable plan.
mod artifacts;
mod compile;
mod io;
mod policy;

use crate::testnet_plan::{prepare_templates, prerequisites, pure_aggregate};
use serde_json::{Value, json};
use std::path::Path;

/// Root registers this before the legacy CLI. No global run-time deadline is
/// introduced; the coordinator owns this single bundle and its process job.
pub(crate) fn run(
    jar: &Path,
    output: &Path,
    publisher_public_key: &str,
    independent_l1_genesis: &str,
    policy_json: &Path,
) -> Result<Value, String> {
    let inputs = policy::load(policy_json, publisher_public_key, independent_l1_genesis)?;
    let jar = io::check_jar(jar)?;
    let (frozen, artifact_records) = artifacts::load(&inputs)?;
    let drafts = prepare_templates(
        &frozen,
        &inputs.policy,
        &inputs.actor,
        inputs.limits.clone(),
    )?;
    let output = io::fresh_output(output)?;
    io::write_json(
        &output.join("draft-intent.json"),
        &json!({"schema": 1,
        "scope": "offline-source-only-testnet-plan-draft", "policySha256": hex::encode(inputs.policy_sha256),
        "deploymentVectorSha256": hex::encode(inputs.vector_sha256), "compilerJarSha256": crate::compiler::JAR_SHA256,
        "compilationContexts": 2, "aggregateExecutions": 1, "genuineReceiptClaims": false,
        "funding": "simulated SDK fixture only", "actualPublisherIdentityConfirmed": false,
        "signaturesCreated": false, "networkCalls": 0, "vmCalls": 0,
        "staticPlanFinalized": false, "signable": false, "publicTestnetAccepted": false}),
    )?;
    let result = (|| {
        let (compiled, script_records) = compile::two(&jar, &output, &drafts, &inputs.artifacts)?;
        let aggregate = pure_aggregate(
            &frozen,
            &inputs.policy,
            &inputs.actor,
            &compiled,
            &inputs.vector,
        )?;
        io::write_json(&output.join("pure-aggregate.json"), &aggregate)?;
        let pending = prerequisites(Some(&inputs.actor), Some(&inputs.policy), None, None, 2);
        if aggregate["passed"] != true
            || pending["signable"] != false
            || pending["staticPlanFinalized"] != false
        {
            return Err("Offline draft scope or prerequisite invariant differs".into());
        }
        let report = json!({"schema": 1, "scope": "offline-source-only-testnet-plan-draft", "passed": true,
            "qualification": "two pinned-JAR syntax templates plus one explicit simulated-funding planner aggregate",
            "policySha256": hex::encode(inputs.policy_sha256), "deploymentVectorSha256": hex::encode(inputs.vector_sha256),
            "actorPublicKeySha256": hex::encode(io::sha(&inputs.actor.public_key)),
            "suppliedLimits": policy::limits_report(&inputs), "preservedArtifacts": artifact_records,
            "compiledTemplates": script_records, "pureAggregate": aggregate,
            "pureFixtureBudget": {"gasAmountMax": 5000000, "gasPriceAtto": "100000000000",
                "feeMaxAtto": "10000000000000000", "deposit": "policy minimum", "funding": "explicitly simulated",
                "requestBytesMax": 1048576, "responseBytesMax": 1048576, "connectTimeoutMs": 10000, "requestTimeoutMs": 10000},
            "prerequisites": pending, "sourceOnlyPrerequisiteReport": true,
            "independentLiveCompiledScriptReviewComplete": false, "actualFundingEstablished": false,
            "genuineReceiptClaims": false, "actualPublisherIdentityConfirmed": false,
            "finalFrozenPlanEmitted": false, "predictedDeploymentIdsEmitted": false,
            "networkCalls": 0, "vmCalls": 0, "signaturesCreated": false,
            "staticPlanFinalized": false, "signable": false, "publicTestnetAccepted": false, "p5Complete": false});
        io::write_json(&output.join("report.json"), &report)?;
        // Console result excludes private source, paths, policy and artifact IDs.
        Ok(
            json!({"scope": "offline-source-only-testnet-plan-draft", "passed": true,
            "compiledTemplates": 2, "aggregateChecks": report["pureAggregate"]["checks"],
            "independentLiveScriptReviewPending": true, "actualFundingEstablished": false,
            "genuineReceiptClaims": false, "networkCalls": 0, "vmCalls": 0,
            "staticPlanFinalized": false, "signable": false, "publicTestnetAccepted": false, "p5Complete": false}),
        )
    })();
    if let Err(error) = &result {
        // Compiler contexts and diagnostics remain intact. The RAII compiler
        // guard joins its owned Java child before errors reach this boundary.
        let failure = json!({"schema": 1, "scope": "offline-source-only-testnet-plan-draft", "passed": false,
            "error": error, "partialPrivateOutputsPreserved": true, "staticPlanFinalized": false,
            "signable": false, "networkCalls": 0, "vmCalls": 0, "signaturesCreated": false, "p5Complete": false});
        let _ = io::write_json(&output.join("failure.json"), &failure);
    }
    result
}
