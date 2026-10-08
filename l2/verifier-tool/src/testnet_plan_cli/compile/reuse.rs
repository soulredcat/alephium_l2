//! Revalidate selected private compiler contexts, never old funding or approval.
use super::{ArtifactInput, artifacts, io, validate_main, validate_project};
use crate::{
    compiler,
    input::Suite,
    testnet_plan::{CompiledScript, ReviewedScriptPins, ScriptDraft},
};
use serde_json::{Value, json};
use std::{fs, path::Path};

pub(in crate::testnet_plan_cli) fn two_reused(
    prior: &Path,
    output: &Path,
    drafts: &[ScriptDraft; 2],
    dependencies: &[ArtifactInput; 3],
) -> Result<([CompiledScript; 2], Vec<Value>), String> {
    let (proof, proof_record) = one(
        &prior.join("proof-template"),
        &output.join("proof-template"),
        &drafts[0],
        dependencies,
    )?;
    let (data, data_record) = one(
        &prior.join("data-template"),
        &output.join("data-template"),
        &drafts[1],
        dependencies,
    )?;
    Ok(([proof, data], vec![proof_record, data_record]))
}

fn one(
    prior: &Path,
    output: &Path,
    draft: &ScriptDraft,
    dependencies: &[ArtifactInput; 3],
) -> Result<(CompiledScript, Value), String> {
    let source = io::read(&prior.join("sources/main.ral"), 131072)?;
    if source != draft.source().as_bytes() || io::sha(&source) != draft.source_sha256() {
        return Err(
            "Prior actual-caller template source differs from the exact current draft".into(),
        );
    }
    let artifact_bytes = io::read(&prior.join("artifacts/main.ral.json"), io::JSON_LIMIT)?;
    let artifact = io::json(&artifact_bytes)?;
    validate_main(&artifact)?;
    let script_bytes = io::read(&prior.join("script.bin"), 32768)?;
    if script_bytes.is_empty()
        || io::text(&artifact, "bytecodeTemplate")? != hex::encode(&script_bytes)
    {
        return Err(
            "Prior production Main artifact does not encode the complete exact script bytes".into(),
        );
    }
    let project_bytes = io::read(&prior.join("artifacts/.project.json"), io::JSON_LIMIT)?;
    validate_project(io::json(&project_bytes)?, draft)?;
    let dependency_records =
        artifacts::check_dependency_outputs(&prior.join("artifacts"), dependencies)?;
    let report_bytes = io::read(&prior.join("report.json"), io::JSON_LIMIT)?;
    let report = io::json(&report_bytes)?;
    io::object(
        &report,
        &[
            "kind",
            "batch",
            "source",
            "artifact",
            "script",
            "sourceSha256",
            "artifactSha256",
            "scriptSha256",
            "scriptBlake2b256",
            "scriptBytes",
            "projectSha256",
            "operationPolicySha256",
            "compilerJarSha256",
            "compilerReportedVersion",
            "warningCount",
            "rawArtifactAndCompleteScriptBound",
            "fixedDependencyArtifacts",
            "pinAuthority",
            "independentLiveCompiledScriptReviewComplete",
            "liveSigningApproved",
            "jvmExecutableIndependentlyPinned",
        ],
    )?;
    if report["kind"] != draft.kind()
        || report["batch"] != json!(draft.batch())
        || report["source"] != "sources/main.ral"
        || report["artifact"] != "artifacts/main.ral.json"
        || report["script"] != "script.bin"
        || io::hash(&report, "sourceSha256")? != draft.source_sha256()
        || io::hash(&report, "artifactSha256")? != io::sha(&artifact_bytes)
        || io::hash(&report, "scriptSha256")? != io::sha(&script_bytes)
        || io::hash(&report, "projectSha256")? != io::sha(&project_bytes)
        || io::hash(&report, "operationPolicySha256")? != draft.operation_policy_sha256()
        || report["compilerJarSha256"] != compiler::JAR_SHA256
        || report["compilerReportedVersion"] != "v4.7.0"
        || report["warningCount"] != 0
        || report["rawArtifactAndCompleteScriptBound"] != true
        || report["fixedDependencyArtifacts"] != dependency_records
        || report["pinAuthority"]
            != "fixed-JAR syntax-qualified actual-caller draft; independent live compiled-script review pending"
        || report["independentLiveCompiledScriptReviewComplete"] != false
        || report["liveSigningApproved"] != false
        || report["jvmExecutableIndependentlyPinned"] != false
        || report["scriptBytes"].as_u64() != Some(script_bytes.len() as u64)
    {
        return Err("Prior actual-caller compiler report differs from current raw source/artifact/project/script bindings".into());
    }
    let pins = ReviewedScriptPins {
        artifact_sha256: io::sha(&artifact_bytes),
        source_sha256: draft.source_sha256(),
        script_sha256: io::sha(&script_bytes),
        compiler_jar_sha256: io::hex_bytes(compiler::JAR_SHA256)?,
    };
    let compiled = CompiledScript::from_reviewed_bytes(draft, script_bytes, &pins)?;
    if io::hash(&report, "scriptBlake2b256")? != compiled.script_blake2b256() {
        return Err("Prior native script digest differs from revalidated complete bytes".into());
    }
    let intent_bytes = io::read(&prior.join("compiler-intent.json"), io::JSON_LIMIT)?;
    let intent = io::json(&intent_bytes)?;
    io::object(
        &intent,
        &[
            "scope",
            "kind",
            "sourceSha256",
            "compilerJarSha256",
            "networkCalls",
            "signing",
            "independentLiveScriptReviewPending",
            "allDependenciesFromFixedSourceInventory",
        ],
    )?;
    if intent["scope"] != "private-actual-caller-template-syntax"
        || intent["kind"] != draft.kind()
        || io::hash(&intent, "sourceSha256")? != draft.source_sha256()
        || intent["compilerJarSha256"] != compiler::JAR_SHA256
        || intent["networkCalls"] != 0
        || intent["signing"] != false
        || intent["independentLiveScriptReviewPending"] != true
        || intent["allDependenciesFromFixedSourceInventory"] != true
    {
        return Err(
            "Prior actual-caller compiler intent differs from its exact syntax scope".into(),
        );
    }
    let mut sources = Vec::new();
    for dependency in Suite::SettlementFactoryCompile.sources() {
        let bytes = io::read(&prior.join("sources").join(dependency.filename), 131072)?;
        if bytes != dependency.bytes {
            return Err(
                "Prior compiler dependency source differs from current source closure".into(),
            );
        }
        sources.push((dependency.filename, bytes));
    }
    let mut raw_dependencies = Vec::new();
    for (suite, dependency) in artifacts::SUITES.iter().zip(dependencies) {
        let bytes = io::read(
            &prior.join("artifacts").join(suite.artifact()),
            io::JSON_LIMIT,
        )?;
        if io::sha(&bytes) != dependency.pins.artifact_sha256 {
            return Err(
                "Reused dependency bytes changed before copying their validated pin".into(),
            );
        }
        raw_dependencies.push((suite.artifact(), bytes));
    }
    fs::create_dir(output).map_err(|_| "Cannot create new reused template context")?;
    let source_dir = output.join("sources");
    let artifact_dir = output.join("artifacts");
    fs::create_dir(&source_dir).map_err(|_| "Cannot create new reused source directory")?;
    fs::create_dir(&artifact_dir).map_err(|_| "Cannot create new reused artifact directory")?;
    for (name, bytes) in sources {
        io::write(&source_dir.join(name), &bytes)?;
    }
    for (name, bytes) in raw_dependencies {
        io::write(&artifact_dir.join(name), &bytes)?;
    }
    io::write(&source_dir.join("main.ral"), &source)?;
    io::write(&artifact_dir.join("main.ral.json"), &artifact_bytes)?;
    io::write(&artifact_dir.join(".project.json"), &project_bytes)?;
    io::write(&output.join("script.bin"), compiled.bytes())?;
    io::write(&output.join("report.json"), &report_bytes)?;
    io::write(&output.join("compiler-intent.json"), &intent_bytes)?;
    let record = json!({"kind": draft.kind(), "sourceSha256": hex::encode(draft.source_sha256()),
        "scriptSha256": hex::encode(compiled.script_sha256()), "scriptBlake2b256": hex::encode(compiled.script_blake2b256()),
        "artifactSha256": hex::encode(compiled.artifact_sha256()), "projectSha256": hex::encode(io::sha(&project_bytes)),
        "priorCompilerReportSha256": hex::encode(io::sha(&report_bytes)), "priorCompilerIntentSha256": hex::encode(io::sha(&intent_bytes)),
        "currentOperationPolicySha256": hex::encode(draft.operation_policy_sha256()),
        "compilerJarSha256": compiler::JAR_SHA256, "compilerReportedVersion": "v4.7.0", "warningCount": 0,
        "rawSourceArtifactScriptProjectAndDependencyBindingsRechecked": true, "newCompilerExecutions": 0,
        "reusedActualCallerTemplate": true, "newCompilerQualificationClaimed": false,
        "sourceToBytecodeBuildLineageCryptographicallyAttested": false,
        "priorContextTrust": "caller-selected preserved local compiler outputs; hashes reconcile bytes but do not prove build lineage",
        "oldFundingObservationsOrApprovalsReused": false, "independentLiveCompiledScriptReviewComplete": false,
        "liveSigningApproved": false});
    io::write_json(&output.join("reuse-report.json"), &record)?;
    Ok((compiled, record))
}
