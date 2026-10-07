//! Load preserved independent pins; reconcile field metadata from exact raw ABI.
use super::{
    io,
    policy::{ArtifactInput, Inputs},
};
use crate::{
    compiler::{self, Compiled},
    compiler_schema,
    input::Suite,
    testnet_plan::{ArtifactPins, FrozenArtifacts, freeze_artifacts, source_closure_fingerprint},
};
use serde_json::{Value, json};
use std::path::Path;

pub(super) const SUITES: [Suite; 3] = [
    Suite::StagedReceipt,
    Suite::SettlementData,
    Suite::SettlementFactoryCompile,
];
const EVIDENCE_KEYS: [&str; 3] = ["childCompiler", "dataCompiler", "compiler"];

pub(super) fn load(inputs: &Inputs) -> Result<(FrozenArtifacts, Vec<Value>), String> {
    let mut compiled = Vec::new();
    let mut records = Vec::new();
    for index in 0..3 {
        let (artifact, record) = load_one(
            &inputs.artifacts[index],
            SUITES[index],
            EVIDENCE_KEYS[index],
        )?;
        compiled.push(artifact);
        records.push(record);
    }
    let pins = std::array::from_fn(|index| {
        let pin = &inputs.artifacts[index].pins;
        ArtifactPins {
            artifact_sha256: pin.artifact_sha256,
            executable_sha256: pin.executable_sha256,
            code_hash: pin.code_hash,
            source_closure_sha256: pin.source_closure_sha256,
        }
    });
    let frozen = freeze_artifacts(&compiled[0], &compiled[1], &compiled[2], &pins)?;
    Ok((frozen, records))
}

fn load_one(
    input: &ArtifactInput,
    suite: Suite,
    evidence_key: &str,
) -> Result<(Compiled, Value), String> {
    if input.artifact.file_name().and_then(|name| name.to_str()) != Some(suite.artifact()) {
        return Err("Selected artifact filename differs from the fixed source inventory".into());
    }
    let raw = io::read(&input.artifact, io::JSON_LIMIT)?;
    let artifact = io::json(&raw)?;
    if io::sha(&raw) != input.pins.artifact_sha256
        || artifact["version"] != "v4.7.0"
        || artifact["name"] != suite.probe()
    {
        return Err("Preserved raw artifact identity differs from independent pins".into());
    }
    let project_path = input
        .artifact
        .parent()
        .ok_or("Artifact directory is missing")?
        .join(".project.json");
    let project_bytes = io::read(&project_path, io::JSON_LIMIT)?;
    let project = io::json(&project_bytes)?;
    compiler::validate_project(&project, suite)?;
    let public_methods = compiler_schema::validate(&artifact, suite)?;
    let bytecode = io::text(&artifact, "bytecode")?;
    if bytecode.is_empty()
        || bytecode.len() > 65536
        || bytecode.len() % 2 != 0
        || !bytecode
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("Preserved production bytecode is not bounded canonical hex".into());
    }
    let executable = hex::decode(bytecode).map_err(|_| "Preserved executable encoding differs")?;
    if io::sha(&executable) != input.pins.executable_sha256
        || io::hash(&artifact, "codeHash")? != input.pins.code_hash
        || source_closure_fingerprint(suite)? != input.pins.source_closure_sha256
    {
        return Err(
            "Preserved code or current source closure differs from independent pins".into(),
        );
    }
    let report = io::pinned_json(&input.evidence, input.evidence_sha256)?;
    let mut evidence = report
        .get(evidence_key)
        .filter(|item| item.is_object())
        .ok_or("Selected preserved compiler evidence is missing")?
        .clone();
    let expected_sources: Vec<Value> = suite
        .sources()
        .iter()
        .map(|source| {
            json!({"path": source.origin,
        "sha256": hex::encode(io::sha(source.bytes)), "bytes": source.bytes.len()})
        })
        .collect();
    let method_index = *public_methods
        .get(suite.entry())
        .ok_or("Selected artifact entry is missing")?;
    if evidence["compilerReportedVersion"] != "v4.7.0"
        || evidence["jarSha256"] != compiler::JAR_SHA256
        || evidence["artifact"] != format!("artifacts/{}", suite.artifact())
        || io::hash(&evidence, "artifactSha256")? != io::sha(&raw)
        || io::hash(&evidence, "executableSha256")? != io::sha(&executable)
        || io::hash(&evidence, "productionCodeHash")? != input.pins.code_hash
        || io::hash(&evidence, "projectSha256")? != io::sha(&project_bytes)
        || evidence["sources"] != json!(expected_sources)
        || evidence["executableBytes"].as_u64() != Some(executable.len() as u64)
        || evidence["publicMethodIndices"] != json!(public_methods)
        || evidence["methodIndex"].as_u64() != Some(method_index as u64)
        || evidence["compilerOptionsUsed"] != project["compilerOptionsUsed"]
    {
        return Err(
            "Preserved compiler byte, source or project evidence differs from raw artifacts".into(),
        );
    }
    let original = json!({"immutableFieldCount": evidence["immutableFieldCount"],
        "mutableFieldCount": evidence["mutableFieldCount"], "fieldsSignature": evidence["fieldsSignature"]});
    let (immutable, mutable) = compiler::field_counts(&artifact)?;
    let derived = json!({"immutableFieldCount": immutable, "mutableFieldCount": mutable,
        "fieldsSignature": artifact["fieldsSig"]});
    evidence["immutableFieldCount"] = json!(immutable);
    evidence["mutableFieldCount"] = json!(mutable);
    evidence["fieldsSignature"] = artifact["fieldsSig"].clone();
    let record = json!({"class": suite.probe(), "artifactSha256": hex::encode(input.pins.artifact_sha256),
        "executableSha256": hex::encode(input.pins.executable_sha256), "codeHash": hex::encode(input.pins.code_hash),
        "sourceClosureSha256": hex::encode(input.pins.source_closure_sha256), "preservedEvidenceSha256": hex::encode(input.evidence_sha256),
        "rawArtifactAndProjectPinsMatched": true, "rawAbiValidated": true,
        "fieldMetadataReconciliation": {"preserved": original, "rawDerived": derived,
            "changedInMemory": original != derived, "originalEvidenceOverwritten": false}});
    Ok((
        Compiled {
            bytecode: bytecode.into(),
            method_index,
            public_methods,
            evidence,
        },
        record,
    ))
}

pub(super) fn check_dependency_outputs(
    directory: &Path,
    inputs: &[ArtifactInput; 3],
) -> Result<Value, String> {
    let mut records = Vec::new();
    for (suite, input) in SUITES.iter().zip(inputs) {
        let bytes = io::read(&directory.join(suite.artifact()), io::JSON_LIMIT)?;
        if io::sha(&bytes) != input.pins.artifact_sha256 {
            return Err(
                "New script context dependency artifact differs from its preserved independent pin"
                    .into(),
            );
        }
        records.push(json!({"class": suite.probe(), "rawArtifactSha256": hex::encode(io::sha(&bytes)), "preservedPinMatched": true}));
    }
    Ok(json!(records))
}
