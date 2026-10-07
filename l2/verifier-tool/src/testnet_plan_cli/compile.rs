//! Exactly two pinned-JAR script compilations inside one offline draft bundle.
//! Fresh derived script pins qualify syntax/mock fixtures, never live review.
use super::{artifacts, io, policy::ArtifactInput};
use crate::{
    compiler,
    input::Suite,
    testnet_plan::{CompiledScript, ReviewedScriptPins, ScriptDraft},
};
use serde_json::{Value, json};
use std::{
    fs,
    path::Path,
    process::{Child, Command, ExitStatus, Stdio},
};

struct OwnedCompiler(Option<Child>);

impl OwnedCompiler {
    fn wait(&mut self) -> Result<ExitStatus, String> {
        let status = self
            .0
            .as_mut()
            .ok_or("Owned compiler is missing")?
            .wait()
            .map_err(|_| "Cannot observe owned offline compiler completion")?;
        self.0 = None;
        Ok(status)
    }
}

impl Drop for OwnedCompiler {
    fn drop(&mut self) {
        if let Some(child) = self.0.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

pub(super) fn two(
    jar: &Path,
    output: &Path,
    drafts: &[ScriptDraft; 2],
    dependencies: &[ArtifactInput; 3],
) -> Result<([CompiledScript; 2], Vec<Value>), String> {
    let (proof, proof_record) = one(
        jar,
        &output.join("proof-template"),
        &drafts[0],
        dependencies,
    )?;
    let (data, data_record) = one(jar, &output.join("data-template"), &drafts[1], dependencies)?;
    Ok(([proof, data], vec![proof_record, data_record]))
}

fn one(
    jar: &Path,
    directory: &Path,
    draft: &ScriptDraft,
    dependencies: &[ArtifactInput; 3],
) -> Result<(CompiledScript, Value), String> {
    if draft.source().is_empty()
        || draft.source().len() > 131072
        || io::sha(draft.source().as_bytes()) != draft.source_sha256()
    {
        return Err("Generated template source violates its exact bounded binding".into());
    }
    fs::create_dir(directory).map_err(|_| "Cannot create fresh template compiler context")?;
    let sources = directory.join("sources");
    let outputs = directory.join("artifacts");
    fs::create_dir(&sources).map_err(|_| "Cannot create fresh template source directory")?;
    fs::create_dir(&outputs).map_err(|_| "Cannot create fresh template artifact directory")?;
    let suite = Suite::SettlementFactoryCompile;
    for source in suite.sources() {
        if source.filename == "main.ral" || source.contract == "Main" || source.bytes.len() > 131072
        {
            return Err("Fixed dependency source conflicts with the template context".into());
        }
        io::write(&sources.join(source.filename), source.bytes)?;
    }
    io::write(&sources.join("main.ral"), draft.source().as_bytes())?;
    io::write_json(
        &directory.join("compiler-intent.json"),
        &json!({"scope": "private-offline-template-syntax",
        "kind": draft.kind(), "sourceSha256": hex::encode(draft.source_sha256()),
        "compilerJarSha256": compiler::JAR_SHA256, "networkCalls": 0, "signing": false,
        "independentLiveScriptReviewPending": true, "allDependenciesFromFixedSourceInventory": true}),
    )?;
    let stdout = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join("compiler.stdout.log"))
        .map_err(|_| "Cannot create private compiler diagnostics")?;
    let stderr = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join("compiler.stderr.log"))
        .map_err(|_| "Cannot create private compiler diagnostics")?;
    let mut command = Command::new("java");
    command
        .arg("-Dfile.encoding=UTF-8")
        .arg("-jar")
        .arg(io::jvm_path(jar)?)
        .arg("-c")
        .arg(io::jvm_path(&sources)?)
        .arg("-a")
        .arg(io::jvm_path(&outputs)?)
        .arg("-w")
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    let mut child = OwnedCompiler(Some(
        command
            .spawn()
            .map_err(|_| "Cannot start pinned offline compiler runtime")?,
    ));
    let status = child.wait()?;
    if !status.success() {
        return Err(
            "Pinned offline template compiler failed; private diagnostics preserved".into(),
        );
    }
    let artifact_bytes = io::read(&outputs.join("main.ral.json"), io::JSON_LIMIT)?;
    let artifact = io::json(&artifact_bytes)?;
    let project_bytes = io::read(&outputs.join(".project.json"), io::JSON_LIMIT)?;
    let project = io::json(&project_bytes)?;
    validate_project(project, draft)?;
    validate_main(&artifact)?;
    let template = io::text(&artifact, "bytecodeTemplate")?;
    if template.is_empty()
        || template.len() > 65536
        || template.len() % 2 != 0
        || !template
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("Template artifact is not a complete bounded canonical StatefulScript".into());
    }
    let bytes =
        hex::decode(template).map_err(|_| "Template production bytecode encoding differs")?;
    let dependency_outputs = artifacts::check_dependency_outputs(&outputs, dependencies)?;
    let pins = ReviewedScriptPins {
        artifact_sha256: io::sha(&artifact_bytes),
        source_sha256: draft.source_sha256(),
        script_sha256: io::sha(&bytes),
        compiler_jar_sha256: io::hex_bytes(compiler::JAR_SHA256)?,
    };
    let compiled = CompiledScript::from_reviewed_bytes(draft, bytes, &pins)?;
    io::write(&directory.join("script.bin"), compiled.bytes())?;
    let record = json!({"kind": draft.kind(), "batch": draft.batch(), "source": "sources/main.ral",
        "artifact": "artifacts/main.ral.json", "script": "script.bin", "sourceSha256": hex::encode(draft.source_sha256()),
        "artifactSha256": hex::encode(compiled.artifact_sha256()), "scriptSha256": hex::encode(compiled.script_sha256()),
        "scriptBlake2b256": hex::encode(compiled.script_blake2b256()), "scriptBytes": compiled.bytes().len(),
        "projectSha256": hex::encode(io::sha(&project_bytes)), "operationPolicySha256": hex::encode(draft.operation_policy_sha256()),
        "compilerJarSha256": compiler::JAR_SHA256, "compilerReportedVersion": "v4.7.0", "warningCount": 0,
        "rawArtifactAndCompleteScriptBound": true, "fixedDependencyArtifacts": dependency_outputs,
        "pinAuthority": "derived from fixed-JAR compiler output for explicitly simulated aggregate only",
        "independentLiveCompiledScriptReviewComplete": false, "liveSigningApproved": false,
        "jvmExecutableIndependentlyPinned": false});
    io::write_json(&directory.join("report.json"), &record)?;
    Ok((compiled, record))
}

fn validate_project(mut project: Value, draft: &ScriptDraft) -> Result<(), String> {
    let infos = project["infos"]
        .as_object_mut()
        .ok_or("Missing template compiler source metadata")?;
    let main = infos
        .remove("Main")
        .ok_or("Template compiler omitted Main source")?;
    if main["sourceFile"] != "main.ral"
        || main["sourceCodeHash"] != hex::encode(draft.source_sha256())
        || main["warnings"] != json!([])
    {
        return Err(
            "Template compiler source hash or warnings differ from exact generated source".into(),
        );
    }
    compiler::validate_project(&project, Suite::SettlementFactoryCompile)
}

fn validate_main(artifact: &Value) -> Result<(), String> {
    if artifact["version"] != "v4.7.0"
        || artifact["name"] != "Main"
        || artifact["fieldsSig"] != json!({"names": [], "types": [], "isMutable": []})
    {
        return Err("Compiled template identity or constructor ABI differs".into());
    }
    let functions = artifact["functions"]
        .as_array()
        .ok_or("Template compiler omitted function ABI")?;
    if functions.len() != 1 {
        return Err("Template artifact contains an unexpected function".into());
    }
    let main = &functions[0];
    if main["name"] != "main"
        || main["isPublic"] != true
        || main["usePreapprovedAssets"] != true
        || main["useAssetsInContract"] != false
        || main["paramNames"] != json!([])
        || main["paramTypes"] != json!([])
        || main["paramIsMutable"] != json!([])
        || main["returnTypes"] != json!([])
    {
        return Err(
            "Template entry ABI or asset authority differs from its generated deployment script"
                .into(),
        );
    }
    Ok(())
}
