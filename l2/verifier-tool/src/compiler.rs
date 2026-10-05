//! Offline compiler invocation in an exclusively owned, new evidence directory.
use crate::{cases::FP_MODULUS, compiler_schema, input::Suite};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

pub const JAR_SHA256: &str = "a8b221ee71b36a1a960da17b0eb32a490ebf8c4a034414a46d0ed57957e832ac";
const COMPILER_VERSION: &str = "v4.7.0";
const MAX_ARTIFACT_BYTES: usize = 1_048_576;

pub struct Compiled {
    pub bytecode: String,
    pub method_index: usize,
    pub public_methods: std::collections::BTreeMap<String, usize>,
    pub evidence: Value,
}

pub fn compile(
    jar: &Path,
    evidence: &Path,
    deadline: Instant,
    suite: Suite,
) -> Result<Compiled, String> {
    let jar = jar
        .canonicalize()
        .map_err(|_| "Compiler JAR is unavailable")?;
    let jar_bytes = read_bounded(&jar, 512 * 1024 * 1024)?;
    if sha256(&jar_bytes) != JAR_SHA256 {
        return Err("Compiler JAR SHA-256 differs from the pinned official compiler".into());
    }
    let source_dir = evidence.join("sources");
    let artifact_dir = evidence.join("artifacts");
    fs::create_dir(&source_dir).map_err(|_| "Cannot create fresh compiler input directory")?;
    fs::create_dir(&artifact_dir).map_err(|_| "Cannot create fresh compiler artifact directory")?;
    let mut source_records = Vec::new();
    for source in suite.sources() {
        let (name, origin, bytes) = (source.filename, source.origin, source.bytes);
        if bytes.len() > 131_072 {
            return Err("Ralph source exceeds the bounded field slice".into());
        }
        fs::write(source_dir.join(name), bytes).map_err(|_| "Cannot snapshot Ralph source")?;
        source_records.push(json!({"path": origin, "sha256": sha256(bytes), "bytes": bytes.len()}));
    }
    let mut command = Command::new("java");
    command
        .arg("-Dfile.encoding=UTF-8")
        .args(["-jar"])
        .arg(jvm_path(&jar)?)
        .arg("-c")
        .arg(jvm_path(&source_dir)?)
        .arg("-a")
        .arg(jvm_path(&artifact_dir)?)
        .arg("-w")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    if Instant::now() >= deadline {
        return Err("Field harness deadline expired before compilation".into());
    }
    let mut child = command
        .spawn()
        .map_err(|_| "Cannot start existing Java compiler runtime")?;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("Field harness deadline expired during offline compilation".into());
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("Cannot observe owned compiler process completion".into());
            }
        }
    };
    if !status.success() {
        return Err(format!(
            "Pinned offline compiler failed with exit code {:?}; output suppressed",
            status.code()
        ));
    }
    let artifact_path = artifact_dir.join(suite.artifact());
    let artifact_bytes = read_bounded(&artifact_path, MAX_ARTIFACT_BYTES)?;
    let artifact: Value = serde_json::from_slice(&artifact_bytes)
        .map_err(|_| "Offline compiler artifact is not JSON")?;
    let project_bytes = read_bounded(&artifact_dir.join(".project.json"), MAX_ARTIFACT_BYTES)?;
    let project: Value = serde_json::from_slice(&project_bytes)
        .map_err(|_| "Offline compiler project metadata is not JSON")?;
    validate_project(&project, suite)?;
    if artifact["version"] != COMPILER_VERSION || artifact["name"] != suite.probe() {
        return Err(
            "Offline compiler artifact identity differs from the pinned field probe".into(),
        );
    }
    let public_methods = compiler_schema::validate(&artifact, suite)?;
    let bytecode = artifact["bytecode"]
        .as_str()
        .ok_or("Missing production bytecode")?;
    let executable =
        hex::decode(bytecode).map_err(|_| "Production bytecode is not canonical hex")?;
    if executable.is_empty() || executable.len() > 32_768 {
        return Err("Production field executable violates the reviewed code-size bound".into());
    }
    let code_hash = artifact["codeHash"]
        .as_str()
        .ok_or("Missing production compiler code hash")?;
    if hex::decode(code_hash)
        .map_err(|_| "Compiler code hash is not hex")?
        .len()
        != 32
    {
        return Err("Compiler code hash has an unexpected length".into());
    }
    let method_index = *public_methods
        .get(suite.entry())
        .ok_or("Missing selected entry index")?;
    Ok(Compiled {
        bytecode: bytecode.into(),
        method_index,
        public_methods: public_methods.clone(),
        evidence: json!({
            "jarSha256": JAR_SHA256, "compilerReportedVersion": COMPILER_VERSION,
            "invocation": "java -Dfile.encoding=UTF-8 -jar <pinned-jar> -c sources -a artifacts -w",
            "sources": source_records, "artifact": format!("artifacts/{}", suite.artifact()),
            "artifactSha256": sha256(&artifact_bytes), "productionCodeHash": code_hash,
            "project": "artifacts/.project.json", "projectSha256": sha256(&project_bytes),
            "projectSourceHashesMatched": true, "compilerOptionsUsed": project["compilerOptionsUsed"],
            "executableSha256": sha256(&executable), "executableBytes": executable.len(),
            "immutableFieldCount": if matches!(suite, Suite::StagedFactory | Suite::StagedFactoryFlow) {3} else {1},
            "mutableFieldCount": if matches!(suite, Suite::StagedReceipt) {81} else {0},
            "estimatedVmFieldBytes": if matches!(suite, Suite::StagedReceipt) {2624} else if matches!(suite, Suite::StagedFactory | Suite::StagedFactoryFlow) {96} else {32},
            "fieldsSignature": artifact["fieldsSig"], "publicMethodIndices": public_methods,
            "serializedFieldBytesIndependentlyMeasured": false,
            "expectedFpModulus": FP_MODULUS, "loadedContracts": 1, "methodIndex": method_index,
            "warningCount": 0, "productionBytecodeUsed": true,
            "externalJvmDependency": true, "jvmExecutableIndependentlyPinned": false
        }),
    })
}

fn validate_project(project: &Value, suite: Suite) -> Result<(), String> {
    if project["compilerOptionsUsed"]
        != json!({
            "ignoreUnusedConstantsWarnings": false, "ignoreUnusedVariablesWarnings": false,
            "ignoreUnusedFieldsWarnings": false, "ignoreUnusedPrivateFunctionsWarnings": false,
            "ignoreUpdateFieldsCheckWarnings": false, "ignoreCheckExternalCallerWarnings": false,
            "ignoreUnusedFunctionReturnWarnings": false,
            "skipAbstractContractCheck": false, "skipTests": false
        })
    {
        return Err(
            "Offline compiler options omit or suppress required checks and warnings".into(),
        );
    }
    let infos = project["infos"]
        .as_object()
        .ok_or("Missing compiler source metadata")?;
    if infos.len() != suite.sources().len() {
        return Err("Offline compiler source closure differs from the fixed field slice".into());
    }
    for source in suite.sources() {
        let info = &project["infos"][source.contract];
        if info["sourceFile"] != source.filename
            || info["sourceCodeHash"] != sha256(source.bytes)
            || info["warnings"] != json!([])
        {
            return Err(format!(
                "Offline compiler source identity or warnings differ for {}",
                source.contract
            ));
        }
    }
    Ok(())
}

// Rust keeps canonical paths for filesystem verification. Java receives ordinary
// drive/UNC syntax because the external JVM does not accept Windows \\?\ prefixes.
// The external compiler boundary requires UTF-8 path text on every platform.
fn jvm_path(path: &Path) -> Result<String, String> {
    let text = path
        .to_str()
        .ok_or("External JVM compiler paths must be valid UTF-8")?;
    #[cfg(windows)]
    {
        if let Some(unc) = text.strip_prefix(r"\\?\UNC\") {
            return Ok(format!(r"\\{unc}"));
        }
        if let Some(drive) = text.strip_prefix(r"\\?\") {
            let bytes = drive.as_bytes();
            if bytes.len() >= 3
                && bytes[0].is_ascii_alphabetic()
                && bytes[1] == b':'
                && bytes[2] == b'\\'
            {
                return Ok(drive.into());
            }
            return Err("Unsupported Windows extended compiler path".into());
        }
    }
    Ok(text.into())
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let file = fs::File::open(path)
        .map_err(|_| "Required bounded compiler input/artifact is unavailable")?;
    if file
        .metadata()
        .map_err(|_| "Cannot inspect compiler input/artifact")?
        .len()
        > limit as u64
    {
        return Err("Compiler input/artifact exceeds its byte bound".into());
    }
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Cannot read bounded compiler input/artifact")?;
    if bytes.len() > limit {
        return Err("Compiler input/artifact exceeds its byte bound".into());
    }
    Ok(bytes)
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
