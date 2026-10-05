//! Rebuild the unchanged vendored Solidity compatibility oracle with an existing compiler.
//! No download, installation, signing, node connection or proof generation occurs here.
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

const COMPILER_SHA256: &str = "ccbd3ed44d5fbd26fe039702d403421f1212d2e8752e3cbe3bfd074986911586";
const COMPILER_VERSION: &str = "0.8.30+commit.73712a01.Windows.msvc";
const SOURCES_SHA256: &str = "fd08bbba8c93b169275199bc6b002635ceff2038bbf72bd9f568b52290cf6c90";
const CONTRACT_PATH: &str = "contracts/src/groth16/RiscZeroGroth16Verifier.sol";
const CONTRACT_NAME: &str = "RiscZeroGroth16Verifier";

fn main() -> Result<(), String> {
    let compiler_arg = std::env::args_os()
        .nth(1)
        .ok_or("provide the existing pinned solc path")?;
    let compiler = Path::new(&compiler_arg)
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let compiler_hash = sha(&read(&compiler)?);
    if compiler_hash != COMPILER_SHA256 {
        return Err("compiler SHA-256 does not match the reviewed local rebuild".into());
    }
    let version = Command::new(&compiler)
        .arg("--version")
        .output()
        .map_err(|e| e.to_string())?;
    if !version.status.success()
        || !String::from_utf8_lossy(&version.stdout).contains(COMPILER_VERSION)
    {
        return Err("compiler version mismatch".into());
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/risc0-groth16");
    let manifest_bytes = read(&root.join("sources.json"))?;
    if sha(&manifest_bytes) != SOURCES_SHA256 {
        return Err("pinned source inventory changed".into());
    }
    let manifest: Value = serde_json::from_slice(&manifest_bytes).map_err(|e| e.to_string())?;
    let records = manifest["files"]
        .as_array()
        .ok_or("missing source inventory")?;
    let mut sources = Map::new();
    for record in records {
        let path = text(record, "path")?;
        let bytes = read(&root.join(path))?;
        if sha(&bytes) != text(record, "sha256")?
            || bytes.len() as u64 != record["bytes"].as_u64().ok_or("missing source length")?
        {
            return Err(format!("source integrity mismatch: {path}"));
        }
        if record["compile"] == true {
            let key = text(record, "source_key")?;
            let content = String::from_utf8(bytes).map_err(|_| "non-UTF8 source")?;
            sources.insert(key.into(), json!({"content": content}));
        }
    }
    if sources.len() != 8 {
        return Err("unexpected compiler source closure".into());
    }
    let input = json!({
        "language": "Solidity", "sources": sources,
        "settings": {
            "optimizer": {"enabled": true, "runs": 10000}, "viaIR": true,
            "evmVersion": "cancun", "metadata": {"bytecodeHash": "none"},
            "outputSelection": {CONTRACT_PATH: {CONTRACT_NAME: [
                "abi", "evm.bytecode.object", "evm.bytecode.linkReferences",
                "evm.deployedBytecode.object", "evm.deployedBytecode.immutableReferences",
                "evm.methodIdentifiers"
            ]}}
        }
    });
    let input_bytes = serde_json::to_vec_pretty(&input).map_err(|e| e.to_string())?;
    let mut child = Command::new(&compiler)
        .arg("--standard-json")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    child
        .stdin
        .take()
        .ok_or("missing compiler input")?
        .write_all(&input_bytes)
        .map_err(|e| e.to_string())?;
    let output = child.wait_with_output().map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err("compiler process failed; payload suppressed".into());
    }
    let result: Value =
        serde_json::from_slice(&output.stdout).map_err(|_| "invalid compiler JSON")?;
    let errors = result["errors"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|e| e["severity"] == "error")
        .count();
    if errors != 0 {
        return Err(format!(
            "compiler reported {errors} errors; payload suppressed"
        ));
    }
    let contract = &result["contracts"][CONTRACT_PATH][CONTRACT_NAME];
    let creation = contract["evm"]["bytecode"]["object"]
        .as_str()
        .ok_or("missing creation code")?;
    let runtime = contract["evm"]["deployedBytecode"]["object"]
        .as_str()
        .ok_or("missing runtime code")?;
    let creation_bytes = hex::decode(creation).map_err(|_| "invalid or unlinked creation code")?;
    let runtime_bytes = hex::decode(runtime).map_err(|_| "invalid or unlinked runtime code")?;
    if creation_bytes.is_empty()
        || runtime_bytes.is_empty()
        || contract["evm"]["bytecode"]["linkReferences"] != json!({})
    {
        return Err("oracle artifact is empty or needs external linking".into());
    }
    if contract["evm"]["methodIdentifiers"]["verify(bytes,bytes32,bytes32)"] != "ab750e75" {
        return Err("canonical verification selector mismatch".into());
    }
    let receipt = fs::read_to_string(root.join("vendor/contracts/test/TestReceiptV3_0.sol"))
        .map_err(|e| e.to_string())?;
    let controls = fs::read_to_string(root.join("vendor/contracts/src/groth16/ControlID.sol"))
        .map_err(|e| e.to_string())?;
    let seal = constant_hex(&receipt, "SEAL")?;
    let image = constant_hex(&receipt, "IMAGE_ID")?;
    let journal = constant_hex(&receipt, "JOURNAL")?;
    let control_root = constant_hex(&controls, "CONTROL_ROOT")?;
    let control_id = constant_hex(&controls, "BN254_CONTROL_ID")?;
    let seal_bytes = hex::decode(&seal).map_err(|_| "invalid fixture seal")?;
    let journal_bytes = hex::decode(&journal).map_err(|_| "invalid fixture journal")?;
    if seal_bytes.len() != 260 || journal_bytes.len() != 21 || !seal.starts_with("73c457ba") {
        return Err("official fixture identity changed".into());
    }
    let artifact = json!({
        "schema": 1, "scope": "historical-cancun-evm-compatibility-oracle-only",
        "creation_bytecode": creation, "runtime_template": runtime,
        "abi": contract["abi"], "immutable_references": contract["evm"]["deployedBytecode"]["immutableReferences"],
        "compiler": {"version": COMPILER_VERSION, "sha256": compiler_hash,
            "local_rebuild": true, "upstream_foundry_compiler": "0.8.26", "settings": input["settings"]},
        "fixture": {"seal": seal, "image_id": image, "journal": journal,
            "journal_digest": sha(&journal_bytes), "control_root": control_root, "bn254_control_id": control_id}
    });
    let artifact_bytes = serde_json::to_vec_pretty(&artifact).map_err(|e| e.to_string())?;
    let record = json!({
        "schema": 1, "source_manifest_sha256": sha(&manifest_bytes),
        "compiler": artifact["compiler"], "input_sha256": sha(&input_bytes),
        "output_sha256": sha(&output.stdout), "artifact_sha256": sha(&artifact_bytes),
        "creation_bytes": creation_bytes.len(), "runtime_template_bytes": runtime_bytes.len(),
        "warning_count": result["errors"].as_array().into_iter().flatten().filter(|e| e["severity"] == "warning").count(),
        "exact_upstream_published_binary_claim": false, "alephium_feasibility_claim": false
    });
    fs::write(root.join("compiler-input.json"), input_bytes).map_err(|e| e.to_string())?;
    fs::write(root.join("compiler-output.json"), output.stdout).map_err(|e| e.to_string())?;
    fs::write(root.join("artifact.json"), artifact_bytes).map_err(|e| e.to_string())?;
    fs::write(
        root.join("compilation.json"),
        serde_json::to_vec_pretty(&record).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    println!(
        "RISC0_BUILD {}",
        json!({"creation_bytes": creation_bytes.len(), "runtime_template_bytes": runtime_bytes.len(), "compiler": COMPILER_VERSION, "artifact_sha256": record["artifact_sha256"]})
    );
    Ok(())
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|e| e.to_string())
}

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str, String> {
    value[field]
        .as_str()
        .ok_or_else(|| format!("missing inventory {field}"))
}

fn constant_hex(source: &str, symbol: &str) -> Result<String, String> {
    let marker = format!("constant {symbol} =");
    let value = source
        .split_once(&marker)
        .ok_or("missing upstream fixture constant")?
        .1;
    let value = value.split_once("hex\"").ok_or("missing fixture hex")?.1;
    let value = value.split_once('"').ok_or("unterminated fixture hex")?.0;
    hex::decode(value).map_err(|_| "invalid upstream fixture hex")?;
    Ok(value.into())
}
