//! Optional local functional dataset for native P4 export, never a proof claim.
use super::storage_fixture::Workspace;
use alephium_l2_node::{
    operator::SettlementDomain,
    protocol::{Genesis, Head},
    service::{GpuSnapshot, NodeHandle},
};
use alloy_primitives::B256;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Serialize)]
pub(super) struct Before {
    pub checkpoint_path: PathBuf,
    pub checkpoint_bytes: u64,
    pub checkpoint_sha256: B256,
    pub genesis_path: PathBuf,
    pub head: Head,
    pub capture_ms: u128,
    pub offline_mock_domain: SettlementDomain,
}

pub(super) fn requested() -> Result<bool, String> {
    match std::env::var("L2_BURST_RETAIN_DATA") {
        Ok(value) if value == "1" => Ok(true),
        Ok(value) if value == "0" => Ok(false),
        Err(std::env::VarError::NotPresent) => Ok(false),
        _ => Err("L2_BURST_RETAIN_DATA must be 0 or 1; absence disables retention".into()),
    }
}

fn private_file(path: &Path) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(|e| e.to_string())
}

fn save_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let mut output = BufWriter::new(private_file(path)?);
    serde_json::to_writer(&mut output, value).map_err(|e| e.to_string())?;
    output.flush().map_err(|e| e.to_string())?;
    output.get_ref().sync_all().map_err(|e| e.to_string())
}

pub(super) fn before(
    node: &NodeHandle,
    storage: &Workspace,
    genesis: &Genesis,
    expected: &Head,
) -> Result<Before, String> {
    let started = Instant::now();
    let directory = storage.capture_directory()?;
    let view = node.view()?;
    if &view.head != expected || node.pending_count() != 0 {
        return Err(
            "Native capture requires the completed setup's immutable committed head".into(),
        );
    }
    let checkpoint = view.execution_checkpoint()?;
    let expected_bytes = checkpoint.encoded_len()?;
    let path = directory.join("before-checkpoint.bin");
    let mut output = BufWriter::with_capacity(64 * 1024, private_file(&path)?);
    let mut digest = Sha256::new();
    let mut written = 0u64;
    checkpoint.write_encoded(&mut |bytes| {
        output.write_all(bytes).map_err(|e| e.to_string())?;
        digest.update(bytes);
        written = written
            .checked_add(bytes.len() as u64)
            .ok_or("Capture byte count overflow")?;
        Ok(())
    })?;
    output.flush().map_err(|e| e.to_string())?;
    output.get_ref().sync_all().map_err(|e| e.to_string())?;
    if written != expected_bytes as u64 {
        return Err("Captured checkpoint length differs from canonical encoding".into());
    }
    let genesis_path = directory.join("genesis.json");
    save_json(&genesis_path, genesis)?;
    let captured = Before {
        checkpoint_path: path,
        checkpoint_bytes: written,
        checkpoint_sha256: B256::from_slice(&digest.finalize()),
        genesis_path,
        head: view.head.clone(),
        capture_ms: started.elapsed().as_millis(),
        offline_mock_domain: SettlementDomain {
            l1_network: 1,
            l1_genesis_id: B256::repeat_byte(0x11),
            settlement_contract_id: B256::repeat_byte(0x22),
        },
    };
    captured.offline_mock_domain.validate()?;
    save_json(&directory.join("before-metadata.json"), &captured)?;
    // The view and full checkpoint drop here; no retained snapshot crosses burst.
    Ok(captured)
}

pub(super) fn annotate(mut report: Value, retain: bool, before: Option<&Before>) -> Value {
    if retain {
        report["scope"] = json!("functional_gpu_large_state_capture_for_native_P4");
        report["performance_comparison_eligible"] = json!(false);
        report["dataset_retention_requested"] = json!(true);
        report["dataset_retained"] = json!(false);
        report["before_burst_capture"] = json!(before);
        report["capture_scope"] = json!(
            "local full canonical snapshot; no held ReadView during burst; no proof or settlement acceptance"
        );
    }
    report
}

pub(super) fn emit(report: &Value) -> Result<(), String> {
    let mut output = std::io::stdout().lock();
    writeln!(output, "{report}").map_err(|e| e.to_string())?;
    output.flush().map_err(|e| e.to_string())
}

pub(super) fn event(phase: &str, requests: usize) -> Result<(), String> {
    let wall_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "Fixture wall clock is before Unix epoch")?
        .as_millis();
    emit(&json!({"event":"measured_burst","phase":phase,
        "wall_unix_ms":wall_unix_ms,"requests":requests}))
}

pub(super) fn retain_success(
    storage: Workspace,
    before: &Before,
    after: &Head,
    state_digest: B256,
    gpu: &GpuSnapshot,
) -> Result<Value, String> {
    let directory = storage.capture_directory()?;
    let report = json!({"scope":"functional_gpu_large_state_capture_for_native_P4",
        "dataset_retained":true,"owned_worker_stopped":true,"ledger_and_reopen_passed":true,
        "performance_comparison_eligible":false,"data_directory":storage.data_dir,
        "owner_directory":storage.directory.path(),"root_volume":storage.root_volume,
        "before":before,"after_head":after,"after_state_digest":state_digest,"gpu":gpu,
        "batch_start":before.head.height+1,"domain_kind":"explicit offline development-only mock; no public target acceptance",
        "native_export_completed":false,"guest_proof_generated":false,"settlement_verified":false,
        "file_privacy":"local owned workspace; Unix requests0600, Windows inherits directory ACL; no stronger access claim"});
    save_json(&directory.join("retained-metadata.json"), &report)?;
    storage.retain()?;
    Ok(report)
}
