//! One operator-selected 1k/10k/100k audit bundle; no ZK or HTTP workload.
#[path = "burst_fixture.rs"]
mod fixture;
#[path = "../../l2/node/tests/support/burst_head_observer.rs"]
mod head_observer;
mod measurement;
mod report;
mod storage;
#[path = "../../l2/node/tests/support/burst_verify.rs"]
mod verification;
use alephium_l2_node::{
    config::{Config, VerificationBackend},
    protocol::{Capacity, Head, Receipt},
    service::{self, NodeHandle},
    storage::Store,
};
use alloy_primitives::{B256, U256};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Component, Path, PathBuf},
    time::Instant,
};

struct Observed {
    expected: fixture::Expected,
    parent: Head,
    durable_ack: bool,
    arrival_ns: u128,
    ack_ns: u128,
    ack_at_ns: u128,
    receipt_ns: Option<u128>,
    receipt_at_ns: Option<u128>,
    receipt_height: Option<u64>,
    receipt_gas_used: Option<u64>,
    receipt_fee_wei: Option<U256>,
    rejection: Option<String>,
    failure: Option<String>,
}
struct Run {
    capacity: Capacity,
    setup: Vec<Receipt>,
    setup_ns: u128,
    signing_ns: u128,
    reopen_ns: u128,
    measured: Option<measurement::Measured>,
    final_head: Option<Head>,
    digest: Option<B256>,
    checkpoint_capacity: (usize, usize),
    available_cpus: usize,
    verification_workers: usize,
    data_directory: PathBuf,
    root_volume: String,
    ledger_verified: bool,
    reopen_verified: bool,
    worker_joined: bool,
    pending_after: usize,
    error: Option<String>,
}
fn capacity() -> Capacity {
    Capacity {
        block_gas: 3_000_000_000,
        block_bytes: 32 * 1024 * 1024,
        max_pending: 100_000,
    }
}
async fn exercise(node: &NodeHandle, plan: &fixture::Plan, run: &mut Run) -> Result<(), String> {
    run.available_cpus = node.available_cpus();
    run.verification_workers = node.verification_workers();
    if run.verification_workers != run.available_cpus.saturating_sub(1).max(1) {
        return Err("Node must use the original logical-CPU-minus-one worker profile".into());
    }
    let selected = node.gpu_metrics();
    if selected.selected != "cuda" || !selected.active {
        return Err("Selected CUDA backend is not active".into());
    }
    let setup = Instant::now();
    run.setup = plan.fund(node).await?;
    run.setup_ns = setup.elapsed().as_nanos();
    let signing = Instant::now();
    let signed = plan.sign()?;
    run.signing_ns = signing.elapsed().as_nanos();
    run.measured = Some(measurement::collect(node, signed).await?);
    Ok(())
}
fn audit(
    node: &NodeHandle,
    plan: &fixture::Plan,
    count: usize,
    run: &mut Run,
) -> Result<Vec<Receipt>, String> {
    let m = run
        .measured
        .as_mut()
        .ok_or("Measurement did not complete")?;
    // Stable final counters after the worker join, with no later transaction work.
    m.metrics_after = node.metrics();
    m.gpu_after = node.gpu_metrics();
    run.checkpoint_capacity = node.checkpoint_capacity();
    run.pending_after = node.pending_count();
    if m.error.is_some()
        || node.failure().is_some()
        || run.pending_after != 0
        || m.observations.len() != count
        || m.committed_count() != count
        || m.ack_count() != count
        || m.elapsed_ns == 0
        || m.observations
            .iter()
            .any(|o| o.failure.is_some() || o.rejection.is_some())
    {
        return Err("All offered requests must ACK and drain to unique successful receipts".into());
    }
    if m.gpu_after.selected != "cuda"
        || !m.gpu_after.active
        || m.gpu_after.failures != 0
        || !m.gpu_after.cpu_oracle_checked
        || m.gpu_after.verified.saturating_sub(m.gpu_before.verified) < count as u64
    {
        return Err("Required real CUDA verification/full CPU parity was not observed".into());
    }
    let view = node.view()?;
    let receipts = verification::verify(&view, &m.observations, &run.setup, plan.contract)?;
    let head = view.head.clone();
    let digest = view.state_digest()?;
    drop(view);
    run.final_head = Some(head);
    run.digest = Some(digest);
    run.ledger_verified = true;
    Ok(receipts)
}
fn reopen(
    config: &Config,
    plan: &fixture::Plan,
    receipts: &[Receipt],
    run: &mut Run,
) -> Result<(), String> {
    let reopening = Instant::now();
    let store = Store::open_existing(&config.data_dir, &config.genesis)?;
    if !store.pending()?.is_empty() {
        return Err("Reopened dataset has pending intents".into());
    }
    let restored = store.view()?;
    let m = run
        .measured
        .as_ref()
        .ok_or("Measurement absent at reopen")?;
    if run.final_head.as_ref() != Some(&restored.head)
        || Some(restored.state_digest()?) != run.digest
        || verification::verify(&restored, &m.observations, &run.setup, plan.contract)?.as_slice()
            != receipts
    {
        return Err("Reopened ledger/receipts/accounting differ".into());
    }
    drop(restored);
    drop(store);
    run.reopen_ns = reopening.elapsed().as_nanos();
    run.reopen_verified = true;
    Ok(())
}
async fn run_count(output: &Path, count: usize) -> Result<Value, String> {
    let workspace = storage::workspace(output, count)?;
    let cap = capacity();
    let mut run = Run {
        capacity: cap,
        setup: vec![],
        setup_ns: 0,
        signing_ns: 0,
        reopen_ns: 0,
        measured: None,
        final_head: None,
        digest: None,
        checkpoint_capacity: (0, 0),
        available_cpus: 0,
        verification_workers: 0,
        data_directory: workspace.data_dir.clone(),
        root_volume: workspace.root_volume.clone(),
        ledger_verified: false,
        reopen_verified: false,
        worker_joined: false,
        pending_after: 0,
        error: None,
    };
    let plan = match fixture::Plan::new(&workspace.directory, count, cap) {
        Ok(plan) => plan,
        Err(error) => {
            run.error = Some(error);
            let value = report::value(&run, count, false);
            report::save(&workspace.directory.join("report.json"), &value)?;
            return Ok(value);
        }
    };
    let config = Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        data_dir: workspace.data_dir.clone(),
        genesis: plan.genesis.clone(),
        min_gas_price: 1,
        max_checkpoint_bytes: cap.producer_checkpoint_bytes()?,
        rpc: Default::default(),
        verification_workers_per_cpu: 1,
        verification_backend: VerificationBackend::Cuda,
        gpu_device: 0,
    };
    let (node, worker) = match service::start(&config) {
        Ok(started) => started,
        Err(error) => {
            run.error = Some(error);
            let value = report::value(&run, count, false);
            report::save(&workspace.directory.join("report.json"), &value)?;
            return Ok(value);
        }
    };
    let outcome = exercise(&node, &plan, &mut run).await;
    node.stop().await;
    let joined = tokio::task::spawn_blocking(move || worker.join()).await;
    run.worker_joined = matches!(joined, Ok(Ok(())));
    if let Err(error) = outcome {
        run.error = Some(error)
    }
    if !run.worker_joined {
        run.error = Some("Owned producer worker did not join normally".into())
    }
    let mut receipts = None;
    if run.error.is_none() {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            audit(&node, &plan, count, &mut run)
        })) {
            Ok(Ok(value)) => receipts = Some(value),
            Ok(Err(error)) => run.error = Some(error),
            Err(_) => {
                run.error = Some("Ledger/reopen audit assertion failed; dataset preserved".into())
            }
        }
    }
    run.pending_after = node.pending_count();
    drop(node);
    // Release every live NodeHandle/ReadView before opening the same Fjall dataset.
    if let Some(receipts) = receipts {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            reopen(&config, &plan, &receipts, &mut run)
        })) {
            Ok(Ok(())) => {}
            Ok(Err(error)) => run.error = Some(error),
            Err(_) => run.error = Some("Reopen audit assertion failed; dataset preserved".into()),
        }
    }
    if let Some(m) = &run.measured {
        report::csv(&workspace.directory.join("transactions.csv"), m)?;
    }
    let passed =
        run.error.is_none() && run.worker_joined && run.ledger_verified && run.reopen_verified;
    let value = report::value(&run, count, passed);
    report::save(&workspace.directory.join("report.json"), &value)?;
    Ok(value)
}
fn output() -> Result<PathBuf, String> {
    let path = PathBuf::from(std::env::var_os("L2_TPS_OUTPUT").ok_or("Set fresh L2_TPS_OUTPUT")?);
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .ok_or("Root unavailable")?;
    if !path.is_absolute()
        || !path.starts_with(root.join("test/private"))
        || path.components().any(|c| matches!(c, Component::ParentDir))
        || path.exists()
    {
        return Err("TPS output must be a fresh absolute main/test/private directory".into());
    }
    let parent = path.parent().ok_or("Output parent unavailable")?;
    for ancestor in parent.ancestors() {
        let meta = fs::symlink_metadata(ancestor).map_err(|_| "Output parent must exist")?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err("Output ancestry redirected".into());
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if meta.file_attributes() & 0x400 != 0 {
                return Err("Output ancestry contains a reparse point".into());
            }
        }
    }
    fs::create_dir(&path).map_err(|_| "Cannot create fresh TPS output")?;
    Ok(path)
}

#[test]
#[ignore = "Operator-selected fresh audit-only CUDA TPS bundle; no ZK or public throughput claim"]
fn auditable_tps_three_sizes() -> Result<(), String> {
    let output = output()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(
            std::thread::available_parallelism()
                .map_err(|e| e.to_string())?
                .get()
                .saturating_sub(1)
                .max(1),
        )
        .enable_all()
        .build()
        .map_err(|_| "Cannot create logical-CPU-minus-one measurement runtime")?;
    let mut rows = Vec::new();
    let mut failed = None;
    for count in [1000, 10_000, 100_000] {
        match runtime.block_on(run_count(&output, count)) {
            Ok(row) => {
                let passed = row["passed"] == true;
                rows.push(row);
                if !passed {
                    failed = Some("Size failed; no retry");
                    break;
                }
            }
            Err(_) => {
                rows.push(json!({"offered_transactions":count,"passed":false,"error":"Audit artifact stage failed; preserve dataset"}));
                failed = Some("Audit artifact stage failed");
                break;
            }
        }
    }
    drop(runtime);
    let passed = failed.is_none() && rows.len() == 3;
    report::save(
        &output.join("aggregate.json"),
        &json!({"schema":1,"passed":passed,
        "requested_sizes":[1000,10000,100000],"results":rows,"automatic_retries":0,
        "proof_generated":false,"zk_receipts":0,"network_calls":0,"http_servers":0,
        "client_workers":std::thread::available_parallelism().map_err(|e|e.to_string())?.get().saturating_sub(1).max(1),"profile":capacity(),"overall_deadline_seconds":null,
        "datasets_preserved":true,"scope":"auditable direct service benchmark only"}),
    )?;
    println!(
        "TPS aggregate completed: sizes={} passed={passed}; audit evidence only, no ZK",
        if passed { 3 } else { rows.len() }
    );
    if passed {
        Ok(())
    } else {
        Err(failed.unwrap_or("Incomplete size inventory").into())
    }
}
