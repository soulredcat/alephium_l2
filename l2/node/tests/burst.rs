//! Bounded live-engine bursts; all offered valid transfers must drain durably.
//! Original arrival-head+1 is reported as a target, with a strict 100 baseline.
//! Funding, signing, observations and verification never pause the producer.
//! Service calls are not HTTP throughput or production capacity evidence.
#[path = "support/burst_capture.rs"]
mod capture;
#[path = "support/burst_fixture.rs"]
mod fixture;
#[path = "support/burst_head_observer.rs"]
mod head_observer;
#[path = "support/burst_limits.rs"]
mod limits;
#[path = "support/burst_parameters.rs"]
mod parameters;
#[path = "support/burst_report.rs"]
mod reporting;
#[path = "support/burst_storage.rs"]
mod storage_fixture;
#[path = "support/burst_verify.rs"]
mod verification;

use alephium_l2_node::{
    config::{Config, VerificationBackend},
    protocol::{Capacity, Head, Receipt},
    service::{self, GpuSnapshot, MetricsSnapshot, NodeHandle},
    storage::Store,
};
use alloy_primitives::U256;
use fixture::{Expected, Plan};
use reporting::report;
use serde_json::json;
use std::time::{Duration, Instant};
use tokio::task::JoinSet;

struct Observed {
    expected: Expected,
    parent: Head,
    durable_ack: bool,
    arrival_ms: u128,
    ack_ms: u128,
    receipt_ms: Option<u128>,
    receipt_height: Option<u64>,
    receipt_gas_used: Option<u64>,
    receipt_fee_wei: Option<U256>,
    rejection: Option<String>,
    failure: Option<String>,
}

struct Run {
    observations: Vec<Observed>,
    setup: Vec<Receipt>,
    setup_head: Head,
    setup_ms: u128,
    signing_ms: u128,
    burst_ms: u128,
    capacity: Capacity,
    metrics_before: MetricsSnapshot,
    metrics_after: MetricsSnapshot,
    data_directory: String,
    root_volume: String,
    available_cpus: usize,
    verification_workers: usize,
    gpu_requested: bool,
    gpu_before_setup: GpuSnapshot,
    gpu_before_burst: GpuSnapshot,
    gpu_after_burst: GpuSnapshot,
    checkpoint_capacity: (usize, usize),
    observer_stats: head_observer::Stats,
    before_capture: Option<capture::Before>,
}

fn refusal_reason(error: &str) -> String {
    match error {
        "Admission queue unavailable or full"
        | "Pending queue full"
        | "Next block is full; retry after the current batch commits"
        | "Original target block has passed; submit a new request"
        | "Original target block deadline exhausted; submit a new request" => error.into(),
        _ => "Unexpected admission failure".into(),
    }
}

async fn submit(
    node: NodeHandle,
    expected: Expected,
    raw: Vec<u8>,
    dispatched: Instant,
    heads: head_observer::Heads,
) -> Result<Observed, String> {
    let started = Instant::now();
    let parent = heads.borrow().head.clone();
    let outcome = node.submit_with_head(raw).await;
    let mut observed = Observed {
        expected,
        parent,
        durable_ack: false,
        arrival_ms: started.duration_since(dispatched).as_millis(),
        ack_ms: started.elapsed().as_millis(),
        receipt_ms: None,
        receipt_height: None,
        receipt_gas_used: None,
        receipt_fee_wei: None,
        rejection: None,
        failure: None,
    };
    match outcome {
        Ok((status, queued_head)) => {
            observed.durable_ack = status.status == "durably_accepted"
                && status.hash == observed.expected.hash
                && status.block_height.is_none()
                && status.error.is_none();
            if !observed.durable_ack {
                observed.failure = Some("New transaction lacked a valid durable ACK".into());
            }
            // This is the head captured by NodeHandle at its initial request
            // entry, before queueing or ACK. Never substitute a later view.
            observed.parent = queued_head;
        }
        Err(error) => {
            observed.rejection = Some(refusal_reason(&error));
            observed.failure = Some("Valid offered request was refused before durable ACK".into());
        }
    }
    if observed.durable_ack {
        match head_observer::receipt(heads, observed.expected.hash).await {
            Ok(receipt) => {
                observed.receipt_ms = Some(started.elapsed().as_millis());
                observed.receipt_height = Some(receipt.block_height);
                observed.receipt_gas_used = Some(receipt.gas_used);
                observed.receipt_fee_wei =
                    Some(U256::from(receipt.gas_used) * U256::from(receipt.gas_price));
                if !receipt.success || receipt.block_height <= observed.parent.height {
                    observed.failure =
                        Some("Accepted request has an invalid execution receipt".into());
                }
            }
            Err(error) => observed.failure = Some(error),
        }
    }
    Ok(observed)
}

async fn exercise(
    node: &NodeHandle,
    plan: &Plan,
    storage: &storage_fixture::Workspace,
    gpu_requested: bool,
    retain: bool,
) -> Result<Run, String> {
    let gpu_before_setup = node.gpu_metrics();
    let setup_started = Instant::now();
    let setup = plan.fund(node).await?;
    let setup_ms = setup_started.elapsed().as_millis();
    let setup_head = node.view()?.head.clone();
    let before_capture = if retain {
        Some(capture::before(node, storage, &plan.genesis, &setup_head)?)
    } else {
        None
    };
    let signing_started = Instant::now();
    let signed = plan.sign()?;
    let signing_ms = signing_started.elapsed().as_millis();
    capture::event("start", signed.len())?;
    let mut observer = head_observer::Observer::start(node.clone())?;
    let metrics_before = node.metrics();
    let gpu_before_burst = node.gpu_metrics();
    let mut requests = JoinSet::new();
    let dispatched = Instant::now();
    // Dispatch immediately. No barrier, queue prefill, scheduler delay, retry,
    // collection wait or synchronization can hold production for this burst.
    for (item, raw) in signed {
        requests.spawn(submit(
            node.clone(),
            item,
            raw,
            dispatched,
            observer.subscribe(),
        ));
    }
    let mut observations = Vec::new();
    let collection = tokio::time::timeout_at(
        tokio::time::Instant::from_std(
            dispatched + Duration::from_secs(head_observer::COLLECTION_TIMEOUT_SECS),
        ),
        async {
            while let Some(result) = requests.join_next().await {
                observations.push(result.map_err(|_| "Burst request task stopped")??);
            }
            Ok::<(), String>(())
        },
    )
    .await
    .map_err(|_| "Aggregate burst collection exceeded its 120-second safety bound".to_string())
    .and_then(|result| result);
    if collection.is_err() {
        requests.abort_all();
        while requests.join_next().await.is_some() {}
    }
    let burst_ms = dispatched.elapsed().as_millis();
    let metrics_after = node.metrics();
    let gpu_after_burst = node.gpu_metrics();
    let observer_result = observer.close().await;
    capture::event("end", observations.len())?;
    collection?;
    let observer_stats = observer_result?;
    Ok(Run {
        observations,
        setup,
        setup_head,
        setup_ms,
        signing_ms,
        burst_ms,
        capacity: node.capacity(),
        metrics_before,
        metrics_after,
        data_directory: storage.data_dir.to_string_lossy().into_owned(),
        root_volume: storage.root_volume.clone(),
        available_cpus: node.available_cpus(),
        verification_workers: node.verification_workers(),
        gpu_requested,
        gpu_before_setup,
        gpu_before_burst,
        gpu_after_burst,
        checkpoint_capacity: node.checkpoint_capacity(),
        observer_stats,
        before_capture,
    })
}

fn target_met(run: &Run, count: usize, head: &Head) -> bool {
    run.observations.len() == count
        && run
            .observations
            .iter()
            .all(|o| o.durable_ack && o.receipt_height == Some(o.parent.height + 1))
        && (count != 100
            || (head.height == run.setup_head.height + 1
                && run.observations.iter().all(|o| o.parent == run.setup_head)))
}

fn gpu_verified(run: &Run, count: usize) -> bool {
    !run.gpu_requested
        || (run.gpu_after_burst.selected == "cuda"
            && run.gpu_after_burst.active
            && run.gpu_after_burst.failures == 0
            && run.gpu_after_burst.cpu_oracle_checked
            && run
                .gpu_after_burst
                .verified
                .saturating_sub(run.gpu_before_burst.verified)
                >= count as u64)
}

async fn run(count: usize, workers: usize) -> Result<(), String> {
    let retain = capture::requested()?;
    let backend = parameters::backend()?;
    if retain && backend != VerificationBackend::Cuda {
        return Err("Retained GPU qualification requires the CUDA verification backend".into());
    }
    // The same explicit development capacity is used for every comparison.
    // Queueing, durable ACK and production stay live throughout the burst.
    let capacity = parameters::capacity();
    limits::check(count, capacity)?;
    let storage = storage_fixture::workspace()?;
    let plan = Plan::new(storage.directory.path(), count, capacity)?;
    let config = Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        data_dir: storage.data_dir.clone(),
        genesis: plan.genesis.clone(),
        min_gas_price: 1,
        max_checkpoint_bytes: capacity.producer_checkpoint_bytes()?,
        rpc: Default::default(),
        verification_workers_per_cpu: parameters::worker_factor()?,
        verification_backend: backend,
        gpu_device: parameters::gpu_device()?,
    };
    let (node, worker) = service::start(&config)?;
    let outcome = exercise(
        &node,
        &plan,
        &storage,
        config.verification_backend == VerificationBackend::Cuda,
        retain,
    )
    .await;
    // Cleanup occurs only after every admission outcome and accepted receipt.
    node.stop().await;
    tokio::task::spawn_blocking(move || worker.join().map_err(|_| "Burst worker panicked"))
        .await
        .map_err(|_| "Burst cleanup task stopped")??;
    let mut run = outcome?;
    // Publication exposes receipts before its checkpoint-byte atomic update;
    // join gives the final head and diagnostics one stable observation point.
    run.checkpoint_capacity = node.checkpoint_capacity();
    run.metrics_after = node.metrics();
    let view = node.view()?;
    let healthy = run.observations.len() == count
        && node.failure().is_none()
        && node.pending_count() == 0
        && run.observations.iter().all(|o| {
            o.failure.is_none()
                && o.durable_ack
                && o.receipt_height.is_some()
                && o.rejection.is_none()
        });
    if !healthy {
        capture::emit(&capture::annotate(
            report(&run, count, &view.head, workers, false),
            retain,
            run.before_capture.as_ref(),
        ))?;
        return Err("All-offered durable acceptance and successful drain failed".into());
    }
    let receipts = verification::verify(&view, &run.observations, &run.setup, plan.contract)?;
    let head = view.head.clone();
    let digest = view.state_digest()?;
    drop(view);
    drop(node);
    let store = Store::open_existing(&config.data_dir, &config.genesis)?;
    assert!(store.pending()?.is_empty());
    let restored = store.view()?;
    assert_eq!(restored.head, head);
    assert_eq!(restored.state_digest()?, digest);
    assert_eq!(
        verification::verify(&restored, &run.observations, &run.setup, plan.contract)?,
        receipts
    );
    drop(restored);
    drop(store);
    let mut qualified_report = capture::annotate(
        report(&run, count, &head, workers, true),
        retain,
        run.before_capture.as_ref(),
    );
    if !gpu_verified(&run, count) {
        capture::emit(&qualified_report)?;
        return Err(
            "Ledger/reopen passed, but required CUDA verification/parity was not observed".into(),
        );
    }
    if count == 100 && !target_met(&run, count, &head) {
        capture::emit(&qualified_report)?;
        return Err(
            "Ledger/reopen passed, but strict100 original-next-block baseline failed".into(),
        );
    }
    if retain {
        let before = run
            .before_capture
            .as_ref()
            .ok_or("Missing requested before-burst checkpoint")?;
        let retained =
            capture::retain_success(storage, before, &head, digest, &run.gpu_after_burst)?;
        qualified_report["dataset_retained"] = json!(true);
        qualified_report["retained_dataset"] = retained;
    }
    capture::emit(&qualified_report)?;
    Ok(())
}

#[test]
#[ignore = "Operator-authorized bounded local bursts; no production throughput claim"]
fn live_burst_accepts_all_valid_requests_and_reports_original_next_block_target()
-> Result<(), String> {
    let (runtime, workers) = parameters::client_runtime()?;
    runtime.block_on(run(parameters::count()?, workers))
}
