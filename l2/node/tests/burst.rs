//! Bounded live-engine bursts; all offered valid transfers must drain durably.
//! Original arrival-head+1 is reported as a target, with a strict 100 baseline.
//! Funding, signing, observations and verification never pause the producer.
//! Service calls are not HTTP throughput or production capacity evidence.
#[path = "support/burst_fixture.rs"]
mod fixture;
#[path = "support/burst_parameters.rs"]
mod parameters;
#[path = "support/burst_storage.rs"]
mod storage_fixture;
#[path = "support/burst_verify.rs"]
mod verification;

use alephium_l2_node::{
    config::Config,
    operator,
    protocol::{BLOCK_INTERVAL_MS, Capacity, Head, Receipt},
    service::{self, MetricsSnapshot, NodeHandle, StageSnapshot},
    storage::Store,
};
use alloy_primitives::U256;
use fixture::{Expected, Plan};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::Write,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
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

fn event(phase: &str, requests: usize) -> Result<(), String> {
    let wall_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "Fixture wall clock is before Unix epoch")?
        .as_millis();
    let mut output = std::io::stdout().lock();
    writeln!(
        output,
        "{}",
        json!({"event":"measured_burst","phase":phase,
        "wall_unix_ms":wall_unix_ms,"requests":requests})
    )
    .map_err(|e| e.to_string())?;
    output.flush().map_err(|e| e.to_string())
}

async fn submit(
    node: NodeHandle,
    expected: Expected,
    raw: Vec<u8>,
    dispatched: Instant,
) -> Result<Observed, String> {
    let started = Instant::now();
    let parent = node.view()?.head.clone();
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
        match fixture::receipt(&node, observed.expected.hash).await {
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
) -> Result<Run, String> {
    let setup_started = Instant::now();
    let setup = plan.fund(node).await?;
    let setup_ms = setup_started.elapsed().as_millis();
    let setup_head = node.view()?.head.clone();
    let signing_started = Instant::now();
    let signed = plan.sign()?;
    let signing_ms = signing_started.elapsed().as_millis();
    event("start", signed.len())?;
    let metrics_before = node.metrics();
    let mut requests = JoinSet::new();
    let dispatched = Instant::now();
    // Dispatch immediately. No barrier, queue prefill, scheduler delay, retry,
    // collection wait or synchronization can hold production for this burst.
    for (item, raw) in signed {
        requests.spawn(submit(node.clone(), item, raw, dispatched));
    }
    let mut observations = Vec::new();
    while let Some(result) = requests.join_next().await {
        observations.push(result.map_err(|_| "Burst request task stopped")??);
    }
    let burst_ms = dispatched.elapsed().as_millis();
    let metrics_after = node.metrics();
    event("end", observations.len())?;
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
    })
}

fn latency(mut values: Vec<u128>) -> Value {
    values.sort_unstable();
    if values.is_empty() {
        return Value::Null;
    }
    let percentile = |percent: usize| values[(values.len() * percent).div_ceil(100) - 1];
    json!({"min":values.first(),"p50":percentile(50),"p95":percentile(95),
        "p99":percentile(99),"max":values.last()})
}

fn stage_delta(before: &StageSnapshot, after: &StageSnapshot) -> Value {
    json!({"total_ns":after.total_ns.saturating_sub(before.total_ns),
        "samples":after.samples.saturating_sub(before.samples),
        "cumulative_max_ns_before":before.max_ns,"cumulative_max_ns_after":after.max_ns})
}

fn metrics_delta(before: &MetricsSnapshot, after: &MetricsSnapshot) -> Value {
    json!({"validation":stage_delta(&before.validation,&after.validation),
        "durable_admission":stage_delta(&before.durable_admission,&after.durable_admission),
        "selection":stage_delta(&before.selection,&after.selection),
        "execution":stage_delta(&before.execution,&after.execution),
        "durable_block_commit":stage_delta(&before.durable_block_commit,&after.durable_block_commit),
        "admitted_transactions":after.admitted_transactions.saturating_sub(before.admitted_transactions),
        "executed_transactions":after.executed_transactions.saturating_sub(before.executed_transactions),
        "boundary":"after funding/signing, before dispatch to after all outcomes/receipts",
        "maxima":"cumulative before/after; never subtracted",
        "durable_admission_scope":"whole Store.admit_batch, including codecs/storage/SyncAll"})
}

fn report(run: &Run, count: usize, head: &Head, workers: usize, passed: bool) -> Value {
    let mut targets = BTreeMap::<u64, (usize, usize, BTreeMap<u64, usize>)>::new();
    let mut refused_observed_heads = BTreeMap::<u64, usize>::new();
    let mut rejections = BTreeMap::<String, usize>::new();
    for observed in &run.observations {
        if observed.durable_ack {
            let target = observed.parent.height + 1;
            let row = targets.entry(target).or_default();
            row.0 += 1;
            row.1 += usize::from(observed.receipt_height == Some(target));
            if let Some(height) = observed.receipt_height {
                *row.2.entry(height).or_default() += 1;
            }
        }
        if let Some(reason) = &observed.rejection {
            *rejections.entry(reason.clone()).or_default() += 1;
            *refused_observed_heads
                .entry(observed.parent.height)
                .or_default() += 1;
        }
    }
    let inclusion: Vec<_> = targets
        .into_iter()
        .map(|(target, (acked, included, blocks))| {
            let late: usize = blocks
                .iter()
                .filter(|(height, _)| **height > target)
                .map(|(_, n)| n)
                .sum();
            json!({"arrival_head":target-1,"original_target_block":target,
            "durable_acks":acked,"included_in_original_target":included,"late_receipts":late,
            "actual_receipt_blocks":blocks})
        })
        .collect();
    json!({
        "scope":"bounded_live_service_burst","passed":passed&&(count!=100||target_met(run,count,head)),
        "ledger_and_reopen_passed":passed,"target_met":target_met(run,count,head),
        "policy":"all offered valid requests must ACK and drain; original block+1 is a performance target",
        "profile":{"chain_id":alephium_l2_node::protocol::CHAIN_ID,"genesis_id":head.genesis_id,
            "build_profile":if cfg!(debug_assertions) {"debug"} else {"release"},
            "block_interval_ms":BLOCK_INTERVAL_MS,"block_gas":run.capacity.block_gas,
            "block_bytes":run.capacity.block_bytes,"max_pending":run.capacity.max_pending,
            "genesis_accounts":1,"client_workers":workers,"available_cpus":run.available_cpus,
            "node_verification_workers":run.verification_workers},
        "storage":{"data_directory":run.data_directory,"root_volume":run.root_volume,
            "placement":"canonical source-project filesystem; unsigned plans and database share an owned root"},
        "setup":{"transactions":run.setup.len(),"head":run.setup_head.height,
            "elapsed_ms":run.setup_ms,"gas_used":run.setup.iter().map(|r|r.gas_used).sum::<u64>(),
            "funding":"actual EVM contract CALLs to distinct EOAs"},
        "signing_ms":run.signing_ms,"requests":count,
        "durable_acks":run.observations.iter().filter(|o|o.durable_ack).count(),
        "rejected_before_ack":rejections.values().sum::<usize>(),"rejection_reasons":rejections,
        "original_next_block_receipts":run.observations.iter().filter(|o|
            o.receipt_height==Some(o.parent.height+1)).count(),
        "late_receipts":run.observations.iter().filter(|o|
            o.receipt_height.is_some_and(|height|height>o.parent.height+1)).count(),
        "measured_gas_charged":run.observations.iter().filter_map(|o|o.receipt_gas_used).sum::<u64>(),
        "measured_fees_charged_wei":run.observations.iter().filter_map(|o|o.receipt_fee_wei).sum::<U256>(),
        "lateness_blocks":latency(run.observations.iter().filter_map(|o|
            o.receipt_height.map(|height|u128::from(height.saturating_sub(o.parent.height+1)))).collect()),
        "measured_blocks":head.height-run.setup_head.height,"burst_elapsed_ms":run.burst_ms,
        "last_request_arrival_ms":run.observations.iter().map(|o|o.arrival_ms).max(),
        "ack_ms":latency(run.observations.iter().filter(|o|o.durable_ack).map(|o|o.ack_ms).collect()),
        "refusal_ms":latency(run.observations.iter().filter(|o|o.rejection.is_some()).map(|o|o.ack_ms).collect()),
        "receipt_ms":latency(run.observations.iter().filter_map(|o|o.receipt_ms).collect()),
        "service_stages":metrics_delta(&run.metrics_before,&run.metrics_after),
        "inclusion_by_original_target":inclusion,
        "accepted_arrival_boundary":"NodeHandle entry capture before queueing or durable ACK",
        "refused_observational_heads":refused_observed_heads,
        "refused_head_boundary":"pre-call view only; no accepted target inferred",
        "failures":run.observations.iter().filter_map(|o|o.failure.as_ref()).collect::<Vec<_>>(),
        "reopen_accounting_verified":passed,"timing_assertions":false
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

async fn run(count: usize, workers: usize) -> Result<(), String> {
    let storage = storage_fixture::workspace()?;
    // The same explicit development capacity is used for every comparison.
    // Queueing, durable ACK and production stay live throughout the burst.
    let capacity = Capacity {
        block_gas: 300_000_000,
        block_bytes: 8 * 1024 * 1024,
        max_pending: 10_000,
    };
    let plan = Plan::new(storage.directory.path(), count, capacity)?;
    let config = Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        data_dir: storage.data_dir.clone(),
        genesis: plan.genesis.clone(),
        min_gas_price: 1,
        max_checkpoint_bytes: operator::MAX_CONTINUATION_CHECKPOINT_BYTES,
        rpc: Default::default(),
        verification_workers_per_cpu: parameters::worker_factor()?,
    };
    let (node, worker) = service::start(&config)?;
    let outcome = exercise(&node, &plan, &storage).await;
    // Cleanup occurs only after every admission outcome and accepted receipt.
    node.stop().await;
    tokio::task::spawn_blocking(move || worker.join().map_err(|_| "Burst worker panicked"))
        .await
        .map_err(|_| "Burst cleanup task stopped")??;
    let run = outcome?;
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
        println!("{}", report(&run, count, &view.head, workers, false));
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
    println!("{}", report(&run, count, &head, workers, true));
    if count == 100 && !target_met(&run, count, &head) {
        return Err(
            "Ledger/reopen passed, but strict100 original-next-block baseline failed".into(),
        );
    }
    Ok(())
}

#[test]
#[ignore = "Operator-authorized bounded local bursts; no production throughput claim"]
fn live_burst_accepts_all_valid_requests_and_reports_original_next_block_target()
-> Result<(), String> {
    let workers = std::thread::available_parallelism()
        .map_err(|e| e.to_string())?
        .get()
        .saturating_sub(1)
        .max(1);
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?
        .block_on(run(parameters::count()?, workers))
}
