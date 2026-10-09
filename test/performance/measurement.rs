//! Monotonic service completion timing; setup and audit I/O are outside this window.
use super::{Observed, fixture::Expected, head_observer};
use alephium_l2_node::service::{GpuSnapshot, MetricsSnapshot, NodeHandle};
use alloy_primitives::U256;
use serde_json::json;
use std::{
    collections::BTreeSet,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tokio::task::JoinSet;

pub(super) struct Measured {
    pub observations: Vec<Observed>,
    pub elapsed_ns: u128,
    pub ack_elapsed_ns: u128,
    pub metrics_before: MetricsSnapshot,
    pub metrics_after: MetricsSnapshot,
    pub gpu_before: GpuSnapshot,
    pub gpu_after: GpuSnapshot,
    pub observer_stats: Option<head_observer::Stats>,
    pub error: Option<String>,
}
impl Measured {
    pub fn committed_count(&self) -> usize {
        self.observations
            .iter()
            .filter(|o| o.durable_ack && o.failure.is_none() && o.receipt_height.is_some())
            .map(|o| o.expected.hash)
            .collect::<BTreeSet<_>>()
            .len()
    }
    pub fn ack_count(&self) -> usize {
        self.observations
            .iter()
            .filter(|o| o.durable_ack)
            .map(|o| o.expected.hash)
            .collect::<BTreeSet<_>>()
            .len()
    }
}
fn event(phase: &str, count: usize) -> Result<(), String> {
    let wall_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "Host wall clock is before Unix epoch")?
        .as_nanos();
    println!(
        "{}",
        json!({"event":"tps_measurement","phase":phase,"transactions":count,
        "wall_unix_ns":wall_ns,"scope":"direct service, not HTTP or L1"})
    );
    Ok(())
}

async fn submit(
    node: NodeHandle,
    expected: Expected,
    raw: Vec<u8>,
    baseline: Instant,
    heads: head_observer::Heads,
) -> Result<Observed, String> {
    let arrival = Instant::now();
    let parent = heads.borrow().head.clone();
    let result = node.submit_with_head(raw).await;
    let ack = Instant::now();
    let mut observed = Observed {
        expected,
        parent,
        durable_ack: false,
        arrival_ns: arrival.duration_since(baseline).as_nanos(),
        ack_ns: ack.duration_since(arrival).as_nanos(),
        ack_at_ns: ack.duration_since(baseline).as_nanos(),
        receipt_ns: None,
        receipt_at_ns: None,
        receipt_height: None,
        receipt_gas_used: None,
        receipt_fee_wei: None,
        rejection: None,
        failure: None,
    };
    match result {
        Ok((status, parent)) => {
            observed.parent = parent;
            observed.durable_ack = status.status == "durably_accepted"
                && status.hash == observed.expected.hash
                && status.block_height.is_none()
                && status.error.is_none();
            if !observed.durable_ack {
                observed.failure = Some("Invalid durable ACK".into());
            }
        }
        Err(_) => {
            observed.rejection = Some("Valid offered request refused before durable ACK".into());
            observed.failure = observed.rejection.clone();
        }
    }
    if observed.durable_ack {
        match head_observer::receipt(heads, observed.expected.hash).await {
            Ok(receipt) => {
                let received = Instant::now();
                observed.receipt_ns = Some(received.duration_since(arrival).as_nanos());
                observed.receipt_at_ns = Some(received.duration_since(baseline).as_nanos());
                observed.receipt_height = Some(receipt.block_height);
                observed.receipt_gas_used = Some(receipt.gas_used);
                observed.receipt_fee_wei =
                    Some(U256::from(receipt.gas_used) * U256::from(receipt.gas_price));
                if !receipt.success || receipt.block_height <= observed.parent.height {
                    observed.failure = Some("Invalid successful committed receipt".into());
                }
            }
            Err(error) => observed.failure = Some(error),
        }
    }
    Ok(observed)
}

pub(super) async fn collect(
    node: &NodeHandle,
    signed: Vec<(Expected, Vec<u8>)>,
) -> Result<Measured, String> {
    // The reused observer's historical constant is not an execution limit here.
    let _ = head_observer::COLLECTION_TIMEOUT_SECS;
    let mut observer = head_observer::Observer::start(node.clone())?;
    let metrics_before = node.metrics();
    let gpu_before = node.gpu_metrics();
    let count = signed.len();
    event("start", count)?;
    let baseline = Instant::now();
    let mut tasks = JoinSet::new();
    for (expected, raw) in signed {
        tasks.spawn(submit(
            node.clone(),
            expected,
            raw,
            baseline,
            observer.subscribe(),
        ));
    }
    let mut observations = Vec::with_capacity(count);
    let mut error = None;
    // No overall collection timer, retry, prefill or producer synchronization.
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(value)) => observations.push(value),
            Ok(Err(failure)) => {
                error = Some(failure);
                break;
            }
            Err(_) => {
                error = Some("Measurement request task stopped".into());
                break;
            }
        }
    }
    if error.is_some() {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    let elapsed_ns = observations
        .iter()
        .filter_map(|o| o.receipt_at_ns)
        .max()
        .unwrap_or(0);
    let ack_elapsed_ns = observations
        .iter()
        .filter(|o| o.durable_ack)
        .map(|o| o.ack_at_ns)
        .max()
        .unwrap_or(0);
    let observer_stats = match observer.close().await {
        Ok(stats) => Some(stats),
        Err(failure) => {
            error.get_or_insert(failure);
            None
        }
    };
    event("end", observations.len())?;
    Ok(Measured {
        observations,
        elapsed_ns,
        ack_elapsed_ns,
        metrics_before,
        metrics_after: node.metrics(),
        gpu_before,
        gpu_after: node.gpu_metrics(),
        observer_stats,
        error,
    })
}
