//! Private audit files; raw signed envelopes and keys never enter the CSV/report.
use super::{Run, measurement::Measured};
use alephium_l2_node::service::StageSnapshot;
use serde_json::{Value, json};
use std::{
    fs::OpenOptions,
    io::{BufWriter, Write},
    path::Path,
};

pub(super) fn save(path: &Path, value: &Value) -> Result<(), String> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| "Cannot create fresh audit report")?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, value).map_err(|_| "Cannot encode audit report")?;
    writer.flush().map_err(|_| "Cannot flush audit report")?;
    writer
        .get_ref()
        .sync_all()
        .map_err(|_| "Cannot sync audit report".to_owned())
}
pub(super) fn csv(path: &Path, measured: &Measured) -> Result<(), String> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| "Cannot create fresh transaction audit CSV")?;
    let mut writer = BufWriter::new(file);
    writeln!(writer,"transaction_hash,sender,recipient,value_wei,arrival_offset_ns,ack_latency_ns,ack_offset_ns,receipt_latency_ns,receipt_offset_ns,arrival_parent_height,receipt_block_height,gas_used,fee_wei,durable_ack,successful_receipt")
        .map_err(|_| "Cannot write CSV header")?;
    let mut rows: Vec<_> = measured.observations.iter().collect();
    rows.sort_by_key(|o| (o.arrival_ns, o.expected.hash));
    for o in rows {
        let field = |v: Option<u128>| v.map(|n| n.to_string()).unwrap_or_default();
        writeln!(
            writer,
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}",
            hex::encode(o.expected.hash),
            hex::encode(o.expected.sender),
            hex::encode(o.expected.recipient),
            o.expected.value,
            o.arrival_ns,
            o.ack_ns,
            o.ack_at_ns,
            field(o.receipt_ns),
            field(o.receipt_at_ns),
            o.parent.height,
            o.receipt_height.map(|v| v.to_string()).unwrap_or_default(),
            o.receipt_gas_used
                .map(|v| v.to_string())
                .unwrap_or_default(),
            o.receipt_fee_wei.map(|v| v.to_string()).unwrap_or_default(),
            o.durable_ack,
            o.receipt_height.is_some() && o.failure.is_none()
        )
        .map_err(|_| "Cannot encode transaction audit CSV")?;
    }
    writer.flush().map_err(|_| "Cannot flush audit CSV")?;
    writer
        .get_ref()
        .sync_all()
        .map_err(|_| "Cannot sync audit CSV".to_owned())
}
fn delta(before: &StageSnapshot, after: &StageSnapshot) -> Value {
    json!({"total_ns":after.total_ns.saturating_sub(before.total_ns),
        "samples":after.samples.saturating_sub(before.samples),
        "cumulative_max_ns_before":before.max_ns,"cumulative_max_ns_after":after.max_ns})
}
fn latency(mut values: Vec<u128>) -> Value {
    values.sort_unstable();
    if values.is_empty() {
        return Value::Null;
    }
    let percentile = |p: usize| values[(values.len() * p).div_ceil(100) - 1];
    json!({"min":values[0],"p50":percentile(50),"p95":percentile(95),
        "p99":percentile(99),"max":values[values.len()-1]})
}
pub(super) fn measured_value(m: &Measured, offered: usize) -> Value {
    let committed = m.committed_count();
    let ack = m.ack_count();
    let rate = |count: usize, ns: u128| {
        if ns == 0 {
            None
        } else {
            Some(count as f64 * 1e9 / ns as f64)
        }
    };
    let a = &m.metrics_before;
    let b = &m.metrics_after;
    json!({"offered_transactions":offered,"observed_requests":m.observations.len(),
        "unique_successful_committed_transactions":committed,"unique_durable_acks":ack,
        "completion_elapsed_ns":m.elapsed_ns,"durable_ack_elapsed_ns":m.ack_elapsed_ns,
        "completion_tps":rate(committed,m.elapsed_ns),"durable_ack_tps":rate(ack,m.ack_elapsed_ns),
        "formula":"unique successful committed hashes * 1000000000 / completion_elapsed_ns",
        "denominator":"before first task spawn through last client-observed committed receipt",
        "failure":m.error,"ack_latency_ns":latency(m.observations.iter().filter(|o|o.durable_ack).map(|o|o.ack_ns).collect()),
        "receipt_latency_ns":latency(m.observations.iter().filter_map(|o|o.receipt_ns).collect()),
        "last_request_arrival_offset_ns":m.observations.iter().map(|o|o.arrival_ns).max(),
        "original_next_block_receipts":m.observations.iter().filter(|o|o.receipt_height==Some(o.parent.height+1)).count(),
        "late_receipts":m.observations.iter().filter(|o|o.receipt_height.is_some_and(|h|h>o.parent.height+1)).count(),
        "target_is_acceptance_gate":false,"overall_deadline_seconds":null,
        "observer":m.observer_stats,"observer_interval_ms":5,"per_request_poll_timers":0,
        "stage_metrics":{"validation":delta(&a.validation,&b.validation),
            "durable_admission":delta(&a.durable_admission,&b.durable_admission),
            "selection":delta(&a.selection,&b.selection),"execution":delta(&a.execution,&b.execution),
            "durable_block_commit":delta(&a.durable_block_commit,&b.durable_block_commit),
            "sync_all_commit":delta(&a.commit_phases.sync_all_commit,&b.commit_phases.sync_all_commit),
            "admitted_transactions":b.admitted_transactions.saturating_sub(a.admitted_transactions),
            "execution_attempt_transactions":b.executed_transactions.saturating_sub(a.executed_transactions),
            "execution_counter_is_tps_numerator":false,"stage_totals_are_not_wall_time":true},
        "gpu":{"before":m.gpu_before,"after":m.gpu_after,
            "verified_delta":m.gpu_after.verified.saturating_sub(m.gpu_before.verified),
            "batches_delta":m.gpu_after.batches.saturating_sub(m.gpu_before.batches),
            "elapsed_ns_delta":m.gpu_after.elapsed_ns.saturating_sub(m.gpu_before.elapsed_ns),
            "scope":"CUDA signature recovery; full CPU oracle; ordered EVM execution is CPU"}})
}
pub(super) fn value(run: &Run, count: usize, passed: bool) -> Value {
    json!({"schema":1,"scope":"auditable direct-service TPS, not HTTP/L1 throughput or ZK proof",
        "passed":passed,"offered_transactions":count,"profile":run.capacity,
        "build_profile":if cfg!(debug_assertions){"debug"}else{"release"},
        "client_workers":run.available_cpus.saturating_sub(1).max(1),"available_cpus":run.available_cpus,
        "actual_verification_workers":run.verification_workers,"requested_verification_workers":run.available_cpus.saturating_sub(1).max(1),
        "sequential_evm_cpu":true,"gpu_full_cpu_oracle_required":true,
        "setup_transactions":run.setup.len(),"setup_elapsed_ns":run.setup_ns,
        "signing_elapsed_ns":run.signing_ns,"reopen_audit_elapsed_ns":run.reopen_ns,
        "outside_tps":"setup/funding/signing/shutdown/reopen/accounting/serialization",
        "measurement":run.measured.as_ref().map(|m|measured_value(m,count)),
        "final_head":run.final_head,"state_digest":run.digest,
        "checkpoint_encoded_bytes":run.checkpoint_capacity.0,"producer_checkpoint_limit":run.checkpoint_capacity.1,
        "ledger_accounting_verified":run.ledger_verified,"reopen_identical":run.reopen_verified,
        "pending_after_cleanup":run.pending_after,"owned_worker_joined":run.worker_joined,
        "data_directory":run.data_directory,"root_volume":run.root_volume,
        "dataset_preserved":true,"csv":"transactions.csv","error":run.error,
        "proof_generated":false,"zk_receipt":false,"settlement_accepted":false,
        "http_server_started":false,"public_capacity_claim":false})
}
