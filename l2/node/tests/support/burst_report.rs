//! Bounded burst observations and honest ledger/target diagnostics.
use super::{Run, gpu_verified, target_met};
use alephium_l2_node::{
    protocol::{BLOCK_INTERVAL_MS, Head},
    service::{MetricsSnapshot, StageSnapshot},
};
use alloy_primitives::U256;
use serde_json::{Value, json};
use std::collections::BTreeMap;
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
        "commit_phases":{
            "validation_pending":stage_delta(&before.commit_phases.validation_pending,&after.commit_phases.validation_pending),
            "prior_normalization":stage_delta(&before.commit_phases.prior_normalization,&after.commit_phases.prior_normalization),
            "encoding_hash":stage_delta(&before.commit_phases.encoding_hash,&after.commit_phases.encoding_hash),
            "checkpoint_capacity":stage_delta(&before.commit_phases.checkpoint_capacity,&after.commit_phases.checkpoint_capacity),
            "batch_build":stage_delta(&before.commit_phases.batch_build,&after.commit_phases.batch_build),
            "sync_all_commit":stage_delta(&before.commit_phases.sync_all_commit,&after.commit_phases.sync_all_commit),
            "publish_view":stage_delta(&before.commit_phases.publish_view,&after.commit_phases.publish_view),
            "scope":"Fjall CPU work plus SyncAll; sync_all_commit is not pure physical SSD latency"},
        "admitted_transactions":after.admitted_transactions.saturating_sub(before.admitted_transactions),
        "executed_transactions":after.executed_transactions.saturating_sub(before.executed_transactions),
        "boundary":"after funding/signing before dispatch to stable final worker join; no later transaction work",
        "maxima":"cumulative before/after; never subtracted",
        "durable_admission_scope":"whole Store.admit_batch, including codecs/storage/SyncAll"})
}

pub(super) fn report(run: &Run, count: usize, head: &Head, workers: usize, passed: bool) -> Value {
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
        "scope":"bounded_live_service_burst","passed":passed&&(count!=100||target_met(run,count,head))&&gpu_verified(run,count),
        "ledger_and_reopen_passed":passed,"target_met":target_met(run,count,head),
        "gpu_verification_passed":if run.gpu_requested {Some(gpu_verified(run,count))} else {None},
        "gpu":{"requested":run.gpu_requested,"before_setup":run.gpu_before_setup,
            "before_measured_burst":run.gpu_before_burst,"after_measured_burst":run.gpu_after_burst,
            "verified_in_measured_burst":run.gpu_after_burst.verified.saturating_sub(run.gpu_before_burst.verified),
            "batches_in_measured_burst":run.gpu_after_burst.batches.saturating_sub(run.gpu_before_burst.batches),
            "elapsed_ns_counter_delta":run.gpu_after_burst.elapsed_ns.saturating_sub(run.gpu_before_burst.elapsed_ns),
            "scope":if run.gpu_requested {"CUDA signature recovery with full CPU oracle; ordered EVM execution remains CPU"}
                else {"CPU reference backend; CUDA not requested"}},
        "policy":"all offered valid requests must ACK and drain; original block+1 is a performance target",
        "profile":{"chain_id":alephium_l2_node::protocol::CHAIN_ID,"genesis_id":head.genesis_id,
            "build_profile":if cfg!(debug_assertions) {"debug"} else {"release"},
            "block_interval_ms":BLOCK_INTERVAL_MS,"block_gas":run.capacity.block_gas,
            "block_bytes":run.capacity.block_bytes,"max_pending":run.capacity.max_pending,
            "genesis_accounts":1,"client_workers":workers,"available_cpus":run.available_cpus,
            "node_verification_workers":run.verification_workers},
        "storage":{"data_directory":run.data_directory,"root_volume":run.root_volume,
            "placement":"canonical source-project filesystem; unsigned plans and database share an owned root"},
        "checkpoint":{"encoded_bytes":run.checkpoint_capacity.0,"producer_limit":run.checkpoint_capacity.1,
            "runtime_format_limit":run.capacity.runtime_checkpoint_bytes().ok(),
            "runtime_record_limit":run.capacity.runtime_record_bytes().ok(),
            "proof_transport_supported":run.capacity.ensure_proof_transport().is_ok()},
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
        "receipt_observer":{"policy":"one fixture head poller every 5ms; watch broadcasts only head changes",
            "stats":run.observer_stats,"per_request_poll_timers":0,
            "collection_timeout_secs":super::head_observer::COLLECTION_TIMEOUT_SECS,
            "timeout_scope":"one aggregate client collection safety bound; no node clock/ACK/production changes",
            "receipt_timestamp":"actual client return elapsed; shared notification delay is included",
            "comparison":"instrumentation changed; earlier per-request-poll result must remain separately labelled"},
        "inclusion_by_original_target":inclusion,
        "accepted_arrival_boundary":"NodeHandle entry capture before queueing or durable ACK",
        "refused_observational_heads":refused_observed_heads,
        "refused_head_boundary":"sampled shared observer pre-call view only; no accepted target inferred",
        "failures":run.observations.iter().filter_map(|o|o.failure.as_ref()).collect::<Vec<_>>(),
        "reopen_accounting_verified":passed,"timing_assertions":false
    })
}
