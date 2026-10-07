//! One fresh 10-TX P4 closure correctness/recovery fixture; no benchmark or wall-clock cap.
#![cfg(feature = "cuda")]
// The aggregate metadata object exceeds serde_json's default macro depth.
#![recursion_limit = "256"]
#[path = "support/p4_development_flow.rs"]
mod flow;
#[path = "support/p4_development_plan.rs"]
mod plan;
#[path = "support/p4_development_storage.rs"]
mod storage_fixture;
#[path = "support/p4_development_verify.rs"]
mod verification;

use alephium_l2_node::{
    config::{Config, VerificationBackend},
    protocol::proof_transport::ProofLimits,
    service::{self, GpuSnapshot, NodeHandle},
    storage::Store,
};
use plan::Plan;
use serde_json::json;
use std::{thread, time::Instant};
use tokio::runtime::{Builder, Runtime};

const TOTAL: usize = 10;

struct OwnedNode {
    runtime: Runtime,
    node: NodeHandle,
    worker: Option<thread::JoinHandle<()>>,
}

impl OwnedNode {
    fn start(config: &Config) -> Result<Self, String> {
        let runtime = Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|_| "Cannot create owned fixture runtime")?;
        let (node, worker) = service::start(config)?;
        Ok(Self {
            runtime,
            node,
            worker: Some(worker),
        })
    }

    fn stop(&mut self) -> Result<(), String> {
        if let Some(worker) = self.worker.take() {
            self.runtime.block_on(self.node.stop());
            worker
                .join()
                .map_err(|_| "Owned fixture worker failed during cleanup")?;
        }
        Ok(())
    }
}

impl Drop for OwnedNode {
    fn drop(&mut self) {
        // The guard lives outside block_on: error and panic all stop/join.
        let _ = self.stop();
    }
}

fn gpu_verified(before: &GpuSnapshot, after: &GpuSnapshot) -> Result<(), String> {
    if before.selected != "cuda"
        || !before.active
        || before.device.is_none()
        || !before.cpu_oracle_checked
        || before.failures != 0
        || before.verified != 0
        || after.selected != "cuda"
        || !after.active
        || !after.cpu_oracle_checked
        || after.failures != 0
        || after.verified.checked_sub(before.verified) != Some(TOTAL as u64)
        || after.batches <= before.batches
        || after.elapsed_ns <= before.elapsed_ns
    {
        return Err("Exactly 10 actual CUDA recoveries with full CPU parity are required".into());
    }
    Ok(())
}

fn verify_restart(
    config: &Config,
    plan: &Plan,
    observations: &[flow::Observed],
    expected: &verification::Snapshot,
) -> Result<(), String> {
    let mut owner = OwnedNode::start(config)?;
    let checked: Result<(), String> = (|| {
        let gpu = owner.node.gpu_metrics();
        if owner.node.pending_count() != 0
            || owner.node.failure().is_some()
            || gpu.selected != "cuda"
            || !gpu.active
            || !gpu.cpu_oracle_checked
            || gpu.verified != 0
            || gpu.failures != 0
        {
            return Err("Restarted fixture node did not preserve its idle CUDA profile".into());
        }
        let view = owner.node.view()?;
        if verification::verify(view.as_ref(), plan, observations)? != *expected {
            return Err("Actual node restart changed fixture head, state or receipts".into());
        }
        Ok(())
    })();
    let stopped = owner.stop();
    drop(owner);
    checked?;
    stopped
}

#[test]
#[ignore = "Requires owned CUDA hardware and a fresh project-drive output; primary coordinates one run"]
fn gpu_closure_10_total_transactions_and_genesis_witness() -> Result<(), String> {
    // The ignored fixture has one coordinator-owned test process. Keep any
    // unexpected assertion payload private while Rust unwinding runs cleanup.
    std::panic::set_hook(Box::new(|_| {
        eprintln!("P4 closure fixture panic; private diagnostic payload suppressed");
    }));
    let bundle_started = Instant::now();
    let root = storage_fixture::workspace()?;
    let plan = Plan::new_with_transactions(&root, TOTAL)?;
    if plan.total != TOTAL || plan.wallets.len() != 6 || plan.genesis.capacity.max_pending != 1_000
    {
        return Err("P4 closure workload count was confused with its node capacity".into());
    }
    let config = Config {
        listen: "127.0.0.1:0"
            .parse()
            .map_err(|_| "Invalid fixture loopback setting")?,
        data_dir: root.join("data"),
        genesis: plan.genesis.clone(),
        min_gas_price: 0,
        max_checkpoint_bytes: 8 * 1024 * 1024,
        rpc: Default::default(),
        verification_workers_per_cpu: 1,
        verification_backend: VerificationBackend::Cuda,
        gpu_device: 0,
    };
    let mut owner = OwnedNode::start(&config)?;
    let before = owner.node.gpu_metrics();
    let execution_started = Instant::now();
    let outcome = owner.runtime.block_on(flow::run(&owner.node, &plan));
    let execution_elapsed_seconds = execution_started.elapsed().as_secs_f64();
    let after = owner.node.gpu_metrics();
    let checked = outcome.and_then(|observations| {
        gpu_verified(&before, &after)?;
        let (checkpoint_bytes, checkpoint_limit) = owner.node.checkpoint_capacity();
        if checkpoint_bytes > checkpoint_limit
            || checkpoint_limit != config.max_checkpoint_bytes
            || owner.node.pending_count() != 0
            || owner.node.failure().is_some()
        {
            return Err("Development fixture checkpoint or drain state differs".into());
        }
        let view = owner.node.view()?;
        let snapshot = verification::verify(view.as_ref(), &plan, &observations)?;
        Ok((observations, snapshot))
    });
    // Cleanup is unconditional before propagating any execution/verification error.
    let stopped = owner.stop();
    // The checkpoint-byte atomic is updated after receipt publication. Joining
    // the owner establishes a stable final observation before writing evidence.
    let final_checkpoint_capacity = owner.node.checkpoint_capacity();
    drop(owner);
    let (observations, before_restart) = match checked {
        Ok(result) => result,
        Err(error) => {
            let _ = storage_fixture::write_json(
                &root.join("failure.json"),
                &json!({"passed":false,"stage":"GPU-node-correctness",
                    "total_transactions":plan.total,"setup_transactions":0,
                    "capacity":plan.genesis.capacity,"wall_clock_limit_seconds":null,
                    "execution_elapsed_seconds":execution_elapsed_seconds,
                    "gpu_verified_delta":after.verified.checked_sub(before.verified),
                    "gpu_failures":after.failures,"worker_stop_join":stopped.is_ok()}),
            );
            return Err(error);
        }
    };
    stopped?;
    let checkpoint_bytes = before_restart.checkpoint.encoded_len()?;
    if final_checkpoint_capacity != (checkpoint_bytes, config.max_checkpoint_bytes) {
        return Err("Joined checkpoint meter differs from canonical final state".into());
    }
    {
        let store = Store::open_existing(&root.join("data"), &plan.genesis)?;
        if !store.pending()?.is_empty() {
            return Err("Reopened fixture has unresolved pending intents".into());
        }
        let reopened = verification::verify(&store.view()?, &plan, &observations)?;
        if reopened != before_restart {
            return Err("Actual reopen changed head, state or any of 10 receipts".into());
        }
    }
    verify_restart(&config, &plan, &observations, &before_restart)?;
    verification::export(&root, &plan, &before_restart)?;
    let original_next_block = observations
        .iter()
        .filter(|o| {
            o.receipt
                .as_ref()
                .is_some_and(|r| r.block_height == o.parent.height + 1)
        })
        .count();
    let limits = ProofLimits::for_capacity(plan.genesis.capacity)?;
    storage_fixture::write_json(
        &root.join("report.json"),
        &json!({
            "schema":1,"scope":"fresh-10-TX-local-P4-closure-correctness",
            "passed":true,"development_only":true,"total_transactions":TOTAL,
            "genesis_funded_wallet_transfers":plan.wallets.len(),"root_lifecycle_transactions":4,
            "setup_transactions":0,"durable_acks":observations.len(),
            "committed_receipts":before_restart.receipts.len(),
            "original_next_block_receipts":original_next_block,"late_receipts":TOTAL-original_next_block,
            "submission_concurrency_limit":flow::CONCURRENCY, "wall_clock_limit_seconds":null,
            "genesis_transfer_concurrency_limit":plan.wallets.len().min(flow::CONCURRENCY),
            "execution_elapsed_seconds":execution_elapsed_seconds,
            "bundle_elapsed_seconds":bundle_started.elapsed().as_secs_f64(),
            "capacity":plan.genesis.capacity,"checkpoint_bytes":checkpoint_bytes,
            "genesis_accounts":plan.genesis.accounts.len(),
            "final_accounts":before_restart.checkpoint.accounts.len(),
            "final_contract_codes":before_restart.checkpoint.codes.len(),
            "executed_gas":before_restart.receipts.iter().map(|r|r.gas_used).sum::<u64>(),
            "producer_checkpoint_limit":config.max_checkpoint_bytes,
            "proof_limits":{"checkpoint_bytes":limits.checkpoint_bytes,
                "transcript_bytes":limits.transcript_bytes,"input_bytes":limits.input_bytes,
                "frame_bytes":limits.frame_bytes},
            "gpu":{"selected":after.selected,"active":after.active,
                "verified_delta":after.verified-before.verified,"batches_delta":after.batches-before.batches,
                "elapsed_ns_delta":after.elapsed_ns-before.elapsed_ns,
                "failures":after.failures,"full_cpu_oracle":after.cpu_oracle_checked},
            "head":before_restart.head,"state_digest":before_restart.state_digest,
            "ordered_ancestry_and_membership_verified":true,"exact_accounting_verified":true,
            "stopped_owned_worker":true,"actual_reopen_verified":true,"actual_node_restart_verified":true,"pending":0,
            "owned_service_starts":2,"owned_service_stop_joins":2,
            "http_listener_started":false,"test_process_exit_requires_coordinator_verification":true,
            "witness_schema":4,"witness_from_genesis":true,
            "guest_proof_generated":false,"settlement_verified":false,"private_outputs_retained":true
        }),
    )
}
