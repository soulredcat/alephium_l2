//! Live development-PC correctness for up to 100 native transfers.
//! Every request targets arrival-head+1; the 100-case must fully enter block 1.
//! No pre-admission, producer barrier, artificial block delay or ACK hold is used.
//! Service-level concurrency is not HTTP throughput or production capacity.
#[path = "support/next_block_fixture.rs"]
mod fixture;

use alephium_l2_node::{
    config::Config,
    operator,
    protocol::{Head, Receipt},
    service::{self, NodeHandle},
    storage::Store,
};
use alloy_primitives::B256;
use fixture::{Expected, Plan, verify};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};
use tokio::task::JoinSet;

struct Observed {
    hash: B256,
    parent: Head,
    durable_ack: bool,
    ack_ms: u128,
    receipt_ms: Option<u128>,
    receipt_height: Option<u64>,
    error: Option<String>,
}

fn count() -> Result<usize, String> {
    let count = match std::env::var("L2_NEXT_BLOCK_TRANSFERS") {
        Ok(value) => value
            .parse()
            .map_err(|_| "Invalid fixture transaction count")?,
        Err(std::env::VarError::NotPresent) => 100,
        Err(_) => return Err("Invalid fixture transaction count encoding".into()),
    };
    if !(1..=100).contains(&count) {
        return Err("Fixture transaction count must be from 1 to 100".into());
    }
    Ok(count)
}

async fn receipt(node: &NodeHandle, hash: B256) -> Result<Receipt, String> {
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if node.failure().is_some() {
                return Err("Producer failed while resolving fixture transactions".into());
            }
            if let Some(receipt) = node.view()?.receipt(hash)? {
                return Ok(receipt);
            }
            // Only this client awaits availability; the core remains independent.
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| "Receipt safety timeout".to_string())?
}

async fn submit(node: NodeHandle, item: Expected, raw: Vec<u8>) -> Result<Observed, String> {
    let started = Instant::now();
    let parent = node.view()?.head.clone();
    let outcome = node.submit_with_head(raw).await;
    let mut observed = Observed {
        hash: item.hash,
        parent,
        durable_ack: false,
        ack_ms: started.elapsed().as_millis(),
        receipt_ms: None,
        receipt_height: None,
        error: None,
    };
    match outcome {
        Ok((status, queued_head)) => {
            observed.durable_ack = status.status == "durably_accepted"
                && status.hash == item.hash
                && status.block_height.is_none()
                && status.error.is_none();
            if !observed.durable_ack {
                observed.error = Some("New transaction did not receive a durable ACK".into());
            } else if queued_head != observed.parent {
                observed.error =
                    Some("Request head changed between arrival observation and enqueue".into());
            }
        }
        Err(error) => observed.error = Some(error),
    }
    if observed.durable_ack {
        match receipt(&node, item.hash).await {
            Ok(receipt) => {
                observed.receipt_ms = Some(started.elapsed().as_millis());
                observed.receipt_height = Some(receipt.block_height);
                if receipt.block_height != observed.parent.height + 1 {
                    observed.error =
                        Some("Accepted transaction missed its original next block".into());
                }
            }
            Err(error) => observed.error = Some(error),
        }
    }
    Ok(observed)
}

async fn exercise(
    node: &NodeHandle,
    plan: &Plan,
) -> Result<(Vec<Expected>, Vec<Observed>, u128), String> {
    // Signing happens with the already running, idle-capable producer.
    let signed = plan.sign()?;
    let expected = signed.iter().map(|(item, _)| item.clone()).collect();
    let mut requests = JoinSet::new();
    let dispatched = Instant::now();
    for (item, raw) in signed {
        requests.spawn(submit(node.clone(), item, raw));
    }
    let outcome = async {
        let mut observations = Vec::new();
        while let Some(result) = requests.join_next().await {
            observations.push(result.map_err(|_| "Fixture request task stopped")??);
        }
        Ok::<_, String>(observations)
    }
    .await;
    drop(requests);
    Ok((expected, outcome?, dispatched.elapsed().as_millis()))
}

fn report(
    observations: &[Observed],
    count: usize,
    blocks: u64,
    elapsed_ms: u128,
    passed: bool,
) -> Value {
    let mut targets = BTreeMap::<u64, (usize, usize, usize)>::new();
    for observed in observations {
        let target = observed.parent.height + 1;
        let row = targets.entry(target).or_default();
        row.0 += 1;
        row.1 += usize::from(observed.durable_ack);
        row.2 += usize::from(observed.receipt_height == Some(target));
    }
    let inclusion: Vec<_> = targets
        .into_iter()
        .map(|(target, (arrived, acked, included))| {
            json!({"arrival_head":target-1,"original_target_block":target,
            "arrivals":arrived,"durable_acks":acked,"included":included})
        })
        .collect();
    json!({
        "scope":"live_native_original_next_block_correctness","passed":passed,
        "transactions":count,
        "durable_acks":observations.iter().filter(|item|item.durable_ack).count(),
        "original_next_block_receipts":observations.iter().filter(|item|
            item.receipt_height==Some(item.parent.height+1)).count(),
        "blocks":blocks,"elapsed_ms":elapsed_ms,
        "ack_ms":{"min":observations.iter().filter(|item|item.durable_ack).map(|item|item.ack_ms).min(),
            "max":observations.iter().filter(|item|item.durable_ack).map(|item|item.ack_ms).max()},
        "receipt_ms":{"min":observations.iter().filter_map(|item|item.receipt_ms).min(),
            "max":observations.iter().filter_map(|item|item.receipt_ms).max()},
        "inclusion_by_original_target":inclusion,
        "errors":observations.iter().filter_map(|item|item.error.as_ref()).collect::<Vec<_>>(),
        "reopen_accounting_verified":passed,"timing_assertions":false
    })
}

#[tokio::test]
async fn live_native_transfers_enter_their_original_next_block_and_survive_reopen()
-> Result<(), String> {
    let count = count()?;
    let directory = tempfile::tempdir().map_err(|error| error.to_string())?;
    let plan = Plan::new(directory.path(), count)?;
    let config = Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        data_dir: directory.path().join("data"),
        genesis: plan.genesis.clone(),
        min_gas_price: 1,
        max_checkpoint_bytes: operator::MAX_CONTINUATION_CHECKPOINT_BYTES,
        rpc: Default::default(),
        verification_workers_per_cpu: 1,
    };
    let (node, worker) = service::start(&config)?;
    assert_eq!(node.view()?.head.height, 0);
    assert_eq!(node.pending_count(), 0);
    let outcome = exercise(&node, &plan).await;
    // All submitted requests are observed before successful cleanup. There is
    // no stop or synchronization during admission, ACK or block production.
    node.stop().await;
    tokio::task::spawn_blocking(move || worker.join().map_err(|_| "Fixture worker panicked"))
        .await
        .map_err(|_| "Fixture cleanup task stopped")??;
    let (expected, observations, elapsed_ms) = outcome?;
    let view = node.view()?;
    let healthy = observations.len() == count
        && node.failure().is_none()
        && node.pending_count() == 0
        && view.head.height == 1
        && observations.iter().all(|item| {
            item.parent.height == 0
                && item.durable_ack
                && item.receipt_height == Some(1)
                && item.error.is_none()
        });
    if !healthy {
        println!(
            "{}",
            report(&observations, count, view.head.height, elapsed_ms, false)
        );
        return Err("Live original-next-block acceptance failed; see observation counters".into());
    }
    let receipts = verify(&view, &expected)?;
    for observed in &observations {
        let receipt = view
            .receipt(observed.hash)?
            .ok_or("Missing arrival-correlated receipt")?;
        let block = view
            .replay_block(receipt.block_height)?
            .ok_or("Missing arrival-correlated block")?;
        assert_eq!(block.parent, observed.parent);
        assert_eq!(receipt.block_height, observed.parent.height + 1);
    }
    let head = view.head.clone();
    let digest = view.state_digest()?;
    drop(view);
    drop(node);

    let store = Store::open_existing(&config.data_dir, &config.genesis)?;
    assert!(store.pending()?.is_empty());
    let restored = store.view()?;
    assert_eq!(restored.head, head);
    assert_eq!(restored.state_digest()?, digest);
    assert_eq!(verify(&restored, &expected)?, receipts);
    println!(
        "{}",
        report(&observations, count, head.height, elapsed_ms, true)
    );
    Ok(())
}
