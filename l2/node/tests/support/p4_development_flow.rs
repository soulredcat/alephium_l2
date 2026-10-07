//! Bounded service submissions and receipt observation, with no HTTP listener.
use super::plan::{Expected, Plan, Signed};
use alephium_l2_node::{
    protocol::{Head, Receipt},
    service::NodeHandle,
};
use std::time::Duration;
use tokio::task::JoinSet;

pub(super) const CONCURRENCY: usize = 32;

pub(super) struct Observed {
    pub expected: Expected,
    pub parent: Head,
    pub receipt: Option<Receipt>,
}

pub(super) async fn run(node: &NodeHandle, plan: &Plan) -> Result<Vec<Observed>, String> {
    let mut inputs = plan.transfers()?.into_iter();
    let mut tasks = JoinSet::new();
    let mut observations = Vec::with_capacity(plan.total);
    for _ in 0..CONCURRENCY {
        if let Some(input) = inputs.next() {
            let node = node.clone();
            tasks.spawn(async move { submit(&node, input).await });
        }
    }
    while let Some(outcome) = tasks.join_next().await {
        observations.push(outcome.map_err(|_| "Fixture admission task failed")??);
        if let Some(input) = inputs.next() {
            let node = node.clone();
            tasks.spawn(async move { submit(&node, input).await });
        }
    }
    if observations.len() != plan.wallets.len() {
        return Err("Fixture transfer admission count differs".into());
    }
    observe(node, &mut observations).await?;
    for step in 0..4 {
        let mut observation = vec![submit(node, plan.root_transaction(step)?).await?];
        observe(node, &mut observation).await?;
        observations.extend(observation);
    }
    while node.pending_count() != 0 && node.failure().is_none() {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    if observations.len() != plan.total || node.pending_count() != 0 || node.failure().is_some() {
        return Err("P4 fixture did not drain its exact declared transaction count".into());
    }
    Ok(observations)
}

async fn submit(node: &NodeHandle, signed: Signed) -> Result<Observed, String> {
    let (status, parent) = node.submit_with_head(signed.raw).await?;
    if status.hash != signed.expected.hash
        || status.status != "durably_accepted"
        || status.block_height.is_some()
        || status.error.is_some()
    {
        return Err("Fixture transaction did not receive a durable admission ACK".into());
    }
    Ok(Observed {
        expected: signed.expected,
        parent,
        receipt: None,
    })
}

async fn observe(node: &NodeHandle, observations: &mut [Observed]) -> Result<(), String> {
    let mut checked_head = None;
    loop {
        if node.failure().is_some() {
            return Err("Node failed during bounded fixture receipt observation".into());
        }
        {
            let view = node.view()?;
            // A durable discard can leave the head unchanged and has no
            // receipt. Treat that actual failure as terminal without a timer.
            for observation in observations.iter().filter(|o| o.receipt.is_none()) {
                let status = view
                    .status(observation.expected.hash)?
                    .ok_or("Durably admitted fixture transaction status disappeared")?;
                if status.status == "rejected" || status.error.is_some() {
                    return Err("Fixture transaction reached a rejected terminal outcome".into());
                }
            }
            if checked_head != Some(view.head.commit_id) {
                checked_head = Some(view.head.commit_id);
                for observation in observations.iter_mut().filter(|o| o.receipt.is_none()) {
                    observation.receipt = view.receipt(observation.expected.hash)?;
                }
            }
        }
        if observations.iter().all(|o| o.receipt.is_some()) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
