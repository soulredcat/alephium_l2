//! One client-only head poller; receipt waiters have no polling timers.
use alephium_l2_node::{protocol::Receipt, service::NodeHandle, storage::ReadView};
use alloy_primitives::B256;
use serde::Serialize;
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{sync::watch, task::JoinHandle};

pub(super) const COLLECTION_TIMEOUT_SECS: u64 = 120;
pub(super) type Heads = watch::Receiver<Arc<ReadView>>;

#[derive(Clone, Copy, Serialize)]
pub(super) struct Stats {
    pub view_polls: u64,
    pub head_broadcasts: u64,
}

#[derive(Default)]
struct Counters {
    polls: AtomicU64,
    broadcasts: AtomicU64,
}

pub(super) struct Observer {
    heads: Heads,
    task: Option<JoinHandle<Result<(), String>>>,
    counters: Arc<Counters>,
}

impl Observer {
    pub(super) fn start(node: NodeHandle) -> Result<Self, String> {
        let initial = node.view()?;
        let mut head = initial.head.commit_id;
        let (sender, heads) = watch::channel(initial);
        let counters = Arc::new(Counters::default());
        counters.polls.store(1, Ordering::Relaxed);
        let task_counters = counters.clone();
        let task = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(5)).await;
                if node.failure().is_some() {
                    return Err("Node failed during shared receipt observation".into());
                }
                let view = node.view()?;
                task_counters.polls.fetch_add(1, Ordering::Relaxed);
                if view.head.commit_id != head {
                    head = view.head.commit_id;
                    sender.send_replace(view);
                    task_counters.broadcasts.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        Ok(Self {
            heads,
            task: Some(task),
            counters,
        })
    }

    pub(super) fn subscribe(&self) -> Heads {
        self.heads.clone()
    }

    /// Always called after collection, including error/timeout. Drop remains
    /// an abort fallback during unwinding; normal outcomes also await join.
    pub(super) async fn close(&mut self) -> Result<Stats, String> {
        if let Some(task) = self.task.take() {
            task.abort();
            match task.await {
                Ok(result) => result?,
                Err(error) if error.is_cancelled() => (),
                Err(_) => return Err("Shared head observer task panicked".into()),
            }
        }
        Ok(Stats {
            view_polls: self.counters.polls.load(Ordering::Relaxed),
            head_broadcasts: self.counters.broadcasts.load(Ordering::Relaxed),
        })
    }
}

impl Drop for Observer {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

pub(super) async fn receipt(mut heads: Heads, hash: B256) -> Result<Receipt, String> {
    let mut checked = None;
    loop {
        // Clone the immutable view, then release the watch lock before DB I/O.
        // The latest view may already contain a receipt when the ACK arrives.
        let view = { heads.borrow_and_update().clone() };
        if checked != Some(view.head.commit_id) {
            checked = Some(view.head.commit_id);
            if let Some(receipt) = view.receipt(hash)? {
                return Ok(receipt);
            }
        }
        drop(view);
        heads
            .changed()
            .await
            .map_err(|_| "Shared head observer stopped".to_string())?;
    }
}
