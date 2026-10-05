//! Payload-free diagnostic counters, independent of commitment and ACK state.
use serde::Serialize;
use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct StageSnapshot {
    pub total_ns: u64,
    pub max_ns: u64,
    pub samples: u64,
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct MetricsSnapshot {
    pub validation: StageSnapshot,
    /// Entire Store.admit_batch call, including codec, lookup and SyncAll.
    pub durable_admission: StageSnapshot,
    pub selection: StageSnapshot,
    pub execution: StageSnapshot,
    /// Entire Store.commit_bounded call; this is not a pure disk measurement.
    pub durable_block_commit: StageSnapshot,
    /// Unique new intents whose admission store call completed successfully.
    pub admitted_transactions: u64,
    /// Receipt-producing executions from completed execution attempts, including
    /// an attempt that later cannot fit the state bound and is retried.
    pub executed_transactions: u64,
}

#[derive(Default)]
pub(super) struct Stage {
    total_ns: AtomicU64,
    max_ns: AtomicU64,
    samples: AtomicU64,
}

fn add(counter: &AtomicU64, value: u64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |prior| {
        Some(prior.saturating_add(value))
    });
}

impl Stage {
    pub(super) fn record(&self, elapsed: Duration) {
        let ns = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
        add(&self.total_ns, ns);
        self.max_ns.fetch_max(ns, Ordering::Relaxed);
        add(&self.samples, 1);
    }

    fn snapshot(&self) -> StageSnapshot {
        StageSnapshot {
            total_ns: self.total_ns.load(Ordering::Relaxed),
            max_ns: self.max_ns.load(Ordering::Relaxed),
            samples: self.samples.load(Ordering::Relaxed),
        }
    }
}

#[derive(Default)]
pub(super) struct Metrics {
    pub(super) validation: Stage,
    pub(super) durable_admission: Stage,
    pub(super) selection: Stage,
    pub(super) execution: Stage,
    pub(super) durable_block_commit: Stage,
    admitted_transactions: AtomicU64,
    executed_transactions: AtomicU64,
}

impl Metrics {
    pub(super) fn admitted(&self, count: usize) {
        add(&self.admitted_transactions, count as u64);
    }

    pub(super) fn executed(&self, count: usize) {
        add(&self.executed_transactions, count as u64);
    }

    pub(super) fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            validation: self.validation.snapshot(),
            durable_admission: self.durable_admission.snapshot(),
            selection: self.selection.snapshot(),
            execution: self.execution.snapshot(),
            durable_block_commit: self.durable_block_commit.snapshot(),
            admitted_transactions: self.admitted_transactions.load(Ordering::Relaxed),
            executed_transactions: self.executed_transactions.load(Ordering::Relaxed),
        }
    }
}
