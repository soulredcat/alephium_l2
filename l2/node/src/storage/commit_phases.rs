//! Wall-clock diagnostics for a successfully durable commit. These intervals
//! describe host work; `sync_all_commit` includes database CPU and persistence,
//! and must never be reported as pure physical-SSD latency.
use std::time::Duration;

#[derive(Clone, Copy, Debug, Default)]
pub struct CommitPhaseTimings {
    pub validation_pending: Duration,
    pub prior_normalization: Duration,
    pub encoding_hash: Duration,
    pub checkpoint_capacity: Duration,
    pub batch_build: Duration,
    pub sync_all_commit: Duration,
    /// Apply tracked checkpoint state and capture the durable ReadView;
    /// caller/service publication is outside this Store interval.
    pub publish_view: Duration,
}
