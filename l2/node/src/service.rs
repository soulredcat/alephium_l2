use crate::{
    config::Config,
    execution,
    protocol::*,
    storage::{ReadView, Store},
};
use alloy_primitives::B256;
use std::{
    sync::{
        Arc, RwLock,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};

mod admission;
mod metrics;
pub use metrics::{MetricsSnapshot, StageSnapshot};
#[cfg(test)]
mod admission_tests;
mod preparation;
mod prepared_cache;
mod production;
#[cfg(test)]
mod queue_tests;
mod scheduling;
#[cfg(test)]
mod tests;

enum Command {
    Submit {
        raw: Vec<u8>,
        head: Head,
        arrived: Instant,
        slot: OwnedSemaphorePermit,
        reply: oneshot::Sender<Result<(TransactionStatus, Head), String>>,
    },
    Stop,
}

#[derive(Clone)]
pub struct NodeHandle {
    sender: mpsc::Sender<Command>,
    queued: Arc<Semaphore>,
    view: Arc<RwLock<Arc<ReadView>>>,
    failure: Arc<RwLock<Option<String>>>,
    pending: Arc<AtomicUsize>,
    min_gas_price: u128,
    checkpoint_bytes: Arc<AtomicUsize>,
    checkpoint_limit: usize,
    capacity: Capacity,
    metrics: Arc<metrics::Metrics>,
    available_cpus: usize,
    hardware_verification_budget: usize,
    workers_per_cpu: usize,
    verification_workers: usize,
}

impl NodeHandle {
    /// Available logical CPUs reported by the OS at startup, respecting the
    /// process environment; this is not a physical-core reservation.
    pub fn available_cpus(&self) -> usize {
        self.available_cpus
    }

    /// Logical CPU-minus-one base budget before the operator's worker factor.
    pub fn hardware_verification_budget(&self) -> usize {
        self.hardware_verification_budget
    }

    /// Operator-selected multiplier; a value greater than one oversubscribes
    /// the hardware base budget and does not add physical CPUs.
    pub fn workers_per_cpu(&self) -> usize {
        self.workers_per_cpu
    }

    /// Configured verification task ceiling, including the owning core. Actual
    /// scoped tasks are also bounded by available inputs.
    pub fn verification_workers(&self) -> usize {
        self.verification_workers
    }

    /// Limits pinned by this node's canonical genesis/profile.
    pub fn capacity(&self) -> Capacity {
        self.capacity
    }

    /// Cumulative diagnostics. Maxima are cumulative and cannot be subtracted.
    pub fn metrics(&self) -> MetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Admission floor for the effective gas price, in wei.
    pub fn min_gas_price(&self) -> u128 {
        self.min_gas_price
    }

    pub fn view(&self) -> Result<Arc<ReadView>, String> {
        self.view
            .read()
            .map(|v| v.clone())
            .map_err(|_| "Read view unavailable".into())
    }

    pub fn failure(&self) -> Option<String> {
        self.failure
            .read()
            .map(|s| s.clone())
            .unwrap_or_else(|_| Some("Node lock failure".into()))
    }

    /// Encoded execution checkpoint size of the published head, and its bound.
    pub fn checkpoint_capacity(&self) -> (usize, usize) {
        (
            self.checkpoint_bytes.load(Ordering::Relaxed),
            self.checkpoint_limit,
        )
    }

    pub fn pending_count(&self) -> usize {
        self.pending.load(Ordering::Relaxed)
    }

    pub fn mark_failed(&self) {
        if let Ok(mut failure) = self.failure.write() {
            *failure = Some("Durable processing stopped; restart and recovery required".into());
        }
        self.queued.close();
    }

    pub async fn submit(&self, raw: Vec<u8>) -> Result<TransactionStatus, String> {
        self.submit_with_head(raw).await.map(|(status, _)| status)
    }

    /// Capture the committed head at request arrival, before the writer queue.
    /// The original next block is a reporting target, not an admission deadline.
    /// This never waits for a receipt or a batch deadline.
    pub async fn submit_with_head(
        &self,
        raw: Vec<u8>,
    ) -> Result<(TransactionStatus, Head), String> {
        if self.failure().is_some() {
            return Err("Recovery required".into());
        }
        if raw.is_empty() || raw.len() > MAX_TRANSACTION_BYTES {
            return Err("Transaction encoding exceeds admission bounds".into());
        }
        let arrived = Instant::now();
        let head = self.view()?.head.clone();
        let slot = self.queued.clone().acquire_owned().await.map_err(|_| {
            if self.failure().is_some() {
                "Recovery required"
            } else {
                "Node stopping before admission"
            }
        })?;
        if self.failure().is_some() {
            return Err("Recovery required".into());
        }
        let (reply, receive) = oneshot::channel();
        self.sender
            .send(Command::Submit {
                raw,
                head,
                arrived,
                slot,
                reply,
            })
            .map_err(|_| "Admission queue unavailable or full")?;
        receive
            .await
            .map_err(|_| "Outcome ambiguous; reconcile original transaction identity".to_string())?
    }

    pub async fn stop(&self) {
        // Wake requests that have not entered the queue. Queued commands keep
        // their permits until received/dropped and retain FIFO Stop ordering.
        self.queued.close();
        let _ = self.sender.send(Command::Stop);
    }
}

struct Core {
    store: Store,
    head: Head,
    pending: Vec<Pending>,
    prepared: std::collections::HashMap<B256, execution::PreparedTransaction>,
    handle: NodeHandle,
}

impl Core {
    fn context(&self) -> Result<BlockContext, String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "Clock is before Unix epoch")?
            .as_secs();
        Ok(BlockContext {
            number: self
                .head
                .height
                .checked_add(1)
                .ok_or("Block height overflow")?,
            timestamp: now.max(self.head.timestamp),
            gas_limit: self.handle.capacity.block_gas,
        })
    }

    fn publish(&mut self, view: ReadView) -> Result<(), String> {
        self.head = view.head.clone();
        *self
            .handle
            .view
            .write()
            .map_err(|_| "Read view publication failure")? = Arc::new(view);
        self.handle
            .pending
            .store(self.pending.len(), Ordering::Relaxed);
        if let Some((bytes, _)) = self.store.checkpoint_capacity() {
            self.handle.checkpoint_bytes.store(bytes, Ordering::Relaxed);
        }
        Ok(())
    }

    fn fail(&self) {
        self.handle.mark_failed();
    }
}

pub fn start(config: &Config) -> Result<(NodeHandle, thread::JoinHandle<()>), String> {
    let (available_cpus, hardware_verification_budget) = preparation::detected_budget();
    let workers_per_cpu = config.verification_workers_per_cpu;
    // Direct Config callers receive the same check before opening/creating data.
    let verification_workers = preparation::configured_budget(available_cpus, workers_per_cpu)?;
    let maximum = crate::operator::MAX_CONTINUATION_CHECKPOINT_BYTES;
    if !(1..=maximum).contains(&config.max_checkpoint_bytes) {
        return Err(format!(
            "Checkpoint capacity must be from 1 to {maximum} bytes"
        ));
    }
    let mut store = Store::open(&config.data_dir, &config.genesis)?;
    // Every committed head may start a proven batch, so the producer keeps
    // the encoded execution checkpoint within the continuation bound.
    store.enable_capacity(config.max_checkpoint_bytes)?;
    let (checkpoint_bytes, checkpoint_limit) = store
        .checkpoint_capacity()
        .ok_or("Checkpoint capacity tracking is unavailable")?;
    let view = store.view()?;
    let capacity = view.capacity();
    let pending = store.pending()?;
    if pending.len() > capacity.max_pending {
        return Err("Persisted pending queue exceeds bound".into());
    }
    let mut senders = std::collections::HashSet::new();
    let raw_inputs: Vec<_> = pending.iter().map(|entry| entry.raw.as_slice()).collect();
    let verified =
        preparation::prepare_parallel(&raw_inputs, view.chain_id(), verification_workers)?;
    let mut prepared = std::collections::HashMap::with_capacity(pending.len());
    for (entry, verified) in pending.iter().zip(verified) {
        let verified = verified?;
        let info = verified.info();
        if info.hash != entry.hash
            || info.sender != entry.sender
            || !senders.insert(info.sender)
            || info.gas_limit > capacity.block_gas
            || entry.raw.len() > MAX_TRANSACTION_BYTES
        {
            return Err("Invalid persisted admission identity".into());
        }
        prepared.insert(entry.hash, verified);
    }
    let (sender, receive) = mpsc::channel();
    let handle = NodeHandle {
        sender,
        queued: Arc::new(Semaphore::new(capacity.max_pending)),
        view: Arc::new(RwLock::new(Arc::new(view.clone()))),
        failure: Arc::new(RwLock::new(None)),
        pending: Arc::new(AtomicUsize::new(pending.len())),
        min_gas_price: config.min_gas_price,
        checkpoint_bytes: Arc::new(AtomicUsize::new(checkpoint_bytes)),
        checkpoint_limit,
        capacity,
        metrics: Arc::new(metrics::Metrics::default()),
        available_cpus,
        hardware_verification_budget,
        workers_per_cpu,
        verification_workers,
    };
    let core = Core {
        store,
        head: view.head,
        pending,
        prepared,
        handle: handle.clone(),
    };
    let worker = thread::Builder::new()
        .name("l2-core".into())
        .spawn(move || scheduling::run(core, receive))
        .map_err(|e| e.to_string())?;
    Ok((handle, worker))
}

pub fn transaction_hash(value: &str) -> Result<B256, String> {
    value
        .parse()
        .map_err(|_| "Invalid transaction identity".into())
}
