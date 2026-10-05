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
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::oneshot;

enum Command {
    Submit(Vec<u8>, oneshot::Sender<Result<TransactionStatus, String>>),
    Stop,
}

#[derive(Clone)]
pub struct NodeHandle {
    sender: mpsc::SyncSender<Command>,
    view: Arc<RwLock<Arc<ReadView>>>,
    failure: Arc<RwLock<Option<String>>>,
    pending: Arc<AtomicUsize>,
}

impl NodeHandle {
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

    pub fn pending_count(&self) -> usize {
        self.pending.load(Ordering::Relaxed)
    }

    pub fn mark_failed(&self) {
        if let Ok(mut failure) = self.failure.write() {
            *failure = Some("Durable processing stopped; restart and recovery required".into());
        }
    }

    pub async fn submit(&self, raw: Vec<u8>) -> Result<TransactionStatus, String> {
        if self.failure().is_some() {
            return Err("Recovery required".into());
        }
        let (reply, receive) = oneshot::channel();
        self.sender
            .try_send(Command::Submit(raw, reply))
            .map_err(|_| "Admission queue unavailable or full")?;
        receive
            .await
            .map_err(|_| "Outcome ambiguous; reconcile original transaction identity".to_string())?
    }

    pub async fn stop(&self) {
        let sender = self.sender.clone();
        let _ = tokio::task::spawn_blocking(move || sender.send(Command::Stop)).await;
    }
}

struct Core {
    store: Store,
    head: Head,
    pending: Vec<Pending>,
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
            gas_limit: BLOCK_GAS,
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
        Ok(())
    }

    fn submit(&mut self, raw: Vec<u8>) -> Result<TransactionStatus, String> {
        if raw.is_empty() || raw.len() > MAX_TRANSACTION_BYTES {
            return Err("Transaction encoding exceeds admission bounds".into());
        }
        let hash = alloy_primitives::keccak256(&raw);
        let view = self.handle.view()?;
        match view.status(hash) {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => (),
            Err(_) => {
                self.fail();
                return Err("Status unavailable; recovery required".into());
            }
        }
        if self.pending.len() >= MAX_PENDING {
            return Err("Pending queue full".into());
        }
        let info =
            execution::validate((*view).clone(), &raw, self.context()?).inspect_err(|e| {
                if execution::is_infrastructure_error(e) {
                    self.fail();
                }
            })?;
        if info.gas_limit > BLOCK_GAS || info.gas_limit == 0 {
            return Err("Transaction cannot fit block gas budget".into());
        }
        if self.pending.iter().any(|p| p.sender == info.sender) {
            return Err("One pending transaction per sender is supported".into());
        }
        let pending = Pending {
            hash,
            sender: info.sender,
            raw,
        };
        // Any ambiguous persistence failure is terminal; a client error cannot undo intent.
        let status = match self.store.admit(pending.clone()) {
            Ok(status) => status,
            Err(_) => {
                self.fail();
                return Err("Durable admission failed; reconcile after recovery".into());
            }
        };
        self.pending.push(pending);
        match self.store.view().and_then(|v| self.publish(v)) {
            Ok(()) => Ok(status),
            Err(_) => {
                self.fail();
                Err("Outcome ambiguous; recovery required".into())
            }
        }
    }

    fn produce(&mut self) -> Result<(), String> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let mut selected = Vec::new();
        let mut reserved_gas = 0u64;
        let mut bytes = 4096usize;
        let view = self.handle.view()?;
        for pending in &self.pending {
            let info = execution::inspect_for_chain(&pending.raw, view.chain_id())?;
            if reserved_gas.saturating_add(info.gas_limit) > BLOCK_GAS
                || bytes.saturating_add(pending.raw.len() + 40) > BLOCK_BYTES
            {
                break;
            }
            reserved_gas += info.gas_limit;
            bytes += pending.raw.len() + 40;
            selected.push(pending.raw.clone());
        }
        if selected.is_empty() {
            return Err("Persisted pending transaction cannot fit block".into());
        }
        let context = self.context()?;
        let result = execution::execute_block((*view).clone(), &selected, context)?;
        let commit = BlockCommit {
            parent: self.head.clone(),
            context,
            transactions: result.receipts.iter().map(|r| r.hash).collect(),
            changes: result.changes,
            receipts: result.receipts,
            rejected: result.rejected,
        };
        let new_view = self.store.commit(commit)?;
        self.pending.drain(..selected.len());
        self.publish(new_view)
    }

    fn fail(&self) {
        self.handle.mark_failed();
    }
}

pub fn start(config: &Config) -> Result<(NodeHandle, thread::JoinHandle<()>), String> {
    let store = Store::open(&config.data_dir, &config.genesis)?;
    let view = store.view()?;
    let pending = store.pending()?;
    if pending.len() > MAX_PENDING {
        return Err("Persisted pending queue exceeds bound".into());
    }
    let mut senders = std::collections::HashSet::new();
    for entry in &pending {
        let info = execution::inspect_for_chain(&entry.raw, view.chain_id())?;
        if info.hash != entry.hash
            || info.sender != entry.sender
            || !senders.insert(info.sender)
            || info.gas_limit > BLOCK_GAS
            || entry.raw.len() > MAX_TRANSACTION_BYTES
        {
            return Err("Invalid persisted admission identity".into());
        }
    }
    let (sender, receive) = mpsc::sync_channel(MAX_PENDING);
    let handle = NodeHandle {
        sender,
        view: Arc::new(RwLock::new(Arc::new(view.clone()))),
        failure: Arc::new(RwLock::new(None)),
        pending: Arc::new(AtomicUsize::new(pending.len())),
    };
    let mut core = Core {
        store,
        head: view.head,
        pending,
        handle: handle.clone(),
    };
    let worker = thread::Builder::new()
        .name("l2-core".into())
        .spawn(move || {
            let interval = Duration::from_millis(BLOCK_INTERVAL_MS);
            let mut deadline = Instant::now() + interval;
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                loop {
                    if Instant::now() >= deadline {
                        if core.handle.failure().is_none() && core.produce().is_err() {
                            core.fail();
                        }
                        deadline = Instant::now() + interval;
                    }
                    match receive.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                        Ok(Command::Submit(raw, reply)) => {
                            let result = if core.handle.failure().is_some() {
                                Err("Recovery required".into())
                            } else {
                                core.submit(raw)
                            };
                            let _ = reply.send(result);
                        }
                        Ok(Command::Stop) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                        Err(mpsc::RecvTimeoutError::Timeout) => (),
                    }
                }
            }));
            if outcome.is_err() {
                core.fail();
            }
        })
        .map_err(|e| e.to_string())?;
    Ok((handle, worker))
}

pub fn transaction_hash(value: &str) -> Result<B256, String> {
    value
        .parse()
        .map_err(|_| "Invalid transaction identity".into())
}
