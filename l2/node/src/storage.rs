mod block;
mod blocks;
mod capacity;
mod checkpoint;
mod commit_phases;
mod discard;
mod publisher;
use crate::protocol::encoding;
pub(crate) mod path;
mod records;
mod recovery;
mod transactions;
mod view;

pub use capacity::CapacityExceeded;
pub use commit_phases::CommitPhaseTimings;
pub use view::ReadView;

use crate::protocol::{Account, Capacity, Genesis, Head};
use alloy_primitives::keccak256;
use fjall::{
    Database, Keyspace, KeyspaceCreateOptions, OwnedWriteBatch as WriteBatch, PersistMode,
};
use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

/// Authoritative writes belong to the sole synchronous core owner.
pub struct Store {
    database: Database,
    items: Keyspace,
    publisher_items: Keyspace,
    chain_id: u64,
    profile_capacity: Capacity,
    block_index_complete: bool,
    /// Checkpoint size tracking, enabled by the block producer.
    capacity: Option<capacity::Capacity>,
    last_commit_phases: Option<CommitPhaseTimings>,
    terminal: Arc<AtomicBool>,
    #[cfg(test)]
    fail_next: bool,
}

impl Store {
    pub fn open(path: &Path, genesis: &Genesis) -> Result<Self, String> {
        Self::open_profile(path, genesis, false)
    }

    /// Recovery/backup callers must never bless lost genesis records by
    /// initializing a new chain in an existing artifact.
    pub fn open_existing(path: &Path, genesis: &Genesis) -> Result<Self, String> {
        Self::open_profile(path, genesis, true)
    }

    fn open_profile(path: &Path, genesis: &Genesis, existing_only: bool) -> Result<Self, String> {
        let identity = records::genesis_bytes(genesis)?;
        let path = if existing_only {
            path::existing_owned(path)?
        } else {
            path::guard(path)?
        };
        let had_version = path
            .join("version")
            .try_exists()
            .map_err(|e| e.to_string())?;
        if existing_only && !had_version {
            return Err("Existing database has no engine version".into());
        }
        // existing_owned already checked the marker and may return a Windows
        // verbatim canonical path. It must not re-enter creation/path parsing.
        if !existing_only {
            path::mark(&path)?;
        }
        let database = Database::builder(path).open().map_err(engine_error)?;
        let items = database
            .keyspace("l2", KeyspaceCreateOptions::default)
            .map_err(engine_error)?;
        let publisher_items = database
            .keyspace("l2-publisher-v1", KeyspaceCreateOptions::default)
            .map_err(engine_error)?;
        let mut store = Self {
            database,
            items,
            publisher_items,
            chain_id: genesis.chain_id,
            profile_capacity: genesis.capacity,
            block_index_complete: false,
            capacity: None,
            last_commit_phases: None,
            terminal: Arc::new(AtomicBool::new(false)),
            #[cfg(test)]
            fail_next: false,
        };
        match store.items.get([0x01]).map_err(engine_error)? {
            Some(existing) if existing.as_ref() != identity => {
                return Err("persisted genesis or protocol profile does not match".into());
            }
            Some(_) => {}
            None => {
                if existing_only || had_version {
                    return Err("Existing database is missing its persisted genesis/profile".into());
                }
                if store.items.iter().next().is_some() {
                    return Err("nonempty database has no development identity".into());
                }
                store.initialize(genesis, &identity)?;
            }
        }
        store.block_index_complete = recovery::validate(&store.view()?, genesis, &identity)?;
        publisher::validate_open(&store)?;
        Ok(store)
    }

    fn initialize(&mut self, genesis: &Genesis, identity: &[u8]) -> Result<(), String> {
        let mut batch = self.batch()?;
        batch.insert(&self.items, vec![0x01], identity.to_vec());
        batch.insert(
            &self.items,
            vec![0x02],
            records::encode_head(&records::genesis_head(identity)),
        );
        batch.insert(&self.items, vec![0x03], 0u64.to_be_bytes().to_vec());
        for funded in &genesis.accounts {
            if funded.balance.is_zero() {
                continue;
            }
            let account = Account {
                balance: funded.balance,
                code_hash: keccak256([]),
                ..Account::default()
            };
            batch.insert(
                &self.items,
                encoding::key(0x10, funded.address.as_slice()),
                records::encode_account(&account, false),
            );
        }
        self.finish(batch)
    }

    pub fn view(&self) -> Result<ReadView, String> {
        self.check()?;
        let snapshot = self.database.snapshot();
        let head = {
            use fjall::Readable;
            let bytes = snapshot
                .get(&self.items, [0x02])
                .map_err(engine_error)?
                .ok_or("missing committed head")?;
            records::decode_head(&bytes)?
        };
        Ok(ReadView {
            snapshot,
            items: self.items.clone(),
            head,
            chain_id: self.chain_id,
            profile_capacity: self.profile_capacity,
            block_index_complete: self.block_index_complete,
            terminal: self.terminal.clone(),
        })
    }

    /// Immutable limits authenticated by the persisted canonical genesis.
    pub fn capacity(&self) -> Capacity {
        self.profile_capacity
    }

    /// Available only after successful durability and snapshot capture for the
    /// latest commit attempt. Admission/discard writes are not block commits.
    pub fn last_commit_phases(&self) -> Option<CommitPhaseTimings> {
        self.last_commit_phases
    }

    /// Offline/restart equality only; never used in admission or block production.
    pub fn state_digest(&self) -> Result<alloy_primitives::B256, String> {
        self.view()?.state_digest()
    }

    fn check(&self) -> Result<(), String> {
        if self.terminal.load(Ordering::Acquire) {
            Err("storage is terminal; restart and reconcile required".into())
        } else {
            Ok(())
        }
    }

    fn batch(&self) -> Result<WriteBatch, String> {
        self.check()?;
        Ok(self.database.batch().durability(Some(PersistMode::SyncAll)))
    }

    fn finish(&mut self, batch: WriteBatch) -> Result<(), String> {
        #[cfg(test)]
        if std::mem::take(&mut self.fail_next) {
            self.terminal.store(true, Ordering::Release);
            return Err("injected durable batch failure; recovery required".into());
        }
        if let Err(error) = batch.commit() {
            self.terminal.store(true, Ordering::Release);
            return Err(format!(
                "durable commit failed; outcome ambiguous, recovery required: {error}"
            ));
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn fail_next_commit_for_test(&mut self) {
        self.fail_next = true;
    }

    fn latest_head(&self) -> Result<Head, String> {
        Ok(self.view()?.head)
    }
}

fn engine_error(error: fjall::Error) -> String {
    format!("storage read/open failed: {error}")
}

#[cfg(test)]
#[path = "storage/failure_test.rs"]
mod failure_test;

#[cfg(test)]
#[path = "storage/capacity_tests.rs"]
mod capacity_tests;

#[cfg(test)]
#[path = "storage/profile_tests.rs"]
mod profile_tests;

#[cfg(test)]
#[path = "storage/extended_codec_tests.rs"]
mod extended_codec_tests;
