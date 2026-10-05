use crate::protocol::Head;
use alloy_primitives::B256;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileEntry {
    pub path: String,
    pub length: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupManifest {
    pub schema: u32,
    pub chain_id: u64,
    pub head: Head,
    pub state_digest: B256,
    pub pending_count: usize,
    pub files: Vec<FileEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackupReport {
    pub head: Head,
    pub state_digest: B256,
    pub pending_count: usize,
    pub file_count: usize,
    pub bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReplayReport {
    pub head: Head,
    pub state_digest: B256,
    pub blocks: u64,
    pub executed_transactions: u64,
    /// Local terminal outcomes that are not inputs to any committed block.
    pub discarded_intents: u64,
    pub rejected_intents: u64,
    pub pending_count: usize,
    pub rejected_policy_revalidated: bool,
    pub execution_engine: String,
}
