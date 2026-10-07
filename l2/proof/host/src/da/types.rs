use alephium_l2_transition_core::{BatchTransitionJournal, protocol::Capacity};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(crate) const MANIFEST_LIMIT: usize = 16 * 1024;
pub(crate) const RETENTION_POLICY: &str = "retain-unsettled/no-pruning-authority/v1";

#[derive(Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct PackageManifest {
    pub schema: u32,
    pub encoding: String,
    pub data_file: String,
    pub data_bytes: usize,
    pub da_commitment: String,
    pub candidate_journal_sha256: String,
    pub capacity: Capacity,
}

#[derive(Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetentionRecord {
    pub schema: u32,
    pub candidate_journal_sha256: String,
    pub da_commitment: String,
    pub policy: String,
    pub pruning_allowed: bool,
}

impl RetentionRecord {
    pub fn expected(manifest: &PackageManifest) -> Self {
        Self {
            schema: 1,
            candidate_journal_sha256: manifest.candidate_journal_sha256.clone(),
            da_commitment: manifest.da_commitment.clone(),
            policy: RETENTION_POLICY.into(),
            pruning_allowed: false,
        }
    }
}

/// Metadata only. These fields cannot grant proof/publication/settlement authority.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DaPackageReport {
    pub schema: u32,
    pub scope: String,
    pub data_bytes: usize,
    pub da_commitment: String,
    pub candidate_journal_sha256: String,
    pub blocks: u64,
    pub executed_transactions: u64,
    pub checkpoint_bytes: usize,
    pub checkpoint_sha256: String,
    pub native_reconstruction_verified: bool,
    pub proof_accepted: bool,
    pub settlement_eligible: bool,
    pub public_data_available: bool,
    pub retention_policy: String,
}

pub(crate) fn journal_sha(journal: &BatchTransitionJournal) -> Result<String, &'static str> {
    let bytes = journal
        .encode()
        .map_err(|_| "Cannot encode DA candidate journal.")?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

pub(crate) fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
