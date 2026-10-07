use super::{ChainHeader, MAX_CANONICAL_CANDIDATES, ReadNodeError as Error, wire};
use alloy_primitives::B256;
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ChainInfo {
    pub current_height: i32,
}

#[derive(Deserialize)]
pub(super) struct Hashes {
    pub headers: wire::List<wire::Hash, MAX_CANONICAL_CANDIDATES>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Header {
    pub hash: wire::Hash,
    pub timestamp: i64,
    pub chain_from: i32,
    pub chain_to: i32,
    pub height: i32,
    pub deps: wire::List<wire::Hash, 7>,
}

impl Header {
    pub(super) fn checked(
        self,
        expected_hash: B256,
        expected_height: u64,
    ) -> Result<ChainHeader, Error> {
        let dependencies: [B256; 7] = self
            .deps
            .0
            .into_iter()
            .map(|hash| hash.0)
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| Error::HeaderMismatch)?;
        if self.hash.0 != expected_hash
            || self.hash.0 == B256::ZERO
            || self.chain_from != 0
            || self.chain_to != 0
            || wire::nonnegative(i64::from(self.height))? != expected_height
            || expected_height == 0 && dependencies.iter().any(|hash| *hash != B256::ZERO)
            || expected_height != 0 && dependencies[3] == B256::ZERO
        {
            return Err(Error::HeaderMismatch);
        }
        Ok(ChainHeader {
            hash: expected_hash,
            height: expected_height,
            timestamp_ms: wire::nonnegative(self.timestamp)?,
            dependencies,
        })
    }
}

pub(super) fn candidates(hashes: Hashes) -> Result<Vec<B256>, Error> {
    let hashes: Vec<_> = hashes.headers.0.into_iter().map(|hash| hash.0).collect();
    let unique: std::collections::BTreeSet<_> = hashes.iter().copied().collect();
    if hashes.is_empty()
        || hashes.len() > MAX_CANONICAL_CANDIDATES
        || unique.len() != hashes.len()
        || hashes.contains(&B256::ZERO)
    {
        return Err(Error::MalformedResponse);
    }
    Ok(hashes)
}

/// All candidates must have a membership observation, including losing forks.
pub(super) fn select_unique(candidates: &[B256], memberships: &[bool]) -> Result<B256, Error> {
    if candidates.len() != memberships.len()
        || candidates.is_empty()
        || candidates.len() > MAX_CANONICAL_CANDIDATES
        || candidates
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != candidates.len()
    {
        return Err(Error::MalformedResponse);
    }
    let mut selected = None;
    for (&hash, &canonical) in candidates.iter().zip(memberships) {
        if canonical && selected.replace(hash).is_some() {
            return Err(Error::AmbiguousCanonicalBlock);
        }
    }
    selected.ok_or(Error::NoCanonicalBlock)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Block {
    #[serde(flatten)]
    pub header: Header,
    pub transactions: wire::List<serde_json::Value, 4096>,
    pub conflicted_txs: Option<wire::List<wire::Hash, 4096>>,
}
