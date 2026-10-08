use super::{
    ChainHeader, MAX_CANONICAL_CANDIDATES, ReadNodeError as Error, transport::Transport, wire,
};
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
        self.checked_owner0(expected_hash, expected_height, 0)
    }

    /// Every supported header targets group zero. Its chain parent therefore
    /// remains outgoing dependency 3, regardless of the source group.
    pub(super) fn checked_owner0(
        self,
        expected_hash: B256,
        expected_height: u64,
        from_group: u8,
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
            || from_group >= 4
            || self.chain_from != i32::from(from_group)
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

pub(super) fn owner0_chain(header: &Header) -> Result<u8, Error> {
    if !(0..4).contains(&header.chain_from) || header.chain_to != 0 {
        return Err(Error::HeaderMismatch);
    }
    Ok(header.chain_from as u8)
}

pub(super) fn owner0_query(from_group: u8) -> Result<[(&'static str, String); 2], Error> {
    if from_group >= 4 {
        return Err(Error::InvalidConfiguration);
    }
    Ok([
        ("fromGroup", from_group.to_string()),
        ("toGroup", "0".into()),
    ])
}

pub(super) fn read_canonical(
    transport: &Transport,
    height: u64,
    from_group: u8,
) -> Result<ChainHeader, Error> {
    if height > i32::MAX as u64 {
        return Err(Error::InvalidConfiguration);
    }
    let mut query = owner0_query(from_group)?.to_vec();
    query.push(("height", height.to_string()));
    let candidates = candidates(transport.get("/blockflow/hashes", &query)?)?;
    let member = |hash: B256| {
        transport.get::<bool>(
            "/blockflow/is-block-in-main-chain",
            &[("blockHash", hex::encode(hash.as_slice()))],
        )
    };
    let memberships = candidates
        .iter()
        .map(|hash| member(*hash))
        .collect::<Result<Vec<_>, _>>()?;
    let selected = select_unique(&candidates, &memberships)?;
    let header: Header = transport.get(
        &format!("/blockflow/headers/{}", hex::encode(selected)),
        &[],
    )?;
    let header = if from_group == 0 {
        header.checked(selected, height)?
    } else {
        header.checked_owner0(selected, height, from_group)?
    };
    if !member(selected)? {
        return Err(Error::ObservationChanged);
    }
    Ok(header)
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
