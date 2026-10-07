//! Stable source semantics committed by the retained operation and handoff.
use super::{CurrentFundingError as Error, CurrentFundingPolicy};
use crate::alephium::{
    FundingModel, alephium_hash,
    read_node::{GenesisPin, GenesisProvenance, NodeVersion, canonical_origin},
};
use alloy_primitives::B256;

const SOURCE_DOMAIN: &[u8] = b"alephium-l2/current-fixed-funding-source/v1";
// This is the allowed version policy, not the current server's version report.
// Both reviewed releases therefore identify the same configured source policy.
const VERSION_POLICY: [u8; 7] = [2, 4, 7, 0, 4, 7, 1];

pub(super) fn allows_version(version: NodeVersion) -> bool {
    matches!(version, NodeVersion::V4_7_0 | NodeVersion::V4_7_1)
}

impl CurrentFundingPolicy {
    /// Blake2b256(DOMAIN || origin-length-u32BE || canonical-origin-UTF8 ||
    /// genesis32 || model-u8 || network1 || group0 || groups4 ||
    /// version-count-u8 || two(version-major/minor/patch-u8) ||
    /// chain-u32BE || from-group-u32BE || to-group-u32BE).
    ///
    /// Construct the ReadNode and FundingPin with this identity. The observer
    /// recomputes it from actual reader identity, so reducing a confirmation
    /// threshold cannot retain the original approved source ID. Resource-count
    /// ceilings remain separate bounded call budgets, not source guarantees.
    pub fn source_id(&self, origin: &str, genesis: GenesisPin) -> Result<B256, Error> {
        let minimum = self.minimum_confirmations;
        if genesis.hash == B256::ZERO
            || genesis.provenance != GenesisProvenance::Independent
            || minimum.chain == 0
            || minimum.from_group == 0
            || minimum.to_group == 0
        {
            return Err(Error::InvalidPolicy);
        }
        // Shared with the reader's strict HTTPS-origin parser. This performs no
        // DNS, client construction or HTTP request and accepts the same forms.
        let origin = canonical_origin(origin)?;
        let length = u32::try_from(origin.len()).map_err(|_| Error::Bounds)?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(SOURCE_DOMAIN);
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(origin.as_bytes());
        bytes.extend_from_slice(genesis.hash.as_slice());
        bytes.extend_from_slice(&[FundingModel::CanonicalFixedCurrentV1 as u8, 1, 0, 4]);
        bytes.extend_from_slice(&VERSION_POLICY);
        bytes.extend_from_slice(&minimum.chain.to_be_bytes());
        bytes.extend_from_slice(&minimum.from_group.to_be_bytes());
        bytes.extend_from_slice(&minimum.to_group.to_be_bytes());
        Ok(alephium_hash(&bytes))
    }
}
