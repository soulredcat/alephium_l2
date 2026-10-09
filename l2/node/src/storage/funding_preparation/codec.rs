//! Versioned bounded private data envelope. Checksums are integrity, not authority.
use crate::{
    funding_preparation::{FundingPreparationError as Error, FundingPreparationRecord},
    protocol::Capacity,
};
use alloy_primitives::B256;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::io::Write;

const DOMAIN: &[u8] = b"ALPH/L2/funding-preparation-storage/v1";
pub(super) const MAX_RECORD_BYTES: usize = 65_536;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Stored {
    pub schema: u32,
    pub node_chain_id: u64,
    pub node_genesis: B256,
    pub capacity: Capacity,
    pub record: FundingPreparationRecord,
}

pub(super) fn encode(stored: &impl Serialize) -> Result<Vec<u8>, Error> {
    let mut payload = Bounded(Vec::new());
    serde_json::to_writer(&mut payload, stored).map_err(|_| Error::ResourceLimit)?;
    let mut bytes = Vec::with_capacity(DOMAIN.len() + 36 + payload.0.len());
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&(payload.0.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&Sha256::digest(&payload.0));
    bytes.extend_from_slice(&payload.0);
    Ok(bytes)
}

pub(super) fn decode<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T, Error> {
    let start = DOMAIN.len() + 36;
    if bytes.len() < start || bytes.len() > MAX_RECORD_BYTES || bytes[..DOMAIN.len()] != *DOMAIN {
        return Err(Error::CorruptState);
    }
    let length = u32::from_be_bytes(
        bytes[DOMAIN.len()..DOMAIN.len() + 4]
            .try_into()
            .map_err(|_| Error::CorruptState)?,
    ) as usize;
    let payload = &bytes[start..];
    if length != payload.len() || Sha256::digest(payload)[..] != bytes[DOMAIN.len() + 4..start] {
        return Err(Error::CorruptState);
    }
    let value: T = serde_json::from_slice(payload).map_err(|_| Error::CorruptState)?;
    if encode(&value).map_err(|_| Error::CorruptState)? != bytes {
        return Err(Error::CorruptState);
    }
    Ok(value)
}

struct Bounded(Vec<u8>);
impl Write for Bounded {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self
            .0
            .len()
            .checked_add(bytes.len())
            .is_none_or(|length| length > MAX_RECORD_BYTES - DOMAIN.len() - 36)
        {
            return Err(std::io::Error::other(
                "Funding preparation record bound exceeded",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
