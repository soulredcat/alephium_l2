//! Versioned bounded publisher records; errors never include private payloads.
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::io::{self, Write};

const DOMAIN: &[u8] = b"ALPH/L2/publisher-storage/v1";
const VERSION: u32 = 1;
pub(super) const MAX_RECORD_BYTES: usize = 16 * 1024 * 1024;
const MAX_PAYLOAD_BYTES: usize = MAX_RECORD_BYTES - DOMAIN.len() - 40;

/// Canonical serde DTO order and fixed envelope make duplicate/alternate JSON
/// encodings invalid on recovery. DTOs must contain no unordered maps/floats.
pub(super) fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut payload = BoundedWriter(Vec::new());
    serde_json::to_writer(&mut payload, value)
        .map_err(|_| "Publisher record encoding exceeds its bound or schema")?;
    let mut bytes = Vec::with_capacity(DOMAIN.len() + 40 + payload.0.len());
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(&(payload.0.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&Sha256::digest(&payload.0));
    bytes.extend_from_slice(&payload.0);
    Ok(bytes)
}

pub(super) fn decode<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T, String> {
    let start = DOMAIN.len() + 40;
    if bytes.len() < start || bytes.len() > MAX_RECORD_BYTES || bytes[..DOMAIN.len()] != *DOMAIN {
        return Err("Publisher record has an unsupported version/domain or size".into());
    }
    let version = u32::from_be_bytes(
        bytes[DOMAIN.len()..DOMAIN.len() + 4]
            .try_into()
            .map_err(|_| "Publisher record version is truncated")?,
    );
    let length = u32::from_be_bytes(
        bytes[DOMAIN.len() + 4..DOMAIN.len() + 8]
            .try_into()
            .map_err(|_| "Publisher record length is truncated")?,
    ) as usize;
    let hash = &bytes[DOMAIN.len() + 8..start];
    let payload = &bytes[start..];
    if version != VERSION || length != payload.len() || &Sha256::digest(payload)[..] != hash {
        return Err("Publisher record integrity, length or version differs".into());
    }
    let value: T = serde_json::from_slice(payload)
        .map_err(|_| "Publisher record schema is corrupt; private bytes suppressed")?;
    if encode(&value)? != bytes {
        return Err("Publisher record is not its exact canonical encoding".into());
    }
    Ok(value)
}

/// Stop serialization before oversized private fields allocate a second buffer.
struct BoundedWriter(Vec<u8>);

impl Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let length = self
            .0
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("Publisher record exceeds its bound"))?;
        if length > MAX_PAYLOAD_BYTES {
            return Err(io::Error::other("Publisher record exceeds its bound"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
