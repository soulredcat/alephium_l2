//! Canonical SHA-256 transcripts with checked byte meters, not retained buffers.
use crate::protocol::hash::{Digest, Sha256};
use crate::protocol::proof_transport::ProofLimits;
use alloy_primitives::B256;

pub(crate) struct CanonicalHash {
    digest: Sha256,
    used: usize,
    limit: usize,
}

impl CanonicalHash {
    pub(crate) fn new(namespace: &[u8], limit: usize) -> Result<Self, String> {
        if limit == 0 {
            return Err("canonical transcript requires a positive byte bound".into());
        }
        let mut hash = Self {
            digest: Sha256::new(),
            used: 0,
            limit,
        };
        hash.bytes(namespace)?;
        Ok(hash)
    }

    pub(crate) fn raw(&mut self, bytes: &[u8]) -> Result<(), String> {
        let next = self
            .used
            .checked_add(bytes.len())
            .ok_or("transcript byte overflow")?;
        if next > self.limit {
            return Err("canonical transcript exceeds its byte bound".into());
        }
        self.digest.update(bytes);
        self.used = next;
        Ok(())
    }

    pub(crate) fn byte(&mut self, value: u8) -> Result<(), String> {
        self.raw(&[value])
    }
    pub(crate) fn u32(&mut self, value: u32) -> Result<(), String> {
        self.raw(&value.to_be_bytes())
    }
    pub(crate) fn u64(&mut self, value: u64) -> Result<(), String> {
        self.raw(&value.to_be_bytes())
    }
    pub(crate) fn hash(&mut self, value: B256) -> Result<(), String> {
        self.raw(value.as_slice())
    }
    pub(crate) fn bytes(&mut self, value: &[u8]) -> Result<(), String> {
        let length = u32::try_from(value.len()).map_err(|_| "transcript field overflow")?;
        // Reserve the complete frame before updating either prefix or payload.
        let required = value
            .len()
            .checked_add(4)
            .ok_or("transcript field overflow")?;
        if self
            .used
            .checked_add(required)
            .is_none_or(|size| size > self.limit)
        {
            return Err("canonical transcript exceeds its byte bound".into());
        }
        self.u32(length)?;
        self.raw(value)
    }
    pub(crate) fn limits(&mut self, limits: ProofLimits) -> Result<(), String> {
        self.raw(&limits.binding_bytes()?)
    }
    pub(crate) fn finish(self) -> B256 {
        B256::from_slice(&self.digest.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::Encoder;

    #[test]
    fn canonical_updates_match_existing_big_endian_encoder_bytes() {
        let mut encoded = Encoder::default();
        encoded.bytes(b"stream-test/v4").unwrap();
        encoded.byte(5);
        encoded.u32(129);
        encoded.u64(90_000);
        encoded.hash(B256::repeat_byte(0x31));
        encoded.bytes(&[1, 2, 3]).unwrap();
        let bytes = encoded.finish().unwrap();
        let mut stream = CanonicalHash::new(b"stream-test/v4", bytes.len()).unwrap();
        stream.byte(5).unwrap();
        stream.u32(129).unwrap();
        stream.u64(90_000).unwrap();
        stream.hash(B256::repeat_byte(0x31)).unwrap();
        stream.bytes(&[1, 2, 3]).unwrap();
        assert_eq!(stream.finish(), crate::batch_journal::hash(&bytes));
    }

    #[test]
    fn exact_bound_passes_and_failed_field_does_not_partially_update() {
        let mut stream = CanonicalHash::new(b"x", 10).unwrap();
        assert!(stream.bytes(&[1, 2]).is_err());
        assert_eq!(stream.used, 5);
        stream.bytes(&[3]).unwrap();
        assert_eq!(stream.used, 10);
        assert!(stream.byte(4).is_err());
        assert_eq!(stream.used, 10);
        assert!(CanonicalHash::new(b"x", 0).is_err());
    }
}
