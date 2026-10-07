//! Bounded private transaction bytes; hex exists only at the JSON boundary.
use crate::protocol::MAX_TRANSACTION_BYTES;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::fmt;

/// This is transport validation only. Execution must still decode the canonical
/// envelope and verify its signature and chain. Never expose a Debug formatter.
#[derive(Clone, PartialEq, Eq)]
pub struct RawEnvelope(Vec<u8>);

impl RawEnvelope {
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_TRANSACTION_BYTES {
            return Err("private envelope exceeds the supported byte bound".into());
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn from_hex(value: &str) -> Result<Self, String> {
        let value = value
            .strip_prefix("0x")
            .ok_or("missing private envelope hex prefix")?;
        if value.is_empty() || value.len() > MAX_TRANSACTION_BYTES * 2 || value.len() % 2 != 0 {
            return Err("private envelope exceeds the supported byte bound".into());
        }
        let bytes = hex::decode(value).map_err(|_| "invalid private envelope hex")?;
        Self::from_bytes(bytes)
    }
}

impl Serialize for RawEnvelope {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("0x{}", hex::encode(&self.0)))
    }
}

impl<'de> Deserialize<'de> for RawEnvelope {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct EnvelopeVisitor;

        impl de::Visitor<'_> for EnvelopeVisitor {
            type Value = RawEnvelope;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded private hex envelope")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                RawEnvelope::from_hex(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(EnvelopeVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_keeps_the_existing_hex_string_boundary() {
        let envelope = RawEnvelope::from_bytes(vec![0, 1, 0xab, 0xff]).unwrap();
        let encoded = serde_json::to_string(&envelope).unwrap();
        assert!(encoded == "\"0x0001abff\"");
        let decoded: RawEnvelope = serde_json::from_str(&encoded).unwrap();
        assert!(decoded == envelope);
        let mixed_case: RawEnvelope = serde_json::from_str("\"0x0001AbFf\"").unwrap();
        assert!(mixed_case == envelope);
    }

    #[test]
    fn transport_bounds_and_errors_do_not_authorize_or_expose_inputs() {
        for text in ["", "0x", "ff", "0xf", "0xprivate-envelope-marker"] {
            let encoded = serde_json::to_string(text).unwrap();
            let error = serde_json::from_str::<RawEnvelope>(&encoded).err().unwrap();
            assert!(!error.to_string().contains("private-envelope-marker"));
        }
        assert!(RawEnvelope::from_bytes(Vec::new()).is_err());
        assert!(RawEnvelope::from_bytes(vec![0; MAX_TRANSACTION_BYTES + 1]).is_err());
        let maximum = RawEnvelope::from_bytes(vec![0; MAX_TRANSACTION_BYTES]).unwrap();
        assert!(maximum.as_bytes().len() == MAX_TRANSACTION_BYTES);
        let too_long = format!("\"0x{}\"", "00".repeat(MAX_TRANSACTION_BYTES + 1));
        assert!(serde_json::from_str::<RawEnvelope>(&too_long).is_err());
        // Signature/canonical-RLP checks remain the execution decoder's job.
        assert!(RawEnvelope::from_bytes(vec![0xff]).is_ok());
    }
}
