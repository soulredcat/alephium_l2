//! Exact Base58 lock-script encoding, without network byte or checksum.
use super::ReadNodeError as Error;
use alloy_primitives::B256;

#[derive(Clone, PartialEq, Eq)]
pub struct P2pkhAddress {
    encoded: String,
    hash: B256,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ContractAddress {
    encoded: String,
    id: B256,
}

fn encode(tag: u8, payload: B256) -> String {
    let mut bytes = [0; 33];
    bytes[0] = tag;
    bytes[1..].copy_from_slice(payload.as_slice());
    bs58::encode(bytes).into_string()
}

fn decode(value: &str, tag: u8) -> Result<B256, Error> {
    if value.is_empty() || value.len() > 46 || !value.is_ascii() {
        return Err(Error::UnsupportedAddress);
    }
    let bytes = bs58::decode(value)
        .into_vec()
        .map_err(|_| Error::UnsupportedAddress)?;
    if bytes.len() != 33 || bytes[0] != tag || bs58::encode(&bytes).into_string() != value {
        return Err(Error::UnsupportedAddress);
    }
    Ok(B256::from_slice(&bytes[1..]))
}

impl P2pkhAddress {
    pub fn from_hash(hash: B256) -> Self {
        Self {
            encoded: encode(0, hash),
            hash,
        }
    }
    pub fn parse(value: &str) -> Result<Self, Error> {
        Ok(Self::from_hash(decode(value, 0)?))
    }
    pub fn as_str(&self) -> &str {
        &self.encoded
    }
    pub fn hash(&self) -> B256 {
        self.hash
    }
    pub fn group(&self) -> u8 {
        let hint = crate::alephium::codec::owner_hint(self.hash);
        ((hint ^ (hint >> 8) ^ (hint >> 16) ^ (hint >> 24)) as u8) % 4
    }
}

impl ContractAddress {
    pub fn from_id(id: B256) -> Result<Self, Error> {
        if id.as_slice()[31] >= 4 || id == B256::ZERO {
            return Err(Error::UnsupportedAddress);
        }
        Ok(Self {
            encoded: encode(3, id),
            id,
        })
    }
    pub fn parse(value: &str) -> Result<Self, Error> {
        Self::from_id(decode(value, 3)?)
    }
    pub fn as_str(&self) -> &str {
        &self.encoded
    }
    pub fn id(&self) -> B256 {
        self.id
    }
    /// Native contract output hint, separate from its UTXO reference key.
    pub fn output_hint(&self) -> u32 {
        crate::alephium::codec::owner_hint(self.id) & !1
    }
    pub fn group(&self) -> u8 {
        self.id.as_slice()[31]
    }
}
