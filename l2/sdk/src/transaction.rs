use crate::ClientError;
use alloy_consensus::{Transaction, TxEnvelope, transaction::SignerRecoverable};
use alloy_eips::eip2718::{Decodable2718, Encodable2718};
use alloy_primitives::{Address, B256};
use std::fmt;

const MAX_TRANSACTION_BYTES: usize = 131_072;

/// A canonical signed envelope validated for one explicitly selected chain.
///
/// This client does not sign transactions or hold signing keys. Preparing an
/// envelope proves its format and signer, not its admission or execution.
#[derive(Clone)]
pub struct PreparedTransaction {
    raw: Vec<u8>,
    hash: B256,
    chain_id: u64,
    sender: Address,
    to: Option<Address>,
    transaction_type: u8,
}

impl PreparedTransaction {
    pub fn new(raw: Vec<u8>, expected_chain: u64) -> Result<Self, ClientError> {
        if raw.is_empty() || raw.len() > MAX_TRANSACTION_BYTES {
            return Err(ClientError::InvalidTransaction);
        }
        let mut remaining = raw.as_slice();
        let envelope =
            TxEnvelope::decode_2718(&mut remaining).map_err(|_| ClientError::InvalidTransaction)?;
        if !remaining.is_empty() || envelope.encoded_2718() != raw {
            return Err(ClientError::InvalidTransaction);
        }
        let transaction_type = match &envelope {
            TxEnvelope::Legacy(_) => 0,
            TxEnvelope::Eip1559(_) => 2,
            _ => return Err(ClientError::InvalidTransaction),
        };
        if envelope.chain_id() != Some(expected_chain)
            || envelope
                .max_priority_fee_per_gas()
                .is_some_and(|priority| priority > envelope.max_fee_per_gas())
        {
            return Err(ClientError::InvalidTransaction);
        }
        // The trait's checked recovery rejects EIP-2 high-S signatures.
        let sender = envelope
            .recover_signer()
            .map_err(|_| ClientError::InvalidTransaction)?;
        Ok(Self {
            raw,
            hash: *envelope.tx_hash(),
            chain_id: expected_chain,
            sender,
            to: envelope.to(),
            transaction_type,
        })
    }

    pub fn hash(&self) -> B256 {
        self.hash
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Sensitive signed bytes intended only for explicit submission transport.
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    pub fn sender(&self) -> Address {
        self.sender
    }

    pub fn to(&self) -> Option<Address> {
        self.to
    }

    pub fn transaction_type(&self) -> u8 {
        self.transaction_type
    }
}

impl fmt::Debug for PreparedTransaction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedTransaction")
            .field("hash", &self.hash)
            .field("chain_id", &self.chain_id)
            .field("byte_count", &self.raw.len())
            .finish()
    }
}
