//! Canonical checksums bind every versioned request/response field, not authority.
use super::{
    operation::{decode_hex, operation_policy_hash},
    types::*,
};
use crate::publisher::{Scope, Token};
use alephium_l2_sdk::alephium::{SUPPORTED_PROFILE, ValidatedUnsignedAlephium};
use alloy_primitives::B256;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::{self, Write};

impl RequestDocument {
    pub(super) fn capture(
        scope: &Scope,
        attempt: Token,
        unsigned: &ValidatedUnsignedAlephium,
        signature: Option<&[u8; 64]>,
    ) -> Result<Self, HandoffError> {
        let operation = unsigned.operation();
        let spec = operation.spec();
        if attempt.revision == 0
            || attempt.fencing_epoch == 0
            || attempt.canonical_head != spec.funding.head_hash
            || unsigned.publication_scope() != scope.identity()?
            || spec.caller_public_key.as_slice() != scope.publisher_key
            || spec.funding.source_id != scope.canonical_source
            || spec.funding.network_id != scope.l1_network
            || spec.funding.network_genesis_id != scope.l1_genesis
        {
            return Err(HandoffError::Binding);
        }
        let binding = Binding {
            profile: SUPPORTED_PROFILE.into(),
            kind: if signature.is_some() {
                RequestKind::Submit
            } else {
                RequestKind::Sign
            },
            attempt,
            scope_id: unsigned.publication_scope(),
            intent_id: unsigned.intent_id(),
            operation_id: unsigned.operation_id(),
            tx_id: unsigned.tx_id(),
            unsigned_sha256: sha(unsigned.unsigned_bytes()),
            authority_key_hex: hex::encode(spec.caller_public_key),
            network_id: spec.funding.network_id,
            network_genesis_id: spec.funding.network_genesis_id,
            operation_policy_sha256: operation_policy_hash(operation),
            signature_sha256: signature.map(|bytes| sha(bytes)),
        };
        let body = RequestBody {
            binding,
            scope: scope.clone(),
            operation: OperationRecord::capture(operation),
            unsigned_hex: hex::encode(unsigned.unsigned_bytes()),
            signature_hex: signature.map(hex::encode),
        };
        let payload = canonical_bytes(&body)?;
        let document = Self {
            version: FORMAT_VERSION,
            request_identity: identity(&payload),
            checksum_sha256: sha(&payload),
            body,
        };
        document.validate()?;
        Ok(document)
    }

    pub fn validate(&self) -> Result<(), HandoffError> {
        let payload = canonical_bytes(&self.body)?;
        if self.version != FORMAT_VERSION
            || self.checksum_sha256 != sha(&payload)
            || self.request_identity != identity(&payload)
        {
            return Err(HandoffError::Format);
        }
        let binding = &self.body.binding;
        let operation = &self.body.operation;
        let scope = &self.body.scope;
        let unsigned = decode_hex(
            &self.body.unsigned_hex,
            alephium_l2_sdk::alephium::MAX_UNSIGNED_BYTES,
        )?;
        let key = decode_hex(&binding.authority_key_hex, 33)?;
        if unsigned.is_empty()
            || key.len() != 33
            || binding.profile != SUPPORTED_PROFILE
            || binding.attempt.revision == 0
            || binding.attempt.fencing_epoch == 0
            || binding.attempt.canonical_head == B256::ZERO
            || binding.scope_id != scope.identity()?
            || binding.scope_id != operation.publication_scope
            || binding.intent_id != operation.intent_id
            || binding.operation_id != operation.operation_id
            || binding.authority_key_hex != operation.caller_public_key_hex
            || key != scope.publisher_key
            || binding.network_id != scope.l1_network
            || binding.network_id != operation.funding.network_id
            || binding.network_genesis_id != scope.l1_genesis
            || binding.network_genesis_id != operation.funding.network_genesis_id
            || operation.funding.source_id != scope.canonical_source
            || operation.funding.head_hash != binding.attempt.canonical_head
            || binding.unsigned_sha256 != sha(&unsigned)
            || binding.tx_id != alephium_l2_sdk::alephium::alephium_hash(&unsigned)
            || binding.operation_policy_sha256 != operation.policy_hash()?
        {
            return Err(HandoffError::Binding);
        }
        match (
            binding.kind,
            &self.body.signature_hex,
            binding.signature_sha256,
        ) {
            (RequestKind::Sign, None, None) => {}
            (RequestKind::Submit, Some(encoded), Some(expected)) => {
                let signature = decode_hex(encoded, 64)?;
                if signature.len() != 64 || sha(&signature) != expected {
                    return Err(HandoffError::Binding);
                }
            }
            _ => return Err(HandoffError::Binding),
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>, HandoffError> {
        self.validate()?;
        canonical_bytes(self)
    }
}

impl ResponseDocument {
    /// For an external Rust wallet after its own explicit operator approval.
    /// This creates response data only; it does not sign, submit or validate a signature.
    pub fn for_request(
        request: &RequestDocument,
        outcome: ResponseOutcome,
    ) -> Result<Self, HandoffError> {
        request.validate()?;
        let body = ResponseBody {
            request_identity: request.request_identity,
            request_checksum_sha256: request.checksum_sha256,
            binding: request.body.binding.clone(),
            outcome,
        };
        let document = Self {
            version: FORMAT_VERSION,
            checksum_sha256: sha(&canonical_bytes(&body)?),
            body,
        };
        document.validate(request)?;
        Ok(document)
    }
    pub fn validate(&self, request: &RequestDocument) -> Result<(), HandoffError> {
        request.validate()?;
        if self.version != FORMAT_VERSION
            || self.checksum_sha256 != sha(&canonical_bytes(&self.body)?)
            || self.body.request_identity != request.request_identity
            || self.body.request_checksum_sha256 != request.checksum_sha256
            || self.body.binding != request.body.binding
        {
            return Err(HandoffError::Binding);
        }
        match (&self.body.outcome, request.body.binding.kind) {
            (ResponseOutcome::Signed { signature_hex }, RequestKind::Sign) => {
                if decode_hex(signature_hex, 64)?.len() != 64 {
                    return Err(HandoffError::Format);
                }
            }
            (ResponseOutcome::SubmissionAcknowledged, RequestKind::Submit)
            | (ResponseOutcome::Cancelled, _) => {}
            _ => return Err(HandoffError::Binding),
        }
        Ok(())
    }
    pub fn encode(&self, request: &RequestDocument) -> Result<Vec<u8>, HandoffError> {
        self.validate(request)?;
        canonical_bytes(self)
    }
}

pub(super) fn sha(bytes: &[u8]) -> B256 {
    B256::from_slice(&Sha256::digest(bytes))
}
fn identity(bytes: &[u8]) -> B256 {
    let mut hash = Sha256::new();
    hash.update(b"ALPH/L2/publisher-handoff-request/v1");
    hash.update(bytes);
    B256::from_slice(&hash.finalize())
}
pub(super) fn canonical_bytes(value: &impl Serialize) -> Result<Vec<u8>, HandoffError> {
    let mut out = Bounded(Vec::new());
    serde_json::to_writer(&mut out, value).map_err(|_| HandoffError::Bounds)?;
    Ok(out.0)
}
struct Bounded(Vec<u8>);
impl Write for Bounded {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let length = self
            .0
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("handoff bound"))?;
        if length > MAX_DOCUMENT_BYTES {
            return Err(io::Error::other("handoff bound"));
        }
        self.0.extend(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
