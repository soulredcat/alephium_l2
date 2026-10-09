//! Once-only approved public-node dispatch; acknowledgement is not acceptance.
use crate::publisher::{ExternalFailure, ExternalSubmitter, Scope, Token};
use alephium_l2_sdk::alephium::{ValidatedSignedAlephium, read_node::OFFICIAL_TESTNET_ORIGIN};
use alloy_primitives::B256;
use reqwest::Url;
use serde_json::{Value, json};
use std::collections::BTreeSet;

#[path = "http_submission_transport.rs"]
pub mod transport;
pub use transport::{
    MAX_RESPONSE_BYTES, ReqwestSubmissionTransport, SubmissionRequest, SubmissionResponse,
    SubmissionTransport,
};

pub struct ApprovedHttpSubmitter<T = ReqwestSubmissionTransport> {
    transport: T,
    url: Url,
    scope: Scope,
    scope_id: B256,
    enabled: bool,
    attempted: BTreeSet<B256>,
}

impl ApprovedHttpSubmitter<ReqwestSubmissionTransport> {
    pub fn from_env(
        path: &std::path::Path,
        origin: &str,
        scope: Scope,
        explicitly_enabled: bool,
    ) -> Result<Self, ExternalFailure> {
        let bytes =
            crate::configured_signer_env::read(path).map_err(|_| ExternalFailure::Rejected)?;
        let values = crate::configured_signer_env::parse(
            bytes.text().map_err(|_| ExternalFailure::Rejected)?,
        )
        .map_err(|_| ExternalFailure::Rejected)?;
        if !explicitly_enabled || values.get("L2_P5_LIVE_SUBMISSION_ENABLED") != Some(&"1") {
            return Err(ExternalFailure::Disabled);
        }
        Self::new(origin, scope, true)
    }
    pub fn new(origin: &str, scope: Scope, enabled: bool) -> Result<Self, ExternalFailure> {
        checked_origin(origin, scope.l1_network)?;
        Self::with_transport(origin, scope, enabled, ReqwestSubmissionTransport::new()?)
    }
}

impl<T: SubmissionTransport> ApprovedHttpSubmitter<T> {
    /// Transport injection does not approve an operation or authorize a callback.
    /// The same scope and official-origin checks apply; Publisher owns durable attempts.
    pub fn with_transport(
        origin: &str,
        scope: Scope,
        enabled: bool,
        transport: T,
    ) -> Result<Self, ExternalFailure> {
        let scope_id = scope.identity().map_err(|_| ExternalFailure::Rejected)?;
        let origin = checked_origin(origin, scope.l1_network)?;
        let url = origin
            .join("/transactions/submit")
            .map_err(|_| ExternalFailure::Rejected)?;
        Ok(Self {
            transport,
            url,
            scope,
            scope_id,
            enabled,
            attempted: BTreeSet::new(),
        })
    }
}

impl<T: SubmissionTransport> ExternalSubmitter for ApprovedHttpSubmitter<T> {
    fn enabled(&self) -> bool {
        self.enabled
    }

    fn submit(
        &mut self,
        attempt: Token,
        signed: &ValidatedSignedAlephium,
    ) -> Result<B256, ExternalFailure> {
        if !self.enabled {
            return Err(ExternalFailure::Disabled);
        }
        let unsigned = signed.unsigned();
        let spec = unsigned.operation().spec();
        if attempt.revision == 0
            || attempt.fencing_epoch == 0
            || attempt.canonical_head == B256::ZERO
            || attempt.canonical_head != spec.funding.head_hash
            || unsigned.publication_scope() != self.scope_id
            || spec.funding.network_id != self.scope.l1_network
            || spec.funding.network_genesis_id != self.scope.l1_genesis
            || spec.funding.source_id != self.scope.canonical_source
            || spec.caller_public_key.as_slice() != self.scope.publisher_key
            || spec.funding.group != 0
            || spec.funding.group_count != 4
            || unsigned.unsigned_bytes().len() > 131_072
            || !self.attempted.insert(signed.tx_id())
        {
            return Err(ExternalFailure::Rejected);
        }
        // Publisher::submit has already synced its durable attempt. A send,
        // timeout, malformed ACK or mismatched ID consumes this local attempt.
        let body = json!({"unsignedTx":hex::encode(unsigned.unsigned_bytes()),
            "signature":hex::encode(signed.signature())});
        let body = serde_json::to_vec(&body).map_err(|_| ExternalFailure::Rejected)?;
        let request = SubmissionRequest::new(self.url.clone(), body)?;
        let response = self.transport.post(&request)?;
        if !(200..300).contains(&response.status()) {
            return Err(ExternalFailure::Rejected);
        }
        if response
            .content_length()
            .is_some_and(|size| size > MAX_RESPONSE_BYTES as u64)
        {
            return Err(ExternalFailure::Rejected);
        }
        parse_ack(response.body(), signed.tx_id())
    }
}

fn checked_origin(origin: &str, network: u8) -> Result<Url, ExternalFailure> {
    let parsed = Url::parse(origin).map_err(|_| ExternalFailure::Rejected)?;
    if network != 1
        || parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !matches!(parsed.path(), "" | "/")
        || parsed.origin().ascii_serialization() != OFFICIAL_TESTNET_ORIGIN
    {
        return Err(ExternalFailure::Rejected);
    }
    Ok(parsed)
}

fn parse_ack(bytes: &[u8], expected: B256) -> Result<B256, ExternalFailure> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| ExternalFailure::Rejected)?;
    let object = value.as_object().ok_or(ExternalFailure::Rejected)?;
    if object.len() != 3 || value["fromGroup"] != 0 || value["toGroup"] != 0 {
        return Err(ExternalFailure::Rejected);
    }
    let encoded = value["txId"].as_str().ok_or(ExternalFailure::Rejected)?;
    let bytes = hex::decode(encoded).map_err(|_| ExternalFailure::Rejected)?;
    if bytes.len() != 32 || B256::from_slice(&bytes) != expected {
        return Err(ExternalFailure::Rejected);
    }
    Ok(expected)
}

#[path = "../../test/publisher/http_submission_checks.rs"]
mod checks;

pub fn pure_checks() -> usize {
    checks::run()
}
