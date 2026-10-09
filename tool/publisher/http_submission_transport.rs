//! Immutable submission requests and a bounded once-only production transport.
use crate::publisher::ExternalFailure;
use alephium_l2_sdk::alephium::{MAX_UNSIGNED_BYTES, read_node::OFFICIAL_TESTNET_ORIGIN};
use reqwest::{Url, blocking::Client, redirect::Policy};
use std::{io::Read, time::Duration};

pub const MAX_RESPONSE_BYTES: usize = 32_768;
const MAX_REQUEST_BYTES: usize = MAX_UNSIGNED_BYTES * 2 + 192;

/// Constructed only by the submitter after scope, origin and signed-input checks.
/// No Debug/Serialize: this contains the private signed submission body.
pub struct SubmissionRequest {
    url: Url,
    body: Vec<u8>,
}
impl SubmissionRequest {
    pub(super) fn new(url: Url, body: Vec<u8>) -> Result<Self, ExternalFailure> {
        if body.is_empty() || body.len() > MAX_REQUEST_BYTES {
            return Err(ExternalFailure::Rejected);
        }
        Ok(Self { url, body })
    }
    pub fn url(&self) -> &Url {
        &self.url
    }
    pub fn origin(&self) -> &'static str {
        OFFICIAL_TESTNET_ORIGIN
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub fn maximum_response_bytes(&self) -> usize {
        MAX_RESPONSE_BYTES
    }
}

/// Bounded response data; neither its construction nor an ACK proves acceptance.
pub struct SubmissionResponse {
    status: u16,
    content_length: Option<u64>,
    body: Vec<u8>,
}
impl SubmissionResponse {
    pub fn from_parts(
        status: u16,
        content_length: Option<u64>,
        body: Vec<u8>,
    ) -> Result<Self, ExternalFailure> {
        if !(100..600).contains(&status) || body.len() > MAX_RESPONSE_BYTES {
            return Err(ExternalFailure::Rejected);
        }
        Ok(Self {
            status,
            content_length,
            body,
        })
    }
    pub fn status(&self) -> u16 {
        self.status
    }
    pub fn content_length(&self) -> Option<u64> {
        self.content_length
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

/// A transport receives only the immutable exact request to the pinned origin.
/// It sends once. Retry/replacement authority never belongs to this interface.
pub trait SubmissionTransport {
    fn post(&mut self, request: &SubmissionRequest) -> Result<SubmissionResponse, ExternalFailure>;
}

pub struct ReqwestSubmissionTransport {
    client: Client,
}
impl ReqwestSubmissionTransport {
    pub(super) fn new() -> Result<Self, ExternalFailure> {
        let client = Client::builder()
            .https_only(true)
            .http1_only()
            .no_proxy()
            .redirect(Policy::none())
            .retry(reqwest::retry::never())
            .pool_max_idle_per_host(0)
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|_| ExternalFailure::Unavailable)?;
        Ok(Self { client })
    }
}
impl SubmissionTransport for ReqwestSubmissionTransport {
    fn post(&mut self, request: &SubmissionRequest) -> Result<SubmissionResponse, ExternalFailure> {
        let response = self
            .client
            .post(request.url().clone())
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(request.body().to_vec())
            .send()
            .map_err(|_| ExternalFailure::Unavailable)?;
        let status = response.status().as_u16();
        let content_length = response.content_length();
        if !(200..300).contains(&status)
            || content_length.is_some_and(|size| size > MAX_RESPONSE_BYTES as u64)
        {
            return Err(ExternalFailure::Rejected);
        }
        let mut body = Vec::new();
        response
            .take(MAX_RESPONSE_BYTES as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|_| ExternalFailure::Unavailable)?;
        SubmissionResponse::from_parts(status, content_length, body)
    }
}
