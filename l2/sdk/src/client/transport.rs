use crate::ClientError;
use reqwest::{
    Url,
    blocking::{Client, Response},
    redirect::Policy,
};
use serde_json::{Value, json};
use std::{
    io::Read,
    net::IpAddr,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

pub(super) const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RESPONSE_BYTES: usize = 1_048_576;

pub(super) struct Transport {
    client: Client,
    endpoint: Url,
    next_id: AtomicU64,
}

impl Transport {
    pub(super) fn connect(endpoint: &str) -> Result<Self, ClientError> {
        let endpoint = endpoint_url(endpoint)?;
        let client = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .retry(reqwest::retry::never())
            // Prevent Hyper's separate retry of unstarted, canceled pooled requests.
            .pool_max_idle_per_host(0)
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|_| ClientError::Transport)?;
        Ok(Self {
            client,
            endpoint,
            next_id: AtomicU64::new(1),
        })
    }

    pub(super) fn health(&self) -> Result<Value, ClientError> {
        let endpoint = self
            .endpoint
            .join("health")
            .map_err(|_| ClientError::InvalidEndpoint)?;
        read_json(
            self.client
                .get(endpoint)
                .timeout(REQUEST_TIMEOUT)
                .send()
                .map_err(|_| ClientError::Transport)?,
        )
    }

    pub(super) fn rpc(
        &self,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<Value, ClientError> {
        let id = self
            .next_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| ClientError::Transport)?;
        let response = self
            .client
            .post(self.endpoint.clone())
            .timeout(timeout.min(REQUEST_TIMEOUT))
            .json(&json!({"jsonrpc":"2.0", "id":id, "method":method, "params":params}))
            .send()
            .map_err(|_| ClientError::Transport)?;
        let value = read_json(response)?;
        if !value.is_object()
            || value.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
            || value.get("id").and_then(Value::as_u64) != Some(id)
        {
            return Err(ClientError::MalformedResponse);
        }
        if let Some(error) = value.get("error") {
            if !error.is_object()
                || error.get("message").and_then(Value::as_str).is_none()
                || value.get("result").is_some()
            {
                return Err(ClientError::MalformedResponse);
            }
            let code = error
                .get("code")
                .and_then(Value::as_i64)
                .ok_or(ClientError::MalformedResponse)?;
            return Err(if code == -32001 {
                ClientError::IdentityMismatch
            } else {
                ClientError::Rpc(code)
            });
        }
        value
            .get("result")
            .cloned()
            .ok_or(ClientError::MalformedResponse)
    }
}

fn endpoint_url(endpoint: &str) -> Result<Url, ClientError> {
    if endpoint
        .bytes()
        .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control() || byte == b'\\')
    {
        return Err(ClientError::InvalidEndpoint);
    }
    let url = Url::parse(endpoint).map_err(|_| ClientError::InvalidEndpoint)?;
    if url.scheme() != "http"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
        || url.port() == Some(0)
    {
        return Err(ClientError::InvalidEndpoint);
    }
    // Inspect the original literal too: URL normalization accepts abbreviated IPv4.
    let tail = endpoint
        .strip_prefix("http://")
        .ok_or(ClientError::InvalidEndpoint)?;
    let (authority, path) = tail.split_once('/').unwrap_or((tail, ""));
    if !path.is_empty() {
        return Err(ClientError::InvalidEndpoint);
    }
    let host = if let Some(rest) = authority.strip_prefix('[') {
        rest.split_once(']').map(|(host, _)| host)
    } else {
        authority.split(':').next()
    }
    .ok_or(ClientError::InvalidEndpoint)?;
    if !host
        .parse::<IpAddr>()
        .is_ok_and(|address| address.is_loopback())
    {
        return Err(ClientError::InvalidEndpoint);
    }
    Ok(url)
}

fn read_json(response: Response) -> Result<Value, ClientError> {
    if !response.status().is_success() {
        return Err(ClientError::Transport);
    }
    if response
        .content_length()
        .is_some_and(|size| size > MAX_RESPONSE_BYTES as u64)
    {
        return Err(ClientError::MalformedResponse);
    }
    let mut bytes = Vec::new();
    response
        .take((MAX_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| ClientError::Transport)?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(ClientError::MalformedResponse);
    }
    serde_json::from_slice(&bytes).map_err(|_| ClientError::MalformedResponse)
}
