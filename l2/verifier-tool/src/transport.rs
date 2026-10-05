//! Fixed loopback mainnet identity reads and synthetic read-only VM execution only.
use reqwest::{
    blocking::{Client, Response},
    redirect::Policy,
};
use serde_json::{Value, json};
use std::{
    io::Read,
    time::{Duration, Instant},
};

pub const ENDPOINT: &str = "http://127.0.0.1:12973";
const MAX_RESPONSE_BYTES: usize = 1_048_576;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

pub enum ProbeError {
    VmAssertion(u64),
    VmGasExhausted,
    Transport,
    Deadline,
}

pub struct ReadOnlyNode {
    client: Client,
    deadline: Instant,
    pub identity: Value,
}

impl ReadOnlyNode {
    pub fn connect(deadline: Instant) -> Result<Self, String> {
        let client = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .retry(reqwest::retry::never())
            .pool_max_idle_per_host(0)
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|_| "Cannot construct bounded read-only RPC client")?;
        let mut node = Self {
            client,
            deadline,
            identity: Value::Null,
        };
        let version = node.get("/infos/version")?;
        let chain = node.get("/infos/chain-params")?;
        let clique = node.get("/infos/self-clique")?;
        if chain["networkId"].as_u64() != Some(0) || clique["synced"].as_bool() != Some(true) {
            return Err(
                "Explicitly selected loopback RPC reports wrong network or unsynchronized state"
                    .into(),
            );
        }
        let reported_version = version["version"]
            .as_str()
            .ok_or("Missing VM reported version")?;
        if reported_version.is_empty()
            || reported_version.len() > 128
            || !reported_version.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err("VM reported version is malformed".into());
        }
        node.identity = json!({
            "version": reported_version, "chainParams": chain,
            "reportedNetworkId": 0, "reportedSynced": true,
            "genesisIndependentlyVerified": false,
            "rpcExecutableIndependentlyVerified": false,
            "forkIndependentlyVerified": false
        });
        Ok(node)
    }

    fn remaining(&self) -> Result<Duration, ProbeError> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .map(|remaining| remaining.min(REQUEST_TIMEOUT))
            .ok_or(ProbeError::Deadline)
    }

    fn get(&self, path: &str) -> Result<Value, String> {
        let timeout = self
            .remaining()
            .map_err(|_| "Field harness deadline expired during identity reads")?;
        let response = self
            .client
            .get(format!("{ENDPOINT}{path}"))
            .timeout(timeout)
            .send()
            .map_err(|_| "Selected loopback identity read failed")?;
        if !response.status().is_success() {
            return Err("Selected loopback identity endpoint is unavailable".into());
        }
        read_json(response)
            .map_err(|_| "Selected loopback identity response is not bounded JSON".into())
    }

    pub fn test(&self, request: &Value) -> Result<Value, ProbeError> {
        let timeout = self.remaining()?;
        let response = self
            .client
            .post(format!("{ENDPOINT}/contracts/test-contract"))
            .timeout(timeout)
            .json(request)
            .send()
            .map_err(|_| ProbeError::Transport)?;
        let status = response.status();
        let body = read_json(response).map_err(|_| ProbeError::Transport)?;
        if status.is_success() {
            return Ok(body);
        }
        // An HTTP failure alone is never a target negative result. Require the exact
        // Alephium VM assertion envelope from this synthetic execution endpoint.
        if status.as_u16() == 500
            && let Some(code) = body["detail"].as_str().and_then(assertion_code)
        {
            return Err(ProbeError::VmAssertion(code));
        }
        if status.as_u16() == 500 && body["detail"] == "VM execution error: OutOfGas" {
            return Err(ProbeError::VmGasExhausted);
        }
        Err(ProbeError::Transport)
    }
}

fn read_json(response: Response) -> Result<Value, ()> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(());
    }
    let mut bytes = Vec::new();
    response
        .take(MAX_RESPONSE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(());
    }
    serde_json::from_slice(&bytes).map_err(|_| ())
}

fn assertion_code(detail: &str) -> Option<u64> {
    let remainder = detail.strip_prefix("VM execution error: Assertion Failed in Contract @ ")?;
    let (address, code) = remainder.split_once(", Error Code: ")?;
    if address.is_empty()
        || address.len() > 100
        || code.is_empty()
        || !address.bytes().all(|byte| {
            b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(&byte)
        })
        || !code.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    code.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::assertion_code;

    #[test]
    fn transport_errors_and_ambiguous_text_do_not_become_vm_rejections() {
        assert_eq!(
            assertion_code(
                "VM execution error: Assertion Failed in Contract @ 123abc, Error Code: 1000"
            ),
            Some(1000)
        );
        for detail in [
            "Gateway unavailable",
            "AssertionFailed 1000",
            "VM execution error: Assertion Failed in Contract @ bad0, Error Code: 1000",
            "VM execution error: Assertion Failed in Contract @ 123abc, Error Code: 1000 trailing",
        ] {
            assert_eq!(assertion_code(detail), None);
        }
    }
}
