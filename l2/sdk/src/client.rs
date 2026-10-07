use crate::{
    ClientError, ExpectedNetwork, Lifecycle, NodeInfo, PreparedTransaction, Submission, receipt,
};
use alloy_primitives::{Address, B256, U256};
use serde_json::{Value, json};
use std::{
    thread,
    time::{Duration, Instant},
};

mod transport;
use transport::{REQUEST_TIMEOUT, Transport};

const DEVELOPMENT_PROFILE: &str = "development/c5-v1";
const MAX_WAIT: Duration = Duration::from_secs(60);
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// A blocking client for the declared local development RPC profile.
/// Its cached handshake and RPC observations do not establish L1 settlement.
pub struct Client {
    transport: Transport,
    info: NodeInfo,
}

impl Client {
    pub fn connect(endpoint: &str, expected: ExpectedNetwork) -> Result<Self, ClientError> {
        if expected.rpc_profile != DEVELOPMENT_PROFILE {
            return Err(ClientError::UnsupportedProfile);
        }
        let transport = Transport::connect(endpoint)?;
        let health = transport.health()?;
        let info = handshake(&health, &expected)?;
        let chain = quantity(&transport.rpc("eth_chainId", json!([]), REQUEST_TIMEOUT)?)?;
        if chain != U256::from(info.chain_id) {
            return Err(ClientError::IdentityMismatch);
        }
        Ok(Self { transport, info })
    }

    /// Identity and head observed during connection; no implicit refresh occurs.
    pub fn node_info(&self) -> &NodeInfo {
        &self.info
    }

    /// Latest committed balance from one server view fenced by the pinned genesis.
    pub fn balance(&self, address: Address) -> Result<U256, ClientError> {
        quantity(&self.transport.rpc(
            "l2_getBalance",
            json!([address, "latest", self.info.genesis_id]),
            REQUEST_TIMEOUT,
        )?)
    }

    pub fn nonce(&self, address: Address, pending: bool) -> Result<u64, ClientError> {
        let tag = if pending { "pending" } else { "latest" };
        quantity(&self.transport.rpc(
            "l2_getTransactionCount",
            json!([address, tag, self.info.genesis_id]),
            REQUEST_TIMEOUT,
        )?)?
        .try_into()
        .map_err(|_| ClientError::MalformedResponse)
    }

    /// Performs one POST. Any uncertain outcome must be reconciled by this hash.
    pub fn submit_once(
        &self,
        transaction: &PreparedTransaction,
    ) -> Result<Submission, ClientError> {
        if transaction.chain_id() != self.info.chain_id
            || !matches!(transaction.transaction_type(), 0 | 2)
        {
            return Err(ClientError::InvalidTransaction);
        }
        let hash = transaction.hash();
        let result = self.transport.rpc(
            "l2_sendRawTransaction",
            json!([
                format!("0x{}", hex::encode(transaction.as_bytes())),
                self.info.genesis_id
            ]),
            REQUEST_TIMEOUT,
        );
        match result {
            Ok(value) if parse_hash(&value) == Ok(hash) => {
                Ok(submission(hash, Lifecycle::DurablyAccepted))
            }
            Err(ClientError::IdentityMismatch) => Err(ClientError::IdentityMismatch),
            _ => Err(ClientError::Ambiguous(hash)),
        }
    }

    /// Queries the original transaction; never resubmits a signed envelope.
    pub fn reconcile(&self, hash: B256) -> Result<Submission, ClientError> {
        self.reconcile_bounded(hash, REQUEST_TIMEOUT)
    }

    /// Waits for a terminal local outcome for at most the requested 60-second cap.
    /// Short deadlines are honored; unknown is not rejection or permission to resend.
    pub fn wait(&self, hash: B256, timeout: Duration) -> Result<Submission, ClientError> {
        let timeout = timeout.min(MAX_WAIT);
        let start = Instant::now();
        loop {
            let budget = remaining(start, timeout, hash)?;
            let outcome = match self.reconcile_bounded(hash, budget) {
                Ok(outcome) => outcome,
                Err(ClientError::IdentityMismatch) => return Err(ClientError::IdentityMismatch),
                Err(_) if start.elapsed() >= timeout => return Err(ClientError::Timeout(hash)),
                Err(error) => return Err(error),
            };
            if matches!(
                outcome.lifecycle,
                Lifecycle::Committed | Lifecycle::Reverted | Lifecycle::Rejected
            ) {
                return Ok(outcome);
            }
            thread::sleep(remaining(start, timeout, hash)?.min(POLL_INTERVAL));
        }
    }

    fn reconcile_bounded(&self, hash: B256, budget: Duration) -> Result<Submission, ClientError> {
        let start = Instant::now();
        let params = json!([hash, self.info.genesis_id]);
        let status = self
            .transport
            .rpc("l2_getTransactionStatus", params.clone(), budget)?;
        let (lifecycle, height) = parse_status(&status, hash)?;
        let mut outcome = submission(hash, lifecycle);
        if matches!(lifecycle, Lifecycle::Committed | Lifecycle::Reverted) {
            let value = self.transport.rpc(
                "l2_getTransactionReceipt",
                params,
                remaining(start, budget, hash)?,
            )?;
            let block = match receipt::required_block(&value)? {
                Some(block_hash) => Some(self.transport.rpc(
                    "eth_getBlockByHash",
                    json!([block_hash, false]),
                    remaining(start, budget, hash)?,
                )?),
                None => None,
            };
            let receipt = receipt::parse(&value, hash, block.as_ref())?;
            if Some(receipt.block_height) != height
                || receipt.success != (lifecycle == Lifecycle::Committed)
            {
                return Err(ClientError::MalformedResponse);
            }
            outcome.receipt = Some(receipt);
        }
        Ok(outcome)
    }
}

fn handshake(health: &Value, expected: &ExpectedNetwork) -> Result<NodeInfo, ClientError> {
    if !health.is_object() {
        return Err(ClientError::MalformedResponse);
    }
    if health.get("status").and_then(Value::as_str) != Some("development")
        || health.get("error").is_none_or(|value| !value.is_null())
    {
        return Err(ClientError::NodeUnhealthy);
    }
    let chain_id = health
        .get("chain_id")
        .and_then(Value::as_u64)
        .ok_or(ClientError::MalformedResponse)?;
    let genesis_id = parse_hash(
        health
            .get("genesis_id")
            .ok_or(ClientError::MalformedResponse)?,
    )?;
    if chain_id != expected.chain_id || genesis_id != expected.genesis_id {
        return Err(ClientError::IdentityMismatch);
    }
    let profile = health
        .get("rpc_profile")
        .and_then(Value::as_str)
        .ok_or(ClientError::MalformedResponse)?;
    let types = health
        .get("transaction_types")
        .and_then(Value::as_array)
        .ok_or(ClientError::MalformedResponse)?;
    if profile != expected.rpc_profile
        || profile != DEVELOPMENT_PROFILE
        || health.get("settlement").and_then(Value::as_str) != Some("unimplemented")
        || types.len() != 2
        || !types.iter().any(|value| value.as_str() == Some("0x0"))
        || !types.iter().any(|value| value.as_str() == Some("0x2"))
    {
        return Err(ClientError::UnsupportedProfile);
    }
    Ok(NodeInfo {
        chain_id,
        genesis_id,
        height: health
            .get("height")
            .and_then(Value::as_u64)
            .ok_or(ClientError::MalformedResponse)?,
        local_commit_id: parse_hash(
            health
                .get("local_commit_id")
                .ok_or(ClientError::MalformedResponse)?,
        )?,
        rpc_profile: profile.to_owned(),
    })
}

fn parse_status(value: &Value, hash: B256) -> Result<(Lifecycle, Option<u64>), ClientError> {
    if value.is_null() {
        return Ok((Lifecycle::Unknown, None));
    }
    if !value.is_object()
        || parse_hash(value.get("hash").ok_or(ClientError::MalformedResponse)?)? != hash
    {
        return Err(ClientError::MalformedResponse);
    }
    let height = match value.get("block_height") {
        Some(Value::Null) => None,
        Some(value) => Some(
            value
                .as_u64()
                .filter(|height| *height > 0)
                .ok_or(ClientError::MalformedResponse)?,
        ),
        None => return Err(ClientError::MalformedResponse),
    };
    let error = value.get("error").ok_or(ClientError::MalformedResponse)?;
    let lifecycle = match value.get("status").and_then(Value::as_str) {
        Some("unknown") if height.is_none() && error.is_null() => Lifecycle::Unknown,
        Some("durably_accepted") if height.is_none() && error.is_null() => {
            Lifecycle::DurablyAccepted
        }
        Some("committed") if height.is_some() && error.is_null() => Lifecycle::Committed,
        Some("reverted") if height.is_some() && error.is_null() => Lifecycle::Reverted,
        Some("rejected") if error.is_string() => Lifecycle::Rejected,
        _ => return Err(ClientError::MalformedResponse),
    };
    Ok((lifecycle, height))
}

fn submission(hash: B256, lifecycle: Lifecycle) -> Submission {
    Submission {
        hash,
        lifecycle,
        receipt: None,
    }
}

fn remaining(start: Instant, timeout: Duration, hash: B256) -> Result<Duration, ClientError> {
    timeout
        .checked_sub(start.elapsed())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(ClientError::Timeout(hash))
}

fn parse_hash(value: &Value) -> Result<B256, ClientError> {
    let raw = value.as_str().ok_or(ClientError::MalformedResponse)?;
    if raw.len() != 66
        || !raw.starts_with("0x")
        || !raw[2..].bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(ClientError::MalformedResponse);
    }
    raw.parse().map_err(|_| ClientError::MalformedResponse)
}

fn quantity(value: &Value) -> Result<U256, ClientError> {
    let raw = value
        .as_str()
        .and_then(|value| value.strip_prefix("0x"))
        .ok_or(ClientError::MalformedResponse)?;
    if raw.is_empty()
        || raw.len() > 64
        || (raw.len() > 1 && raw.starts_with('0'))
        || !raw.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(ClientError::MalformedResponse);
    }
    U256::from_str_radix(raw, 16).map_err(|_| ClientError::MalformedResponse)
}
