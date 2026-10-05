use crate::{protocol::*, service::NodeHandle};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::Semaphore;

#[cfg(test)]
mod batch_tests;
mod block;
mod call;
#[cfg(test)]
mod compat_tests;
mod estimate;
mod fee_history;
mod logs;
mod read;
mod receipt;
mod transaction;

#[derive(Clone)]
struct RpcState {
    node: NodeHandle,
    reads: Arc<Semaphore>,
    simulations: Arc<Semaphore>,
}

/// Common client libraries batch by default (ethers v6 up to 100 calls).
const MAX_BATCH: usize = 100;
/// Later batch members fail once responses exceed this; one member is <= BLOCK_BYTES.
const MAX_BATCH_RESPONSE_BYTES: usize = 4 * BLOCK_BYTES;

pub fn router(node: NodeHandle) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/", post(request))
        .layer(DefaultBodyLimit::max(BLOCK_BYTES))
        .with_state(state(node))
}

fn state(node: NodeHandle) -> RpcState {
    RpcState {
        node,
        reads: Arc::new(Semaphore::new(32)),
        simulations: Arc::new(Semaphore::new(4)),
    }
}

async fn health(State(state): State<RpcState>) -> Json<Value> {
    let failure = state.node.failure();
    let view = state.node.view().ok();
    let head = view.as_ref().map(|view| &view.head);
    Json(
        json!({"status":if failure.is_some() {"recovery_required"} else {"development"},
        "chain_id":view.as_ref().map(|view| view.chain_id()),"height":head.map(|h| h.height),
        "local_commit_id":head.as_ref().map(|h| h.commit_id),
        "genesis_id":head.as_ref().map(|h| h.genesis_id),
        "pending":state.node.pending_count(),"settlement":"unimplemented","error":failure,
        "rpc_profile":"development/c5-v1","transaction_types":["0x0","0x2"],"base_fee":"0x0",
        "min_gas_price":format!("0x{:x}", state.node.min_gas_price())}),
    )
}

async fn request(State(state): State<RpcState>, headers: HeaderMap, body: Bytes) -> Response {
    // Same media types the previous JSON extractor accepted.
    if !json_content(&headers) {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }
    match respond(state, &body).await {
        Some(response) => Json(response).into_response(),
        None => StatusCode::NO_CONTENT.into_response(),
    }
}

fn json_content(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(|mime| mime.trim().to_ascii_lowercase())
        .is_some_and(|mime| {
            mime == "application/json"
                || mime.starts_with("application/") && mime.ends_with("+json")
        })
}

/// JSON-RPC 2.0 single or batch request. Batch members run in order and each
/// keeps the single-request bounds; malformed JSON is a -32700 response.
async fn respond(state: RpcState, body: &[u8]) -> Option<Value> {
    let Ok(input) = serde_json::from_slice::<Value>(body) else {
        return Some(error(Value::Null, -32700, "Parse error"));
    };
    let Value::Array(calls) = input else {
        return single(state, input, false).await;
    };
    if calls.is_empty() || calls.len() > MAX_BATCH {
        return Some(error(Value::Null, -32600, "Invalid request"));
    }
    let mut responses = Vec::with_capacity(calls.len());
    let mut bytes = 0usize;
    for call in calls {
        let Some(response) = single(state.clone(), call, bytes > MAX_BATCH_RESPONSE_BYTES).await
        else {
            continue;
        };
        bytes = bytes.saturating_add(serde_json::to_vec(&response).map_or(0, |bytes| bytes.len()));
        responses.push(response);
    }
    (!responses.is_empty()).then_some(Value::Array(responses))
}

async fn single(state: RpcState, input: Value, response_limit_reached: bool) -> Option<Value> {
    let id = input.get("id").cloned();
    let valid_id = id
        .as_ref()
        .is_none_or(|id| id.is_null() || id.is_string() || id.is_number());
    if !input.is_object()
        || input.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || input.get("method").and_then(Value::as_str).is_none()
        || input
            .get("params")
            .is_some_and(|params| !params.is_array() && !params.is_object())
        || !valid_id
    {
        let id = if valid_id {
            id.unwrap_or(Value::Null)
        } else {
            Value::Null
        };
        return Some(error(id, -32600, "Invalid request"));
    }
    // Notifications still execute, including after the response budget is used;
    // they never contribute a response. MAX_BATCH bounds their work count too.
    let result = if response_limit_reached && id.is_some() {
        Err(RpcError::from("Batch response exceeds bound".to_string()))
    } else {
        dispatch(state, input).await
    };
    let id = id?;
    Some(match result {
        Ok(value) => json!({"jsonrpc":"2.0","id":id,"result":value}),
        Err(failure) => {
            let mut response = error(id, failure.code, &failure.message);
            if let Some(data) = failure.data {
                response["error"]["data"] = data;
            }
            response
        }
    })
}

#[derive(Debug)]
struct RpcError {
    code: i64,
    message: String,
    data: Option<Value>,
}
impl From<String> for RpcError {
    fn from(message: String) -> Self {
        Self {
            code: -32000,
            message,
            data: None,
        }
    }
}
impl From<&str> for RpcError {
    fn from(message: &str) -> Self {
        Self {
            code: -32602,
            message: message.into(),
            data: None,
        }
    }
}

fn error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}

async fn dispatch(state: RpcState, input: Value) -> Result<Value, RpcError> {
    let method = input
        .get("method")
        .and_then(Value::as_str)
        .ok_or("Missing method")?;
    if state.node.failure().is_some() {
        return Err("Recovery required".to_string().into());
    }
    if matches!(method, "eth_sendRawTransaction" | "l2_sendRawTransaction") {
        let pinned = method == "l2_sendRawTransaction";
        let count = if pinned { 2 } else { 1 };
        let params = parameters(&input, count, count)?;
        if pinned {
            let view = state.node.view()?;
            genesis_pin(view.as_ref(), &params[1])?;
        }
        let raw = bytes(
            params[0].as_str().ok_or("Expected transaction bytes")?,
            MAX_TRANSACTION_BYTES,
        )?;
        let status = state.node.submit(raw).await?;
        return Ok(json!(status.hash));
    }
    if matches!(method, "eth_gasPrice" | "eth_maxPriorityFeePerGas") {
        parameters(&input, 0, 0)?;
        // With a zero base fee the priority fee is the whole price; never suggest zero.
        return Ok(json!(format!("0x{:x}", state.node.min_gas_price().max(1))));
    }
    let pool = if matches!(method, "eth_call" | "eth_estimateGas") {
        state.simulations
    } else {
        state.reads
    };
    let permit = pool
        .try_acquire_owned()
        .map_err(|_| RpcError::from("Read workers busy".to_string()))?;
    let view = state.node.view()?;
    let node = state.node.clone();
    // The permit lives inside the work, not inside the HTTP waiter.
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        read::dispatch(view, &input).inspect_err(|failure| {
            if failure.message.starts_with("Storage read failed")
                || crate::execution::is_infrastructure_error(&failure.message)
            {
                node.mark_failed();
            }
        })
    })
    .await
    .map_err(|_| {
        state.node.mark_failed();
        RpcError::from("Read worker failed; recovery required".to_string())
    })?
}

fn genesis_pin(view: &crate::storage::ReadView, expected: &Value) -> Result<(), RpcError> {
    let expected = expected
        .as_str()
        .ok_or("Expected genesis identity")?
        .parse::<alloy_primitives::B256>()
        .map_err(|_| RpcError::from("Invalid genesis identity"))?;
    if view.head.genesis_id != expected {
        return Err(RpcError {
            code: -32001,
            message: "Pinned genesis identity differs".into(),
            data: None,
        });
    }
    Ok(())
}

fn parameters(input: &Value, min: usize, max: usize) -> Result<&[Value], RpcError> {
    let params = match input.get("params") {
        None => &[][..],
        Some(Value::Array(params)) => params.as_slice(),
        _ => return Err("Expected parameters array".into()),
    };
    if params.len() < min || params.len() > max {
        return Err("Invalid parameter count".into());
    }
    Ok(params)
}

fn latest(params: &[Value], index: usize) -> Result<(), RpcError> {
    if params
        .get(index)
        .is_some_and(|v| v.as_str() != Some("latest"))
    {
        return Err("Only latest committed state is supported".into());
    }
    Ok(())
}

fn bytes(value: &str, max: usize) -> Result<Vec<u8>, RpcError> {
    let raw = value.strip_prefix("0x").ok_or("Expected 0x data")?;
    if raw.len() > max.saturating_mul(2) || raw.len() % 2 != 0 {
        return Err("Data size or encoding invalid".into());
    }
    hex::decode(raw).map_err(|_| "Invalid hexadecimal data".into())
}

fn quantity(value: &str) -> Result<alloy_primitives::U256, RpcError> {
    let raw = value
        .strip_prefix("0x")
        .ok_or("Expected hexadecimal quantity")?;
    if raw.is_empty() || raw.len() > 64 || (raw.len() > 1 && raw.starts_with('0')) {
        return Err("Noncanonical quantity".into());
    }
    alloy_primitives::U256::from_str_radix(raw, 16).map_err(|_| "Invalid quantity".into())
}
