use crate::{protocol::*, service::NodeHandle};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    routing::{get, post},
};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::Semaphore;

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

pub fn router(node: NodeHandle) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/", post(request))
        .layer(DefaultBodyLimit::max(BLOCK_BYTES))
        .with_state(RpcState {
            node,
            reads: Arc::new(Semaphore::new(32)),
            simulations: Arc::new(Semaphore::new(4)),
        })
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
        "rpc_profile":"development/c5-v1","transaction_types":["0x0","0x2"],"base_fee":"0x0"}),
    )
}

async fn request(State(state): State<RpcState>, Json(input): Json<Value>) -> Json<Value> {
    let id = input.get("id").cloned().unwrap_or(Value::Null);
    if !input.is_object()
        || input.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || !(id.is_null() || id.is_string() || id.is_number())
    {
        return Json(error(id, -32600, "Invalid request"));
    }
    let result = dispatch(state, input).await;
    Json(match result {
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
