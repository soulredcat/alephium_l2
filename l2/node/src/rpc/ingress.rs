use super::{RpcState, error};
use axum::{
    Json,
    extract::FromRequestParts,
    http::{StatusCode, request::Parts},
    response::{IntoResponse, Response},
};
use serde_json::Value;
use tokio::sync::OwnedSemaphorePermit;

/// Wait for processing capacity before Bytes collects the body or JSON is
/// parsed. Waiting requests have no admission ACK and hold no parsed payload.
#[derive(Debug)]
pub(super) struct RequestSlot {
    _permit: OwnedSemaphorePermit,
}

impl FromRequestParts<RpcState> for RequestSlot {
    type Rejection = Response;

    async fn from_request_parts(_: &mut Parts, state: &RpcState) -> Result<Self, Self::Rejection> {
        state
            .requests
            .clone()
            .acquire_owned()
            .await
            .map(|permit| Self { _permit: permit })
            .map_err(|_| {
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(error(
                        Value::Null,
                        -32000,
                        "Server unavailable before admission",
                    )),
                )
                    .into_response()
            })
    }
}

#[cfg(test)]
mod tests {
    use super::RequestSlot;
    use crate::{config::Config, development, operator, rpc, service};
    use axum::{
        body::{Body, to_bytes},
        extract::{DefaultBodyLimit, FromRequestParts},
        handler::Handler,
        http::{Request, StatusCode, header::CONTENT_TYPE},
    };
    use serde_json::Value;
    use std::{
        future::Future,
        task::{Context, Waker},
    };

    #[tokio::test]
    async fn ingress_waits_before_body_and_releases_on_all_handler_paths() {
        let directory = tempfile::tempdir().unwrap();
        let config = Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            data_dir: directory.path().join("data"),
            genesis: development::genesis(),
            min_gas_price: 0,
            max_checkpoint_bytes: operator::MAX_CONTINUATION_CHECKPOINT_BYTES,
            rpc: Default::default(),
            verification_workers_per_cpu: 1,
            verification_backend: crate::config::VerificationBackend::Cpu,
            gpu_device: 0,
        };
        let (node, worker) = service::start(&config).unwrap();
        let state = rpc::state(node.clone());
        let max_requests = state.limits.request_inflight;
        let mut slots = Vec::new();
        for _ in 0..max_requests {
            let (mut parts, _) = Request::new(Body::empty()).into_parts();
            slots.push(
                RequestSlot::from_request_parts(&mut parts, &state)
                    .await
                    .unwrap(),
            );
        }
        assert_eq!(state.requests.available_permits(), 0);

        // The zero-byte limit would produce 413 if Bytes ran first. With all
        // slots occupied, the actual handler remains pending before Bytes.
        let input = Request::builder()
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from("{"))
            .unwrap();
        let waiting = rpc::request
            .layer(DefaultBodyLimit::max(0))
            .call(input, state.clone());
        let mut waiting = std::pin::pin!(waiting);
        let mut context = Context::from_waker(Waker::noop());
        assert!(waiting.as_mut().poll(&mut context).is_pending());
        assert_eq!(node.pending_count(), 0);
        assert_eq!(state.requests.available_permits(), 0);

        // Canceling another waiter removes it without consuming a permit.
        let mut canceled = rpc::request.call(Request::new(Body::empty()), state.clone());
        assert!(canceled.as_mut().poll(&mut context).is_pending());
        drop(canceled);
        assert_eq!(state.requests.available_permits(), 0);

        // Health remains reachable when every RPC ingress slot is occupied.
        let response = rpc::health
            .call(Request::new(Body::empty()), state.clone())
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 4096).await.unwrap();
        let health: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            health["capacity"]["block_gas"],
            config.genesis.capacity.block_gas
        );
        assert_eq!(health["rpc_limits"]["request_inflight"], max_requests);
        drop(slots.pop().unwrap());
        let response = waiting.await;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(state.requests.available_permits(), 1);
        drop(slots);
        assert_eq!(state.requests.available_permits(), max_requests);

        let limits = rpc::RpcLimits {
            request_inflight: 2,
            read_inflight: 1,
            simulation_inflight: 1,
            ..Default::default()
        };
        let smaller = rpc::state_with_limits(node.clone(), limits);
        assert_eq!(smaller.requests.available_permits(), 2);
        assert_eq!(smaller.reads.available_permits(), 1);
        assert_eq!(smaller.simulations.available_permits(), 1);
        assert!(rpc::router_with_limits(node.clone(), limits).is_ok());
        assert!(
            rpc::router_with_limits(
                node.clone(),
                rpc::RpcLimits {
                    request_inflight: 0,
                    ..limits
                }
            )
            .is_err()
        );

        for (body, content_type, expected) in [
            ("{", "application/json", StatusCode::OK),
            ("{}", "text/plain", StatusCode::UNSUPPORTED_MEDIA_TYPE),
            (
                r#"{"jsonrpc":"2.0","method":"eth_chainId"}"#,
                "application/json",
                StatusCode::NO_CONTENT,
            ),
            (
                r#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId"}"#,
                "application/json",
                StatusCode::OK,
            ),
        ] {
            let input = Request::builder()
                .header(CONTENT_TYPE, content_type)
                .body(Body::from(body))
                .unwrap();
            let response = rpc::request.call(input, state.clone()).await;
            assert_eq!(response.status(), expected);
            assert_eq!(state.requests.available_permits(), max_requests);
        }
        let response = rpc::request
            .layer(DefaultBodyLimit::max(0))
            .call(Request::new(Body::from("{")), state.clone())
            .await;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(state.requests.available_permits(), max_requests);

        node.stop().await;
        worker.join().unwrap();
    }
}
