use super::{MAX_BATCH, RpcState, json_content, request, respond, single, state};
use crate::{config::Config, development, execution, operator, service};
use axum::{
    body::{Bytes, to_bytes},
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header::CONTENT_TYPE},
};
use serde_json::{Value, json};

async fn send(rpc: &RpcState, body: &str) -> Value {
    respond(rpc.clone(), body.as_bytes()).await.unwrap()
}

fn call(id: Value, method: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":method,"params":[]})
}

#[tokio::test]
async fn batches_and_parse_errors_follow_json_rpc() {
    let directory = tempfile::tempdir().unwrap();
    let config = Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        data_dir: directory.path().join("data"),
        genesis: development::genesis(),
        min_gas_price: 0,
        max_checkpoint_bytes: operator::MAX_CONTINUATION_CHECKPOINT_BYTES,
    };
    let (node, worker) = service::start(&config).unwrap();
    let rpc = state(node.clone());
    assert_eq!(send(&rpc, "{").await["error"]["code"], -32700);
    assert_eq!(send(&rpc, "[]").await["error"]["code"], -32600);
    let oversized = Value::Array(vec![call(json!(1), "eth_chainId"); MAX_BATCH + 1]);
    assert_eq!(
        send(&rpc, &oversized.to_string()).await["error"]["code"],
        -32600
    );

    let single_response = send(&rpc, &call(json!(7), "eth_chainId").to_string()).await;
    assert_eq!(single_response["id"], 7);
    assert_eq!(
        single_response["result"],
        format!("0x{:x}", development::genesis().chain_id)
    );

    let batch = json!([
        call(json!(1), "eth_chainId"),
        call(json!("b"), "eth_blockNumber"),
        {"jsonrpc":"1.0","id":3,"method":"eth_chainId"},
        call(json!(4), "eth_unknown"),
        5
    ]);
    let responses = send(&rpc, &batch.to_string()).await;
    let responses = responses.as_array().unwrap();
    assert_eq!(responses.len(), 5);
    assert_eq!(responses[0]["id"], 1);
    assert_eq!(responses[0]["result"], single_response["result"]);
    assert_eq!(responses[1]["id"], "b");
    assert_eq!(responses[1]["result"], "0x0");
    assert_eq!(responses[2]["error"]["code"], -32600);
    assert_eq!(responses[3]["error"]["code"], -32601);
    assert_eq!(responses[4]["error"]["code"], -32600);

    let notification = json!({"jsonrpc":"2.0","method":"eth_chainId","params":[]});
    let unknown = json!({"jsonrpc":"2.0","method":"eth_unknown"});
    let mixed = json!([notification, call(Value::Null, "eth_chainId"), unknown]);
    let responses = send(&rpc, &mixed.to_string()).await;
    assert_eq!(responses.as_array().unwrap().len(), 1);
    assert!(responses[0]["id"].is_null());
    assert!(responses[0].get("result").is_some());
    let invalid = send(&rpc, r#"{"jsonrpc":"2.0"}"#).await;
    assert_eq!(invalid["error"]["code"], -32600);
    let invalid = send(
        &rpc,
        r#"{"jsonrpc":"2.0","method":"eth_chainId","params":0}"#,
    )
    .await;
    assert_eq!(invalid["error"]["code"], -32600);
    let invalid_id = send(&rpc, &call(json!({}), "eth_chainId").to_string()).await;
    assert!(invalid_id["id"].is_null());
    assert_eq!(invalid_id["error"]["code"], -32600);

    // Single and all-notification batches have no HTTP response body.
    for input in [notification.clone(), json!([notification, unknown])] {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let response = request(State(rpc.clone()), headers, Bytes::from(input.to_string())).await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(
            to_bytes(response.into_body(), 1024)
                .await
                .unwrap()
                .is_empty()
        );
    }

    // Suppressing a notification response must not suppress its durable action,
    // even when previous batch responses have exhausted the response budget.
    let raw = development::sign(
        0,
        Some(alloy_primitives::Address::repeat_byte(0x77)),
        alloy_primitives::U256::from(1),
        vec![],
        21_000,
    )
    .unwrap();
    let hash = execution::inspect(&raw).unwrap().hash;
    let submit = json!({"jsonrpc":"2.0","method":"eth_sendRawTransaction",
        "params":[format!("0x{}", hex::encode(raw))]});
    assert!(single(rpc.clone(), submit, true).await.is_none());
    assert!(node.view().unwrap().status(hash).unwrap().is_some());
    let limited = single(rpc.clone(), call(json!(9), "eth_chainId"), true)
        .await
        .unwrap();
    assert_eq!(limited["error"]["code"], -32000);

    node.stop().await;
    worker.join().unwrap();
}

#[test]
fn only_json_media_types_are_accepted() {
    let mut headers = HeaderMap::new();
    assert!(!json_content(&headers));
    for (value, accepted) in [
        ("application/json", true),
        ("Application/JSON; charset=utf-8", true),
        ("application/json-rpc+json", true),
        ("text/plain", false),
        ("application/x-www-form-urlencoded", false),
    ] {
        headers.insert(CONTENT_TYPE, HeaderValue::from_static(value));
        assert_eq!(json_content(&headers), accepted, "{value}");
    }
}
