use super::{MAX_BATCH, RpcState, json_content, respond, state};
use crate::{config::Config, development, service};
use axum::http::{HeaderMap, HeaderValue, header::CONTENT_TYPE};
use serde_json::{Value, json};

async fn send(rpc: &RpcState, body: &str) -> Value {
    respond(rpc.clone(), body.as_bytes()).await
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

    let single = send(&rpc, &call(json!(7), "eth_chainId").to_string()).await;
    assert_eq!(single["id"], 7);
    assert_eq!(
        single["result"],
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
    assert_eq!(responses[0]["result"], single["result"]);
    assert_eq!(responses[1]["id"], "b");
    assert_eq!(responses[1]["result"], "0x0");
    assert_eq!(responses[2]["error"]["code"], -32600);
    assert_eq!(responses[3]["error"]["code"], -32601);
    assert_eq!(responses[4]["error"]["code"], -32600);

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
