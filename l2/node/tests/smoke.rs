//! One bounded development flow, not a benchmark or physical power-loss qualification.
use alephium_l2_node::{development, protocol::CHAIN_ID};
use alloy_primitives::{Address, U256, keccak256};
use reqwest::blocking::Client;
use serde_json::{Value, json};
use std::{
    io::Read,
    net::TcpListener,
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

#[path = "support/smoke_profile.rs"]
mod profile;

struct OwnedNode(Child);

impl OwnedNode {
    fn start(port: u16, data: &Path, genesis: &Path) -> Self {
        Self(
            Command::new(env!("CARGO_BIN_EXE_alephium-l2-node"))
                .arg("--data-dir")
                .arg(data)
                .arg("--genesis")
                .arg(genesis)
                .args(["--listen", &format!("127.0.0.1:{port}")])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn isolated owned development child"),
        )
    }

    fn ready(&mut self, api: &Api) {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                let mut diagnostic = String::new();
                self.0
                    .stderr
                    .take()
                    .unwrap()
                    .take(2048)
                    .read_to_string(&mut diagnostic)
                    .unwrap();
                panic!("startup child exited ({status}): {diagnostic}");
            }
            if let Ok(response) = api.client.get(format!("{}/health", api.url)).send()
                && response.status().is_success()
            {
                return;
            }
            assert!(Instant::now() < deadline, "startup readiness exceeded");
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn kill(&mut self) {
        // This exact child handle is the only process termination authority.
        self.0.kill().expect("terminate owned child");
        self.0.wait().expect("reap owned child");
    }

    fn expect_refused(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.0.try_wait().unwrap() {
                assert!(!status.success(), "incompatible identity was accepted");
                let mut diagnostics = String::new();
                self.0
                    .stderr
                    .take()
                    .unwrap()
                    .take(16_384)
                    .read_to_string(&mut diagnostics)
                    .unwrap();
                assert!(
                    diagnostics.to_ascii_lowercase().contains("genesis"),
                    "startup failed for an unrelated reason"
                );
                return;
            }
            assert!(
                Instant::now() < deadline,
                "invalid identity did not stop startup"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}

impl Drop for OwnedNode {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

struct Api {
    client: Client,
    url: String,
}

impl Api {
    fn new(port: u16) -> Self {
        Self::endpoint(format!("http://127.0.0.1:{port}"))
    }

    fn endpoint(url: String) -> Self {
        Self {
            client: Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .pool_max_idle_per_host(0)
                .timeout(Duration::from_secs(3))
                .build()
                .unwrap(),
            url,
        }
    }

    fn health(&self) -> Value {
        self.client
            .get(format!("{}/health", self.url))
            .send()
            .unwrap()
            .json()
            .unwrap()
    }

    fn response(&self, method: &str, params: Value) -> Value {
        self.client
            .post(&self.url)
            .json(&json!({"jsonrpc":"2.0", "id":1, "method":method, "params":params}))
            .send()
            .unwrap()
            .json()
            .unwrap()
    }

    fn rpc(&self, method: &str, params: Value) -> Value {
        let response = self.response(method, params);
        assert!(
            response.get("error").is_none(),
            "RPC method {method} failed"
        );
        response["result"].clone()
    }

    fn admit(&self, raw: &[u8]) -> String {
        let expected = format!("{:#x}", keccak256(raw));
        let result = self.rpc(
            "eth_sendRawTransaction",
            json!([format!("0x{}", hex::encode(raw))]),
        );
        assert_eq!(result, expected, "admission changed canonical identity");
        expected
    }

    fn receipt(&self, hash: &str) -> Value {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let value = self.rpc("eth_getTransactionReceipt", json!([hash]));
            if !value.is_null() {
                assert_eq!(value["transactionHash"], hash);
                return value;
            }
            assert!(
                Instant::now() < deadline,
                "durable intent did not reach a receipt"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn transact(&self, nonce: u64, to: Option<Address>, value: u64, input: Vec<u8>) -> Value {
        let raw = development::sign(nonce, to, U256::from(value), input, 500_000).unwrap();
        self.receipt(&self.admit(&raw))
    }

    fn balance(&self, address: Address) -> U256 {
        quantity(&self.rpc("eth_getBalance", json!([format!("{address:#x}"), "latest"])))
    }

    fn nonce(&self) -> U256 {
        quantity(&self.rpc(
            "eth_getTransactionCount",
            json!([format!("{:#x}", development::address()), "latest"]),
        ))
    }

    fn slot(&self, address: Address) -> Value {
        self.rpc(
            "eth_getStorageAt",
            json!([format!("{address:#x}"), "0x0", "latest"]),
        )
    }

    fn call(&self, address: Address, input: Vec<u8>) -> Value {
        self.rpc(
            "eth_call",
            json!([{
            "to":format!("{address:#x}"), "data":format!("0x{}", hex::encode(input)),
            "gas":"0x7a120"
        }, "latest"]),
        )
    }
}

fn quantity(value: &Value) -> U256 {
    U256::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}

fn contract(receipt: &Value) -> Address {
    assert_eq!(receipt["status"], "0x1");
    receipt["contractAddress"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap()
}

#[test]
fn durable_transfer_contracts_and_owned_restart() {
    if let Some(mode) = std::env::var_os("L2_SMOKE_MODE") {
        profile::run(mode.to_str().expect("smoke mode must be Unicode"));
        return;
    }
    let fixture = tempfile::tempdir().unwrap();
    let genesis_path = fixture.path().join("genesis.json");
    let data = fixture.path().join("new-chain");
    std::fs::write(
        &genesis_path,
        serde_json::to_vec(&development::genesis()).unwrap(),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let api = Api::new(port);
    let sender = development::address();
    let recipient = Address::repeat_byte(0x77);
    let mut node = OwnedNode::start(port, &data, &genesis_path);
    node.ready(&api);
    assert_eq!(api.health()["chain_id"], CHAIN_ID);
    assert_eq!(api.health()["settlement"], "unimplemented");
    assert_eq!(
        quantity(&api.rpc("eth_chainId", json!([]))),
        U256::from(CHAIN_ID)
    );
    assert_eq!(
        api.balance(sender),
        U256::from(development::INITIAL_BALANCE)
    );

    let raw = development::sign(0, Some(recipient), U256::from(123), vec![], 21_000).unwrap();
    let hash = api.admit(&raw);
    node.kill(); // ACK may describe a pending intent or a completed block; both must recover.
    node = OwnedNode::start(port, &data, &genesis_path);
    node.ready(&api);
    let transfer = api.receipt(&hash); // Reconcile by identity; never automatic rebroadcast.
    assert_eq!(transfer["status"], "0x1");
    assert_eq!(quantity(&transfer["gasUsed"]), U256::from(21_000));
    assert_eq!(api.balance(recipient), U256::from(123));
    assert_eq!(
        api.balance(sender),
        U256::from(development::INITIAL_BALANCE - 123 - 21_000)
    );
    assert_eq!(api.nonce(), U256::from(1));
    let duplicate_head = api.health()["local_commit_id"].clone();
    assert_eq!(api.admit(&raw), hash);
    assert_eq!(api.receipt(&hash), transfer);
    assert_eq!(api.health()["local_commit_id"], duplicate_head);
    assert!(api.response("eth_sendRawTransaction", json!(["0xff"]))["error"].is_object());
    assert_eq!(api.nonce(), U256::from(1));
    assert_eq!(api.balance(recipient), U256::from(123));

    let deploy_a = api.transact(1, None, 0, development::contract_init());
    let a = contract(&deploy_a);
    let deploy_b = api.transact(2, None, 0, development::contract_init());
    let b = contract(&deploy_b);
    let expected_code = format!("0x{}", hex::encode(development::contract_runtime()));
    assert_eq!(
        api.rpc("eth_getCode", json!([format!("{a:#x}"), "latest"])),
        expected_code
    );
    let write = api.transact(3, Some(b), 0, development::contract_input(1, None));
    assert_eq!(write["status"], "0x1");
    assert_eq!(write["logs"].as_array().unwrap().len(), 1);
    let word_42 = format!("0x{:064x}", U256::from(42));
    assert_eq!(write["logs"][0]["topics"][0], word_42);
    assert_eq!(write["logs"][0]["data"], word_42);
    assert_eq!(api.slot(b), word_42);
    assert_eq!(api.call(b, development::contract_input(0, None)), word_42);
    let zero_word = format!("0x{:064x}", U256::ZERO);
    assert_eq!(api.slot(a), zero_word);
    assert_eq!(api.call(a, development::contract_input(1, None)), "0x");
    assert_eq!(
        api.slot(a),
        zero_word,
        "simulation persisted its private overlay"
    );
    assert_eq!(api.nonce(), U256::from(4));
    let nested_input = development::contract_input(3, Some(b));
    assert_eq!(api.call(a, nested_input.clone()), word_42);
    let nested = api.transact(4, Some(a), 0, nested_input);
    assert_eq!(nested["status"], "0x1");
    assert_eq!(nested["logs"].as_array().unwrap().len(), 1);
    assert_eq!(nested["logs"][0]["address"], format!("{a:#x}"));
    assert_eq!(nested["logs"][0]["topics"][0], word_42);
    assert_eq!(nested["logs"][0]["data"], word_42);
    let reverted = api.transact(5, Some(b), 77, development::contract_input(2, None));
    assert_eq!(reverted["status"], "0x0");
    assert!(reverted["logs"].as_array().unwrap().is_empty());
    assert_eq!(api.balance(b), U256::ZERO);
    assert_eq!(api.slot(b), word_42);
    assert_eq!(api.nonce(), U256::from(6));
    let receipts = [transfer, deploy_a, deploy_b, write, nested, reverted];
    let total_gas = receipts.iter().fold(U256::ZERO, |sum, receipt| {
        sum + quantity(&receipt["gasUsed"])
    });
    assert_eq!(
        api.balance(sender),
        U256::from(development::INITIAL_BALANCE - 123) - total_gas
    );
    assert_eq!(api.balance(Address::ZERO), total_gas);
    let health = api.health();
    let sender_balance = api.balance(sender);
    node.kill();
    node = OwnedNode::start(port, &data, &genesis_path);
    node.ready(&api);
    assert_eq!(api.health()["height"], health["height"]);
    assert_eq!(api.health()["local_commit_id"], health["local_commit_id"]);
    assert_eq!(api.balance(sender), sender_balance);
    assert_eq!(api.nonce(), U256::from(6));
    assert_eq!(api.slot(b), word_42);
    assert_eq!(
        api.rpc("eth_getCode", json!([format!("{a:#x}"), "latest"])),
        expected_code
    );
    for receipt in &receipts {
        assert_eq!(
            api.receipt(receipt["transactionHash"].as_str().unwrap()),
            *receipt
        );
    }
    node.kill();

    let mut incompatible = development::genesis();
    incompatible.accounts[0].balance += U256::from(1);
    let wrong_path = fixture.path().join("incompatible-genesis.json");
    std::fs::write(&wrong_path, serde_json::to_vec(&incompatible).unwrap()).unwrap();
    OwnedNode::start(port, &data, &wrong_path).expect_refused();
}
