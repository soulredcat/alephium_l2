//! Owned child and HTTP helpers for one isolated wallet interoperability flow.
use alephium_l2_node::{development, protocol::CHAIN_ID};
use alloy_eips::eip2930::AccessList;
use alloy_primitives::{Address, U256, keccak256};
use reqwest::blocking::Client;
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Read},
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

pub(crate) struct OwnedNode(Child);

impl OwnedNode {
    pub(crate) fn start(port: u16, data: &Path, genesis: &Path) -> Self {
        Self(
            Command::new(env!("CARGO_BIN_EXE_alephium-l2-node"))
                .args(["--data-dir", data.to_str().unwrap()])
                .args(["--genesis", genesis.to_str().unwrap()])
                .args(["--listen", &format!("127.0.0.1:{port}")])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn isolated owned wallet-flow child"),
        )
    }

    pub(crate) fn ready(&mut self, api: &Api) {
        // Main prints this line only after this child's bind and store startup.
        // Never send test transactions to a listener merely sharing the port.
        let stdout = self.0.stdout.take().unwrap();
        let (sent, received) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut line = String::new();
            let _ = BufReader::new(stdout.take(2048)).read_line(&mut line);
            let _ = sent.send(line);
        });
        let startup = received
            .recv_timeout(Duration::from_secs(15))
            .expect("owned child's startup acknowledgement exceeded deadline");
        reader.join().expect("owned startup reader failed");
        let expected = format!(
            "Development-only EVM node on {}; chain {CHAIN_ID}; settlement unimplemented",
            api.url.trim_start_matches("http://")
        );
        assert_eq!(
            startup.trim(),
            expected,
            "owned child did not acknowledge its bound endpoint"
        );
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
                && let Ok(health) = response.json::<Value>()
                && health["chain_id"] == CHAIN_ID
                && health["status"] == "development"
                && self.0.try_wait().unwrap().is_none()
            {
                return;
            }
            assert!(Instant::now() < deadline, "startup readiness exceeded");
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    pub(crate) fn kill(&mut self) {
        self.0.kill().expect("terminate this owned child only");
        self.0.wait().expect("reap owned child");
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

pub(crate) struct Api {
    client: Client,
    url: String,
}

impl Api {
    pub(crate) fn new(port: u16) -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(3))
                .build()
                .unwrap(),
            url: format!("http://127.0.0.1:{port}"),
        }
    }

    pub(crate) fn response(&self, method: &str, params: Value) -> Value {
        self.client
            .post(&self.url)
            .json(&json!({"jsonrpc":"2.0", "id":1, "method":method, "params":params}))
            .send()
            .unwrap()
            .json()
            .unwrap()
    }

    pub(crate) fn rpc(&self, method: &str, params: Value) -> Value {
        let result = self.response(method, params);
        assert!(result.get("error").is_none(), "RPC method {method} failed");
        result["result"].clone()
    }

    pub(crate) fn health(&self) -> Value {
        self.client
            .get(format!("{}/health", self.url))
            .send()
            .unwrap()
            .json()
            .unwrap()
    }

    pub(crate) fn admit(&self, raw: &[u8]) -> String {
        let hash = format!("{:#x}", keccak256(raw));
        let accepted = self.rpc(
            "eth_sendRawTransaction",
            json!([format!("0x{}", hex::encode(raw))]),
        );
        assert_eq!(accepted, hash, "canonical identity changed");
        hash
    }

    pub(crate) fn receipt(&self, hash: &str) -> Value {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let value = self.rpc("eth_getTransactionReceipt", json!([hash]));
            if !value.is_null() {
                assert_eq!(value["transactionHash"], hash);
                return value;
            }
            assert!(
                Instant::now() < deadline,
                "durable intent did not reach receipt"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    pub(crate) fn balance(&self, address: Address) -> U256 {
        quantity(&self.rpc("eth_getBalance", json!([format!("{address:#x}"), "latest"])))
    }

    pub(crate) fn nonce(&self) -> U256 {
        quantity(&self.rpc(
            "eth_getTransactionCount",
            json!([format!("{:#x}", development::address()), "latest"]),
        ))
    }

    pub(crate) fn slot(&self, address: Address) -> Value {
        self.rpc(
            "eth_getStorageAt",
            json!([format!("{address:#x}"), "0x0", "latest"]),
        )
    }

    pub(crate) fn estimate(&self, to: Option<Address>, data: &[u8], priority: u64) -> u64 {
        let mut call = json!({
            "from":format!("{:#x}", development::address()),
            "data":format!("0x{}", hex::encode(data)), "value":"0x0",
            "maxFeePerGas":"0xa", "maxPriorityFeePerGas":format!("0x{priority:x}")
        });
        if let Some(to) = to {
            call["to"] = json!(format!("{to:#x}"));
        }
        quantity(&self.rpc("eth_estimateGas", json!([call, "latest"]))).to::<u64>()
    }

    pub(crate) fn transact(
        &self,
        nonce: u64,
        to: Option<Address>,
        value: u64,
        data: Vec<u8>,
        gas: u64,
        priority: u128,
    ) -> Value {
        let raw = development::sign_type2(
            nonce,
            to,
            U256::from(value),
            data,
            gas,
            10,
            priority,
            AccessList::default(),
        )
        .unwrap();
        self.receipt(&self.admit(&raw))
    }
}

pub(crate) fn quantity(value: &Value) -> U256 {
    U256::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
}
