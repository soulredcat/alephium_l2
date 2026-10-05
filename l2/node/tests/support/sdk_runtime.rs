//! Isolated child ownership and direct identity-rejection probe for the SDK flow.
use alephium_l2_node::protocol::CHAIN_ID;
use alloy_primitives::B256;
use reqwest::blocking::Client;
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Read},
    path::Path,
    process::{Child, Command, Stdio},
    thread::JoinHandle,
    time::Duration,
};

pub(crate) struct OwnedNode {
    child: Child,
    endpoint: String,
    startup_reader: Option<JoinHandle<()>>,
}

impl OwnedNode {
    pub(crate) fn start(port: u16, data: &Path, genesis: &Path) -> Self {
        Self::start_for_chain(port, data, genesis, CHAIN_ID)
    }

    pub(crate) fn start_for_chain(port: u16, data: &Path, genesis: &Path, chain_id: u64) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_alephium-l2-node"))
            .arg("--data-dir")
            .arg(data)
            .arg("--genesis")
            .arg(genesis)
            .args(["--chain-id", &chain_id.to_string()])
            .args(["--listen", &format!("127.0.0.1:{port}")])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn isolated owned SDK child");
        let mut node = Self {
            child,
            endpoint: format!("http://127.0.0.1:{port}"),
            startup_reader: None,
        };
        let stdout = node.child.stdout.take().unwrap();
        let (sent, received) = std::sync::mpsc::channel();
        node.startup_reader = Some(std::thread::spawn(move || {
            let mut line = String::new();
            let _ = BufReader::new(stdout.take(2048)).read_line(&mut line);
            let _ = sent.send(line);
        }));
        // The child prints only after binding this endpoint and opening its store.
        // Drop kills/reaps it before joining the reader on every timeout/panic path.
        let startup = received
            .recv_timeout(Duration::from_secs(15))
            .expect("owned SDK child startup acknowledgement exceeded deadline");
        node.startup_reader.take().unwrap().join().unwrap();
        let expected = format!(
            "Development-only EVM node on 127.0.0.1:{port}; chain {chain_id}; settlement unimplemented"
        );
        assert!(
            startup.trim() == expected,
            "owned SDK child did not acknowledge its bound endpoint"
        );
        assert!(
            node.child.try_wait().unwrap().is_none(),
            "owned SDK child exited during startup"
        );
        node
    }

    pub(crate) fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub(crate) fn reject_wrong_genesis(&self, raw: &[u8]) {
        let response: Value = Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap()
            .post(&self.endpoint)
            .json(&json!({
                "jsonrpc":"2.0", "id":1, "method":"l2_sendRawTransaction",
                "params":[format!("0x{}", hex::encode(raw)), B256::ZERO]
            }))
            .send()
            .expect("wrong-genesis probe transport failed")
            .json()
            .expect("wrong-genesis probe returned malformed JSON");
        assert!(
            response["error"]["code"] == -32001 && response.get("result").is_none(),
            "wrong-genesis submission was not rejected before admission"
        );
    }

    pub(crate) fn kill(&mut self) {
        self.child
            .kill()
            .expect("terminate only this owned SDK child");
        self.child.wait().expect("reap owned SDK child");
    }
}

impl Drop for OwnedNode {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        if let Some(reader) = self.startup_reader.take() {
            let _ = reader.join();
        }
    }
}
