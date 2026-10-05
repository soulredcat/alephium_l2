//! Fresh two-chain data, safe RPC observations, and a single optional checkpoint record.
use super::runtime;
use alephium_l2_node::{
    development, operator,
    protocol::{CHAIN_ID, Genesis, Head},
    storage::Store,
};
use alephium_l2_sdk::{Client, ExpectedNetwork, PreparedTransaction};
use alloy_primitives::{Address, B256, U256};
use reqwest::blocking::Client as HttpClient;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

pub(super) struct Fixture {
    pub(super) genesis: Genesis,
    pub(super) genesis_path: PathBuf,
    pub(super) data: PathBuf,
    pub(super) port: u16,
    pub(super) network: ExpectedNetwork,
}

impl Fixture {
    pub(super) fn new(root: &Path, name: &str, chain_id: u64, port: u16) -> Result<Self, String> {
        let genesis = development::genesis_for_chain(chain_id)?;
        let genesis_path = root.join(format!("{name}-genesis.json"));
        let data = root.join(format!("{name}-data"));
        fs::write(&genesis_path, serde_json::to_vec(&genesis).unwrap()).map_err(io_error)?;
        // Pin canonical identity from the supplied genesis independently of
        // the subsequent HTTP handshake. Close this fresh Store before startup.
        let store = Store::open(&data, &genesis)?;
        let view = store.view()?;
        assert_eq!(view.chain_id(), chain_id);
        assert_eq!(view.head.height, 0);
        assert_eq!(view.pending_counter()?, 0);
        let network = ExpectedNetwork {
            chain_id,
            genesis_id: view.head.genesis_id,
            rpc_profile: "development/c5-v1".to_owned(),
        };
        drop(view);
        drop(store);
        Ok(Self {
            genesis,
            genesis_path,
            data,
            port,
            network,
        })
    }

    pub(super) fn start(&self) -> runtime::OwnedNode {
        if self.network.chain_id == CHAIN_ID {
            runtime::OwnedNode::start(self.port, &self.data, &self.genesis_path)
        } else {
            runtime::OwnedNode::start_for_chain(
                self.port,
                &self.data,
                &self.genesis_path,
                self.network.chain_id,
            )
        }
    }

    pub(super) fn connect(&self, node: &runtime::OwnedNode) -> Client {
        Client::connect(node.endpoint(), self.network.clone()).unwrap()
    }

    pub(super) fn check_identity(&self, api: &Api) {
        let health = api.health();
        assert_eq!(health["status"], "development");
        assert_eq!(health["chain_id"], self.network.chain_id);
        assert_eq!(
            health["genesis_id"],
            format!("{:#x}", self.network.genesis_id)
        );
        assert_eq!(health["rpc_profile"], self.network.rpc_profile);
        assert_eq!(health["settlement"], "unimplemented");
        assert!(health["error"].is_null());
        assert_eq!(
            api.rpc("eth_chainId", json!([])),
            format!("0x{:x}", self.network.chain_id)
        );
        assert_eq!(
            api.rpc("net_version", json!([])),
            self.network.chain_id.to_string()
        );
        // Creation simulation executes CHAINID, MSTORE and RETURN without
        // deploying a contract or changing the committed view.
        assert_eq!(
            api.rpc(
                "eth_call",
                json!([{
            "from":development::address(), "data":"0x4660005260206000f3", "gas":"0x186a0"
        }, "latest"])
            ),
            format!("0x{:064x}", self.network.chain_id)
        );
        assert_eq!(
            api.health(),
            health,
            "CHAINID simulation changed committed state"
        );
    }

    pub(super) fn closed_snapshot(&self, own: B256, foreign: B256) -> Result<(Head, B256), String> {
        let store = Store::open_existing(&self.data, &self.genesis)?;
        let view = store.view()?;
        assert_eq!(view.chain_id(), self.network.chain_id);
        assert_eq!(view.head.genesis_id, self.network.genesis_id);
        // The legitimate transfer is the sole durable admission. A foreign
        // envelope must not leave even a rejected intent/raw envelope behind.
        assert_eq!(view.pending_counter()?, 1);
        assert!(store.pending()?.is_empty());
        assert_eq!(view.status(own)?.unwrap().status, "committed");
        assert!(view.receipt(own)?.unwrap().success);
        assert!(view.status(foreign)?.is_none());
        assert!(view.receipt(foreign)?.is_none());
        assert!(view.raw_transaction(foreign)?.is_none());
        Ok((view.head.clone(), view.state_digest()?))
    }

    pub(super) fn verify_backup_replay(
        &self,
        root: &Path,
        snapshot: &(Head, B256),
    ) -> Result<(), String> {
        let backup = root.join("custom-chain-backup");
        let work = root.join("custom-chain-replay");
        let backed_up = operator::backup(&self.data, &backup, &self.genesis)?;
        assert_eq!(&backed_up.head, &snapshot.0);
        assert_eq!(backed_up.state_digest, snapshot.1);
        assert_eq!(backed_up.pending_count, 0);
        let replayed = operator::verify_replay(&backup, &self.genesis, &work)?;
        assert_eq!(&replayed.head, &snapshot.0);
        assert_eq!(replayed.state_digest, snapshot.1);
        assert_eq!(replayed.blocks, 1);
        assert_eq!(replayed.executed_transactions, 1);
        assert_eq!(replayed.rejected_intents, 0);
        assert_eq!(replayed.pending_count, 0);
        let restored = Store::open_existing(&work.join("replayed"), &self.genesis)?;
        assert_eq!(restored.view()?.chain_id(), self.network.chain_id);
        assert_eq!(restored.state_digest()?, snapshot.1);
        Ok(())
    }
}

pub(super) struct Api {
    client: HttpClient,
    endpoint: String,
}

impl Api {
    pub(super) fn new(node: &runtime::OwnedNode) -> Self {
        Self {
            client: HttpClient::builder()
                .no_proxy()
                .timeout(Duration::from_secs(3))
                .build()
                .unwrap(),
            endpoint: node.endpoint().to_owned(),
        }
    }

    pub(super) fn health(&self) -> Value {
        self.client
            .get(format!("{}/health", self.endpoint))
            .send()
            .unwrap()
            .json()
            .unwrap()
    }

    pub(super) fn response(&self, method: &str, params: Value) -> Value {
        self.client
            .post(&self.endpoint)
            .json(&json!({"jsonrpc":"2.0", "id":1, "method":method, "params":params}))
            .send()
            .unwrap()
            .json()
            .unwrap()
    }

    pub(super) fn rpc(&self, method: &str, params: Value) -> Value {
        let response = self.response(method, params);
        assert!(
            response.get("error").is_none(),
            "RPC method {method} failed"
        );
        response["result"].clone()
    }
}

pub(super) fn owned_data() -> Result<tempfile::TempDir, String> {
    let mut builder = tempfile::Builder::new();
    builder.prefix("l2-c17-identity-");
    if let Some(parent) = std::env::var_os("L2_IDENTITY_DATA_ROOT") {
        let parent = PathBuf::from(parent);
        if !parent.is_absolute() {
            return Err("L2_IDENTITY_DATA_ROOT must be an absolute development path".into());
        }
        fs::create_dir_all(&parent).map_err(io_error)?;
        builder.tempdir_in(parent).map_err(io_error)
    } else {
        builder.tempdir().map_err(io_error)
    }
}

pub(super) fn transfer(fixture: &Fixture, recipient: Address, value: u64) -> PreparedTransaction {
    let raw = development::sign_for_chain(
        fixture.network.chain_id,
        0,
        Some(recipient),
        U256::from(value),
        vec![],
        21_000,
    )
    .unwrap();
    PreparedTransaction::new(raw, fixture.network.chain_id).unwrap()
}

pub(super) fn check_accounting(client: &Client, recipient: Address, value: u64) {
    assert_eq!(client.nonce(development::address(), false).unwrap(), 1);
    assert_eq!(client.nonce(development::address(), true).unwrap(), 1);
    assert_eq!(client.balance(recipient).unwrap(), U256::from(value));
    assert_eq!(client.balance(Address::ZERO).unwrap(), U256::from(21_000));
    assert_eq!(
        client.balance(development::address()).unwrap(),
        U256::from(development::INITIAL_BALANCE) - U256::from(value + 21_000)
    );
}

pub(super) fn reject_database_identity(data: &Path, genesis: &Genesis) {
    for error in [
        Store::open_existing(data, genesis).err(),
        Store::open(data, genesis).err(),
    ] {
        assert_eq!(
            error.as_deref(),
            Some("persisted genesis or protocol profile does not match"),
            "database identity mismatch was accepted or failed for another reason"
        );
    }
}

pub(super) fn binary_hash() -> Result<String, String> {
    Ok(hex::encode(Sha256::digest(
        fs::read(env!("CARGO_BIN_EXE_alephium-l2-node")).map_err(io_error)?,
    )))
}

pub(super) fn write_evidence(evidence: &Value) -> Result<(), String> {
    if let Some(directory) = std::env::var_os("L2_IDENTITY_EVIDENCE_DIR") {
        let directory = PathBuf::from(directory);
        if !directory.is_absolute() {
            return Err("L2_IDENTITY_EVIDENCE_DIR must be an absolute development path".into());
        }
        fs::create_dir_all(&directory).map_err(io_error)?;
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(directory.join("acceptance.json"))
            .map_err(io_error)?;
        output
            .write_all(&serde_json::to_vec_pretty(evidence).unwrap())
            .map_err(io_error)?;
        output.sync_all().map_err(io_error)?;
    }
    Ok(())
}

pub(super) fn io_error(error: std::io::Error) -> String {
    error.to_string()
}
