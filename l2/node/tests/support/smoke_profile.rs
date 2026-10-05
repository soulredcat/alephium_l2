//! Existing smoke flow against an operator-owned node; restart stays with its owner.
use super::{Api, contract, quantity};
use alephium_l2_node::development;
use alephium_l2_sdk::{Client, ClientError, ExpectedNetwork, Lifecycle, PreparedTransaction};
use alloy_primitives::{Address, U256};
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

struct Profile {
    api: Api,
    client: Client,
    network: ExpectedNetwork,
    evidence: PathBuf,
}

pub(super) fn run(mode: &str) {
    assert!(
        matches!(mode, "exercise" | "verify-restart"),
        "unknown smoke mode"
    );
    let endpoint = required("L2_SMOKE_ENDPOINT");
    let network = ExpectedNetwork {
        chain_id: required("L2_SMOKE_CHAIN_ID")
            .parse()
            .expect("invalid chain ID"),
        genesis_id: required("L2_SMOKE_GENESIS_ID")
            .parse()
            .expect("invalid genesis ID"),
        rpc_profile: "development/c5-v1".into(),
    };
    // Both identities are supplied by the trusted profile, never learned from RPC.
    let client = Client::connect(&endpoint, network.clone()).expect("pinned SDK connection failed");
    let profile = Profile {
        api: Api::endpoint(endpoint),
        client,
        network,
        evidence: required("L2_SMOKE_EVIDENCE_DIR").into(),
    };
    if mode == "exercise" {
        profile.exercise();
    } else {
        profile.verify_restart();
    }
}

impl Profile {
    fn exercise(&self) {
        assert_eq!(
            self.api.health()["pending"],
            0,
            "smoke requires no pending work"
        );
        // Refuse reuse: an interrupted flow must be reconciled, never replayed.
        fs::create_dir(&self.evidence).expect("use a new smoke evidence directory");
        let sender = development::address();
        let recipient = Address::repeat_byte(0x77);
        let start_nonce = self.client.nonce(sender, false).unwrap();
        let sender_before = self.client.balance(sender).unwrap();
        let recipient_before = self.client.balance(recipient).unwrap();
        let fees_before = self.client.balance(Address::ZERO).unwrap();
        persist_new(
            &self.evidence.join("flow.json"),
            &json!({
                "endpoint":self.api.url, "chain_id":self.network.chain_id,
                "genesis_id":self.network.genesis_id, "sender":sender,
                "recipient":recipient, "start_nonce":start_nonce,
                "settlement":"unimplemented"
            }),
        );

        let transfer = self.transact(start_nonce, Some(recipient), 123, vec![], 21_000, true);
        assert_eq!(quantity(&transfer["gasUsed"]), U256::from(21_000));
        assert_eq!(
            self.client.balance(recipient).unwrap(),
            recipient_before + U256::from(123)
        );
        assert_eq!(
            self.client.balance(sender).unwrap(),
            sender_before - U256::from(21_123)
        );
        let deploy = self.transact(
            start_nonce + 1,
            None,
            0,
            development::contract_init(),
            500_000,
            true,
        );
        let address = contract(&deploy);
        let code = format!("0x{}", hex::encode(development::contract_runtime()));
        assert_eq!(
            self.api.rpc("eth_getCode", json!([address, "latest"])),
            code
        );
        let zero = format!("0x{:064x}", U256::ZERO);
        assert_eq!(self.api.slot(address), zero);
        assert_eq!(
            self.api.call(address, development::contract_input(0, None)),
            zero
        );
        // Existing contract call path uses a private overlay, not persisted state.
        assert_eq!(
            self.api.call(address, development::contract_input(1, None)),
            "0x"
        );
        assert_eq!(self.api.slot(address), zero);
        let write = self.transact(
            start_nonce + 2,
            Some(address),
            0,
            development::contract_input(1, None),
            500_000,
            true,
        );
        let word = format!("0x{:064x}", U256::from(42));
        assert_eq!(write["logs"].as_array().unwrap().len(), 1);
        assert_eq!(write["logs"][0]["topics"][0], word);
        assert_eq!(write["logs"][0]["data"], word);
        assert_eq!(self.api.slot(address), word);
        assert_eq!(
            self.api.call(address, development::contract_input(0, None)),
            word
        );
        let reverted = self.transact(
            start_nonce + 3,
            Some(address),
            77,
            development::contract_input(2, None),
            500_000,
            false,
        );
        assert!(reverted["logs"].as_array().unwrap().is_empty());
        assert_eq!(self.client.balance(address).unwrap(), U256::ZERO);
        assert_eq!(self.api.slot(address), word);
        let receipts = vec![transfer, deploy, write, reverted];
        let fees = receipts.iter().fold(U256::ZERO, |total, receipt| {
            total + quantity(&receipt["gasUsed"]) * quantity(&receipt["effectiveGasPrice"])
        });
        assert_eq!(
            self.client.balance(sender).unwrap(),
            sender_before - U256::from(123) - fees
        );
        assert_eq!(
            self.client.balance(recipient).unwrap(),
            recipient_before + U256::from(123)
        );
        assert_eq!(
            self.client.balance(Address::ZERO).unwrap(),
            fees_before + fees
        );
        assert_eq!(self.client.nonce(sender, false).unwrap(), start_nonce + 4);
        assert_eq!(self.client.nonce(sender, true).unwrap(), start_nonce + 4);
        let snapshot = self.snapshot(recipient, address, &receipts);
        persist_new(&self.evidence.join("before-restart.json"), &snapshot);
        println!(
            "EVM smoke exercise passed: transfer, deploy, call/write/read, revert, 4 receipts, exact accounting; restart verification pending"
        );
    }

    fn transact(
        &self,
        nonce: u64,
        to: Option<Address>,
        value: u64,
        input: Vec<u8>,
        gas: u64,
        success: bool,
    ) -> Value {
        persist_new(
            &self.evidence.join(format!("{nonce}-intent.json")),
            &json!({
                "chain_id":self.network.chain_id, "genesis_id":self.network.genesis_id,
                "sender":development::address(), "nonce":nonce, "to":to,
                "value":value.to_string(), "input":format!("0x{}", hex::encode(&input)),
                "gas_limit":gas, "gas_price":"1", "development_only":true
            }),
        );
        let raw = development::sign_for_chain(
            self.network.chain_id,
            nonce,
            to,
            U256::from(value),
            input,
            gas,
        )
        .expect("public development signing failed");
        let prepared = PreparedTransaction::new(raw, self.network.chain_id).unwrap();
        let hash = prepared.hash();
        persist_new(
            &self.evidence.join(format!("{nonce}-submission.json")),
            &json!({
                "hash":hash, "nonce":nonce, "endpoint":self.api.url,
                "state":"publication_may_occur_once; reconcile_by_hash"
            }),
        );
        match self.client.submit_once(&prepared) {
            Ok(accepted) => assert_eq!(accepted.lifecycle, Lifecycle::DurablyAccepted),
            Err(ClientError::Ambiguous(original)) => assert_eq!(original, hash),
            Err(error) => panic!("submission failed: {error}"),
        }
        let outcome = self.client.wait(hash, Duration::from_secs(15)).unwrap();
        assert_eq!(
            outcome.lifecycle,
            if success {
                Lifecycle::Committed
            } else {
                Lifecycle::Reverted
            }
        );
        let receipt = outcome.receipt.expect("terminal execution receipt missing");
        assert_eq!(receipt.hash, hash);
        assert_eq!(receipt.from, development::address());
        assert_eq!(receipt.to, to);
        assert_eq!(receipt.success, success);
        assert_eq!(receipt.effective_gas_price, 1);
        let value = self.api.rpc(
            "l2_getTransactionReceipt",
            json!([hash, self.network.genesis_id]),
        );
        assert_eq!(value["transactionHash"], format!("{hash:#x}"));
        persist_new(&self.evidence.join(format!("{nonce}-receipt.json")), &value);
        value
    }

    fn snapshot(&self, recipient: Address, address: Address, receipts: &[Value]) -> Value {
        let health = self.api.health();
        assert_eq!(health["pending"], 0);
        assert_eq!(health["chain_id"], self.network.chain_id);
        assert_eq!(
            health["genesis_id"],
            format!("{:#x}", self.network.genesis_id)
        );
        let stored_receipts: Vec<Value> = receipts
            .iter()
            .map(|receipt| {
                let stored = self.api.rpc(
                    "l2_getTransactionReceipt",
                    json!([receipt["transactionHash"], self.network.genesis_id]),
                );
                assert_eq!(&stored, receipt, "receipt changed");
                stored
            })
            .collect();
        let value = json!({
            "health":health, "recipient":recipient, "contract":address,
            "sender_balance":self.client.balance(development::address()).unwrap(),
            "recipient_balance":self.client.balance(recipient).unwrap(),
            "fee_balance":self.client.balance(Address::ZERO).unwrap(),
            "contract_balance":self.client.balance(address).unwrap(),
            "sender_nonce":self.client.nonce(development::address(), false).unwrap(),
            "pending_nonce":self.client.nonce(development::address(), true).unwrap(),
            "contract_code":self.api.rpc("eth_getCode", json!([address, "latest"])),
            "contract_slot":self.api.slot(address),
            "contract_read":self.api.call(address, development::contract_input(0, None)),
            "receipts":stored_receipts
        });
        assert_eq!(self.api.health(), health, "node changed during snapshot");
        value
    }

    fn verify_restart(&self) {
        let expected: Value = serde_json::from_slice(
            &fs::read(self.evidence.join("before-restart.json"))
                .expect("missing pre-restart snapshot"),
        )
        .expect("invalid pre-restart snapshot");
        let recipient = expected["recipient"].as_str().unwrap().parse().unwrap();
        let address = expected["contract"].as_str().unwrap().parse().unwrap();
        let receipts = expected["receipts"].as_array().unwrap();
        let actual = self.snapshot(recipient, address, receipts);
        assert_eq!(
            actual, expected,
            "restart changed committed state or receipts"
        );
        persist_new(
            &self.evidence.join("restart-verified.json"),
            &json!({
                "status":"passed", "endpoint":self.api.url,
                "chain_id":self.network.chain_id, "genesis_id":self.network.genesis_id,
                "height":actual["health"]["height"], "local_commit_id":actual["health"]["local_commit_id"],
                "receipt_count":receipts.len(), "state_and_receipts_equal":true,
                "settlement":"unimplemented", "process_restart_owned_by_operator":true
            }),
        );
        println!(
            "EVM smoke restart passed: same identity, head, balances, nonce, code, storage, call result and 4 receipts; node left running by operator"
        );
    }
}

fn required(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("set {name} explicitly"))
}

fn persist_new(path: &Path, value: &Value) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .expect("refusing to overwrite smoke intent or evidence");
    file.write_all(&serde_json::to_vec_pretty(value).unwrap())
        .expect("write smoke record");
    file.sync_all()
        .expect("sync smoke record before continuing");
}
