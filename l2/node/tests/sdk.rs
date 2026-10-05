//! One local SDK flow, plus a counted ambiguous-reply fixture; no settlement claim.
use alephium_l2_node::{development, protocol::CHAIN_ID};
use alephium_l2_sdk::{
    Client, ClientError, ExpectedNetwork, Lifecycle, PreparedTransaction, Receipt,
};
use alloy_eips::eip2930::AccessList;
use alloy_primitives::{Address, B256, U256, keccak256};
use std::{net::TcpListener, time::Duration};

#[path = "support/sdk_mock.rs"]
mod mock;
#[path = "support/sdk_runtime.rs"]
mod runtime;

fn expected_network() -> ExpectedNetwork {
    ExpectedNetwork {
        chain_id: CHAIN_ID,
        genesis_id: "0x4a2c8a134bb0fbc3febf67981d953f67404813209cf28aecf1a42cf1308b39a7"
            .parse()
            .unwrap(),
        rpc_profile: "development/c5-v1".to_owned(),
    }
}

fn prepared(nonce: u64, recipient: Address) -> PreparedTransaction {
    let raw = development::sign_type2(
        nonce,
        Some(recipient),
        U256::from(123),
        vec![],
        21_000,
        10,
        3,
        AccessList::default(),
    )
    .expect("public development transaction signing failed");
    let hash = keccak256(&raw);
    assert!(
        matches!(
            PreparedTransaction::new(raw.clone(), CHAIN_ID + 1),
            Err(ClientError::InvalidTransaction)
        ),
        "wrong-chain envelope was prepared"
    );
    let mut trailing = raw.clone();
    trailing.push(0);
    assert!(
        matches!(
            PreparedTransaction::new(trailing, CHAIN_ID),
            Err(ClientError::InvalidTransaction)
        ),
        "trailing envelope bytes were prepared"
    );
    let transaction = PreparedTransaction::new(raw.clone(), CHAIN_ID).unwrap();
    assert_eq!(transaction.hash(), hash);
    assert_eq!(transaction.sender(), development::address());
    assert_eq!(transaction.to(), Some(recipient));
    assert_eq!(transaction.transaction_type(), 2);
    let debug = format!("{transaction:?}");
    assert!(
        !debug.contains(&hex::encode(&raw))
            && !debug.contains(&format!("{raw:?}"))
            && !debug.contains("raw")
            && !debug.contains("signature"),
        "prepared transaction Debug exposed signed envelope material"
    );
    transaction
}

fn check_receipt(receipt: &Receipt, transaction: &PreparedTransaction, recipient: Address) {
    assert_eq!(receipt.hash, transaction.hash());
    assert_eq!(receipt.from, development::address());
    assert_eq!(receipt.to, Some(recipient));
    assert!(receipt.success);
    assert_eq!(receipt.contract, None);
    assert_eq!(receipt.block_height, 1);
    assert_eq!(receipt.transaction_type, 2);
    assert_eq!(receipt.gas_used, 21_000);
    assert_eq!(receipt.effective_gas_price, 3);
    assert_ne!(receipt.block_hash, B256::ZERO);
}

#[test]
fn sdk_identity_durable_flow_restart_and_ambiguous_reply() {
    let fixture = tempfile::tempdir().unwrap();
    let genesis = fixture.path().join("genesis.json");
    let data = fixture.path().join("sdk-chain");
    std::fs::write(
        &genesis,
        serde_json::to_vec(&development::genesis()).unwrap(),
    )
    .unwrap();
    let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = reservation.local_addr().unwrap().port();
    drop(reservation);
    let recipient = Address::repeat_byte(0x68);
    let sender = development::address();
    let transaction = prepared(0, recipient);
    let mut node = runtime::OwnedNode::start(port, &data, &genesis);
    let client = Client::connect(node.endpoint(), expected_network()).unwrap();
    assert_eq!(client.node_info().chain_id, CHAIN_ID);
    assert_eq!(client.node_info().genesis_id, expected_network().genesis_id);
    assert_eq!(client.node_info().rpc_profile, "development/c5-v1");
    assert_eq!(client.node_info().height, 0);
    let mut wrong_network = expected_network();
    wrong_network.genesis_id = B256::ZERO;
    assert!(
        matches!(
            Client::connect(node.endpoint(), wrong_network),
            Err(ClientError::IdentityMismatch)
        ),
        "client accepted a different genesis identity"
    );
    assert_eq!(
        client.balance(sender).unwrap(),
        U256::from(development::INITIAL_BALANCE)
    );
    assert_eq!(client.nonce(sender, false).unwrap(), 0);
    assert_eq!(client.nonce(sender, true).unwrap(), 0);
    let accepted = client.submit_once(&transaction).unwrap();
    assert_eq!(accepted.hash, transaction.hash());
    assert_eq!(accepted.lifecycle, Lifecycle::DurablyAccepted);
    assert!(accepted.receipt.is_none());
    let committed = client
        .wait(transaction.hash(), Duration::from_secs(10))
        .unwrap();
    assert_eq!(committed.lifecycle, Lifecycle::Committed);
    let receipt = committed.receipt.unwrap();
    check_receipt(&receipt, &transaction, recipient);
    let fees = U256::from(receipt.gas_used) * U256::from(receipt.effective_gas_price);
    let balance = U256::from(development::INITIAL_BALANCE - 123) - fees;
    assert_eq!(client.balance(sender).unwrap(), balance);
    assert_eq!(client.balance(recipient).unwrap(), U256::from(123));
    assert_eq!(client.balance(Address::ZERO).unwrap(), fees);
    assert_eq!(client.nonce(sender, false).unwrap(), 1);
    assert_eq!(client.nonce(sender, true).unwrap(), 1);
    let next = prepared(1, recipient);
    node.reject_wrong_genesis(next.as_bytes());
    assert_eq!(client.nonce(sender, false).unwrap(), 1);
    assert_eq!(client.nonce(sender, true).unwrap(), 1);
    assert_eq!(client.balance(sender).unwrap(), balance);
    assert_eq!(
        client.reconcile(next.hash()).unwrap().lifecycle,
        Lifecycle::Unknown
    );
    node.kill();
    node = runtime::OwnedNode::start(port, &data, &genesis);
    let restarted = Client::connect(node.endpoint(), expected_network()).unwrap();
    assert_eq!(restarted.node_info().height, 1);
    assert_eq!(restarted.balance(sender).unwrap(), balance);
    assert_eq!(restarted.balance(recipient).unwrap(), U256::from(123));
    assert_eq!(restarted.balance(Address::ZERO).unwrap(), fees);
    assert_eq!(restarted.nonce(sender, false).unwrap(), 1);
    assert_eq!(restarted.nonce(sender, true).unwrap(), 1);
    let reconciled = restarted.reconcile(transaction.hash()).unwrap();
    assert_eq!(reconciled.lifecycle, Lifecycle::Committed);
    let recovered_receipt = reconciled.receipt.unwrap();
    check_receipt(&recovered_receipt, &transaction, recipient);
    assert_eq!(recovered_receipt.block_hash, receipt.block_hash);
    node.kill();

    // This fixture only checks client transport/lifecycle semantics, not execution.
    let mock = mock::Mock::start(expected_network(), transaction.hash(), sender, recipient);
    let client = Client::connect(mock.endpoint(), expected_network()).unwrap();
    assert_eq!(client.balance(sender).unwrap(), U256::from(123));
    assert_eq!(client.nonce(sender, false).unwrap(), 7);
    assert_eq!(client.nonce(sender, true).unwrap(), 8);
    assert!(
        matches!(client.submit_once(&transaction), Err(ClientError::Ambiguous(hash))
        if hash == transaction.hash()),
        "malformed reply lost original ambiguous identity"
    );
    let outcome = client.reconcile(transaction.hash()).unwrap();
    assert_eq!(outcome.hash, transaction.hash());
    assert_eq!(outcome.lifecycle, Lifecycle::Committed);
    check_receipt(&outcome.receipt.unwrap(), &transaction, recipient);
    mock.finish();
}
