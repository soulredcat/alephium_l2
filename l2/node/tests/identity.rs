//! One bounded two-chain identity/durability flow; no settlement or capacity claim.
use alephium_l2_node::{development, protocol::CHAIN_ID};
use alephium_l2_sdk::{Client, ClientError, Lifecycle};
use alloy_primitives::{Address, U256};
use serde_json::json;
use std::{net::TcpListener, time::Duration};

#[path = "support/identity_fixture.rs"]
mod fixture;
#[path = "support/sdk_runtime.rs"]
mod runtime;

use fixture::{Api, Fixture, check_accounting, io_error, reject_database_identity, transfer};

#[test]
fn two_chain_identity_durable_transfer_and_restart() -> Result<(), String> {
    let owned = fixture::owned_data()?;
    let retain_data = std::env::var_os("L2_IDENTITY_DATA_ROOT").is_some();
    // Hold both reservations simultaneously so each fixture gets a distinct
    // fresh loopback port. Startup acknowledgement binds the actual child.
    let reservations = [
        TcpListener::bind("127.0.0.1:0").map_err(io_error)?,
        TcpListener::bind("127.0.0.1:0").map_err(io_error)?,
    ];
    let a = Fixture::new(
        owned.path(),
        "chain-a",
        CHAIN_ID,
        reservations[0].local_addr().map_err(io_error)?.port(),
    )?;
    let b = Fixture::new(
        owned.path(),
        "chain-b",
        CHAIN_ID + 1,
        reservations[1].local_addr().map_err(io_error)?.port(),
    )?;
    assert_ne!(a.port, b.port);
    assert_ne!(a.data, b.data);
    assert_ne!(a.network.genesis_id, b.network.genesis_id);
    drop(reservations);
    let mut nodes = [a.start(), b.start()];
    let fixtures = [&a, &b];
    let apis = [Api::new(&nodes[0]), Api::new(&nodes[1])];
    let clients = [a.connect(&nodes[0]), b.connect(&nodes[1])];
    let recipients = [Address::repeat_byte(0x71), Address::repeat_byte(0x72)];
    let values = [123, 456];
    let transfers = [
        transfer(&a, recipients[0], values[0]),
        transfer(&b, recipients[1], values[1]),
    ];
    for index in 0..2 {
        fixtures[index].check_identity(&apis[index]);
        assert_eq!(clients[index].node_info().height, 0);
        assert_eq!(
            clients[index].nonce(development::address(), false).unwrap(),
            0
        );
        assert_eq!(
            clients[index].balance(development::address()).unwrap(),
            U256::from(development::INITIAL_BALANCE)
        );
    }

    let before = apis[1].health();
    for (method, params) in [
        (
            "eth_sendRawTransaction",
            json!([format!("0x{}", hex::encode(transfers[0].as_bytes()))]),
        ),
        (
            "l2_sendRawTransaction",
            json!([
                format!("0x{}", hex::encode(transfers[0].as_bytes())),
                b.network.genesis_id
            ]),
        ),
    ] {
        let rejected = apis[1].response(method, params);
        assert_eq!(rejected["error"]["code"], -32000);
        assert!(rejected.get("result").is_none());
        assert!(
            rejected["error"]["message"]
                .as_str()
                .unwrap()
                .contains("chain")
        );
    }
    assert_eq!(apis[1].health(), before);
    assert_eq!(clients[1].nonce(development::address(), true).unwrap(), 0);
    assert_eq!(
        clients[1].reconcile(transfers[0].hash()).unwrap().lifecycle,
        Lifecycle::Unknown
    );
    nodes[0].reject_wrong_genesis(transfers[0].as_bytes());
    let mut wrong_network = b.network.clone();
    wrong_network.genesis_id = a.network.genesis_id;
    assert!(matches!(
        Client::connect(nodes[1].endpoint(), wrong_network),
        Err(ClientError::IdentityMismatch)
    ));

    let mut receipts = Vec::new();
    let mut heads = Vec::new();
    for index in 0..2 {
        let accepted = clients[index].submit_once(&transfers[index]).unwrap();
        assert_eq!(accepted.hash, transfers[index].hash());
        assert_eq!(accepted.lifecycle, Lifecycle::DurablyAccepted);
        let committed = clients[index]
            .wait(accepted.hash, Duration::from_secs(10))
            .unwrap();
        assert_eq!(committed.lifecycle, Lifecycle::Committed);
        let receipt = committed.receipt.unwrap();
        assert!(receipt.success);
        assert_eq!(receipt.from, development::address());
        assert_eq!(receipt.to, Some(recipients[index]));
        assert_eq!(receipt.gas_used, 21_000);
        assert_eq!(receipt.effective_gas_price, 1);
        assert_eq!(receipt.block_height, 1);
        assert_eq!(receipt.transaction_type, 0);
        check_accounting(&clients[index], recipients[index], values[index]);
        assert_eq!(
            clients[index].balance(recipients[1 - index]).unwrap(),
            U256::ZERO
        );
        let transaction = apis[index].rpc("eth_getTransactionByHash", json!([accepted.hash]));
        assert_eq!(
            transaction["chainId"],
            format!("0x{:x}", fixtures[index].network.chain_id)
        );
        receipts.push(apis[index].rpc(
            "l2_getTransactionReceipt",
            json!([accepted.hash, fixtures[index].network.genesis_id]),
        ));
        heads.push(apis[index].health());
        nodes[index].kill();
    }
    let snapshots = [
        a.closed_snapshot(transfers[0].hash(), transfers[1].hash())?,
        b.closed_snapshot(transfers[1].hash(), transfers[0].hash())?,
    ];
    let mut altered_genesis = a.genesis.clone();
    altered_genesis.accounts[0].balance += U256::from(1);
    reject_database_identity(&a.data, &b.genesis);
    reject_database_identity(&a.data, &altered_genesis);

    for index in 0..2 {
        nodes[index] = fixtures[index].start();
        let restarted = fixtures[index].connect(&nodes[index]);
        let api = Api::new(&nodes[index]);
        assert_eq!(api.health(), heads[index]);
        assert_eq!(restarted.node_info().height, 1);
        assert_eq!(
            restarted.node_info().genesis_id,
            fixtures[index].network.genesis_id
        );
        assert_eq!(
            restarted.node_info().local_commit_id,
            snapshots[index].0.commit_id
        );
        check_accounting(&restarted, recipients[index], values[index]);
        fixtures[index].check_identity(&api);
        assert_eq!(
            restarted.balance(recipients[1 - index]).unwrap(),
            U256::ZERO
        );
        let reconciled = restarted.reconcile(transfers[index].hash()).unwrap();
        assert_eq!(reconciled.lifecycle, Lifecycle::Committed);
        assert_eq!(
            api.rpc(
                "l2_getTransactionReceipt",
                json!([transfers[index].hash(), fixtures[index].network.genesis_id])
            ),
            receipts[index]
        );
        nodes[index].kill();
        assert_eq!(
            fixtures[index]
                .closed_snapshot(transfers[index].hash(), transfers[1 - index].hash())?,
            snapshots[index]
        );
    }
    drop(nodes);
    // One custom-chain recovery qualification reuses the existing operator,
    // closes its Stores, and compares the complete reexecuted committed state.
    b.verify_backup_replay(owned.path(), &snapshots[1])?;

    fixture::write_evidence(&json!({
        "checkpoint":"C17/local-chain-identity", "status":"passed", "settlement":"unimplemented",
        "binary_sha256":fixture::binary_hash()?, "same_binary":"verified",
        "build_profile":if cfg!(debug_assertions) {"debug"} else {"release"},
        "fresh_development_assets":"verified", "separate_data_directories":"verified",
        "owned_child_cleanup":"verified",
        "development_data_retained":if retain_data {"requested_after_success"} else {"not_requested"},
        "nodes":fixtures.iter().enumerate().map(|(index, fixture)| json!({
            "chain_id":fixture.network.chain_id, "genesis_id":fixture.network.genesis_id,
            "port":fixture.port, "transaction_hash":transfers[index].hash(),
            "local_commit_id":snapshots[index].0.commit_id, "state_digest":snapshots[index].1,
            "data_directory":retain_data.then_some(&fixture.data),
            "genesis_path":retain_data.then_some(&fixture.genesis_path),
            "durable_admissions":1, "receipt_restart_equality":"verified", "head_restart_equality":"verified"
        })).collect::<Vec<_>>(),
        "chainid_simulation":"verified", "durable_acknowledgements":2, "exact_accounting":"verified",
        "cross_chain_rpc_refusals":2, "foreign_durable_records":0,
        "rpc_wrong_genesis_refusals":1, "sdk_wrong_genesis_refusals":1,
        "database_wrong_chain_refusals":2, "database_wrong_genesis_refusals":2,
        "custom_chain_backup_replay":"verified", "replayed_blocks":1, "replayed_transactions":1,
        "limits":["local process restart only", "no L1 integration", "no benchmark", "no physical power-loss claim"]
    }))?;
    if retain_data {
        // Only successful opt-in fixtures survive; every child is already
        // reaped and all Stores are closed. Ordinary test runs clean up.
        let _ = owned.keep();
    }
    println!(
        "C17 local identity acceptance passed: 2 chains, 2 durable transfers, 2 identical restarts"
    );
    Ok(())
}
