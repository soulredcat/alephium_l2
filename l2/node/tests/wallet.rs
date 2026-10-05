//! One bounded developer-wallet flow. No load campaign or settlement claim.
use alephium_l2_node::{development, protocol::CHAIN_ID};
use alloy_eips::eip2930::{AccessList, AccessListItem};
use alloy_primitives::{Address, B256, U256};
use serde_json::json;
use std::net::TcpListener;

#[path = "support/wallet_runtime.rs"]
mod runtime;
use runtime::{Api, OwnedNode, quantity};

#[test]
fn typed_wallet_estimation_queries_and_restart() {
    let fixture = tempfile::tempdir().unwrap();
    let genesis = fixture.path().join("genesis.json");
    let data = fixture.path().join("wallet-chain");
    std::fs::write(
        &genesis,
        serde_json::to_vec(&development::genesis()).unwrap(),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let api = Api::new(port);
    let sender = development::address();
    let recipient = Address::repeat_byte(0x66);
    let mut node = OwnedNode::start(port, &data, &genesis);
    node.ready(&api);
    assert_eq!(api.rpc("net_version", json!([])), CHAIN_ID.to_string());
    assert_eq!(api.rpc("eth_gasPrice", json!([])), "0x1");
    assert_eq!(api.rpc("eth_maxPriorityFeePerGas", json!([])), "0x1");

    let access_list = AccessList(vec![AccessListItem {
        address: recipient,
        storage_keys: vec![B256::ZERO],
    }]);
    let raw = development::sign_type2(
        0,
        Some(recipient),
        U256::from(123),
        vec![],
        25_300,
        10,
        3,
        access_list,
    )
    .unwrap();
    let hash = api.admit(&raw);
    assert_eq!(
        api.rpc(
            "eth_getTransactionCount",
            json!([format!("{sender:#x}"), "pending"])
        ),
        "0x1"
    );
    let transfer = api.receipt(&hash);
    assert_eq!(transfer["type"], "0x2");
    assert_eq!(transfer["status"], "0x1");
    assert_eq!(quantity(&transfer["gasUsed"]), U256::from(25_300));
    assert_eq!(transfer["effectiveGasPrice"], "0x3");
    assert_eq!(api.balance(recipient), U256::from(123));
    let before = api.balance(sender);
    assert_eq!(
        before,
        U256::from(development::INITIAL_BALANCE - 123 - 25_300 * 3)
    );
    assert_eq!(api.nonce(), U256::from(1));
    let duplicate_head = api.health()["local_commit_id"].clone();
    assert_eq!(api.admit(&raw), hash);
    assert_eq!(api.receipt(&hash), transfer);
    assert_eq!(api.health()["local_commit_id"], duplicate_head);

    let invalid = development::sign_type2(
        1,
        Some(recipient),
        U256::ZERO,
        vec![],
        21_000,
        2,
        3,
        AccessList::default(),
    )
    .unwrap();
    assert!(
        api.response(
            "eth_sendRawTransaction",
            json!([format!("0x{}", hex::encode(invalid))])
        )["error"]
            .is_object()
    );
    assert_eq!(api.balance(sender), before);
    assert_eq!(api.nonce(), U256::from(1));

    let transaction = api.rpc("eth_getTransactionByHash", json!([hash]));
    assert_eq!(transaction["hash"], hash);
    assert_eq!(transaction["type"], "0x2");
    assert_eq!(transaction["from"], format!("{sender:#x}"));
    assert_eq!(transaction["to"], format!("{recipient:#x}"));
    assert_eq!(transaction["nonce"], "0x0");
    assert_eq!(quantity(&transaction["gas"]), U256::from(25_300));
    assert_eq!(transaction["value"], "0x7b");
    assert_eq!(transaction["input"], "0x");
    assert_eq!(transaction["maxFeePerGas"], "0xa");
    assert_eq!(transaction["maxPriorityFeePerGas"], "0x3");
    assert_eq!(transaction["gasPrice"], "0x3");
    assert_eq!(
        transaction["accessList"][0]["address"],
        format!("{recipient:#x}")
    );
    assert_eq!(
        transaction["accessList"][0]["storageKeys"][0],
        format!("{:#x}", B256::ZERO)
    );
    assert_eq!(transaction["blockHash"], transfer["blockHash"]);
    assert_eq!(transaction["blockNumber"], transfer["blockNumber"]);
    assert_eq!(
        transaction["transactionIndex"],
        transfer["transactionIndex"]
    );
    let block = api.rpc(
        "eth_getBlockByNumber",
        json!([transfer["blockNumber"], false]),
    );
    assert_eq!(block["hash"], transfer["blockHash"]);
    assert_eq!(block["number"], transfer["blockNumber"]);
    assert_eq!(block["baseFeePerGas"], "0x0");
    assert_eq!(block["transactions"][0], hash);
    assert_eq!(
        api.rpc("eth_getBlockByHash", json!([block["hash"], false])),
        block
    );
    let full_block = api.rpc("eth_getBlockByHash", json!([block["hash"], true]));
    assert_eq!(full_block["transactions"][0]["hash"], hash);

    let init = development::contract_init();
    let gas = api.estimate(None, &init, 3);
    assert!((53_000..500_000).contains(&gas));
    assert_eq!(
        api.balance(sender),
        before,
        "estimation debited committed account"
    );
    assert_eq!(api.nonce(), U256::from(1), "estimation consumed nonce");
    let deploy = api.transact(1, None, 0, init, gas, 3);
    assert_eq!(deploy["type"], "0x2");
    assert_eq!(
        deploy["status"], "0x1",
        "estimated deployment gas was insufficient"
    );
    let contract: Address = deploy["contractAddress"].as_str().unwrap().parse().unwrap();
    let zero = format!("0x{:064x}", U256::ZERO);
    assert_eq!(api.slot(contract), zero);
    let before_estimate = api.balance(sender);
    let write_data = development::contract_input(1, None);
    let write_gas = api.estimate(Some(contract), &write_data, 5);
    assert_eq!(
        api.slot(contract),
        zero,
        "estimation persisted private storage"
    );
    assert_eq!(api.balance(sender), before_estimate);
    assert_eq!(api.nonce(), U256::from(2));
    let simulated = api.rpc(
        "eth_call",
        json!([{
        "from":format!("{sender:#x}"), "to":format!("{contract:#x}"),
        "data":format!("0x{}", hex::encode(&write_data)), "gasPrice":"0x5"
    }, "latest"]),
    );
    assert_eq!(simulated, "0x");
    assert_eq!(api.slot(contract), zero);
    assert_eq!(api.balance(sender), before_estimate);
    assert_eq!(api.nonce(), U256::from(2));
    let write = api.transact(2, Some(contract), 0, write_data, write_gas, 5);
    assert_eq!(
        write["status"], "0x1",
        "estimated write gas was insufficient"
    );
    assert_eq!(write["effectiveGasPrice"], "0x5");
    assert_eq!(write["logs"].as_array().unwrap().len(), 1);
    let word = format!("0x{:064x}", U256::from(42));
    assert_eq!(api.slot(contract), word);
    let logs = api.rpc(
        "eth_getLogs",
        json!([{
            "fromBlock":write["blockNumber"], "toBlock":write["blockNumber"],
            "address":format!("{contract:#x}"), "topics":[word]
        }]),
    );
    assert_eq!(logs, write["logs"]);
    assert_eq!(
        api.rpc(
            "eth_getLogs",
            json!([{
                "fromBlock":write["blockNumber"], "toBlock":write["blockNumber"],
                "address":[], "topics":[[]]
            }])
        ),
        write["logs"]
    );
    assert_eq!(logs[0]["removed"], false);
    assert_eq!(logs[0]["data"], word);
    for filter in [
        json!({"fromBlock":write["blockNumber"], "toBlock":write["blockNumber"], "address":format!("{recipient:#x}")}),
        json!({"fromBlock":write["blockNumber"], "toBlock":write["blockNumber"], "topics":[format!("0x{:064x}", U256::from(43))]}),
    ] {
        assert!(
            api.rpc("eth_getLogs", json!([filter]))
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
    assert!(
        api.response(
            "eth_getLogs",
            json!([{"fromBlock":"0x0", "toBlock":"0x10000"}])
        )["error"]
            .is_object()
    );
    let reverted = api.transact(
        3,
        Some(contract),
        77,
        development::contract_input(2, None),
        100_000,
        1,
    );
    assert_eq!(reverted["type"], "0x2");
    assert_eq!(reverted["status"], "0x0");
    assert_eq!(reverted["effectiveGasPrice"], "0x1");
    assert!(reverted["logs"].as_array().unwrap().is_empty());
    assert_eq!(api.slot(contract), word);
    assert_eq!(api.balance(contract), U256::ZERO);
    let receipts = [transfer, deploy, write, reverted];
    let fees = receipts.iter().fold(U256::ZERO, |sum, receipt| {
        sum + quantity(&receipt["gasUsed"]) * quantity(&receipt["effectiveGasPrice"])
    });
    assert_eq!(
        api.balance(sender),
        U256::from(development::INITIAL_BALANCE - 123) - fees
    );
    assert_eq!(api.balance(Address::ZERO), fees);
    assert_eq!(api.nonce(), U256::from(4));
    let health = api.health();
    let balance = api.balance(sender);
    node.kill();
    node = OwnedNode::start(port, &data, &genesis);
    node.ready(&api);
    assert_eq!(api.health()["height"], health["height"]);
    assert_eq!(api.health()["local_commit_id"], health["local_commit_id"]);
    assert_eq!(api.balance(sender), balance);
    assert_eq!(api.balance(Address::ZERO), fees);
    assert_eq!(api.nonce(), U256::from(4));
    assert_eq!(api.slot(contract), word);
    for receipt in &receipts {
        assert_eq!(
            api.receipt(receipt["transactionHash"].as_str().unwrap()),
            *receipt
        );
    }
    assert_eq!(
        api.rpc("eth_getTransactionByHash", json!([hash]))["gasPrice"],
        "0x3"
    );
}
