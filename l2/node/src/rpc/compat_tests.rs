//! Responses must deserialize as the standard Alloy RPC types that Rust
//! clients (for example Foundry) use, not only as this node's own JSON.
//! Transaction objects deliberately omit signature fields, so typed
//! transaction parsing is outside this check.
use super::read;
use crate::{development, execution, protocol::*, storage::Store};
use alloy_consensus::{EMPTY_ROOT_HASH, TxEnvelope, proofs::calculate_transaction_root};
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::U256;
use alloy_rpc_types_eth::{Block, FeeHistory, Log, TransactionReceipt};
use serde_json::{Value, json};
use std::sync::Arc;

fn commit(store: &mut Store, raw: Vec<u8>) -> Receipt {
    let info = execution::inspect(&raw).unwrap();
    store
        .admit(Pending {
            hash: info.hash,
            sender: info.sender,
            raw: raw.clone(),
        })
        .unwrap();
    let view = store.view().unwrap();
    let context = BlockContext {
        number: view.head.height + 1,
        timestamp: view.head.timestamp + 1,
        gas_limit: BLOCK_GAS,
    };
    let result = execution::execute_block(view.clone(), &[raw], context).unwrap();
    let receipt = result.receipts[0].clone();
    store
        .commit(BlockCommit {
            parent: view.head.clone(),
            context,
            transactions: vec![receipt.hash],
            changes: result.changes,
            receipts: result.receipts,
            rejected: result.rejected,
        })
        .unwrap();
    receipt
}

fn rpc(store: &Store, method: &str, params: Value) -> Value {
    let input = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params});
    read::dispatch(Arc::new(store.view().unwrap()), &input).unwrap()
}

fn typed<T: serde::de::DeserializeOwned>(value: Value, what: &str) -> T {
    serde_json::from_value(value.clone())
        .unwrap_or_else(|error| panic!("{what} is not a standard RPC object: {error}\n{value}"))
}

#[test]
fn blocks_receipts_and_logs_deserialize_as_standard_alloy_types() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = Store::open(&directory.path().join("data"), &development::genesis()).unwrap();
    let deploy = development::sign(0, None, U256::ZERO, development::contract_init(), 500_000);
    let contract = commit(&mut store, deploy.unwrap()).contract.unwrap();
    let write = development::sign_type2(
        1,
        Some(contract),
        U256::ZERO,
        development::contract_input(1, None),
        200_000,
        10,
        2,
        Default::default(),
    );
    let receipt = commit(&mut store, write.unwrap());
    let hash = format!("{:#x}", receipt.hash);

    let block: Block = typed(
        rpc(&store, "eth_getBlockByNumber", json!(["0x2", false])),
        "block",
    );
    assert_eq!(block.header.number, 2);
    assert_eq!(block.transactions.len(), 1);
    let by_hash = rpc(
        &store,
        "eth_getBlockByHash",
        json!([format!("{:#x}", block.header.hash), false]),
    );
    assert_eq!(
        typed::<Block>(by_hash, "block by hash").header,
        block.header
    );
    let genesis: Block = typed(
        rpc(&store, "eth_getBlockByNumber", json!(["earliest", false])),
        "genesis block",
    );
    assert_eq!(genesis.header.number, 0);
    assert_eq!(genesis.header.transactions_root, EMPTY_ROOT_HASH);
    assert_eq!(genesis.header.receipts_root, EMPTY_ROOT_HASH);

    // The derived root is the Ethereum trie root of the stored signed envelope.
    let stored = store
        .view()
        .unwrap()
        .raw_transaction(receipt.hash)
        .unwrap()
        .unwrap();
    let envelope = TxEnvelope::decode_2718(&mut stored.as_slice()).unwrap();
    assert_eq!(
        block.header.transactions_root,
        calculate_transaction_root(&[envelope])
    );

    let typed_receipt: TransactionReceipt = typed(
        rpc(&store, "eth_getTransactionReceipt", json!([hash])),
        "receipt",
    );
    assert!(typed_receipt.status());
    assert_eq!(block.header.logs_bloom, *typed_receipt.inner.logs_bloom());
    let logs: Vec<Log> = typed(
        rpc(
            &store,
            "eth_getLogs",
            json!([{"fromBlock":"0x0","toBlock":"latest"}]),
        ),
        "logs",
    );
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].address(), contract);

    // Alloy's default EIP-1559 estimator (used by Foundry) calls eth_feeHistory.
    let history: FeeHistory = typed(
        rpc(
            &store,
            "eth_feeHistory",
            json!(["0x3", "latest", [0.0, 50.0, 100.0]]),
        ),
        "fee history",
    );
    assert_eq!(history.oldest_block, 0);
    assert_eq!(history.base_fee_per_gas, vec![0; 4]);
    assert_eq!(history.gas_used_ratio.len(), 3);
    assert_eq!(history.gas_used_ratio[0], 0.0);
    // Genesis is empty; the legacy fixture pays 1 wei, the type-2 write 2 wei.
    let reward = history.reward.unwrap();
    assert_eq!(reward, vec![vec![0; 3], vec![1; 3], vec![2; 3]]);
    let latest: FeeHistory = typed(
        rpc(&store, "eth_feeHistory", json!([1, "pending"])),
        "fee history without rewards",
    );
    assert_eq!((latest.oldest_block, latest.reward), (2, None));
    for (method, expected) in [
        ("eth_syncing", json!(false)),
        ("eth_accounts", json!([])),
        ("net_listening", json!(true)),
    ] {
        assert_eq!(rpc(&store, method, json!([])), expected);
    }
    assert!(
        rpc(&store, "web3_clientVersion", json!([]))
            .as_str()
            .unwrap()
            .starts_with("alephium-l2-node/v")
    );
    let input = json!({"jsonrpc":"2.0","id":1,"method":"eth_feeHistory","params":["0x0","latest"]});
    assert!(read::dispatch(Arc::new(store.view().unwrap()), &input).is_err());
    let input = json!({"jsonrpc":"2.0","id":1,"method":"eth_feeHistory","params":["0x1","latest",[50.0, 10.0]]});
    assert!(read::dispatch(Arc::new(store.view().unwrap()), &input).is_err());
}
