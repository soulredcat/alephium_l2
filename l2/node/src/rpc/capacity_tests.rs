use super::{block, call, estimate};
use crate::{development, storage::Store};
use alloy_primitives::Address;
use serde_json::json;
use std::sync::Arc;

#[test]
fn call_and_estimate_use_the_committed_profile_gas_capacity() {
    let directory = tempfile::tempdir().unwrap();
    let mut genesis = development::genesis();
    genesis.capacity.block_gas = 100_000_000;
    genesis.capacity.block_bytes = 2 * 1024 * 1024;
    genesis.capacity.max_pending = 10_000;
    let store = Store::open(&directory.path().join("data"), &genesis).unwrap();
    let view = Arc::new(store.view().unwrap());
    let input = json!({"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{
        "from":development::address(),"to":Address::repeat_byte(0x77),"gas":"0x3938700"
    }]});
    let parsed = call::parse(&input, view.capacity().block_gas).unwrap();
    assert_eq!(parsed.request.gas_limit, 60_000_000);
    assert_eq!(call::context(&view).gas_limit, 100_000_000);
    assert_eq!(call::query(view.clone(), &input).unwrap(), "0x");
    assert_eq!(estimate::query(view.clone(), &input).unwrap(), "0x5208");

    let mut omitted = input.clone();
    omitted["params"][0].as_object_mut().unwrap().remove("gas");
    assert_eq!(
        call::parse(&omitted, view.capacity().block_gas)
            .unwrap()
            .request
            .gas_limit,
        100_000_000
    );
    let mut over = input;
    over["params"][0]["gas"] = json!("0x5f5e101");
    assert!(call::query(view.clone(), &over).is_err());

    let block_query =
        json!({"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["earliest",false]});
    assert_eq!(
        block::query(view, &block_query).unwrap()["gasLimit"],
        "0x5f5e100"
    );
}
