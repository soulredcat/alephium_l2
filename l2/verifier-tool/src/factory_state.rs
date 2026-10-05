//! Exact VM contract-state and response boundary for the synthetic factory flow.
use crate::{
    cases::{FP_MODULUS, word},
    compiler::Compiled,
    staged_cases,
    staged_state::asset,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub(crate) fn fixture_id(domain: &[u8]) -> [u8; 32] {
    let mut id: [u8; 32] = Sha256::digest(domain).into();
    id[31] = 0;
    id
}

pub(crate) fn child_state(compiled: &Compiled, id: &[u8; 32], fields: Vec<Value>) -> Value {
    json!({"address": staged_cases::contract_address(id), "bytecode": compiled.bytecode,
        "codeHash": compiled.evidence["productionCodeHash"], "immFields": [word(FP_MODULUS)],
        "mutFields": fields, "asset": asset()})
}

pub(crate) fn state_at(state: &Value, id: &[u8; 32]) -> Value {
    let mut state = state.clone();
    state["address"] = json!(staged_cases::contract_address(id));
    state
}

pub(crate) fn envelope(response: &Value, target: &Value) -> bool {
    response["address"] == target["address"]
        && response["codeHash"] == target["codeHash"]
        && response["debugMessages"] == json!([])
        && response["gasUsed"]
            .as_u64()
            .is_some_and(|gas| gas > 0 && gas <= 5_000_000)
}

pub(crate) fn checked_states(response: &Value, expected: &[&Value]) -> Result<Vec<Value>, String> {
    let states = response["contracts"]
        .as_array()
        .ok_or("Missing factory VM contract states")?;
    if states.len() != expected.len() {
        return Err("Unexpected factory VM contract count".into());
    }
    for expected_state in expected {
        let matches = states
            .iter()
            .filter(|state| state["address"] == expected_state["address"])
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err("Missing or duplicated expected VM contract address".into());
        }
        let state = matches[0];
        if ["bytecode", "codeHash", "immFields", "mutFields", "asset"]
            .iter()
            .any(|key| state[key] != expected_state[key])
        {
            return Err("Factory VM executable, fields or virtual assets differ".into());
        }
        let hash = state["initialStateHash"]
            .as_str()
            .ok_or("Missing VM initial state hash")?;
        if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("VM initial state hash is not exactly 32 bytes".into());
        }
    }
    Ok(states.clone())
}
