//! Bounded native-producer ecrecover witness for unchanged guest parity checks.
#[allow(dead_code)]
#[path = "support/recovery_fixture.rs"]
mod fixture;

use alephium_l2_node::{
    development, execution,
    operator::{self, SettlementDomain},
    protocol::{CHAIN_ID, CallRequest, Receipt},
    storage::Store,
};
use alloy_consensus::TxEnvelope;
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{Address, B256, Signature, U256, keccak256, uint};
use fixture::{admit, commit, context, io_error};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

const ORDER: U256 = uint!(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141_U256);
const GAS: u64 = 150_000;

// Private precompile calldata contains signature scalars: never derive Debug.
struct Case {
    name: &'static str,
    input: Vec<u8>,
    expected: U256,
}

#[test]
fn export_ecrecover_low_high_s_parity_and_invalid_inputs() -> Result<(), String> {
    let temporary = tempfile::Builder::new()
        .prefix("l2-p4-precompile-")
        .tempdir()
        .map_err(io_error)?;
    let root = if let Some(path) = std::env::var_os("L2_PRECOMPILE_OUTPUT") {
        let path = PathBuf::from(path);
        fs::create_dir(&path).map_err(io_error)?;
        path
    } else {
        temporary.path().to_path_buf()
    };
    let cases = recovery_cases(&root)?;
    assert_eq!(cases.len(), 11);
    let genesis = development::genesis();
    let mut store = Store::open(&root.join("source"), &genesis)?;
    let runtime = contract_runtime()?;
    assert_eq!(runtime.len(), 34);
    let mut init = vec![0x60, 34, 0x60, 12, 0x60, 0, 0x39, 0x60, 34, 0x60, 0, 0xf3];
    init.extend(&runtime);
    let deployed = execute(&mut store, &root, "deploy", 0, None, init)?;
    let contract = deployed
        .contract
        .ok_or("Missing ecrecover fixture deployment")?;
    let mut fees = U256::from(deployed.gas_used);
    let mut results = Vec::new();
    for (index, case) in cases.into_iter().enumerate() {
        let nonce = index as u64 + 1;
        let view = store.view()?;
        let before = view.state_digest()?;
        let simulation = execution::simulate(
            view.clone(),
            CallRequest {
                from: development::address(),
                to: Some(contract),
                data: case.input.clone(),
                value: U256::ZERO,
                gas_limit: GAS,
                gas_price: 1,
                access_list: Default::default(),
            },
            context(nonce + 1),
        )?;
        assert!(
            simulation.success && !simulation.halted,
            "ecrecover fixture simulation failed"
        );
        assert_eq!(simulation.output, case.expected.to_be_bytes::<32>());
        assert_eq!(view.state_digest()?, before);
        drop(view);
        let input_bytes = case.input.len();
        let input_keccak = keccak256(&case.input);
        let receipt = execute(
            &mut store,
            &root,
            case.name,
            nonce,
            Some(contract),
            case.input,
        )?;
        assert_eq!(receipt.gas_used, simulation.gas_used);
        assert_eq!(store.view()?.slot(contract, U256::ZERO)?, case.expected);
        fees = fees
            .checked_add(U256::from(receipt.gas_used))
            .ok_or("Fixture fee overflow")?;
        results.push(json!({
            "name": case.name, "input_bytes": input_bytes, "input_keccak": input_keccak,
            "expected_word": case.expected, "gas_used": receipt.gas_used,
            "transaction_hash": receipt.hash, "success": receipt.success,
        }));
    }
    let view = store.view()?;
    assert_eq!(view.head.height, 12);
    let sender = view
        .account(development::address())?
        .ok_or("Missing fixture sender")?;
    assert_eq!(sender.nonce, 12);
    assert_eq!(
        sender.balance,
        U256::from(development::INITIAL_BALANCE) - fees
    );
    assert_eq!(
        view.account(Address::ZERO)?
            .ok_or("Missing fee recipient")?
            .balance,
        fees
    );
    assert_eq!(view.slot(contract, U256::ZERO)?, U256::ZERO);
    assert_eq!(
        view.code(
            view.account(contract)?
                .ok_or("Missing fixture contract")?
                .code_hash
        )?,
        runtime
    );
    drop(view);
    drop(store);
    operator::backup(&root.join("source"), &root.join("backup"), &genesis)?;
    let exported = operator::prepare_transition_batch(
        &root.join("backup"),
        &genesis,
        &root.join("export"),
        1,
        SettlementDomain {
            l1_network: 1,
            l1_genesis_id: B256::from([0x11; 32]),
            settlement_contract_id: B256::from([0x22; 32]),
        },
    )?;
    assert_eq!(exported.blocks, 12);
    assert_eq!(exported.executed_transactions, 12);
    write_json(
        &root.join("genesis.json"),
        &serde_json::to_value(genesis).map_err(|_| "Cannot encode fixture genesis")?,
    )?;
    write_json(
        &root.join("report.json"),
        &json!({
            "scope": "cancun-ecrecover-native-producer-fixture/v1", "cases": results,
            "export": exported, "guest_proof_generated": false, "settlement_verified": false,
        }),
    )?;
    Ok(())
}

fn contract_runtime() -> Result<Vec<u8>, String> {
    // CALLDATACOPY input to [0..128); independently zero output at [128..160).
    // STATICCALL(0x01, input, out=128, size=32); POP success; SSTORE(0, MLOAD(128)); RETURN.
    // Ecrecover returns empty bytes for malformed signatures. Disjoint zeroed output
    // prevents the input hash or a prior nonzero storage value becoming a false result.
    hex::decode("36600060003760006080526020608036600060015afa5060805160005560206080f3")
        .map_err(|_| "Invalid reviewed fixture bytecode".to_owned())
}

fn recovery_cases(root: &Path) -> Result<Vec<Case>, String> {
    let mut vectors: [Option<(B256, Signature)>; 2] = [None, None];
    let recipient = Address::from([0x45; 20]);
    // Deterministic bounded vector generation only; these envelopes are never submitted.
    for nonce in 0..32_u64 {
        write_json(
            &root.join(format!("vector-{nonce:02}.intent.json")),
            &json!({
                "scope": "isolated-development-ecrecover-vector", "chain_id": CHAIN_ID,
                "type": 0, "nonce": nonce, "to": recipient, "value": "0",
                "gas": 21000, "gas_price": 1, "data_keccak": keccak256([]),
            }),
        )?;
        let raw = development::sign(nonce, Some(recipient), U256::ZERO, vec![], 21_000)?;
        let mut input = raw.as_slice();
        let envelope = TxEnvelope::decode_2718(&mut input)
            .map_err(|_| "Cannot decode private fixture vector")?;
        if !input.is_empty() {
            return Err("Trailing private fixture vector bytes".into());
        }
        let signature = (*envelope.signature()).normalized_s();
        assert!(signature.s() > U256::ZERO && signature.s() <= ORDER / U256::from(2));
        vectors[usize::from(signature.v())].get_or_insert((envelope.signature_hash(), signature));
        if vectors.iter().all(Option::is_some) {
            break;
        }
    }
    let mut cases = Vec::new();
    let expected = U256::from_be_slice(development::address().as_slice());
    for (parity, low_name, high_name) in [
        (0, "low-s-v27", "high-s-v28"),
        (1, "low-s-v28", "high-s-v27"),
    ] {
        let (hash, low) =
            vectors[parity].ok_or("Bounded vectors did not cover both parity bits")?;
        let high = Signature::new(low.r(), ORDER - low.s(), !low.v());
        assert!(high.s() > ORDER / U256::from(2));
        assert!(
            high.normalize_s() == Some(low),
            "High-s normalization differs"
        );
        cases.push(Case {
            name: low_name,
            input: recovery_input(hash, low),
            expected,
        });
        cases.push(Case {
            name: high_name,
            input: recovery_input(hash, high),
            expected,
        });
    }
    let base = cases[0].input.clone();
    for (name, range, scalar) in [
        ("r-zero", 64..96, U256::ZERO),
        ("r-order", 64..96, ORDER),
        ("s-zero", 96..128, U256::ZERO),
        ("s-order", 96..128, ORDER),
    ] {
        let mut input = base.clone();
        input[range].copy_from_slice(&scalar.to_be_bytes::<32>());
        cases.push(Case {
            name,
            input,
            expected: U256::ZERO,
        });
    }
    let mut invalid_v = base.clone();
    invalid_v[63] = 29;
    cases.push(Case {
        name: "v-29",
        input: invalid_v,
        expected: U256::ZERO,
    });
    let mut invalid_padding = base.clone();
    invalid_padding[32] = 1;
    cases.push(Case {
        name: "v-padding",
        input: invalid_padding,
        expected: U256::ZERO,
    });
    cases.push(Case {
        name: "truncated-64",
        input: base[..64].to_vec(),
        expected: U256::ZERO,
    });
    Ok(cases)
}

fn recovery_input(hash: B256, signature: Signature) -> Vec<u8> {
    let mut input = vec![0_u8; 128];
    input[..32].copy_from_slice(hash.as_slice());
    input[63] = 27 + u8::from(signature.v());
    input[64..96].copy_from_slice(&signature.r().to_be_bytes::<32>());
    input[96..].copy_from_slice(&signature.s().to_be_bytes::<32>());
    input
}

fn execute(
    store: &mut Store,
    root: &Path,
    name: &str,
    nonce: u64,
    to: Option<Address>,
    data: Vec<u8>,
) -> Result<Receipt, String> {
    write_json(
        &root.join(format!("transaction-{nonce:02}.intent.json")),
        &json!({
            "scope": "isolated-development-ecrecover-fixture", "name": name,
            "chain_id": CHAIN_ID, "type": 0, "nonce": nonce, "to": to, "value": "0",
            "gas": GAS, "gas_price": 1, "data_keccak": keccak256(&data),
        }),
    )?;
    let raw = development::sign(nonce, to, U256::ZERO, data, GAS)?;
    let hash = admit(store, &raw, nonce + 1)?;
    let mut receipts = commit(store, &[raw], nonce + 1)?;
    let receipt = receipts.pop().ok_or("Missing fixture receipt")?;
    assert_eq!(receipt.hash, hash);
    assert!(
        receipt.success && receipt.logs.is_empty(),
        "Fixture transaction failed"
    );
    assert_eq!(receipt.gas_price, 1);
    assert!(receipt.gas_used >= 21_000 && receipt.gas_used < GAS);
    assert_eq!(receipt.block_height, nonce + 1);
    assert_eq!(receipt.transaction_index, 0);
    assert_eq!(receipt.cumulative_gas, receipt.gas_used);
    Ok(receipt)
}

fn write_json(path: &Path, value: &Value) -> Result<(), String> {
    let bytes =
        serde_json::to_vec_pretty(value).map_err(|_| "Cannot encode safe fixture record")?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(io_error)?;
    file.write_all(&bytes).map_err(io_error)?;
    file.sync_all().map_err(io_error)
}
