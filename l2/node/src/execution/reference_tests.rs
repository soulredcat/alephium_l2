//! A Geth-filled oracle for the actual new-runtime delta normalizer and overlay.
//! Ethereum fixture context is test-only: production admission rejects its
//! unprotected envelope and production engine/genesis policy is not bypassed.

use super::{changes::Changes, inspect};
use crate::protocol::{AccountChange, EventLog};
use alloy_consensus::transaction::SignerRecoverable;
use alloy_consensus::{SignableTransaction, Transaction, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::{Decodable2718, Encodable2718};
use alloy_primitives::{Address, B256, Signature, U256, address, keccak256};
use revm::context::{BlockEnv, TxEnv};
use revm::database::InMemoryDB;
use revm::handler::SystemCallEvm;
use revm::primitives::{TxKind, eip4844::BLOB_BASE_FEE_UPDATE_FRACTION_CANCUN, hardfork::SpecId};
use revm::state::{AccountInfo, Bytecode};
use revm::{Context, ExecuteCommitEvm, ExecuteEvm, MainBuilder, MainContext};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const FIXTURE: &[u8] = include_bytes!("../../fixtures/reference/add11.json");
const LICENSE: &[u8] = include_bytes!("../../fixtures/reference/LICENSE");
const MANIFEST: &str = include_str!("../../fixtures/reference/manifest.json");
const CASE: &str = "add11_d0g0v0_Cancun";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct ReferenceAccount {
    balance: U256,
    nonce: u64,
    code_hash: B256,
    code: Vec<u8>,
    slots: BTreeMap<U256, U256>,
}

type Allocation = BTreeMap<Address, ReferenceAccount>;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Observation {
    state: Allocation,
    gas_used: u64,
    success: bool,
    logs: Vec<EventLog>,
}

fn quantity(value: &Value) -> U256 {
    U256::from_str_radix(
        value
            .as_str()
            .expect("fixture quantity")
            .strip_prefix("0x")
            .expect("hex prefix"),
        16,
    )
    .expect("valid fixture quantity")
}

fn bytes(value: &Value) -> Vec<u8> {
    hex::decode(
        value
            .as_str()
            .expect("fixture bytes")
            .strip_prefix("0x")
            .expect("hex prefix"),
    )
    .expect("valid fixture bytes")
}

fn parse_allocation(value: &Value) -> Allocation {
    value
        .as_object()
        .expect("fixture allocation")
        .iter()
        .map(|(address, account)| {
            let code = bytes(&account["code"]);
            let slots = account["storage"]
                .as_object()
                .expect("fixture storage")
                .iter()
                .map(|(slot, value)| (quantity(&Value::String(slot.clone())), quantity(value)))
                .filter(|(_, value)| !value.is_zero())
                .collect();
            (
                address.parse().expect("fixture address"),
                ReferenceAccount {
                    balance: quantity(&account["balance"]),
                    nonce: quantity(&account["nonce"]).to(),
                    code_hash: keccak256(&code),
                    code,
                    slots,
                },
            )
        })
        .collect()
}

fn fixture_database(pre: &Allocation) -> InMemoryDB {
    let mut db = InMemoryDB::default();
    for (address, account) in pre {
        db.insert_account_info(
            *address,
            AccountInfo {
                balance: account.balance,
                nonce: account.nonce,
                code_hash: account.code_hash,
                code: Some(Bytecode::new_raw(account.code.clone().into())),
                ..Default::default()
            },
        );
        for (slot, value) in &account.slots {
            db.insert_account_storage(*address, *slot, *value)
                .expect("in-memory fixture storage");
        }
    }
    db
}

/// Separate test materializer: apply only emitted node deltas, never REVM state.
fn apply_changes(mut allocation: Allocation, changes: &[AccountChange]) -> Allocation {
    for change in changes {
        if change.deleted {
            allocation.remove(&change.address);
            continue;
        }
        let account = allocation.entry(change.address).or_default();
        if change.storage_reset {
            account.slots.clear();
        }
        account.balance = change.balance;
        account.nonce = change.nonce;
        account.code_hash = change.code_hash;
        if let Some(code) = &change.code {
            account.code.clone_from(code);
        }
        assert_eq!(keccak256(&account.code), account.code_hash);
        for (slot, value) in &change.slots {
            if value.is_zero() {
                account.slots.remove(slot);
            } else {
                account.slots.insert(*slot, *value);
            }
        }
    }
    allocation
}

fn overlay_allocation(db: &InMemoryDB) -> Allocation {
    db.cache
        .accounts
        .iter()
        .filter_map(|(address, account)| {
            let info = account.info()?;
            let code = db.cache.contracts[&info.code_hash]
                .original_bytes()
                .to_vec();
            Some((
                *address,
                ReferenceAccount {
                    balance: info.balance,
                    nonce: info.nonce,
                    code_hash: info.code_hash,
                    code,
                    slots: account
                        .storage
                        .iter()
                        .filter(|(_, value)| !value.is_zero())
                        .map(|(slot, value)| (*slot, *value))
                        .collect(),
                },
            ))
        })
        .collect()
}

fn signed_fixture_transaction(value: &Value) -> (TxEnv, Vec<u8>) {
    let parity = quantity(&value["v"]).to::<u64>();
    assert!(matches!(parity, 27 | 28), "selected fixture is unprotected");
    let signed = TxLegacy {
        chain_id: None,
        nonce: quantity(&value["nonce"]).to(),
        gas_price: quantity(&value["gasPrice"]).to(),
        gas_limit: quantity(&value["gasLimit"]).to(),
        to: TxKind::Call(value["to"].as_str().unwrap().parse().unwrap()),
        value: quantity(&value["value"]),
        input: bytes(&value["data"]).into(),
    }
    .into_signed(Signature::new(
        quantity(&value["r"]),
        quantity(&value["s"]),
        parity == 28,
    ));
    let envelope = TxEnvelope::Legacy(signed);
    let raw = envelope.encoded_2718();
    let mut remaining = raw.as_slice();
    let decoded = TxEnvelope::decode_2718(&mut remaining).expect("canonical fixture envelope");
    // Boolean assertions never format signatures or raw payloads on failure.
    assert!(remaining.is_empty() && decoded.encoded_2718() == raw);
    let caller = decoded.recover_signer().expect("valid fixture signature");
    assert_eq!(
        caller,
        value["sender"]
            .as_str()
            .unwrap()
            .parse::<Address>()
            .unwrap()
    );
    let tx = TxEnv::builder()
        .tx_type(Some(0))
        .caller(caller)
        .chain_id(None)
        .nonce(decoded.nonce())
        .gas_limit(decoded.gas_limit())
        .gas_price(decoded.gas_price().unwrap())
        .kind(decoded.kind())
        .value(decoded.value())
        .data(decoded.input().clone())
        .build()
        .expect("fixture transaction environment");
    (tx, raw)
}

#[test]
fn official_cancun_add11_matches_new_delta_normalizer_and_overlay() {
    let manifest: Value = serde_json::from_str(MANIFEST).expect("reference manifest");
    assert_eq!(
        hex::encode(Sha256::digest(FIXTURE)),
        manifest["fixture_sha256"]
    );
    assert_eq!(
        hex::encode(Sha256::digest(LICENSE)),
        manifest["license_sha256"]
    );
    assert_eq!(manifest["selected_case"], CASE);
    let fixture: Value = serde_json::from_slice(FIXTURE).expect("official fixture");
    let case = &fixture[CASE];
    assert_eq!(case["network"], "Cancun");
    assert_eq!(
        case["_info"]["filling-rpc-server"],
        manifest["filling_client"]
    );
    let blocks = case["blocks"].as_array().unwrap();
    assert_eq!(blocks.len(), 1);
    assert!(blocks[0]["withdrawals"].as_array().unwrap().is_empty());
    assert!(blocks[0]["uncleHeaders"].as_array().unwrap().is_empty());
    let transactions = blocks[0]["transactions"].as_array().unwrap();
    assert_eq!(transactions.len(), 1);
    let header = &blocks[0]["blockHeader"];
    assert!(bytes(&header["bloom"]).iter().all(|byte| *byte == 0));
    let pre = parse_allocation(&case["pre"]);
    let expected = Observation {
        state: parse_allocation(&case["postState"]),
        gas_used: quantity(&header["gasUsed"]).to(),
        success: true,
        logs: Vec::new(),
    };
    let (tx, raw) = signed_fixture_transaction(&transactions[0]);
    assert_eq!(
        inspect(&raw).unwrap_err(),
        "transaction belongs to an unsupported chain"
    );
    let mut block = BlockEnv {
        number: quantity(&header["number"]),
        timestamp: quantity(&header["timestamp"]),
        gas_limit: quantity(&header["gasLimit"]).to(),
        basefee: quantity(&header["baseFeePerGas"]).to(),
        beneficiary: header["coinbase"].as_str().unwrap().parse().unwrap(),
        difficulty: quantity(&header["difficulty"]),
        prevrandao: Some(header["mixHash"].as_str().unwrap().parse().unwrap()),
        ..Default::default()
    };
    block.set_blob_excess_gas_and_price(
        quantity(&header["excessBlobGas"]).to(),
        BLOB_BASE_FEE_UPDATE_FRACTION_CANCUN,
    );
    let mut evm = Context::mainnet()
        .with_db(fixture_database(&pre))
        .modify_cfg_chained(|cfg| {
            cfg.chain_id = 1;
            cfg.set_spec_and_mainnet_gas_params(SpecId::CANCUN);
        })
        .with_block(block)
        .build_mainnet();
    let mut changes = Changes::default();
    let beacon = address!("000f3df6d732807ef1319fb7b8bb8522d0beac02");
    let mut system = evm
        .system_call(beacon, bytes(&header["parentBeaconBlockRoot"]).into())
        .expect("fixture EIP-4788 transition");
    assert!(system.result.is_success());
    changes.absorb(&mut system.state);
    evm.commit(system.state);
    let mut outcome = evm.transact(tx).expect("fixture transaction execution");
    changes.absorb(&mut outcome.state);
    evm.commit(outcome.state);
    let deltas = changes.finish();
    let observed = Observation {
        state: apply_changes(pre.clone(), &deltas),
        gas_used: outcome.result.tx_gas_used(),
        success: outcome.result.is_success(),
        logs: outcome
            .result
            .logs()
            .iter()
            .map(|log| EventLog {
                address: log.address,
                topics: log.data.topics().to_vec(),
                data: log.data.data.to_vec(),
            })
            .collect(),
    };
    assert_eq!(observed, expected, "complete Geth-filled output comparison");
    assert_eq!(
        overlay_allocation(&evm.ctx.journaled_state.database),
        expected.state
    );
    assert_delta_mutation_detection(&expected.state, &pre, &deltas, beacon);
}

fn assert_delta_mutation_detection(
    expected: &Allocation,
    pre: &Allocation,
    deltas: &[AccountChange],
    beacon: Address,
) {
    let mut corrupted = deltas.to_vec();
    corrupted
        .iter_mut()
        .find(|change| change.address == beacon)
        .unwrap()
        .nonce += 1;
    assert_ne!(
        apply_changes(pre.clone(), &corrupted),
        *expected,
        "wrong nonce delta"
    );
    let mut corrupted = deltas.to_vec();
    corrupted
        .iter_mut()
        .find(|change| change.address == beacon)
        .unwrap()
        .slots
        .iter_mut()
        .find(|(slot, _)| *slot == U256::from(1000))
        .unwrap()
        .1 = U256::ONE;
    assert_ne!(
        apply_changes(pre.clone(), &corrupted),
        *expected,
        "wrong slot delta"
    );
}
