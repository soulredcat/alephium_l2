//! Pinned artifact loading, ABI encoding and isolated local execution helpers.
use alephium_l2_node::{
    development, execution,
    protocol::{BLOCK_GAS, BlockCommit, BlockContext, CallRequest, CallResult, Pending, Receipt},
    storage::{ReadView, Store},
};
use alloy_eips::eip2930::AccessList;
use alloy_primitives::{Address, U256};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

pub(super) const VERIFY_SELECTOR: [u8; 4] = [0xab, 0x75, 0x0e, 0x75];
pub(super) const RECEIPT_SELECTOR: [u8; 4] = [0x73, 0xc4, 0x57, 0xba];
pub(super) const VERIFICATION_FAILED: [u8; 4] = [0x43, 0x9c, 0xc0, 0xcd];
pub(super) const SELECTOR_MISMATCH: [u8; 4] = [0xb8, 0xb3, 0x8d, 0x4c];
const ARTIFACT_SHA256: &str = "474672cdba6abd067038e784d85e96c06638b2602f1b8675804dd40042b35be3";

#[derive(Deserialize)]
pub(super) struct Artifact {
    pub creation_bytecode: String,
    pub runtime_template: String,
    pub compiler: Value,
    pub fixture: Fixture,
}

impl Artifact {
    pub fn load() -> Result<Self, String> {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/risc0-groth16/artifact.json");
        let bytes = fs::read(path).map_err(|_| "missing pinned RISC Zero oracle artifact")?;
        if hex::encode(Sha256::digest(&bytes)) != ARTIFACT_SHA256 {
            return Err("pinned RISC Zero oracle artifact integrity mismatch".into());
        }
        serde_json::from_slice(&bytes)
            .map_err(|_| "invalid pinned RISC Zero oracle artifact".into())
    }
}

#[derive(Deserialize)]
pub(super) struct Fixture {
    pub seal: String,
    pub image_id: String,
    pub journal: String,
    pub journal_digest: String,
    pub control_root: String,
    pub bn254_control_id: String,
}

pub(super) fn decode(value: &str) -> Result<Vec<u8>, String> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value))
        .map_err(|_| "invalid hex in pinned oracle artifact".into())
}

pub(super) fn word(value: &str) -> Result<[u8; 32], String> {
    decode(value)?
        .try_into()
        .map_err(|_| "invalid bytes32 in oracle artifact".into())
}

pub(super) fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn context(number: u64) -> BlockContext {
    BlockContext {
        number,
        timestamp: 1_800_000_000 + number * 2,
        gas_limit: BLOCK_GAS,
    }
}

pub(super) fn deploy(store: &mut Store, init: Vec<u8>) -> Result<Receipt, String> {
    let raw = development::sign(0, None, U256::ZERO, init, BLOCK_GAS)?;
    let context = context(1);
    let info = execution::validate(store.view()?, &raw, context)?;
    let admitted = store.admit(Pending {
        hash: info.hash,
        sender: info.sender,
        raw: raw.clone(),
    })?;
    assert!(
        admitted.status == "durably_accepted",
        "verifier deployment was not durably admitted"
    );
    let view = store.view()?;
    let parent = view.head.clone();
    let result = execution::execute_block(view, &[raw], context)?;
    assert!(
        result.rejected.is_empty(),
        "verifier deployment was rejected"
    );
    assert!(
        result.receipts.len() == 1,
        "verifier deployment receipt missing"
    );
    assert!(result.receipts[0].success, "verifier deployment reverted");
    assert!(
        result.receipts[0].contract == Some(development::address().create(0)),
        "unexpected verifier address"
    );
    let view = store.commit(BlockCommit {
        parent,
        context,
        transactions: result.receipts.iter().map(|receipt| receipt.hash).collect(),
        changes: result.changes,
        receipts: result.receipts,
        rejected: result.rejected,
    })?;
    assert!(
        store.pending()?.is_empty(),
        "verifier deployment remained pending"
    );
    view.receipt(info.hash)?
        .ok_or_else(|| "missing durable verifier receipt".into())
}

pub(super) fn call(
    view: &ReadView,
    contract: Address,
    input: Vec<u8>,
) -> Result<CallResult, String> {
    execution::simulate(
        view.clone(),
        CallRequest {
            from: development::address(),
            to: Some(contract),
            data: input,
            value: U256::ZERO,
            gas_limit: BLOCK_GAS,
            gas_price: 0,
            access_list: AccessList::default(),
        },
        context(2),
    )
}

pub(super) fn verify_input(seal: &[u8], image: [u8; 32], journal: [u8; 32]) -> Vec<u8> {
    let mut input = VERIFY_SELECTOR.to_vec();
    input.extend(U256::from(96).to_be_bytes::<32>());
    input.extend(image);
    input.extend(journal);
    input.extend(U256::from(seal.len()).to_be_bytes::<32>());
    input.extend(seal);
    let padded = seal.len().div_ceil(32) * 32;
    input.resize(4 + 96 + 32 + padded, 0);
    input
}
