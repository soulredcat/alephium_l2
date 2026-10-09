//! One isolated development qualification; no live keys, RPC or callbacks.
use crate::{development, funding_preparation::*, storage::Store};
use alephium_l2_sdk::alephium::{
    OutputRef, alephium_hash,
    funding_preparation::{FundingPreparationSpec, inspect_funding_preparation_wire},
    publisher_address_from_public_key,
};
use alloy_primitives::{B256, U256};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use std::path::PathBuf;

fn synthetic_record() -> (FundingPreparationRecord, Vec<u8>) {
    let secp = Secp256k1::new();
    let (secret, key) = (1..=255_u8)
        .find_map(|value| {
            // Published deterministic TEST material, never operator key custody.
            let secret = SecretKey::from_byte_array([value; 32]).ok()?;
            let key = PublicKey::from_secret_key(&secp, &secret).serialize();
            (publisher_address_from_public_key(&key).ok()?.group() == 0).then_some((secret, key))
        })
        .expect("Bounded public development-key selection failed");
    let owner = alephium_hash(&key);
    // Pinned native hint fixture, independent of the preparation encoder.
    let hint = owner.as_slice().iter().fold(5381_u32, |value, byte| {
        value.wrapping_mul(33).wrapping_add(u32::from(*byte))
    }) | 1;
    let input = OutputRef {
        hint,
        key: B256::repeat_byte(8),
    };
    let spec = FundingPreparationSpec {
        purpose_id: B256::repeat_byte(40),
        operator_source: B256::repeat_byte(41),
        caller_public_key: key,
        network_genesis_id: B256::repeat_byte(42),
        funding_source_id: B256::repeat_byte(43),
        gas_amount: 100_000,
        gas_price: U256::from(100_000_000_000_u64),
    };
    let input_amount = U256::from(2_000_000_000_000_000_000_u64);
    // Manual ordinary-v0 compact golden: gas100000,price1e11,one fullP2PKH,
    // four outputs each0.4975ALPH. No preparation/compact encoder is called.
    let mut raw = hex::decode("000100800186a0c1174876e80001").unwrap();
    raw.extend_from_slice(&hint.to_be_bytes());
    raw.extend_from_slice(input.key.as_slice());
    raw.push(0);
    raw.extend_from_slice(&key);
    raw.push(4);
    for _ in 0..4 {
        raw.extend_from_slice(&hex::decode("c406e7799d37c1c000").unwrap());
        raw.push(0);
        raw.extend_from_slice(owner.as_slice());
        raw.extend_from_slice(&[0; 10]);
    }
    let wire = inspect_funding_preparation_wire(&spec, &raw, input, input_amount)
        .expect("Manual development wire must pass the pure native shape audit");
    let signature = secp
        .sign_ecdsa(Message::from_digest(wire.tx_id().0), &secret)
        .serialize_compact()
        .to_vec();
    let record = FundingPreparationRecord {
        schema: 1,
        revision: 1,
        immutable: FundingPreparationImmutable {
            purpose_id: spec.purpose_id,
            operator_source: spec.operator_source,
            network: 1,
            network_genesis_id: spec.network_genesis_id,
            funding_source_id: spec.funding_source_id,
            caller_public_key: key.to_vec(),
            input_refs: vec![FundingPreparationReference::capture(input)],
            input_amount,
            unsigned: raw,
            transaction_id: wire.tx_id(),
            gas_amount: spec.gas_amount,
            gas_price: spec.gas_price,
            fee: wire.fee(),
            minimum_confirmations: [6; 3],
            outputs: wire
                .outputs()
                .iter()
                .map(|output| FundingPreparationOutput {
                    index: output.index(),
                    reference: FundingPreparationReference::capture(output.reference()),
                    amount: output.amount(),
                    owner_hash: output.owner_hash(),
                    lock_time_ms: 0,
                })
                .collect(),
        },
        phase: FundingPreparationPhase::Planned,
        sign_attempts: 0,
        submit_attempts: 0,
        signature: None,
        inclusion: None,
    };
    (record, signature)
}

fn private_output() -> PathBuf {
    let requested = PathBuf::from(
        std::env::var_os("L2_FUNDING_PREPARATION_TEST_OUTPUT")
            .expect("Explicit E-drive test/private output required"),
    );
    let allowed = PathBuf::from("E:/alphiumL2/test/private");
    crate::storage::path::checked_absolute(&allowed)
        .expect("Test/private parent must have no redirected ancestors");
    crate::storage::path::checked_absolute(&requested)
        .expect("Test output must have no redirected ancestors");
    std::fs::create_dir_all(&allowed).expect("Cannot provision named test/private parent");
    let allowed = allowed
        .canonicalize()
        .expect("Test/private parent is unresolved");
    // Root provisions the aggregate output directory before launching the job.
    assert!(
        requested.is_absolute(),
        "Test output must be an absolute E-drive path"
    );
    let canonical = requested
        .canonicalize()
        .expect("Test output must already exist");
    assert!(
        canonical.starts_with(&allowed),
        "Qualification output must remain in E-drive test/private"
    );
    let output = requested.join("funding-preparation-store");
    std::fs::create_dir(&output)
        .expect("Fresh qualification child required; preserve prior results");
    output
}

#[test]
#[ignore = "Requires a fresh explicitly owned main-repository private output directory"]
fn p5_funding_preparation_store_bulk() {
    let output = private_output();
    let signer_checks = crate::funding_preparation_signer::run_funding_preparation_signer_checks();
    assert!(
        signer_checks == 62,
        "Funding preparation signer aggregate inventory changed"
    );
    let genesis = development::genesis();
    let (planned, signature) = synthetic_record();
    let dispatch_checks =
        crate::funding_preparation_service::tests::run_checks(&output, &planned, &signature);
    let http_checks = crate::funding_preparation_submitter::tests::run_checks();
    let normal_path = output.join("normal");
    let mut normal =
        Store::open(&normal_path, &genesis).expect("Normal isolated Store open failed");
    let mut corrupt =
        Store::open(&output.join("corrupt"), &genesis).expect("Corrupt isolated Store open failed");
    let mut uncertain = Store::open(&output.join("uncertain"), &genesis)
        .expect("Uncertain isolated Store open failed");
    let count = super::run_checks(
        &mut normal,
        &mut corrupt,
        &mut uncertain,
        &planned,
        &signature,
    )
    .expect("Coherent funding preparation aggregate failed; private records suppressed");
    assert!(
        count == 25,
        "Funding preparation aggregate inventory changed"
    );
    let confirmed = normal
        .load_funding_preparation(planned.immutable.purpose_id)
        .expect("Historical confirmed record load failed")
        .expect("Confirmed record missing");
    drop(normal);
    drop(corrupt);
    drop(uncertain);
    let reopened =
        Store::open_existing(&normal_path, &genesis).expect("Header/index recovery failed");
    assert!(
        reopened
            .load_funding_preparation(planned.immutable.purpose_id)
            .expect("Reopened record load failed")
            == Some(confirmed),
        "Durable preparation recovery changed; private bytes suppressed"
    );
    drop(reopened);
    // Reopening corrupt namespaces must fail, never recreate Planned/empty.
    assert!(
        Store::open_existing(&output.join("corrupt"), &genesis).is_err(),
        "Missing input index must refuse restart"
    );
    println!(
        "P5 funding preparation aggregate: PASS store_checks={count} restart_checks=2 signer_checks={signer_checks} dispatch_checks={dispatch_checks} http_checks={http_checks}; synthetic keys only, no live network"
    );
}
