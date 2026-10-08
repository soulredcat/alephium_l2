//! One parent-owned aggregate calls this helper. All chain/funding facts here
//! are simulated; the script file is compile-qualified, never VM-qualified.
mod context_checks;
mod creator_profile;
mod diagnostics;
mod fixture;
mod head_capability;
mod head_progress;
mod lock_binding;
mod lock_time;
mod materialize;
mod policy_checks;

use super::{checks, creator, *};
use crate::alephium::{
    FundingModel, alephium_hash,
    read_node::{ConfirmationCounts, GenesisProvenance, TokenAmount, UnanchoredUtxo},
};
use alloy_primitives::{B256, U256};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::io::Read;

fn approved_script() -> Vec<u8> {
    let path = std::env::var_os("L2_PUBLISHER_SCRIPT_FILE")
        .expect("Explicit private script fixture path required");
    let expected = std::env::var("L2_PUBLISHER_SCRIPT_SHA256")
        .expect("Explicit compiled script SHA-256 pin required");
    let expected: [u8; 32] = hex::decode(expected)
        .expect("Invalid script pin")
        .try_into()
        .expect("Script pin must be 32 bytes");
    let file = std::fs::File::open(path).expect("Cannot open compiled script fixture");
    let mut bytes = Vec::new();
    file.take(32_769)
        .read_to_end(&mut bytes)
        .expect("Cannot read script fixture");
    assert!(
        !bytes.is_empty() && bytes.len() <= 32_768,
        "Invalid compiled fixture size"
    );
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    assert!(digest == expected, "Compiled fixture pin mismatch");
    bytes
}

/// Parent may select this affected bulk after diagnostic-only changes; it does
/// not load signing/script fixtures or rerun unrelated funding/codec checks.
pub(crate) fn run_head_diagnostic_checks() -> usize {
    head_progress::run_checks()
}

pub(crate) fn run_checks() -> usize {
    let script = approved_script();
    let f = fixture::build(None);
    let mut count = materialize::run_checks(&script);
    let mut check = |ok: bool| {
        assert!(
            ok,
            "Current-funding aggregate check failed; payload suppressed"
        );
        count += 1;
    };
    let outputs = creator::fixed_outputs(&f.details, f.creator_id, None).unwrap();
    check(outputs.len() == 2);
    // Even mutually consistent RPC txId/output-key metadata must not replace
    // hashing the actual canonical unsigned body.
    let mut altered_raw = f.creator_raw.clone();
    *altered_raw.last_mut().unwrap() ^= 1;
    let counterfeit_id = alephium_hash(&altered_raw);
    let mut counterfeit = f.details.clone();
    counterfeit["unsigned"]["txId"] = json!(hex::encode(counterfeit_id));
    for index in 0..2 {
        let reference = fixture::reference(counterfeit_id, index, f.fixed[0].reference.hint);
        counterfeit["unsigned"]["fixedOutputs"][index as usize]["key"] =
            json!(hex::encode(reference.key));
    }
    check(creator::fixed_outputs(&counterfeit, counterfeit_id, None).is_err());
    check(outputs[1].reference == f.fixed[1].reference && outputs[1].amount == f.fixed[1].amount);
    check(
        checks::fixed_output(&outputs, &f.fixed[1].reference)
            .unwrap()
            .0
            == 1,
    );
    // Index2 would be the first generated output. It is outside the signed
    // fixed-output vector even if an untrusted metadata record supplies its key.
    let generated = fixture::reference(f.creator_id, 2, f.fixed[1].reference.hint);
    check(matches!(
        checks::fixed_output(&outputs, &generated),
        Err(CurrentFundingError::NotFixedOutput)
    ));
    check(creator::fixed_outputs(&f.details, B256::repeat_byte(99), None).is_err());
    for mutation in 0..15 {
        let mut changed = f.details.clone();
        let unsigned = &mut changed["unsigned"];
        match mutation {
            0 => unsigned["txId"] = json!(hex::encode(B256::repeat_byte(99))),
            1 => unsigned["networkId"] = json!(0),
            2 => unsigned["version"] = json!(1),
            3 => unsigned["gasAmount"] = json!(19_999),
            4 => unsigned["gasPrice"] = json!("1000000000"),
            5 => unsigned["fixedOutputs"][1]["attoAlphAmount"] = json!("2000000000000000001"),
            6 => unsigned["fixedOutputs"][1]["attoAlphAmount"] = json!(1),
            7 => unsigned["fixedOutputs"][1]["attoAlphAmount"] = json!("01"),
            8 => unsigned["fixedOutputs"][1]["lockTime"] = json!(u64::MAX),
            9 => unsigned["fixedOutputs"][1]["tokens"] = json!([{"id":"00","amount":"1"}]),
            10 => unsigned["fixedOutputs"][1]["message"] = json!("00"),
            11 => unsigned["fixedOutputs"][1]
                .as_object_mut()
                .unwrap()
                .remove("key")
                .map(|_| ())
                .unwrap(),
            12 => unsigned["unexpected"] = json!(true),
            13 => unsigned["inputs"][0]["unlockScript"] = json!("03"),
            _ => unsigned["fixedOutputs"][1]["key"] = json!(hex::encode(outputs[0].reference.key)),
        }
        check(creator::fixed_outputs(&changed, f.creator_id, None).is_err());
    }
    let mut many = f.details.clone();
    many["unsigned"]["inputs"] = json!(vec![f.details["unsigned"]["inputs"][0].clone(); 257]);
    check(matches!(
        creator::fixed_outputs(&many, f.creator_id, None),
        Err(CurrentFundingError::Bounds)
    ));
    let mut absent = f.details.clone();
    absent["unsigned"]
        .as_object_mut()
        .unwrap()
        .remove("fixedOutputs");
    check(creator::fixed_outputs(&absent, f.creator_id, None).is_err());
    let with_script = fixture::build(Some(&script));
    check(
        creator::fixed_outputs(&with_script.details, with_script.creator_id, Some(&script)).is_ok(),
    );
    check(creator::fixed_outputs(&with_script.details, with_script.creator_id, None).is_err());
    check(creator::fixed_outputs(&f.details, f.creator_id, Some(&script)).is_err());
    let mut wrong_script = script.clone();
    wrong_script[0] ^= 1;
    check(
        creator::fixed_outputs(
            &with_script.details,
            with_script.creator_id,
            Some(&wrong_script),
        )
        .is_err(),
    );
    check(
        creator::fixed_outputs(
            &with_script.details,
            with_script.creator_id,
            Some(&vec![0; 32_769]),
        )
        .is_err(),
    );

    let pin = f.observation.pin();
    let references = [f.fixed[1].reference];
    check(checks::request(pin, &references, f.observation.policy()).is_ok());
    check(checks::request(pin, &[references[0]; 2], f.observation.policy()).is_err());
    check(checks::request(pin, &[], f.observation.policy()).is_err());
    let mut exact_pin = pin.clone();
    exact_pin.model = FundingModel::ExactHeadSnapshotV1;
    check(matches!(
        checks::request(&exact_pin, &references, f.observation.policy()),
        Err(CurrentFundingError::WrongFundingModel)
    ));
    let minimum = f.observation.policy.minimum_confirmations;
    for component in 0..3 {
        let mut actual = minimum;
        match component {
            0 => actual.chain -= 1,
            1 => actual.from_group -= 1,
            _ => actual.to_group -= 1,
        }
        check(checks::confirmations(actual, minimum).is_err());
        let mut policy = f.observation.policy.clone();
        policy.minimum_confirmations = ConfirmationCounts {
            chain: 1,
            from_group: 1,
            to_group: 1,
        };
        match component {
            0 => policy.minimum_confirmations.chain = 0,
            1 => policy.minimum_confirmations.from_group = 0,
            _ => policy.minimum_confirmations.to_group = 0,
        }
        check(checks::request(pin, &references, &policy).is_err());
    }
    check(checks::confirmations(minimum, minimum).is_ok());
    for component in 0..3 {
        let mut head = f.observation.before.header.clone();
        match component {
            0 => head.hash = B256::repeat_byte(88),
            1 => head.height += 1,
            _ => head.timestamp_ms += 1,
        }
        check(checks::head(pin, &head).is_err());
    }
    check(checks::head(pin, &f.observation.after.header).is_ok());
    let mut identity = f.observation.before.identity.clone();
    identity.chain_0_0_genesis.provenance = GenesisProvenance::DiagnosticObserved;
    check(checks::identity(pin, &identity, f.observation.policy()).is_err());
    identity = f.observation.before.identity.clone();
    identity.source_id = B256::repeat_byte(88);
    check(checks::identity(pin, &identity, f.observation.policy()).is_err());
    let owner = alephium_hash(&f.operation.spec().caller_public_key);
    let effective = &f.observation.outputs()[0];
    let provenance = &f.observation.provenance()[0];
    check(checks::latest(effective, &f.latest, provenance, owner, pin.timestamp_ms).is_ok());
    for mutation in 0..6 {
        let mut latest = UnanchoredUtxo {
            reference: f.latest.reference,
            amount: f.latest.amount,
            tokens: vec![],
            lock_time_ms: Some(0),
            additional_data: Some(vec![]),
        };
        match mutation {
            0 => latest.amount += U256::from(1),
            1 => latest.reference = f.fixed[0].reference,
            2 => latest.lock_time_ms = None,
            3 => latest.additional_data = None,
            4 => latest.additional_data = Some(vec![1]),
            _ => latest.tokens.push(TokenAmount {
                id: B256::repeat_byte(88),
                amount: U256::from(1),
            }),
        }
        check(checks::latest(effective, &latest, provenance, owner, pin.timestamp_ms).is_err());
    }
    check(
        checks::latest(
            effective,
            &f.latest,
            provenance,
            B256::repeat_byte(88),
            pin.timestamp_ms,
        )
        .is_err(),
    );
    check(validate_current_unsigned(&f.operation, &f.observation, &f.spend).is_ok());
    check(
        crate::alephium::validate_unsigned(&f.operation, &f.observation.funding, &f.spend).is_err(),
    );
    for mutation in 0..6 {
        let mut bad = fixture::build(None);
        match mutation {
            0 => bad.observation.funding.outputs[0].amount += U256::from(1),
            1 => bad.operation.spec.limits.max_fee -= U256::from(1),
            2 => bad.operation.spec.limits.contract_deposit = U256::from(1),
            3 => bad.observation.funding.outputs[0].locking_script[1] ^= 1,
            4 => bad.observation.funding.pin.model = FundingModel::ExactHeadSnapshotV1,
            _ => bad.operation.spec.funding.model = FundingModel::ExactHeadSnapshotV1,
        }
        check(validate_current_unsigned(&bad.operation, &bad.observation, &bad.spend).is_err());
    }
    let mut trailing = f.spend.clone();
    trailing.push(0);
    check(validate_current_unsigned(&f.operation, &f.observation, &trailing).is_err());
    count
        + policy_checks::run_checks()
        + context_checks::run_checks()
        + diagnostics::run_checks()
        + creator_profile::run_checks()
        + run_head_diagnostic_checks()
        + head_capability::run_checks()
        + lock_time::run_checks()
        + lock_binding::run_checks()
}
