//! One root-coordinated aggregate hook. All correlation here is simulated.
use super::*;
use crate::alephium::alephium_hash;
use alloy_primitives::B256;
use serde_json::json;
#[path = "execution_fixture.rs"]
mod fixture;

pub(crate) fn run_checks() -> usize {
    let mut count = 0;
    let mut check = |ok: bool| {
        assert!(ok, "Executed evidence aggregate failed; payload suppressed");
        count += 1;
    };
    let (observed, raw) = fixture::build();
    let evidence = decode_executed_transaction(&observed, &raw).unwrap();
    check(
        evidence.transaction_id() == alephium_hash(&raw)
            && evidence.script_bytes() == fixture::SCRIPT
            && evidence.script_hash() == alephium_hash(fixture::SCRIPT),
    );
    check(
        evidence.outcome() == ExecutedOutcome::Succeeded
            && evidence.fixed_output_count() == 1
            && evidence.contract_inputs().is_empty()
            && evidence.generated_outputs().len() == 2,
    );
    let contract = &evidence.generated_outputs()[0];
    let asset = &evidence.generated_outputs()[1];
    check(
        contract.global_index() == 1
            && contract.reference().key == fixture::output_key(evidence.transaction_id(), 1)
            && contract.lock_time_ms().is_none()
            && contract.additional_data().is_none()
            && contract.group() == 0,
    );
    check(
        asset.global_index() == 2
            && asset.lock_time_ms() == Some(0)
            && asset.additional_data() == Some(&[][..]),
    );
    check(
        evidence.inclusion().block_hash == evidence.header().hash
            && evidence.identity().network_id == 1,
    );
    if let ExecutedOutputAddress::Contract(address) = contract.address() {
        let mut creation_id = fixture::output_key(evidence.transaction_id(), 1).0;
        creation_id[31] = 0;
        check(address.id() == B256::from(creation_id));
    } else {
        check(false);
    }

    let (mut failed, raw) = fixture::build();
    let (inclusion, header) = match &failed.observation.outcome {
        TransactionOutcome::ScriptSucceeded { inclusion, header } => {
            (inclusion.clone(), header.clone())
        }
        _ => unreachable!(),
    };
    failed.observation.outcome = TransactionOutcome::ScriptFailed { inclusion, header };
    failed.retained_details.as_mut().unwrap()["scriptExecutionOk"] = json!(false);
    check(
        decode_executed_transaction(&failed, &raw)
            .unwrap()
            .outcome()
            == ExecutedOutcome::Failed,
    );

    let (init, raw) = fixture::mutate(|details| {
        // Existing contract update: its CID is not derived from this new txId.
        let mut cid = [42_u8; 32];
        cid[31] = 0;
        let address = ContractAddress::from_id(B256::from(cid)).unwrap();
        details["contractInputs"] = json!([{"hint":(crate::alephium::codec::owner_hint(address.id()) & !1) as i32,
            "key":hex::encode([44;32])}]);
        details["generatedOutputs"][0]["address"] = json!(address.as_str());
        details["generatedOutputs"][0]["hint"] =
            json!((crate::alephium::codec::owner_hint(address.id()) & !1) as i32);
    });
    let init = decode_executed_transaction(&init, &raw).unwrap();
    check(
        init.contract_inputs()[0].key == B256::repeat_byte(44)
            && init.generated_outputs()[0].reference().key
                == fixture::output_key(init.transaction_id(), 1),
    );
    let (missing_effect, raw) = fixture::mutate(|details| details["generatedOutputs"] = json!([]));
    check(
        decode_executed_transaction(&missing_effect, &raw)
            .unwrap()
            .generated_outputs()
            .is_empty(),
    );
    // Empty effects are data, not a successful deployment predicate.
    let (token, raw) = fixture::mutate(|details| {
        details["generatedOutputs"][0]["tokens"] = json!([{"id":hex::encode([5;32]),"amount":"1"}])
    });
    check(
        decode_executed_transaction(&token, &raw)
            .unwrap()
            .generated_outputs()[0]
            .tokens()
            .len()
            == 1,
    );

    for mutation in 0..24 {
        let (mut observed, mut raw) = fixture::build();
        let details = observed.retained_details.as_mut().unwrap();
        match mutation {
            0 => details["unsigned"]["gasAmount"] = json!(100001),
            1 => details["unsigned"]["scriptOpt"] = json!("0100"),
            2 => details["unsigned"]["scriptOpt"] = json!(null),
            3 => {
                details["unsigned"]["fixedOutputs"][0]["attoAlphAmount"] =
                    json!("2000000000000000001")
            }
            4 => details["unsigned"]["unexpected"] = json!(0),
            5 => details["generatedOutputs"][0]["key"] = json!(hex::encode([0; 32])),
            6 => details["generatedOutputs"][0]["hint"] = json!(1),
            7 => details["generatedOutputs"][0]["type"] = json!("UnknownOutput"),
            8 => details["generatedOutputs"][0]["lockTime"] = json!(0),
            9 => details["generatedOutputs"][1]
                .as_object_mut()
                .unwrap()
                .remove("lockTime")
                .map(|_| ())
                .unwrap(),
            10 => details["generatedOutputs"][1]["lockTime"] = json!(null),
            11 => details["generatedOutputs"][1]["lockTime"] = json!(i64::MAX as u64 + 1),
            12 => details["generatedOutputs"][0]["attoAlphAmount"] = json!("00"),
            13 => {
                details["generatedOutputs"][0]["tokens"] =
                    json!([{"id":hex::encode([5;32]),"amount":"0"}])
            }
            14 => details["contractInputs"] = json!([{"hint":1,"key":hex::encode([44;32])}]),
            15 => {
                details["contractInputs"] = json!([{"hint":2,"key":hex::encode([44;32])},{"hint":2,"key":hex::encode([44;32])}])
            }
            16 => details["scriptExecutionOk"] = json!(false),
            17 => details["inputSignatures"] = json!([]),
            18 => details["scriptSignatures"] = json!(["00".repeat(64)]),
            19 => details["unexpected"] = json!(0),
            20 => observed.observation.identity.network_id = 0,
            21 => observed.observation.transaction_id = B256::repeat_byte(99),
            22 => raw.push(0),
            _ => raw[0] = 1,
        }
        check(decode_executed_transaction(&observed, &raw).is_err());
    }
    let (pending, raw) = fixture::build();
    for outcome in [
        TransactionOutcome::MemPooled,
        TransactionOutcome::TxNotFound,
    ] {
        let observed = TransactionDetailsObservation {
            observation: TransactionObservation {
                identity: pending.observation.identity.clone(),
                transaction_id: pending.observation.transaction_id,
                outcome,
            },
            retained_details: None,
        };
        check(
            decode_executed_transaction(&observed, &raw).err()
                == Some(ExecutedTransactionError::Unconfirmed),
        );
    }
    let (bounded, _) = fixture::build();
    check(decode_executed_transaction(&bounded, &[]).is_err());
    check(
        decode_executed_transaction(&bounded, &vec![0; crate::alephium::MAX_UNSIGNED_BYTES + 1])
            .is_err(),
    );
    let (oversized, raw) = fixture::mutate(|details| {
        let output = details["generatedOutputs"][0].clone();
        details["generatedOutputs"] = json!(vec![output; 65]);
    });
    check(decode_executed_transaction(&oversized, &raw).is_err());
    let (bad_header, raw) = fixture::build();
    let mut bad_header = bad_header;
    if let TransactionOutcome::ScriptSucceeded { header, .. } = &mut bad_header.observation.outcome
    {
        header.hash = B256::repeat_byte(99);
    }
    check(
        decode_executed_transaction(&bad_header, &raw).err()
            == Some(ExecutedTransactionError::Inclusion),
    );
    count
}
