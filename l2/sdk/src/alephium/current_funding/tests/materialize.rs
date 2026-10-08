//! One existing aggregate calls these offline materialization/subset checks.
//! Funding and headers are explicit fixtures, never real unspentness evidence.
use super::fixture;
use crate::alephium::{
    AlephiumValidationError as Error, FundingModel, LocalScriptApproval, MIN_CHANGE_AMOUNT,
    OperationSpec, alephium_hash, approve_operation,
    current_funding::{CurrentFundingError, materialize_current_unsigned},
};
use alloy_primitives::{B256, U256};

struct ScriptApproval<'a> {
    bytes: &'a [u8],
}
impl LocalScriptApproval for ScriptApproval<'_> {
    fn approved_script(&self, spec: &OperationSpec) -> Result<Option<Vec<u8>>, Error> {
        if spec.script_blake2b256 != Some(alephium_hash(self.bytes)) {
            return Err(Error::InvalidApproval);
        }
        Ok(Some(self.bytes.to_vec()))
    }
}

pub(super) fn run_checks(script: &[u8]) -> usize {
    let price = U256::from(100_000_000_000_u64);
    let fee = U256::from(10_000_000_000_000_000_u64);
    let mut count = 0;
    let mut check = |condition: bool| {
        assert!(
            condition,
            "Materializer aggregate failed; payload suppressed"
        );
        count += 1;
    };
    let f = fixture::build(None);
    let transfer =
        materialize_current_unsigned(&f.operation, &f.observation, 100_000, price).unwrap();
    // Literal compact thresholds from pinned v4.7.0 source: gas100000, price1e11,
    // change2ALPH-0.01ALPH=1.99ALPH. This does not use codec/compact encoders.
    let golden = source_vector(&f.operation, &f.observation, None, "c41b9de674df070000");
    check(transfer.unsigned_bytes() == golden);
    check(transfer.unsigned_bytes() == f.spend); // retained regression, not independent golden
    check(transfer.fixed_output_count() == 1 && transfer.fee() == fee);
    check(transfer.input_refs() == [f.observation.outputs()[0].reference]);
    let mut spec = f.operation.spec().clone();
    spec.script_blake2b256 = Some(alephium_hash(script));
    spec.limits.contract_deposit = U256::from(100_000_000_000_000_000_u64);
    spec.limits.max_total_debit = fee + spec.limits.contract_deposit;
    let operation = approve_operation(spec.clone(), &ScriptApproval { bytes: script }).unwrap();
    let deployed =
        materialize_current_unsigned(&operation, &f.observation, 100_000, price).unwrap();
    let golden = source_vector(
        &operation,
        &f.observation,
        Some(script),
        "c41a3aa0fc817d0000",
    );
    check(deployed.unsigned_bytes() == golden); // 2ALPH - fee0.01 - deposit0.1 = 1.89
    check(
        deployed.fixed_output_count() == 1
            && deployed.change() + fee + spec.limits.contract_deposit == deployed.input_amount(),
    );
    let mut invalid_approval = spec.clone();
    invalid_approval.script_blake2b256 = Some(B256::repeat_byte(19));
    check(approve_operation(invalid_approval, &ScriptApproval { bytes: script }).is_err());
    for gas in [19_999, 100_001, 5_000_001] {
        check(matches!(
            materialize_current_unsigned(&operation, &f.observation, gas, price),
            Err(Error::FeeExceeded)
        ));
    }
    for gas_price in [price - U256::from(1), price + U256::from(1), U256::MAX] {
        check(matches!(
            materialize_current_unsigned(&operation, &f.observation, 100_000, gas_price),
            Err(Error::FeeExceeded)
        ));
    }
    let mut narrow = spec.clone();
    narrow.limits.max_fee = fee - U256::from(1);
    let narrow = approve_operation(narrow, &ScriptApproval { bytes: script }).unwrap();
    check(matches!(
        materialize_current_unsigned(&narrow, &f.observation, 100_000, price),
        Err(Error::FeeExceeded)
    ));
    let mut narrow = spec.clone();
    narrow.limits.max_total_debit -= U256::from(1);
    let narrow = approve_operation(narrow, &ScriptApproval { bytes: script }).unwrap();
    check(matches!(
        materialize_current_unsigned(&narrow, &f.observation, 100_000, price),
        Err(Error::FeeExceeded)
    ));
    let mut overflow = spec.clone();
    overflow.limits.contract_deposit = U256::MAX;
    overflow.limits.max_total_debit = U256::MAX;
    let overflow = approve_operation(overflow, &ScriptApproval { bytes: script }).unwrap();
    check(matches!(
        materialize_current_unsigned(&overflow, &f.observation, 100_000, price),
        Err(Error::Overflow)
    ));
    let mut changed = operation.clone();
    changed.spec.funding.model = FundingModel::ExactHeadSnapshotV1;
    check(matches!(
        materialize_current_unsigned(&changed, &f.observation, 100_000, price),
        Err(Error::UnsupportedProfile)
    ));
    let mut changed = operation.clone();
    changed.spec.funding.head_hash = B256::repeat_byte(25);
    check(matches!(
        materialize_current_unsigned(&changed, &f.observation, 100_000, price),
        Err(Error::FundingMismatch)
    ));
    for mutation in 0..6 {
        let mut f = fixture::build(None);
        let fixed = &mut f.observation.funding.outputs[0];
        match mutation {
            0 => fixed.lock_time_ms = f.operation.spec().funding.timestamp_ms + 1,
            1 => fixed.tokens.push((B256::repeat_byte(1), U256::from(1))),
            2 => fixed.additional_data.push(0),
            3 => fixed.locking_script[1] ^= 1,
            4 => fixed.reference.hint ^= 1,
            _ => fixed.amount = U256::ZERO,
        }
        check(materialize_current_unsigned(&f.operation, &f.observation, 100_000, price).is_err());
    }
    for available in [
        fee - U256::from(1),
        fee,
        fee + U256::from(MIN_CHANGE_AMOUNT) - U256::from(1),
    ] {
        let mut f = fixture::build(None);
        f.observation.funding.outputs[0].amount = available;
        check(matches!(
            materialize_current_unsigned(&f.operation, &f.observation, 100_000, price),
            Err(Error::AmountMismatch)
        ));
    }
    let mut exhausted = fixture::build(None);
    exhausted.observation.funding.outputs[0].amount = fee + spec.limits.contract_deposit;
    check(matches!(
        materialize_current_unsigned(&operation, &exhausted.observation, 100_000, price),
        Err(Error::AmountMismatch)
    ));
    let mut duplicate = fixture::build(None);
    duplicate
        .observation
        .funding
        .outputs
        .push(duplicate.observation.funding.outputs[0].clone());
    check(matches!(
        materialize_current_unsigned(&duplicate.operation, &duplicate.observation, 100_000, price),
        Err(Error::OwnershipMismatch)
    ));
    let mut sum = fixture::build(None);
    sum.observation.funding.outputs[0].amount = U256::MAX;
    let mut second = sum.observation.funding.outputs[0].clone();
    second.amount = U256::from(1);
    second.reference.key = B256::repeat_byte(27);
    sum.observation.funding.outputs.push(second);
    check(matches!(
        materialize_current_unsigned(&sum.operation, &sum.observation, 100_000, price),
        Err(Error::Overflow)
    ));
    subsets(&mut check, price);
    count
}

fn source_vector(
    op: &crate::alephium::ApprovedOperation,
    observed: &crate::alephium::current_funding::CurrentFixedFundingObservation,
    script: Option<&[u8]>,
    encoded_change: &str,
) -> Vec<u8> {
    let mut raw = vec![0, 1, u8::from(script.is_some())];
    if let Some(script) = script {
        raw.extend_from_slice(script);
    }
    raw.extend_from_slice(&hex::decode("800186a0c1174876e80001").unwrap());
    let reference = observed.outputs()[0].reference;
    raw.extend_from_slice(&reference.hint.to_be_bytes());
    raw.extend_from_slice(reference.key.as_slice());
    raw.push(0);
    raw.extend_from_slice(&op.spec().caller_public_key);
    raw.push(1);
    raw.extend_from_slice(&hex::decode(encoded_change).unwrap());
    raw.push(0);
    raw.extend_from_slice(crate::alephium::alephium_hash(&op.spec().caller_public_key).as_slice());
    raw.extend_from_slice(&[0; 10]);
    raw
}

fn subsets(check: &mut impl FnMut(bool), price: U256) {
    let mut f = fixture::build(None);
    // Both records already exist in the same simulated authenticated creator.
    let mut other = f.fixed[0].clone();
    let mut proof = f.observation.provenance[0].clone();
    proof.reference = other.reference;
    proof.fixed_output_index = 0;
    proof.committed_lock_time_ms = other.lock_time_ms;
    proof.effective_lock_time_ms = other.lock_time_ms.max(proof.creator_block_timestamp_ms);
    other.lock_time_ms = proof.effective_lock_time_ms;
    f.observation.funding.outputs.push(other.clone());
    f.observation.provenance.push(proof);
    let references = [f.observation.outputs()[0].reference, other.reference];
    let one = f.observation.select_references(&references[..1]).unwrap();
    let two = f.observation.select_references(&references[1..]).unwrap();
    check(one.outputs()[0].reference != two.outputs()[0].reference);
    check(
        one.pin() == f.observation.pin()
            && two.pin() == one.pin()
            && one.head_before().header == f.observation.head_before().header
            && one.head_after().header == f.observation.head_after().header
            && one.policy() == f.observation.policy(),
    );
    check(
        one.provenance()[0].reference == references[0]
            && two.provenance()[0].reference == references[1],
    );
    check(one.select_references(&references[1..]).is_err());
    check(matches!(
        f.observation.select_references(&[]),
        Err(CurrentFundingError::Bounds)
    ));
    check(
        f.observation
            .select_references(&[references[0], references[0]])
            .is_err(),
    );
    let mut unknown = references[0];
    unknown.key = B256::repeat_byte(31);
    check(f.observation.select_references(&[unknown]).is_err());
    let reordered = f
        .observation
        .select_references(&[references[1], references[0]])
        .unwrap();
    check(
        reordered.outputs()[0].reference == references[1]
            && reordered.provenance()[0].reference == references[1],
    );
    let both = materialize_current_unsigned(&f.operation, &reordered, 100_000, price).unwrap();
    check(both.input_refs() == [references[1], references[0]] && both.fixed_output_count() == 1);

    // A subset preserves the original window evidence; it cannot renew it.
    let before = f.observation.before.header.clone();
    let mut after = before.clone();
    after.hash = B256::repeat_byte(30);
    after.height += 1;
    after.timestamp_ms += 1;
    after.dependencies[3] = before.hash;
    f.observation.after.header = after.clone();
    f.observation.funding.pin.head_hash = after.hash;
    f.observation.funding.pin.head_height = after.height;
    f.observation.funding.pin.timestamp_ms = after.timestamp_ms;
    f.observation.current_window = true;
    f.observation.head_lineage = vec![before, after];
    let one = f.observation.select_references(&references[..1]).unwrap();
    let two = f.observation.select_references(&references[1..]).unwrap();
    check(
        [&one, &two].iter().all(|subset| {
            subset.is_current_window()
                && subset.head_advance() == 1
                && subset.head_lineage() == f.observation.head_lineage()
                && subset.head_before().header == f.observation.head_before().header
                && subset.head_after().header == f.observation.head_after().header
                && subset.pin() == f.observation.pin()
                && subset.policy() == f.observation.policy()
        }) && one.outputs()[0].reference.key != two.outputs()[0].reference.key,
    );
}
