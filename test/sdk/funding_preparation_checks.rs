//! One pure aggregate: source-derived wire vectors and simulated sealed inputs.
use super::*;
use crate::alephium::{
    OutputRef,
    current_funding::tests::{funding_preparation_fixture, funding_preparation_invalid_fixture},
};
use std::collections::BTreeSet;

const INPUT_AMOUNT: u64 = 2_000_000_000_000_000_000;
const FEE: u64 = 10_000_000_000_000_000;
const QUARTER: u64 = 497_500_000_000_000_000;

fn spec(key: [u8; 33], selected: &CurrentFixedFundingObservation) -> FundingPreparationSpec {
    FundingPreparationSpec {
        purpose_id: B256::repeat_byte(41),
        operator_source: B256::repeat_byte(42),
        caller_public_key: key,
        network_genesis_id: selected.pin().network_genesis_id,
        funding_source_id: selected.pin().source_id,
        gas_amount: 100_000,
        gas_price: U256::from(100_000_000_000u64),
    }
}

/// Pinned v4.7 CompactInteger rules, written without the production encoder.
/// 100000 => 800186a0, 1e11 => c1174876e800; counts1/4 are single bytes.
fn golden(spec: &FundingPreparationSpec, input: OutputRef, amounts: [&[u8]; 4]) -> Vec<u8> {
    let mut raw = hex::decode("000100800186a0c1174876e80001").unwrap();
    raw.extend_from_slice(&input.hint.to_be_bytes());
    raw.extend_from_slice(input.key.as_slice());
    raw.push(0);
    raw.extend_from_slice(&spec.caller_public_key);
    raw.push(4);
    let owner = alephium_hash(&spec.caller_public_key);
    for amount in amounts {
        raw.extend_from_slice(amount);
        raw.push(0);
        raw.extend_from_slice(owner.as_slice());
        raw.extend_from_slice(&[0; 10]); // LockTime8, empty tokens and data.
    }
    raw
}

pub(crate) fn run_checks() -> usize {
    let (key, selected) = funding_preparation_fixture();
    let spec = spec(key, &selected);
    let input = selected.outputs()[0].reference;
    // (2 ALPH - .01 ALPH) / 4 = .4975 ALPH, eight-byte unsigned payload.
    let quarter = hex::decode("c406e7799d37c1c000").unwrap();
    let raw = golden(&spec, input, [&quarter; 4]);
    let mut count = 0;
    let mut check = |condition: bool| {
        assert!(
            condition,
            "Funding preparation check failed; payload suppressed"
        );
        count += 1;
    };
    check(raw.len() == 293 && selected.outputs()[0].amount == U256::from(INPUT_AMOUNT));
    let prepared = prepare_funding_split(&spec, &selected).unwrap();
    check(prepared.unsigned_bytes() == raw.as_slice());
    check(prepared.tx_id() == alephium_hash(&raw));
    check(prepared.input_ref() == input && prepared.input_refs() == [input]);
    check(prepared.input_amount() == U256::from(INPUT_AMOUNT) && prepared.fee() == U256::from(FEE));
    check(
        prepared.pin() == selected.pin()
            && prepared.spec().purpose_id == spec.purpose_id
            && prepared.spec().operator_source == spec.operator_source
            && prepared.spec().caller_public_key == key
            && prepared.spec().network_genesis_id == spec.network_genesis_id
            && prepared.spec().funding_source_id == spec.funding_source_id
            && prepared.spec().gas_amount == spec.gas_amount
            && prepared.spec().gas_price == spec.gas_price,
    );
    let owner = alephium_hash(&key);
    let mut keys = BTreeSet::new();
    for (index, output) in prepared.outputs().iter().enumerate() {
        let mut preimage = prepared.tx_id().as_slice().to_vec();
        preimage.extend_from_slice(&(index as u32).to_be_bytes());
        check(
            output.index() == index as u32
                && output.amount() == U256::from(QUARTER)
                && output.owner_hash() == owner
                && output.reference().hint == input.hint
                && output.reference().key == alephium_hash(&preimage)
                && keys.insert(output.reference().key),
        );
    }
    let decoded = validate_funding_split(&spec, &selected, &raw).unwrap();
    check(
        decoded.unsigned_bytes() == raw.as_slice()
            && decoded.tx_id() == prepared.tx_id()
            && decoded.outputs() == prepared.outputs(),
    );
    let inspected =
        inspect_funding_preparation_wire(&spec, &raw, input, U256::from(INPUT_AMOUNT)).unwrap();
    check(
        inspected.tx_id() == prepared.tx_id()
            && inspected.input_ref() == input
            && inspected.input_refs() == [input]
            && inspected.input_amount() == prepared.input_amount()
            && inspected.fee() == prepared.fee()
            && inspected.outputs() == prepared.outputs(),
    );

    // Header, exact fees, input ownership/reference, every output and closed fields.
    for offset in [
        0, 1, 2, 6, 12, 13, 14, 18, 50, 51, 84, 93, 94, 95, 134, 135, 136, 145, 197, 249,
    ] {
        let mut changed = raw.clone();
        changed[offset] ^= 1;
        check(validate_funding_split(&spec, &selected, &changed).is_err());
    }
    for (offset, value) in [(50, 3), (50, 2), (84, 3), (94, 2)] {
        let mut changed = raw.clone();
        changed[offset] = value;
        check(validate_funding_split(&spec, &selected, &changed).is_err());
    }
    // Both compact modes decode the value, but only the shortest form is allowed.
    for (offset, width, replacement) in [
        (3, 4, hex::decode("c0000186a0").unwrap()),
        (13, 1, hex::decode("4001").unwrap()),
        (84, 1, hex::decode("4004").unwrap()),
        (85, 9, hex::decode("c50006e7799d37c1c000").unwrap()),
    ] {
        let mut changed = raw.clone();
        drop(changed.splice(offset..offset + width, replacement));
        check(validate_funding_split(&spec, &selected, &changed).is_err());
    }
    let mut trailing = raw.clone();
    trailing.push(0);
    check(validate_funding_split(&spec, &selected, &trailing).is_err());
    check(
        validate_funding_split(&spec, &selected, &[0; FUNDING_PREPARATION_MAX_BYTES + 1]).is_err(),
    );
    // Sample every structural boundary and partial fixed-width field, in one job.
    for end in [
        0, 1, 2, 3, 6, 7, 12, 13, 14, 17, 18, 49, 50, 51, 83, 84, 85, 93, 94, 95, 126, 127, 134,
        135, 136, 137, 188, 240, 292,
    ] {
        check(validate_funding_split(&spec, &selected, &raw[..end]).is_err());
    }

    // Data-only inspection cannot mint a current-funding or signing capability.
    for remainder in 1..=3u64 {
        let mut last = quarter.clone();
        last[8] = remainder as u8;
        let changed = golden(&spec, input, [&quarter, &quarter, &quarter, &last]);
        let inspected = inspect_funding_preparation_wire(
            &spec,
            &changed,
            input,
            U256::from(INPUT_AMOUNT + remainder),
        )
        .unwrap();
        check(
            inspected.outputs()[..3]
                .iter()
                .all(|output| output.amount() == U256::from(QUARTER))
                && inspected.outputs()[3].amount() == U256::from(QUARTER + remainder)
                && inspected.fee() == U256::from(FEE)
                && inspected.input_amount() == U256::from(INPUT_AMOUNT + remainder),
        );
        check(
            inspect_funding_preparation_wire(
                &spec,
                &raw,
                input,
                U256::from(INPUT_AMOUNT + remainder),
            )
            .is_err(),
        );
    }
    // 1e15 (dust) is seven unsigned payload bytes; fee + four dust outputs fits.
    let dust_bytes = hex::decode("c3038d7ea4c68000").unwrap();
    let dust_raw = golden(&spec, input, [&dust_bytes; 4]);
    let dust_input = U256::from(FEE) + U256::from(MIN_CHANGE_AMOUNT) * U256::from(4);
    let dust = inspect_funding_preparation_wire(&spec, &dust_raw, input, dust_input).unwrap();
    check(
        dust.outputs()
            .iter()
            .all(|output| output.amount() == U256::from(MIN_CHANGE_AMOUNT))
            && dust.fee() == U256::from(FEE),
    );
    for amount in [
        U256::ZERO,
        U256::from(FEE - 1),
        U256::from(FEE),
        dust_input - U256::from(1),
        U256::from(MAX_ALPH_VALUE),
        U256::MAX,
    ] {
        let expected = if amount.is_zero() || amount >= U256::from(MAX_ALPH_VALUE) {
            FundingPreparationError::Bounds
        } else {
            FundingPreparationError::InsufficientAmount
        };
        check(inspect_funding_preparation_wire(&spec, &raw, input, amount).err() == Some(expected));
    }
    let mut wrong_input = input;
    wrong_input.key = B256::repeat_byte(99);
    check(
        inspect_funding_preparation_wire(&spec, &raw, wrong_input, U256::from(INPUT_AMOUNT))
            .is_err(),
    );
    wrong_input = input;
    wrong_input.hint ^= 1;
    check(
        inspect_funding_preparation_wire(&spec, &raw, wrong_input, U256::from(INPUT_AMOUNT))
            .is_err(),
    );

    for mutation in 0..10 {
        let mut changed = spec.clone();
        match mutation {
            0 => changed.purpose_id = B256::ZERO,
            1 => changed.operator_source = B256::ZERO,
            2 => changed.network_genesis_id = B256::ZERO,
            3 => changed.funding_source_id = B256::ZERO,
            4 => changed.network_genesis_id = B256::repeat_byte(99),
            5 => changed.funding_source_id = B256::repeat_byte(99),
            6 => changed.caller_public_key = [0; 33],
            7 => changed.caller_public_key[0] = 4,
            8 => changed.gas_amount += 1,
            _ => changed.gas_price += U256::from(1),
        }
        check(prepare_funding_split(&changed, &selected).is_err());
        check(validate_funding_split(&changed, &selected, &raw).is_err());
    }
    // Only the cfg(test) bridge creates these deliberately inconsistent facts.
    // Empty/multiple inputs, future maturity, pin/source/head and asset tampering.
    for case in 0..14 {
        let (_, altered) = funding_preparation_invalid_fixture(case);
        if case == 2 {
            check(
                prepare_funding_split(&spec, &altered).err()
                    == Some(FundingPreparationError::ImmatureInput),
            );
            check(
                validate_funding_split(&spec, &altered, &raw).err()
                    == Some(FundingPreparationError::ImmatureInput),
            );
        } else {
            check(prepare_funding_split(&spec, &altered).is_err());
            check(validate_funding_split(&spec, &altered, &raw).is_err());
        }
    }
    // Wrapper refusals only; no signing or rerun of the existing ECDSA vectors.
    for invalid in [
        Vec::new(),
        vec![0; 63],
        vec![0; 64],
        vec![0; 65],
        vec![255; 64],
    ] {
        check(verify_funding_preparation_signature(&prepared, &invalid).is_err());
        check(
            verify_funding_preparation_signature_wire(
                &spec,
                &raw,
                input,
                U256::from(INPUT_AMOUNT),
                &invalid,
            )
            .is_err(),
        );
    }
    count
}
