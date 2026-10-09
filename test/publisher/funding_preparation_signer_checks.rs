//! One pure aggregate with a synthetic key and DATA-only native wire facts.
//! This test bridge never mints a production SDK capability or opens root env.
use super::*;
use crate::funding_preparation::{
    FundingPreparationImmutable, FundingPreparationInclusion,
    FundingPreparationOutput as StoredOutput, FundingPreparationReference,
};
use alephium_l2_sdk::alephium::funding_preparation::{
    inspect_funding_preparation_wire, verify_funding_preparation_signature_wire,
};

fn identity() -> (SecretKey, [u8; 33], String) {
    for value in 1..=128_u8 {
        let mut bytes = [0; 32];
        bytes[31] = value;
        let key = SecretKey::from_byte_array(bytes).unwrap();
        let public = PublicKey::from_secret_key(&Secp256k1::signing_only(), &key).serialize();
        let owner = publisher_address_from_public_key(&public).unwrap();
        if owner.group() == 0 {
            return (key, public, owner.as_str().to_owned());
        }
    }
    panic!("Synthetic group-zero identity unavailable");
}

fn env(key: &SecretKey, public: [u8; 33], address: &str, enabled: u8) -> String {
    format!(
        "L2_P5_PUBLISHER_PRIVATE_KEY={}\nL2_P5_PUBLISHER_PUBLIC_KEY={}\nL2_P5_PUBLISHER_ADDRESS={address}\nL2_P5_L1_NETWORK_ID=1\nL2_P5_L1_GROUP=0\nALEPHIUM_NETWORK_ID=1\nL2_P5_LIVE_SIGNING_ENABLED={enabled}\nWALLET_1_PRIVATE_KEY=ignored_generic_wallet\n",
        hex::encode(key.secret_bytes()),
        hex::encode(public),
    )
}

fn wire(spec: &FundingPreparationSpec, input: OutputRef) -> Vec<u8> {
    // Source-derived v4.7 native integer vector: gas100000, price1e11,
    // one input and four .4975ALPH self outputs from 2ALPH minus .01ALPH.
    let mut raw = hex::decode("000100800186a0c1174876e80001").unwrap();
    raw.extend_from_slice(&input.hint.to_be_bytes());
    raw.extend_from_slice(input.key.as_slice());
    raw.push(0);
    raw.extend_from_slice(&spec.caller_public_key);
    raw.push(4);
    for _ in 0..4 {
        raw.extend_from_slice(&hex::decode("c406e7799d37c1c00000").unwrap());
        raw.extend_from_slice(alephium_hash(&spec.caller_public_key).as_slice());
        raw.extend_from_slice(&[0; 10]);
    }
    raw
}

pub(super) fn run_checks() -> usize {
    let (mut key, public, address) = identity();
    let spec = FundingPreparationSpec {
        purpose_id: B256::repeat_byte(41),
        operator_source: B256::repeat_byte(42),
        caller_public_key: public,
        network_genesis_id: B256::repeat_byte(43),
        funding_source_id: B256::repeat_byte(44),
        gas_amount: FUNDING_PREPARATION_GAS,
        gas_price: U256::from(FUNDING_PREPARATION_GAS_PRICE),
    };
    let owner = alephium_hash(&public);
    let hint = owner.as_slice().iter().fold(5381_u32, |hash, byte| {
        hash.wrapping_mul(33).wrapping_add(u32::from(*byte))
    }) | 1;
    let input = OutputRef {
        hint,
        key: B256::repeat_byte(45),
    };
    let raw = wire(&spec, input);
    let amount = U256::from(2_000_000_000_000_000_000_u64);
    let inspected = inspect_funding_preparation_wire(&spec, &raw, input, amount).unwrap();
    let pin = FundingPin {
        model: FundingModel::CanonicalFixedCurrentV1,
        source_id: spec.funding_source_id,
        network_id: 1,
        network_genesis_id: spec.network_genesis_id,
        group: 0,
        group_count: 4,
        head_hash: B256::repeat_byte(46),
        head_height: 10,
        timestamp_ms: 1000,
    };
    let facts = NativeFacts {
        spec: &spec,
        pin: &pin,
        raw: &raw,
        transaction_id: inspected.tx_id(),
        inputs: inspected.input_refs(),
        input_amount: inspected.input_amount(),
        fee: inspected.fee(),
        outputs: inspected.outputs(),
    };
    let record = FundingPreparationRecord {
        schema: 1,
        revision: 2,
        immutable: FundingPreparationImmutable {
            purpose_id: spec.purpose_id,
            operator_source: spec.operator_source,
            network: 1,
            network_genesis_id: spec.network_genesis_id,
            funding_source_id: spec.funding_source_id,
            caller_public_key: public.to_vec(),
            input_refs: vec![FundingPreparationReference::capture(input)],
            input_amount: amount,
            unsigned: raw.clone(),
            transaction_id: inspected.tx_id(),
            gas_amount: spec.gas_amount,
            gas_price: spec.gas_price,
            fee: inspected.fee(),
            outputs: inspected
                .outputs()
                .iter()
                .map(|output| StoredOutput {
                    index: output.index(),
                    reference: FundingPreparationReference::capture(output.reference()),
                    amount: output.amount(),
                    owner_hash: output.owner_hash(),
                    lock_time_ms: 0,
                })
                .collect(),
            minimum_confirmations: [6; 3],
        },
        phase: FundingPreparationPhase::SignAttempted,
        sign_attempts: 1,
        submit_attempts: 0,
        signature: None,
        inclusion: None,
    };
    let text = env(&key, public, &address, 1);
    let mut count = 0;
    let mut check = |condition: bool| {
        assert!(
            condition,
            "Funding signer aggregate failed; private values suppressed"
        );
        count += 1;
    };
    for (configuration, explicit) in [
        (env(&key, public, &address, 0), true),
        (text.clone(), false),
    ] {
        let mut disabled =
            FundingPreparationSigner::from_text(&configuration, spec.clone(), explicit).unwrap();
        check(!disabled.enabled());
        check(
            disabled.sign_facts(&record, &facts).err()
                == Some(FundingPreparationSignerError::Disabled),
        );
    }
    let mut signer = FundingPreparationSigner::from_text(&text, spec.clone(), true).unwrap();
    check(signer.enabled() && signer.matches(&record, &facts));
    for case in 0..31 {
        let mut changed = record.clone();
        let identity = &mut changed.immutable;
        match case {
            0 => changed.schema = 2,
            1 => changed.revision = 1,
            2 => changed.phase = FundingPreparationPhase::Planned,
            3 => changed.sign_attempts = 0,
            4 => changed.sign_attempts = 2,
            5 => changed.submit_attempts = 1,
            6 => changed.signature = Some(vec![0; 64]),
            7 => {
                changed.inclusion = Some(FundingPreparationInclusion {
                    transaction_id: inspected.tx_id(),
                    block_hash: B256::repeat_byte(50),
                    height: 1,
                    canonical_head: pin.head_hash,
                    observed_at_ms: 1000,
                    confirmations: [6; 3],
                })
            }
            8 => identity.minimum_confirmations = [5; 3],
            9 => identity.network = 0,
            10 => identity.purpose_id = B256::repeat_byte(99),
            11 => identity.operator_source = B256::repeat_byte(99),
            12 => identity.caller_public_key[1] ^= 1,
            13 => identity.network_genesis_id = B256::repeat_byte(99),
            14 => identity.funding_source_id = B256::repeat_byte(99),
            15 => identity.input_refs[0].hint ^= 1,
            16 => identity.input_refs[0].key = B256::repeat_byte(99),
            17 => identity.input_refs.clear(),
            18 => identity.input_amount += U256::from(1),
            19 => identity.unsigned[0] ^= 1,
            20 => identity.transaction_id = B256::repeat_byte(99),
            21 => identity.gas_amount += 1,
            22 => identity.gas_price += U256::from(1),
            23 => identity.fee += U256::from(1),
            24 => identity.outputs.pop().map(|_| ()).unwrap(),
            25 => identity.outputs[0].index += 1,
            26 => identity.outputs[0].reference.hint ^= 1,
            27 => identity.outputs[0].reference.key = B256::repeat_byte(99),
            28 => identity.outputs[0].amount += U256::from(1),
            29 => identity.outputs[0].owner_hash = B256::repeat_byte(99),
            _ => identity.outputs[0].lock_time_ms = 1,
        }
        check(
            signer.sign_facts(&changed, &facts).err()
                == Some(FundingPreparationSignerError::RecordMismatch),
        );
    }
    for case in 0..4 {
        let mut expected = spec.clone();
        match case {
            0 => expected.purpose_id = B256::repeat_byte(99),
            1 => expected.operator_source = B256::repeat_byte(99),
            2 => expected.network_genesis_id = B256::repeat_byte(99),
            _ => expected.funding_source_id = B256::repeat_byte(99),
        }
        let mut changed = FundingPreparationSigner::from_text(&text, expected, true).unwrap();
        check(
            changed.sign_facts(&record, &facts).err()
                == Some(FundingPreparationSignerError::RecordMismatch),
        );
    }
    for case in 0..7 {
        let mut wrong_pin = pin.clone();
        match case {
            0 => wrong_pin.model = FundingModel::ExactHeadSnapshotV1,
            1 => wrong_pin.network_id = 0,
            2 => wrong_pin.group = 1,
            3 => wrong_pin.group_count = 8,
            4 => wrong_pin.network_genesis_id = B256::repeat_byte(99),
            5 => wrong_pin.source_id = B256::repeat_byte(99),
            _ => wrong_pin.head_hash = B256::ZERO,
        }
        let changed = NativeFacts {
            pin: &wrong_pin,
            ..facts
        };
        check(
            signer.sign_facts(&record, &changed).err()
                == Some(FundingPreparationSignerError::RecordMismatch),
        );
    }
    for bad in [
        text.replace("L2_P5_L1_NETWORK_ID=1", "L2_P5_L1_NETWORK_ID=0"),
        text.replace("L2_P5_L1_GROUP=0", "L2_P5_L1_GROUP=1"),
        text.replace("ALEPHIUM_NETWORK_ID=1", "ALEPHIUM_NETWORK_ID=01"),
        text.replace(
            "L2_P5_LIVE_SIGNING_ENABLED=1",
            "L2_P5_LIVE_SIGNING_ENABLED=2",
        ),
        text.replace(
            &format!("L2_P5_PUBLISHER_ADDRESS={address}"),
            "L2_P5_PUBLISHER_ADDRESS=invalid",
        ),
        text.replace(
            &format!(
                "L2_P5_PUBLISHER_PRIVATE_KEY={}",
                hex::encode(key.secret_bytes())
            ),
            &format!("L2_P5_PUBLISHER_PRIVATE_KEY={}", hex::encode([200; 32])),
        ),
        text.lines()
            .filter(|line| !line.starts_with("L2_P5_PUBLISHER_PRIVATE_KEY="))
            .map(|line| format!("{line}\n"))
            .collect(),
    ] {
        check(FundingPreparationSigner::from_text(&bad, spec.clone(), true).is_err());
    }
    for case in 0..4 {
        let mut wrong = spec.clone();
        match case {
            0 => wrong.purpose_id = B256::ZERO,
            1 => wrong.operator_source = B256::ZERO,
            2 => wrong.gas_amount += 1,
            _ => wrong.gas_price += U256::from(1),
        }
        check(FundingPreparationSigner::from_text(&text, wrong, true).is_err());
    }
    let signature = signer.sign_facts(&record, &facts).unwrap();
    check(
        signature.len() == 64
            && verify_funding_preparation_signature_wire(&spec, &raw, input, amount, &signature)
                .is_ok(),
    );
    check(
        signer.sign_facts(&record, &facts).err() == Some(FundingPreparationSignerError::Consumed),
    );
    let mut altered = signature;
    altered[0] ^= 1;
    check(verify_funding_preparation_signature_wire(&spec, &raw, input, amount, &altered).is_err());
    let mut ambiguous = record;
    ambiguous.phase = FundingPreparationPhase::SignAmbiguous;
    ambiguous.revision = 3;
    let mut restarted = FundingPreparationSigner::from_text(&text, spec.clone(), true).unwrap();
    check(
        restarted.sign_facts(&ambiguous, &facts).err()
            == Some(FundingPreparationSignerError::RecordMismatch),
    );
    key.non_secure_erase();
    count
}
