//! Explicit detached Alephium signing profile, separate from EVM wallet formats.
//! Supported consensus context: v4.7.0 ordinary transactions after Rhone.
//! No wallet, network, key custody, signing, reservation or submission is built in.
//! Approval/funding callbacks must be independently configured trusted sources;
//! a signature binds unsigned bytes, not local intent/genesis/artifact metadata.
mod codec;
mod compact;
mod contract_state_hash;
pub use contract_state_hash::{ContractInitialStateHashError, contract_initial_state_hash};
pub mod current_funding;
pub mod funding_preparation;
pub mod read_node;
mod types;
mod validation;

#[cfg(test)]
mod qualification_tests;

pub use types::*;
pub use validation::{
    alephium_hash, approve_operation, observe_funding, publisher_address_from_public_key,
    unsigned_input_refs, validate_detached_signature, validate_unsigned, verify_detached_signature,
};

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{B256, U256};
    use secp256k1::ecdsa::Signature;

    // Public verify-only vector from secp256k1 0.31.1 src/lib.rs::test_low_s,
    // CC0-1.0. No signing key is copied or used. It is a primitive ECDSA
    // vector, not an Alephium transaction/receipt or funding-authentication test.
    const VECTOR_DER: &str = "3046022100839c1fbc5304de944f697c9f4b1d01d1faeba32d751c0f7acb21ac8a0f436a72022100e89bd46bb3a5a62adc679f659b7ce876d83ee297c7a5587b2011c4fcc72eab45";
    const VECTOR_PK: &str = "031ee99d2b786ab3b0991325f2de8489246a6a3fdb700f6d0511b1d80cf5f4cd43";
    const VECTOR_PREHASH: &str = "a4965ca63b7d8562736ceec36dfa5a11bf426eb65be8ea3f7a49ae363032da0d";

    struct ScriptSource;
    impl LocalScriptApproval for ScriptSource {
        fn approved_script(
            &self,
            spec: &OperationSpec,
        ) -> Result<Option<Vec<u8>>, AlephiumValidationError> {
            if spec.operation_id != B256::repeat_byte(2)
                || spec.publication_scope != B256::repeat_byte(10)
                || spec.source_artifact_sha256 != B256::repeat_byte(3)
            {
                return Err(AlephiumValidationError::InvalidApproval);
            }
            Ok(None)
        }
    }

    #[derive(Clone)]
    struct FundingSource {
        pin: FundingPin,
        output: PreviousOutput,
    }
    impl CanonicalFundingSource for FundingSource {
        fn source_id(&self) -> B256 {
            self.pin.source_id
        }
        fn unspent_outputs(
            &self,
            pin: &FundingPin,
            refs: &[OutputRef],
        ) -> Result<Vec<PreviousOutput>, AlephiumValidationError> {
            if pin != &self.pin || refs != [self.output.reference] {
                return Err(AlephiumValidationError::FundingUnavailable);
            }
            Ok(vec![self.output.clone()])
        }
    }

    fn fixture() -> (ApprovedOperation, FundingSource, Vec<u8>) {
        let caller_public_key: [u8; 33] = hex::decode(VECTOR_PK).unwrap().try_into().unwrap();
        let owner = alephium_hash(&caller_public_key);
        let funding = FundingPin {
            model: FundingModel::ExactHeadSnapshotV1,
            source_id: B256::repeat_byte(4),
            network_id: 2,
            network_genesis_id: B256::repeat_byte(5),
            group: codec::owner_group(owner, 4).unwrap(),
            group_count: 4,
            head_hash: B256::repeat_byte(6),
            head_height: 7,
            timestamp_ms: 10_000,
        };
        let spec = OperationSpec {
            intent_id: B256::repeat_byte(1),
            operation_id: B256::repeat_byte(2),
            publication_scope: B256::repeat_byte(10),
            source_artifact_sha256: B256::repeat_byte(3),
            script_blake2b256: None,
            caller_public_key,
            funding: funding.clone(),
            limits: SpendLimits {
                min_gas_amount: 20_000,
                max_gas_amount: 100_000,
                max_gas_price: U256::from(100_000_000_000u64),
                max_fee: U256::from(10_000_000_000_000_000u64),
                contract_deposit: U256::ZERO,
                max_total_debit: U256::from(10_000_000_000_000_000u64),
                minimum_change: U256::from(1_000_000_000_000_000u64),
            },
        };
        let op = approve_operation(spec, &ScriptSource).unwrap();
        let reference = OutputRef {
            hint: codec::owner_hint(owner),
            key: B256::repeat_byte(8),
        };
        let mut locking_script = vec![0];
        locking_script.extend_from_slice(owner.as_slice());
        let source = FundingSource {
            pin: funding,
            output: PreviousOutput {
                reference,
                amount: U256::from(1_010_000_000_000_000_000u64),
                locking_script,
                lock_time_ms: 0,
                tokens: vec![],
                additional_data: vec![],
            },
        };
        // Source-derived manual wire: gas100000, price1e11, one full P2PKH input,
        // one 1-ALPH change output. This is not labelled an upstream tx-ID vector.
        let mut raw = hex::decode("000200800186a0c1174876e80001").unwrap();
        raw.extend_from_slice(&reference.hint.to_be_bytes());
        raw.extend_from_slice(reference.key.as_slice());
        raw.push(0);
        raw.extend_from_slice(&caller_public_key);
        raw.extend_from_slice(&hex::decode("01c40de0b6b3a764000000").unwrap());
        raw.extend_from_slice(owner.as_slice());
        raw.extend_from_slice(&[0; 10]); // LockTime8, empty token vector, empty data.
        (op, source, raw)
    }

    #[test]
    fn aggregate_alephium_codec_spend_and_detached_signature_boundaries() {
        // v4.7.0 CompactIntegerSpec literal0/1, then source-derived threshold
        // vectors from CompactInteger.scala; these are big endian, not SCALE.
        for (value, encoded) in [
            (0, "00"),
            (1, "01"),
            (31, "1f"),
            (32, "4020"),
            (8191, "5fff"),
            (8192, "80002000"),
            (536_870_911, "9fffffff"),
            (536_870_912, "c020000000"),
            (i32::MAX as u32, "c07fffffff"),
        ] {
            let bytes = hex::decode(encoded).unwrap();
            let mut out = Vec::new();
            compact::put_int(&mut out, value).unwrap();
            assert!(out == bytes);
            let mut reader = compact::Reader::new(&bytes);
            assert!(reader.int().unwrap() == value);
            assert!(reader.finish().is_ok());
        }
        for (value, encoded) in [
            (0, "00"),
            (63, "3f"),
            (64, "4040"),
            (16383, "7fff"),
            (16384, "80004000"),
            (1_073_741_823, "bfffffff"),
            (1_073_741_824, "c040000000"),
        ] {
            let bytes = hex::decode(encoded).unwrap();
            let mut out = Vec::new();
            compact::put_amount(&mut out, U256::from(value as u64));
            assert!(out == bytes);
            let mut reader = compact::Reader::new(&bytes);
            assert!(reader.amount().unwrap() == U256::from(value as u64));
            assert!(reader.finish().is_ok());
        }
        for encoded in ["3f", "7fff", "bfffffff", "c080000000", "c1"] {
            assert!(
                compact::Reader::new(&hex::decode(encoded).unwrap())
                    .int()
                    .is_err()
            );
        }
        assert!(compact::Reader::new(&[0xdd]).amount().is_err());
        let mut maximum = vec![0xdc];
        maximum.extend_from_slice(&[255; 32]);
        assert!(compact::Reader::new(&maximum).amount().unwrap() == U256::MAX);
        let mut reencoded = Vec::new();
        compact::put_amount(&mut reencoded, U256::MAX);
        assert!(reencoded == maximum);

        let (op, source, raw) = fixture();
        // Official v4.7.0 no-input-and-output.serialized.txt unsigned prefix;
        // TransactionSpec.scala139-157. Correct codec, invalid funding profile.
        let upstream = hex::decode("000200800186a0bb9aca000000").unwrap();
        let decoded = codec::decode(&upstream, &op).unwrap();
        assert!(decoded.gas_amount == 100_000 && decoded.gas_price == U256::from(1_000_000_000u64));
        assert!(decoded.inputs.is_empty() && decoded.outputs.is_empty());
        assert!(unsigned_input_refs(&op, &upstream).is_err());
        assert!(observe_funding(&op, &[], &source).is_err());
        let refs = unsigned_input_refs(&op, &raw).unwrap();
        let observation = observe_funding(&op, &refs, &source).unwrap();
        let unsigned = validate_unsigned(&op, &observation, &raw).unwrap();
        assert!(unsigned.unsigned_bytes() == raw && unsigned.input_refs() == refs);
        assert!(unsigned.fee() == U256::from(10_000_000_000_000_000u64));
        assert!(unsigned.change() == U256::from(1_000_000_000_000_000_000u64));
        assert!(unsigned.tx_id() == alephium_hash(&raw)); // Identity integration, not independent golden.
        for end in 0..raw.len() {
            assert!(validate_unsigned(&op, &observation, &raw[..end]).is_err());
        }
        let mut trailing = raw.clone();
        trailing.push(0);
        assert!(validate_unsigned(&op, &observation, &trailing).is_err());
        assert!(unsigned_input_refs(&op, &[0; MAX_UNSIGNED_BYTES + 1]).is_err());
        for offset in [0, 1, 2, 6, 12, 14, 50, 51, 94, 95, 134, 135, 136] {
            let mut changed = raw.clone();
            changed[offset] ^= 1;
            assert!(validate_unsigned(&op, &observation, &changed).is_err());
        }
        let mut nonminimal = raw[..3].to_vec();
        nonminimal.extend_from_slice(&[0xc0, 0, 1, 0x86, 0xa0]);
        nonminimal.extend_from_slice(&raw[7..]);
        assert!(validate_unsigned(&op, &observation, &nonminimal).is_err());
        let mut below_price_floor = raw[..7].to_vec();
        below_price_floor.extend_from_slice(&hex::decode("bb9aca00").unwrap());
        below_price_floor.extend_from_slice(&raw[13..]);
        assert!(validate_unsigned(&op, &observation, &below_price_floor).is_err());
        let mut duplicate = raw[..13].to_vec();
        duplicate.push(2);
        duplicate.extend_from_slice(&raw[14..84]);
        duplicate.extend_from_slice(&raw[14..]);
        let duplicate_refs = unsigned_input_refs(&op, &duplicate).unwrap();
        assert!(observe_funding(&op, &duplicate_refs, &source).is_err());
        assert!(validate_unsigned(&op, &observation, &duplicate).is_err());
        let changes: &[fn(&mut FundingSource)] = &[
            |s| s.output.amount += U256::from(1),
            |s| s.output.locking_script[1] ^= 1,
            |s| s.output.lock_time_ms = s.pin.timestamp_ms + 1,
            |s| s.output.tokens.push((B256::repeat_byte(9), U256::from(1))),
            |s| s.output.additional_data.push(1),
            |s| s.pin.source_id = B256::repeat_byte(9),
        ];
        for mutate in changes {
            let mut wrong = source.clone();
            mutate(&mut wrong);
            let result = observe_funding(&op, &refs, &wrong)
                .and_then(|facts| validate_unsigned(&op, &facts, &raw));
            assert!(result.is_err());
        }
        let mut fee_only = source.clone();
        fee_only.output.amount = U256::from(10_000_000_000_000_000u64);
        let fee_only_funding = observe_funding(&op, &refs, &fee_only).unwrap();
        let mut no_outputs = raw[..84].to_vec();
        no_outputs.push(0);
        assert!(validate_unsigned(&op, &fee_only_funding, &no_outputs).is_err());
        let mut wrong_spec = op.spec().clone();
        wrong_spec.script_blake2b256 = Some(B256::repeat_byte(9));
        assert!(approve_operation(wrong_spec, &ScriptSource).is_err());
        let mut wrong_spec = op.spec().clone();
        wrong_spec.publication_scope = B256::repeat_byte(11);
        assert!(approve_operation(wrong_spec, &ScriptSource).is_err());
        let mut wrong_spec = op.spec().clone();
        wrong_spec.limits.max_total_debit -= U256::from(1);
        let reduced = approve_operation(wrong_spec, &ScriptSource).unwrap();
        assert!(validate_unsigned(&reduced, &observation, &raw).is_err());
        for change in [
            |limits: &mut SpendLimits| limits.min_gas_amount = MIN_GAS_AMOUNT - 1,
            |limits: &mut SpendLimits| limits.max_gas_amount = MAX_GAS_AMOUNT + 1,
            |limits: &mut SpendLimits| limits.max_gas_price = U256::from(MIN_GAS_PRICE - 1),
            |limits: &mut SpendLimits| limits.max_gas_price = U256::from(MAX_ALPH_VALUE),
            |limits: &mut SpendLimits| limits.minimum_change = U256::from(MIN_CHANGE_AMOUNT - 1),
        ] {
            let mut invalid_spec = op.spec().clone();
            change(&mut invalid_spec.limits);
            assert!(approve_operation(invalid_spec, &ScriptSource).is_err());
        }

        let public_key: [u8; 33] = hex::decode(VECTOR_PK).unwrap().try_into().unwrap();
        let digest = B256::from_slice(&hex::decode(VECTOR_PREHASH).unwrap());
        let der = hex::decode(VECTOR_DER).unwrap();
        let mut signature = Signature::from_der(&der).unwrap();
        assert!(
            validation::verify_prehash(digest, &public_key, &signature.serialize_compact())
                .is_err()
        );
        signature.normalize_s();
        let low_s = signature.serialize_compact();
        assert!(validation::verify_prehash(digest, &public_key, &low_s).is_ok());
        assert!(
            validation::verify_prehash(alephium_hash(digest.as_slice()), &public_key, &low_s)
                .is_err()
        );
        let mut other_key = public_key;
        other_key[0] ^= 1;
        assert!(validation::verify_prehash(digest, &other_key, &low_s).is_err());
        assert!(validation::verify_prehash(digest, &public_key, &der).is_err());
        assert!(validation::verify_prehash(digest, &public_key, &[0; 64]).is_err());
        assert!(validate_detached_signature(unsigned, &low_s).is_err());
    }
}
