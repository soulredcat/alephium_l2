//! One aggregate helper: synthetic keys/capabilities only, never root env.
use super::*;
use alephium_l2_sdk::alephium::{
    AlephiumValidationError, CanonicalFundingSource, FundingModel, FundingPin, LocalScriptApproval,
    OperationSpec, OutputRef, PreviousOutput, SpendLimits, approve_operation, observe_funding,
    validate_unsigned,
};
use alloy_primitives::U256;

fn identity(excluded: Option<[u8; 33]>) -> (SecretKey, [u8; 33], String) {
    for value in 1..=128_u8 {
        let mut bytes = [0; 32];
        bytes[31] = value;
        let key = SecretKey::from_byte_array(bytes).unwrap();
        let public = PublicKey::from_secret_key(&Secp256k1::signing_only(), &key).serialize();
        let address = publisher_address_from_public_key(&public).unwrap();
        if address.group() == 0 && Some(public) != excluded {
            return (key, public, address.as_str().to_owned());
        }
    }
    panic!("Synthetic group-zero identity unavailable");
}

fn scope(public: [u8; 33]) -> Scope {
    Scope {
        l1_network: 1,
        l1_genesis: B256::repeat_byte(2),
        l2_chain_id: 424_246,
        l2_genesis: B256::repeat_byte(3),
        factory: B256::repeat_byte(4),
        execution_profile: B256::repeat_byte(5),
        publisher_key: public.to_vec(),
        canonical_source: B256::repeat_byte(6),
    }
}

fn env(key: &SecretKey, public: [u8; 33], address: &str, interlock: u8) -> String {
    format!(
        "L2_P5_PUBLISHER_PRIVATE_KEY={}\nL2_P5_PUBLISHER_PUBLIC_KEY={}\nL2_P5_PUBLISHER_ADDRESS={address}\nL2_P5_L1_NETWORK_ID=1\nL2_P5_L1_GROUP=0\nALEPHIUM_NETWORK_ID=1\nL2_P5_LIVE_SIGNING_ENABLED={interlock}\nWALLET1_PRIVATE_KEY=ignored_generic_wallet\n",
        hex::encode(key.secret_bytes()),
        hex::encode(public)
    )
}

struct Script;
impl LocalScriptApproval for Script {
    fn approved_script(
        &self,
        _: &OperationSpec,
    ) -> Result<Option<Vec<u8>>, AlephiumValidationError> {
        Ok(Some(vec![1, 0]))
    }
}
struct Funding {
    pin: FundingPin,
    output: PreviousOutput,
}
impl CanonicalFundingSource for Funding {
    fn source_id(&self) -> B256 {
        self.pin.source_id
    }
    fn unspent_outputs(
        &self,
        pin: &FundingPin,
        refs: &[OutputRef],
    ) -> Result<Vec<PreviousOutput>, AlephiumValidationError> {
        if *pin != self.pin || refs != [self.output.reference] {
            return Err(AlephiumValidationError::FundingMismatch);
        }
        Ok(vec![self.output.clone()])
    }
}

fn unsigned(scope: &Scope, public: [u8; 33], tag: u8) -> ValidatedUnsignedAlephium {
    let owner = alephium_hash(&public);
    let hint = owner.as_slice().iter().fold(5381_u32, |hash, byte| {
        hash.wrapping_mul(33).wrapping_add(u32::from(*byte))
    }) | 1;
    let reference = OutputRef {
        hint,
        key: B256::repeat_byte(tag),
    };
    let pin = FundingPin {
        model: FundingModel::ExactHeadSnapshotV1,
        source_id: scope.canonical_source,
        network_id: scope.l1_network,
        network_genesis_id: scope.l1_genesis,
        group: 0,
        group_count: 4,
        head_hash: B256::repeat_byte(7),
        head_height: 1,
        timestamp_ms: 1000,
    };
    let fee = U256::from(200_000_u64) * U256::from(100_000_000_000_u64);
    let spec = OperationSpec {
        intent_id: B256::repeat_byte(tag),
        operation_id: B256::repeat_byte(tag + 1),
        publication_scope: scope.identity().unwrap(),
        source_artifact_sha256: B256::repeat_byte(8),
        script_blake2b256: Some(alephium_hash(&[1, 0])),
        caller_public_key: public,
        funding: pin.clone(),
        limits: SpendLimits {
            min_gas_amount: 20_000,
            max_gas_amount: 200_000,
            max_gas_price: U256::from(100_000_000_000_u64),
            max_fee: fee,
            contract_deposit: U256::ZERO,
            max_total_debit: fee,
            minimum_change: U256::from(1_000_000_000_000_000_u64),
        },
    };
    let approved = approve_operation(spec, &Script).unwrap();
    let mut locking = vec![0];
    locking.extend_from_slice(owner.as_slice());
    let source = Funding {
        pin,
        output: PreviousOutput {
            reference,
            amount: U256::from(1_000_000_000_000_000_000_u64) + fee,
            locking_script: locking,
            lock_time_ms: 0,
            tokens: vec![],
            additional_data: vec![],
        },
    };
    let observation = observe_funding(&approved, &[reference], &source).unwrap();
    // Source-derived native CompactInteger fields: gas200000, price1e11,
    // one input/full-P2PKH unlock and one 1ALPH same-owner fixed change.
    let mut raw = vec![0, scope.l1_network, 1, 1, 0];
    raw.extend_from_slice(&hex::decode("80030d40c1174876e80001").unwrap());
    raw.extend_from_slice(&hint.to_be_bytes());
    raw.extend_from_slice(reference.key.as_slice());
    raw.push(0);
    raw.extend_from_slice(&public);
    raw.extend_from_slice(&hex::decode("01c40de0b6b3a764000000").unwrap());
    raw.extend_from_slice(owner.as_slice());
    raw.extend_from_slice(&[0; 10]);
    validate_unsigned(&approved, &observation, &raw).unwrap()
}

pub(super) fn run_checks() -> usize {
    let (mut key, public, address) = identity(None);
    let approved_scope = scope(public);
    let text = env(&key, public, &address, 1);
    let disabled_text = env(&key, public, &address, 0);
    let tx = unsigned(&approved_scope, public, 10);
    let token = Token {
        revision: 4,
        fencing_epoch: 1,
        canonical_head: tx.operation().spec().funding.head_hash,
    };
    let mut count = 0;
    let mut check = |ok: bool| {
        assert!(
            ok,
            "Configured signer aggregate failed; private values suppressed"
        );
        count += 1;
    };
    let mut disabled =
        ConfiguredNativeSigner::from_text(&disabled_text, approved_scope.clone(), true).unwrap();
    check(!disabled.enabled());
    check(disabled.sign(token, &tx) == Err(ExternalFailure::Disabled));
    let mut disabled =
        ConfiguredNativeSigner::from_text(&text, approved_scope.clone(), false).unwrap();
    check(!disabled.enabled());
    check(disabled.sign(token, &tx) == Err(ExternalFailure::Disabled));
    let mut signer =
        ConfiguredNativeSigner::from_text(&text, approved_scope.clone(), true).unwrap();
    check(signer.enabled());
    let signature = signer.sign(token, &tx).unwrap();
    check(signature.len() == 64 && verify_detached_signature(&tx, &signature).is_ok());
    check(signer.sign(token, &tx) == Err(ExternalFailure::Rejected));
    let mut altered = signature;
    altered[0] ^= 1;
    check(verify_detached_signature(&tx, &altered).is_err());
    for bad in [
        Token {
            revision: 0,
            ..token
        },
        Token {
            fencing_epoch: 0,
            ..token
        },
        Token {
            canonical_head: B256::ZERO,
            ..token
        },
        Token {
            canonical_head: B256::repeat_byte(88),
            ..token
        },
    ] {
        let mut fresh =
            ConfiguredNativeSigner::from_text(&text, approved_scope.clone(), true).unwrap();
        check(fresh.sign(bad, &tx) == Err(ExternalFailure::Rejected));
    }
    let mut wrong_scope = approved_scope.clone();
    wrong_scope.factory = B256::repeat_byte(99);
    let mut fresh = ConfiguredNativeSigner::from_text(&text, wrong_scope, true).unwrap();
    check(fresh.sign(token, &tx) == Err(ExternalFailure::Rejected));
    let (mut other_key, other_public, _) = identity(Some(public));
    let other_caller = unsigned(&approved_scope, other_public, 60);
    let mut fresh = ConfiguredNativeSigner::from_text(&text, approved_scope.clone(), true).unwrap();
    check(fresh.sign(token, &other_caller) == Err(ExternalFailure::Rejected));
    other_key.non_secure_erase();
    for change in [
        |s: &mut Scope| s.l1_genesis = B256::repeat_byte(99),
        |s: &mut Scope| s.canonical_source = B256::repeat_byte(99),
    ] {
        let mut mismatched = approved_scope.clone();
        change(&mut mismatched);
        let tx = unsigned(&mismatched, public, 20);
        let mut fresh =
            ConfiguredNativeSigner::from_text(&text, approved_scope.clone(), true).unwrap();
        check(fresh.sign(token, &tx) == Err(ExternalFailure::Rejected));
    }
    for bad in [
        text.replace("L2_P5_L1_NETWORK_ID=1", "L2_P5_L1_NETWORK_ID=0"),
        text.replace("ALEPHIUM_NETWORK_ID=1", "ALEPHIUM_NETWORK_ID=2"),
        text.replace("L2_P5_L1_GROUP=0", "L2_P5_L1_GROUP=1"),
        text.replace(
            &format!("L2_P5_PUBLISHER_ADDRESS={address}"),
            "L2_P5_PUBLISHER_ADDRESS=invalid",
        ),
        text.replace(
            &format!(
                "L2_P5_PUBLISHER_PRIVATE_KEY={}",
                hex::encode(key.secret_bytes())
            ),
            "L2_P5_PUBLISHER_PRIVATE_KEY=00",
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
        check(ConfiguredNativeSigner::from_text(&bad, approved_scope.clone(), true).is_err());
    }
    check(configuration::parse(&(text.clone() + "L2_P5_LIVE_SIGNING_ENABLED=1\n")).is_err());
    check(
        configuration::parse(&text.replace(
            "L2_P5_LIVE_SIGNING_ENABLED=1",
            "L2_P5_LIVE_SIGNING_ENABLED=$FLAG",
        ))
        .is_err(),
    );
    check(configuration::parse(&"#".repeat(32_769)).is_err());
    let without_key: String = disabled_text
        .lines()
        .filter(|line| !line.starts_with("L2_P5_PUBLISHER_PRIVATE_KEY="))
        .map(|line| format!("{line}\n"))
        .collect();
    check(
        ConfiguredNativeSigner::from_text(&without_key, approved_scope.clone(), true)
            .is_ok_and(|signer| !signer.enabled()),
    );
    check(
        ConfiguredNativeSigner::from_text(
            &text.replace("ALEPHIUM_NETWORK_ID=1", "ALEPHIUM_NETWORK_ID=01"),
            approved_scope.clone(),
            true,
        )
        .is_err(),
    );
    let next = unsigned(&approved_scope, public, 30);
    check(
        signer.sign(
            Token {
                revision: 3,
                ..token
            },
            &next,
        ) == Err(ExternalFailure::Rejected),
    );
    check(
        signer.sign(
            Token {
                revision: 8,
                fencing_epoch: 0,
                ..token
            },
            &next,
        ) == Err(ExternalFailure::Rejected),
    );
    check(
        signer
            .sign(
                Token {
                    revision: 8,
                    ..token
                },
                &next,
            )
            .is_ok(),
    );
    let fenced = unsigned(&approved_scope, public, 40);
    check(
        signer
            .sign(
                Token {
                    revision: 12,
                    fencing_epoch: 2,
                    ..token
                },
                &fenced,
            )
            .is_ok(),
    );
    let stale = unsigned(&approved_scope, public, 50);
    check(
        signer.sign(
            Token {
                revision: 16,
                fencing_epoch: 1,
                ..token
            },
            &stale,
        ) == Err(ExternalFailure::Rejected),
    );
    key.non_secure_erase();
    count
}
