//! Public development transaction and synthetic in-memory signed ledger only.
use alephium_l2_node::publisher::*;
use alephium_l2_sdk::alephium::*;
use alloy_primitives::{B256, U256};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use std::{cell::RefCell, rc::Rc};
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
        if pin != &self.pin || refs != [self.output.reference] {
            return Err(AlephiumValidationError::FundingMismatch);
        }
        Ok(vec![self.output.clone()])
    }
}

pub(super) fn fixture() -> (Scope, ValidatedSignedAlephium) {
    let secp = Secp256k1::signing_only();
    let (mut key, public) = (1..=128u8)
        .find_map(|n| {
            let mut scalar = [0; 32];
            scalar[31] = n;
            let key = SecretKey::from_byte_array(scalar).unwrap();
            let public = PublicKey::from_secret_key(&secp, &key).serialize();
            (publisher_address_from_public_key(&public).unwrap().group() == 0)
                .then_some((key, public))
        })
        .expect("Public development group-zero fixture required");
    let mut factory = [4; 32];
    factory[31] = 0;
    let scope = Scope {
        l1_network: 1,
        l1_genesis: B256::repeat_byte(2),
        l2_chain_id: 424246,
        l2_genesis: B256::repeat_byte(3),
        factory: factory.into(),
        execution_profile: B256::repeat_byte(5),
        publisher_key: public.to_vec(),
        canonical_source: B256::repeat_byte(6),
    };
    let owner = alephium_hash(&public);
    let hint = owner.iter().fold(5381u32, |h, b| {
        h.wrapping_mul(33).wrapping_add(u32::from(*b))
    }) | 1;
    let reference = OutputRef {
        hint,
        key: B256::repeat_byte(10),
    };
    let pin = FundingPin {
        model: FundingModel::ExactHeadSnapshotV1,
        source_id: scope.canonical_source,
        network_id: 1,
        network_genesis_id: scope.l1_genesis,
        group: 0,
        group_count: 4,
        head_hash: B256::repeat_byte(7),
        head_height: 1,
        timestamp_ms: 1000,
    };
    let price = U256::from(100_000_000_000u64);
    let fee = U256::from(200_000u64) * price;
    let operation = approve_operation(
        OperationSpec {
            intent_id: B256::repeat_byte(10),
            operation_id: B256::repeat_byte(11),
            publication_scope: scope.identity().unwrap(),
            source_artifact_sha256: B256::repeat_byte(8),
            script_blake2b256: Some(alephium_hash(&[1, 0])),
            caller_public_key: public,
            funding: pin.clone(),
            limits: SpendLimits {
                min_gas_amount: 20_000,
                max_gas_amount: 200_000,
                max_gas_price: price,
                max_fee: fee,
                contract_deposit: U256::ZERO,
                max_total_debit: fee,
                minimum_change: U256::from(MIN_CHANGE_AMOUNT),
            },
        },
        &Script,
    )
    .unwrap();
    let mut locking = vec![0];
    locking.extend_from_slice(owner.as_slice());
    let funding = Funding {
        pin,
        output: PreviousOutput {
            reference,
            amount: U256::from(1_000_000_000_000_000_000u64) + fee,
            locking_script: locking,
            lock_time_ms: 0,
            tokens: vec![],
            additional_data: vec![],
        },
    };
    let observed = observe_funding(&operation, &[reference], &funding).unwrap();
    // Retained native CompactInteger vector: gas200000, price1e11, change1ALPH.
    let mut raw = vec![0, 1, 1, 1, 0];
    raw.extend(hex::decode("80030d40c1174876e80001").unwrap());
    raw.extend(hint.to_be_bytes());
    raw.extend(reference.key.as_slice());
    raw.push(0);
    raw.extend(public);
    raw.extend(hex::decode("01c40de0b6b3a764000000").unwrap());
    raw.extend(owner.as_slice());
    raw.extend([0; 10]);
    let unsigned = validate_unsigned(&operation, &observed, &raw).unwrap();
    let mut signature = secp.sign_ecdsa(Message::from_digest(unsigned.tx_id().0), &key);
    signature.normalize_s();
    key.non_secure_erase();
    let signed = validate_detached_signature(unsigned, &signature.serialize_compact()).unwrap();
    (scope, signed)
}

pub(super) struct Memory(Rc<RefCell<PublisherSnapshot>>);
impl Repository for Memory {
    fn publisher_load(&self, _: &Scope) -> Result<Option<PublisherSnapshot>, PublisherError> {
        Ok(Some(self.0.borrow().clone()))
    }
    fn publisher_cas(
        &mut self,
        revision: u64,
        fence: u64,
        next: &PublisherSnapshot,
    ) -> Result<PublisherSnapshot, PublisherError> {
        let mut old = self.0.borrow_mut();
        if old.revision != revision || old.fencing_epoch != fence {
            return Err(PublisherError::Conflict);
        }
        *old = next.clone();
        Ok(next.clone())
    }
}
pub(super) fn publisher(scope: &Scope, signed: &ValidatedSignedAlephium) -> Publisher<Memory> {
    let unsigned = signed.unsigned();
    let spec = unsigned.operation().spec();
    let mut snapshot = PublisherSnapshot::empty(scope.clone());
    let kinds = [
        AuditKind::Fence,
        AuditKind::CanonicalHead,
        AuditKind::Intent,
        AuditKind::SignAttempt,
        AuditKind::Signed,
    ];
    for (i, kind) in kinds.into_iter().enumerate() {
        snapshot.history.push(AuditEntry {
            revision: i as u64 + 1,
            fencing_epoch: 1,
            intent_id: if i < 2 {
                None
            } else {
                Some(unsigned.intent_id())
            },
            kind,
            at_ms: 1000 + i as u64,
            canonical_head: if i == 0 {
                B256::ZERO
            } else {
                spec.funding.head_hash
            },
            inclusion: None,
        });
    }
    snapshot.revision = 5;
    snapshot.fencing_epoch = 1;
    snapshot.canonical_head = spec.funding.head_hash;
    snapshot.records.push(Publication {
        intent: Intent {
            id: unsigned.intent_id(),
            operation_id: unsigned.operation_id(),
            operation_policy_sha256: handoff::operation_policy_hash(unsigned.operation()),
            parent: None,
            tx_id: signed.tx_id(),
            unsigned: signed.unsigned_bytes().to_vec(),
            inputs: unsigned
                .input_refs()
                .iter()
                .map(|r| ReservedInput {
                    hint: r.hint,
                    key: r.key,
                })
                .collect(),
            network: 1,
            l1_genesis: scope.l1_genesis,
            canonical_source: scope.canonical_source,
            artifact_hash: spec.source_artifact_sha256,
            script_hash: spec.script_blake2b256.unwrap(),
            expected_effect: B256::repeat_byte(12),
            authority_key: scope.publisher_key.clone(),
            created_at_ms: 1002,
            review_after_ms: 999999,
            confirmations: 6,
        },
        phase: Phase::Signed,
        sign_attempts: 1,
        submit_attempts: 0,
        signature: Some(signed.signature().to_vec()),
        inclusion: None,
        reservations_retained: true,
    });
    Publisher::open(Memory(Rc::new(RefCell::new(snapshot))), scope.clone()).unwrap()
}
