//! Explicit simulated approval/funding for the single pure planner harness.
//! No wallet, signature, network observation, deployment prediction or real funds.
use super::super::{
    literal,
    types::{Actor, CompiledScript, Policy, ScriptDraft},
};
use alephium_l2_sdk::alephium::{
    AlephiumValidationError, CanonicalFundingSource, FundingModel, FundingPin, LocalScriptApproval,
    MIN_CHANGE_AMOUNT, MIN_GAS_AMOUNT, OperationSpec, OutputRef, PreviousOutput, SpendLimits,
    ValidatedUnsignedAlephium, alephium_hash, approve_operation, observe_funding,
    validate_unsigned,
};
use alloy_primitives::{B256, U256};
use num_bigint::BigUint;

struct SimulatedApproval {
    expected: OperationSpec,
    script: Vec<u8>,
}

impl LocalScriptApproval for SimulatedApproval {
    fn approved_script(
        &self,
        operation: &OperationSpec,
    ) -> Result<Option<Vec<u8>>, AlephiumValidationError> {
        let expected = &self.expected;
        if operation.intent_id != expected.intent_id
            || operation.operation_id != expected.operation_id
            || operation.publication_scope != expected.publication_scope
            || operation.source_artifact_sha256 != expected.source_artifact_sha256
            || operation.script_blake2b256 != expected.script_blake2b256
            || operation.caller_public_key != expected.caller_public_key
            || operation.funding != expected.funding
            || operation.limits.min_gas_amount != expected.limits.min_gas_amount
            || operation.limits.max_gas_amount != expected.limits.max_gas_amount
            || operation.limits.max_gas_price != expected.limits.max_gas_price
            || operation.limits.max_fee != expected.limits.max_fee
            || operation.limits.contract_deposit != expected.limits.contract_deposit
            || operation.limits.max_total_debit != expected.limits.max_total_debit
            || operation.limits.minimum_change != expected.limits.minimum_change
        {
            return Err(AlephiumValidationError::InvalidApproval);
        }
        Ok(Some(self.script.clone()))
    }
}

struct SimulatedExactHead {
    pin: FundingPin,
    output: PreviousOutput,
}

impl CanonicalFundingSource for SimulatedExactHead {
    fn source_id(&self) -> B256 {
        self.pin.source_id
    }

    fn unspent_outputs(
        &self,
        pin: &FundingPin,
        references: &[OutputRef],
    ) -> Result<Vec<PreviousOutput>, AlephiumValidationError> {
        if pin != &self.pin
            || references.len() != 1
            || references.first() != Some(&self.output.reference)
        {
            return Err(AlephiumValidationError::FundingMismatch);
        }
        Ok(vec![self.output.clone()])
    }
}

fn identifier(domain: &[u8], tag: u8) -> [u8; 32] {
    let mut bytes = domain.to_vec();
    bytes.push(tag);
    literal::sha(&bytes)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn validated(
    draft: &ScriptDraft,
    script: &CompiledScript,
    policy: &Policy,
    actor: &Actor,
    input_tag: u8,
    with_change: bool,
    approved_gas_cap: u32,
    approved_price_cap: u64,
) -> Result<ValidatedUnsignedAlephium, String> {
    let owner = alephium_hash(&actor.public_key);
    let hint = owner.as_slice().iter().fold(5381_u32, |value, byte| {
        value.wrapping_mul(33).wrapping_add(u32::from(*byte))
    }) | 1;
    let reference = OutputRef {
        hint,
        key: [input_tag; 32].into(),
    };
    let pin = FundingPin {
        model: FundingModel::ExactHeadSnapshotV1,
        source_id: actor.canonical_source.into(),
        network_id: 1,
        network_genesis_id: policy.l1_genesis.into(),
        group: 0,
        group_count: 4,
        head_hash: identifier(b"ALPH/L2/simulated-funding-head/v1", input_tag).into(),
        head_height: 1,
        timestamp_ms: 1_800_000_000_000,
    };
    let change = if with_change {
        1_000_000_000_000_000_000_u64
    } else {
        0
    };
    // The SDK requires a positive minimum-change policy even when a script has
    // zero actual change. Preserve that guard; it is unused by the zero-output path.
    let minimum_change = if with_change {
        change
    } else {
        MIN_CHANGE_AMOUNT
    };
    let spec = OperationSpec {
        intent_id: identifier(b"ALPH/L2/simulated-intent/v1", input_tag).into(),
        operation_id: identifier(b"ALPH/L2/simulated-operation/v1", input_tag).into(),
        publication_scope: literal::sha(b"ALPH/L2/simulated-publication-scope/v1").into(),
        source_artifact_sha256: script.artifact_sha256.into(),
        script_blake2b256: Some(script.script_blake2b256.into()),
        caller_public_key: actor.public_key,
        funding: pin.clone(),
        limits: SpendLimits {
            min_gas_amount: MIN_GAS_AMOUNT,
            max_gas_amount: approved_gas_cap,
            max_gas_price: U256::from(approved_price_cap),
            max_fee: draft
                .limits
                .fee_max
                .to_string()
                .parse()
                .map_err(|_| "Simulated fixture fee does not fit U256")?,
            contract_deposit: draft
                .limits
                .deposit
                .to_string()
                .parse()
                .map_err(|_| "Simulated fixture deposit does not fit U256")?,
            max_total_debit: draft
                .limits
                .debit_max
                .to_string()
                .parse()
                .map_err(|_| "Simulated fixture debit does not fit U256")?,
            minimum_change: U256::from(minimum_change),
        },
    };
    let approval = SimulatedApproval {
        expected: spec.clone(),
        script: script.bytes.clone(),
    };
    let operation =
        approve_operation(spec, &approval).map_err(|_| "Simulated fixture approval was refused")?;
    let mut locking_script = vec![0];
    locking_script.extend_from_slice(owner.as_slice());
    let amount =
        BigUint::from(10_000_000_000_000_000_u64) + &draft.limits.deposit + BigUint::from(change);
    let funding = SimulatedExactHead {
        pin,
        output: PreviousOutput {
            reference,
            amount: amount
                .to_string()
                .parse()
                .map_err(|_| "Simulated previous amount does not fit U256")?,
            locking_script,
            lock_time_ms: 0,
            tokens: vec![],
            additional_data: vec![],
        },
    };
    let observation = observe_funding(&operation, &[reference], &funding)
        .map_err(|_| "Simulated exact-head funding was refused")?;
    let mut raw = vec![0, 1, 1]; // unsigned v0, network1, Some StatefulScript
    raw.extend_from_slice(&script.bytes);
    raw.extend_from_slice(&[0x80, 0x01, 0x86, 0xa0]); // gas 100,000
    raw.extend_from_slice(&[0xc1, 0x17, 0x48, 0x76, 0xe8, 0x00]); // price 10^11
    raw.push(1); // one full P2PKH input
    raw.extend_from_slice(&hint.to_be_bytes());
    raw.extend_from_slice(reference.key.as_slice());
    raw.push(0);
    raw.extend_from_slice(&actor.public_key);
    raw.push(u8::from(with_change));
    if with_change {
        raw.extend_from_slice(&[0xc4, 0x0d, 0xe0, 0xb6, 0xb3, 0xa7, 0x64, 0x00, 0x00]);
        raw.push(0);
        raw.extend_from_slice(owner.as_slice());
        raw.extend_from_slice(&[0; 8]); // no lock, tokens or additional data
        raw.extend_from_slice(&[0, 0]);
    }
    validate_unsigned(&operation, &observation, &raw)
        .map_err(|_| "Simulated fixture unsigned bytes were refused".into())
}
