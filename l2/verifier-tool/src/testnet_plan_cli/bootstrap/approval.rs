//! Typed local frozen-script validation; this grants no live operator approval.
use super::super::io;
use super::limits::{self, Budget};
use crate::{
    p5_env::BootstrapConfig,
    testnet_plan::{CompiledScript, ScriptDraft},
};
use alephium_l2_sdk::alephium::{
    AlephiumValidationError, ApprovedOperation, FundingPin, LocalScriptApproval, MIN_GAS_AMOUNT,
    OperationSpec, SpendLimits, alephium_hash, approve_operation,
};
use alloy_primitives::B256;
use serde_json::{Value, json};

struct FrozenDraftApproval<'a> {
    expected: &'a OperationSpec,
    script: &'a CompiledScript,
}

impl LocalScriptApproval for FrozenDraftApproval<'_> {
    fn approved_script(
        &self,
        operation: &OperationSpec,
    ) -> Result<Option<Vec<u8>>, AlephiumValidationError> {
        let expected = self.expected;
        let actual_limits = &operation.limits;
        let expected_limits = &expected.limits;
        if operation.intent_id != expected.intent_id
            || operation.operation_id != expected.operation_id
            || operation.publication_scope != expected.publication_scope
            || operation.source_artifact_sha256 != expected.source_artifact_sha256
            || operation.script_blake2b256 != expected.script_blake2b256
            || operation.caller_public_key != expected.caller_public_key
            || operation.funding != expected.funding
            || actual_limits.min_gas_amount != expected_limits.min_gas_amount
            || actual_limits.max_gas_amount != expected_limits.max_gas_amount
            || actual_limits.max_gas_price != expected_limits.max_gas_price
            || actual_limits.max_fee != expected_limits.max_fee
            || actual_limits.contract_deposit != expected_limits.contract_deposit
            || actual_limits.max_total_debit != expected_limits.max_total_debit
            || actual_limits.minimum_change != expected_limits.minimum_change
        {
            return Err(AlephiumValidationError::InvalidApproval);
        }
        Ok(Some(self.script.bytes().to_vec()))
    }
}

pub(super) fn operation(
    config: &BootstrapConfig,
    budget: &Budget,
    draft: &ScriptDraft,
    script: &CompiledScript,
    pin: &FundingPin,
    scope: B256,
) -> Result<ApprovedOperation, String> {
    let (fee, deposit, debit) = limits::operation_amounts(config, budget, draft)?;
    if io::sha(draft.source().as_bytes()) != draft.source_sha256()
        || script.source_sha256() != draft.source_sha256()
        || io::sha(script.bytes()) != script.script_sha256()
        || alephium_hash(script.bytes()).0 != script.script_blake2b256()
    {
        return Err(
            "Exact compiler script/source binding differs before local unsigned construction"
                .into(),
        );
    }
    let mut intent = b"ALPH/L2/private-template-unsigned-intent/v1".to_vec();
    intent.extend_from_slice(scope.as_slice());
    intent.extend_from_slice(&draft.operation_policy_sha256());
    intent.extend_from_slice(&script.script_sha256());
    intent.extend_from_slice(pin.head_hash.as_slice());
    let spec = OperationSpec {
        intent_id: B256::from(io::sha(&intent)),
        operation_id: draft.operation_policy_sha256().into(),
        publication_scope: scope,
        source_artifact_sha256: script.artifact_sha256().into(),
        script_blake2b256: Some(script.script_blake2b256().into()),
        caller_public_key: config.funding.caller_public_key,
        funding: pin.clone(),
        limits: SpendLimits {
            min_gas_amount: MIN_GAS_AMOUNT,
            max_gas_amount: config.max_gas,
            max_gas_price: config.max_gas_price,
            max_fee: fee,
            contract_deposit: deposit,
            max_total_debit: debit,
            minimum_change: config.funding.minimum_change_reserve_atto,
        },
    };
    let approval = FrozenDraftApproval {
        expected: &spec,
        script,
    };
    approve_operation(spec.clone(), &approval).map_err(|error| error.to_string())
}

pub(super) fn metadata(operation: &ApprovedOperation) -> Value {
    let spec = operation.spec();
    json!({"intentId": hex::encode(spec.intent_id.as_slice()), "operationId": hex::encode(spec.operation_id.as_slice()),
        "publicationScope": hex::encode(spec.publication_scope.as_slice()), "scriptArtifactSha256": hex::encode(spec.source_artifact_sha256.as_slice()),
        "scriptBlake2b256": spec.script_blake2b256.map(|hash| hex::encode(hash.as_slice())),
        "callerPublicKeySha256": hex::encode(io::sha(&spec.caller_public_key)),
        "fundingSource": hex::encode(spec.funding.source_id.as_slice()), "fundingHead": hex::encode(spec.funding.head_hash.as_slice()),
        "limits": {"minGasAmount": spec.limits.min_gas_amount, "maxGasAmount": spec.limits.max_gas_amount,
            "maxGasPriceAtto": spec.limits.max_gas_price.to_string(), "maxFeeAtto": spec.limits.max_fee.to_string(),
            "contractDepositAtto": spec.limits.contract_deposit.to_string(), "maxTotalDebitAtto": spec.limits.max_total_debit.to_string(),
            "minimumChangeAtto": spec.limits.minimum_change.to_string()},
        "authority": "local exact compiler-script/type validation for private draft only", "liveOperatorApproval": false,
        "publisherHandoffPolicyHash": null, "publisherHandoffPacketFinalized": false,
        "plannerOperationPolicyHashIsPublisherHandoffHash": false})
}
