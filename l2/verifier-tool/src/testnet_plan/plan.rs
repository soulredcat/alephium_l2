//! Frozen review package; projected effects are never canonical observations.
use super::{artifacts::FrozenArtifacts, batches::PreparedBatch, literal, types::*};
use num_bigint::BigUint;
use serde_json::{Value, json};
use std::collections::BTreeSet;

// The current draft CLI cannot instantiate this type without the unresolved
// real deployment identities, two genuine receipts and thirty reviewed scripts.
#[allow(dead_code)]
pub(crate) struct FrozenPlan {
    value: Value,
    sha256: [u8; 32],
}
#[allow(dead_code)]
impl FrozenPlan {
    /// Includes private source/receipt/DA literals: persist locally, never log/upload.
    pub fn private_value(&self) -> &Value {
        &self.value
    }
    pub fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
}

#[allow(dead_code, clippy::too_many_arguments)]
pub(crate) fn assemble(
    artifacts: &FrozenArtifacts,
    policy: &Policy,
    actor: &Actor,
    deployments: &[Deployment; 3],
    batches: &[PreparedBatch; 2],
    drafts: Vec<ScriptDraft>,
    compiled: Vec<CompiledScript>,
    total: &TotalLimit,
) -> Result<FrozenPlan, String> {
    policy.validate(actor)?;
    if drafts.len() != 30 || compiled.len() != 30 {
        return Err("Thirty complete reviewed operations required".into());
    }
    let mut scope = b"ALPH/L2/publisher-scope/v1".to_vec();
    scope.push(1);
    scope.extend(policy.l1_genesis);
    scope.extend(policy.l2_chain_id.to_be_bytes());
    scope.extend(policy.l2_genesis);
    scope.extend(deployments[2].contract_id);
    scope.extend(policy.execution_profile);
    scope.extend(actor.public_key);
    scope.extend(actor.canonical_source);
    let publication_scope = literal::sha(&scope);
    let mut reservations = BTreeSet::new();
    for deployment in deployments {
        if deployment.reserved_input_keys.is_empty()
            || deployment
                .reserved_input_keys
                .iter()
                .any(|key| !reservations.insert(*key))
        {
            return Err("Deployment funding inputs conflict or are missing".into());
        }
    }
    for (index, kind) in [
        "deploy-proof-template",
        "deploy-data-template",
        "deploy-factory",
    ]
    .into_iter()
    .enumerate()
    {
        if drafts[index].kind != kind
            || deployments[index].kind != kind
            || deployments[index].script_sha256 != compiled[index].script_sha256
            || deployments[index].caller_public_key_sha256 != literal::sha(&actor.public_key)
            || deployments[index].funding_source != actor.canonical_source
            || deployments[index].group != 0
            || deployments[index].publication_scope != publication_scope
        {
            return Err("Deployment identity/operation roles differ".into());
        }
    }
    if drafts[3].kind != "initialize-genesis"
        || deployments[0].expected_code_hash != artifacts.proof.code_hash
        || deployments[1].expected_code_hash != artifacts.data.code_hash
        || deployments[2].expected_code_hash != artifacts.factory.code_hash
        || batches[0].journal.factory != deployments[2].contract_id
        || batches[1].journal.factory != deployments[2].contract_id
        || batches[0].journal.parent.bytes != policy.genesis_head
        || batches[0].journal.old_root != policy.genesis_root(&deployments[2].contract_id)
        || batches[1].journal.parent != batches[0].journal.head
        || batches[1].journal.old_root != batches[0].journal.new_root
    {
        return Err("Factory initialization or consecutive anchors differ".into());
    }
    let kinds = [
        "create-candidate",
        "begin-proof",
        "advance-proof",
        "advance-proof",
        "advance-proof",
        "advance-proof",
        "advance-proof",
        "advance-proof",
        "advance-proof",
        "advance-proof",
        "advance-proof",
        "finish-proof",
        "finalize-batch",
    ];
    for batch in 0..2 {
        for (offset, kind) in kinds.into_iter().enumerate() {
            let operation = &drafts[4 + batch * 13 + offset];
            if operation.kind != kind || operation.batch != Some(batch as u8 + 1) {
                return Err("Consecutive operation sequence differs".into());
            }
        }
    }
    // Re-render the complete typed dependency graph. Individually valid drafts
    // from another factory, actor, policy or predecessor cannot be mixed here.
    let templates = super::scripts::prepare_templates(
        artifacts,
        policy,
        actor,
        [drafts[0].limits.clone(), drafts[1].limits.clone()],
    )?;
    let mut expected = Vec::from(templates);
    expected.push(super::scripts::prepare_factory(
        artifacts,
        policy,
        actor,
        &deployments[0],
        &deployments[1],
        drafts[2].limits.clone(),
    )?);
    expected.push(super::scripts::prepare_initialize(
        policy,
        actor,
        &deployments[2],
        drafts[3].limits.clone(),
    )?);
    for (batch, prepared) in batches.iter().enumerate() {
        let limits = drafts[4 + batch * 13..17 + batch * 13]
            .iter()
            .map(|draft| draft.limits.clone())
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| "Batch budget inventory differs")?;
        expected.extend(super::batches::calls(
            prepared,
            batch as u8 + 1,
            policy,
            actor,
            limits,
        )?);
    }
    for (actual, expected) in drafts.iter().zip(&expected) {
        if actual.source_sha256 != expected.source_sha256
            || actual.argument_sha256 != expected.argument_sha256
            || actual.expected_effect_sha256 != expected.expected_effect_sha256
            || actual.operation_policy_sha256 != expected.operation_policy_sha256
        {
            return Err(
                "Instantiated draft differs from exact deployment/batch/policy graph".into(),
            );
        }
    }
    let mut fees = BigUint::from(0_u8);
    let mut deposits = BigUint::from(0_u8);
    let mut debit = BigUint::from(0_u8);
    let mut operations = Vec::with_capacity(30);
    for (index, (draft, script)) in drafts.iter().zip(&compiled).enumerate() {
        if literal::sha(draft.source.as_bytes()) != draft.source_sha256
            || script.source_sha256 != draft.source_sha256
            || literal::sha(&script.bytes) != script.script_sha256
            || literal::blake(&script.bytes) != script.script_blake2b256
        {
            return Err("Reviewed compiled script/source binding changed".into());
        }
        let required = if index < 3 {
            policy.minimum_contract_deposit.clone()
        } else if index == 4 || index == 17 {
            &policy.minimum_contract_deposit * BigUint::from(2_u8)
        } else {
            BigUint::from(0_u8)
        };
        draft.limits.validate(&required)?;
        // Conservative v4.7.0 single-signer request allowance, not a measured fee.
        let request_floor = script
            .bytes
            .len()
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(16384))
            .ok_or("Request bound overflow")?;
        if request_floor > draft.limits.request_bytes_max {
            return Err("Reviewed script request exceeds approved byte bound".into());
        }
        fees += &draft.limits.fee_max;
        deposits += &draft.limits.deposit;
        debit += &draft.limits.debit_max;
        let dependencies = match index {
            0 | 1 => vec![],
            2 => vec![0, 1],
            _ => vec![index - 1],
        };
        let mut effect = draft.expected_effect.clone();
        if index < 3 {
            effect["predictedContractId"] = json!(hex::encode(deployments[index].contract_id));
            effect["creationOutputIndex"] = json!(deployments[index].creation_output_index);
        }
        let effect_sha = literal::hash_value(b"ALPH/L2/testnet-effects/v1", &effect)?;
        let request = json!({"schema":1,"index":index,"kind":draft.kind,"batch":draft.batch,
            "publicationScope":hex::encode(publication_scope),"sourceSha256":hex::encode(draft.source_sha256),
            "statefulScriptSha256":hex::encode(script.script_sha256),"scriptBlake2b256":hex::encode(script.script_blake2b256),
            "argumentsSha256":hex::encode(draft.argument_sha256),"effectSha256":hex::encode(effect_sha),
            "artifactSha256":hex::encode(script.artifact_sha256),"limits":draft.limits.value(),
            "contractCodeHashes":[hex::encode(artifacts.proof.code_hash),hex::encode(artifacts.data.code_hash),hex::encode(artifacts.factory.code_hash)],
            "sourceClosureHashes":[hex::encode(artifacts.proof.source_closure_sha256),hex::encode(artifacts.data.source_closure_sha256),hex::encode(artifacts.factory.source_closure_sha256)]});
        let request_sha = literal::hash_value(b"ALPH/L2/testnet-request/v1", &request)?;
        let operation_policy_sha =
            literal::hash_value(b"ALPH/L2/testnet-approved-operation/v1", &request)?;
        operations.push(json!({"index":index,"kind":draft.kind,"batch":draft.batch,
            "requiresCanonicalConfirmationOfOperations":dependencies,"confirmations":policy.confirmations,
            "source":draft.source,"sourceSha256":hex::encode(draft.source_sha256),
            "argumentsSha256":hex::encode(draft.argument_sha256),"compiledArtifactSha256":hex::encode(script.artifact_sha256),
            "statefulScriptSha256":hex::encode(script.script_sha256),"scriptBlake2b256":hex::encode(script.script_blake2b256),
            "statefulScriptHex":hex::encode(&script.bytes),
            "requestSha256":hex::encode(request_sha),"operation_policy_sha256":hex::encode(operation_policy_sha),
            "preCompilerDraftPolicySha256":hex::encode(draft.operation_policy_sha256),
            "preDeploymentEffectSha256":hex::encode(draft.expected_effect_sha256),
            "expectedEffect":effect,"expectedEffectSha256":hex::encode(effect_sha),
            "limits":draft.limits.value(),"requiresFreshCanonicalFundingBeforeDispatch":true,"signable":false}));
    }
    for value in [
        &fees,
        &deposits,
        &debit,
        &total.fee_max,
        &total.deposit_max,
        &total.debit_max,
    ] {
        if value.bits() > 256 {
            return Err("Aggregate amount exceeds U256".into());
        }
    }
    if fees > total.fee_max || deposits > total.deposit_max || debit > total.debit_max {
        return Err("Thirty operations exceed explicit aggregate approval ceilings".into());
    }
    let deployment_values=deployments.iter().map(|item|json!({"kind":item.kind,
        "predictedContractId":hex::encode(item.contract_id),"unsignedTxId":hex::encode(item.tx_id),
        "unsignedSha256":hex::encode(item.unsigned_sha256),"creationOutputIndex":item.creation_output_index,
        "group":item.group,"scriptSha256":hex::encode(item.script_sha256),
        "fundingHead":hex::encode(item.funding_head),"fundingSource":hex::encode(item.funding_source),
        "reservedInputKeys":item.reserved_input_keys.iter().map(hex::encode).collect::<Vec<_>>(),
        "actualCanonicalCreationNotYetObserved":true})).collect::<Vec<_>>();
    let batch_values=batches.iter().map(|batch|json!({"journalSha256":hex::encode(batch.journal.digest),
        "parentHead":hex::encode(batch.journal.parent.bytes),"head":hex::encode(batch.journal.head.bytes),
        "oldRoot":hex::encode(batch.journal.old_root),"newRoot":hex::encode(batch.journal.new_root),
        "dataBytes":batch.data.bytes.len(),"dataSha256":hex::encode(batch.journal.data_hash),
        "predecessorCheckpointSha256":hex::encode(batch.data.checkpoint_sha256),
        "candidateKey":hex::encode(batch.key),"proofChild":hex::encode(batch.proof_id),
        "dataChild":hex::encode(batch.data_id),"statementSha256":hex::encode(batch.statement)})).collect::<Vec<_>>();
    let artifact_value = |item: &super::artifacts::FrozenArtifact| {
        json!({"class":item.class,
        "artifactSha256":hex::encode(item.artifact_sha256),"executableSha256":hex::encode(item.executable_sha256),
        "productionCodeHash":hex::encode(item.code_hash),"sourceClosureSha256":hex::encode(item.source_closure_sha256),
        "publicMethods":item.public_methods})
    };
    let value = json!({"schema":1,"scope":"offline-public-testnet-operation-review/v1","network":1,"group":0,
        "privateMaterial":true,"staticInstantiatedArtifactsComplete":true,"operationCount":30,
        "signerPublicKeySha256":hex::encode(literal::sha(&actor.public_key)),"canonicalSource":hex::encode(actor.canonical_source),
        "publicationScope":hex::encode(publication_scope),
        "l1Genesis":hex::encode(policy.l1_genesis),"l2Genesis":hex::encode(policy.l2_genesis),"l2ChainId":policy.l2_chain_id,
        "executionProfile":hex::encode(policy.execution_profile),"approvedImage":hex::encode(policy.approved_image),
        "programSha256":hex::encode(policy.program_sha256),"maxFutureSeconds":policy.max_future_seconds,
        "artifacts":[artifact_value(&artifacts.proof),artifact_value(&artifacts.data),artifact_value(&artifacts.factory)],
        "deployments":deployment_values,"batches":batch_values,"operations":operations,
        "aggregateLimits":{"feeMaxAtto":total.fee_max.to_string(),"depositMaxAtto":total.deposit_max.to_string(),
            "totalDebitMaxAtto":total.debit_max.to_string(),"sumOperationFeeMaxAtto":fees.to_string(),
            "sumOperationDepositsAtto":deposits.to_string(),"sumOperationDebitMaxAtto":debit.to_string()},
        "gasMeasured":false,"signedWalletEnvelopesIncluded":false,"signingPerformed":false,"deploymentPerformed":false,
        "canonicalSettlementObserved":false,"publicDataRetrievalObserved":false,"p5_3Accepted":false,
        "liveApprovalRequired":true,"perCallFreshFundingRequired":true,"targetTimeEligibilityMustBeRevalidated":true,
        "automaticRetries":false});
    let sha256 = literal::hash_value(b"ALPH/L2/testnet-frozen-plan/v1", &value)?;
    Ok(FrozenPlan { value, sha256 })
}

pub(crate) fn prerequisites(
    actor: Option<&Actor>,
    policy: Option<&Policy>,
    deployments: Option<&[Deployment; 3]>,
    batches: Option<&[PreparedBatch; 2]>,
    compiled_operations: usize,
) -> Value {
    let mut missing = Vec::new();
    if actor.is_none() {
        missing.push("actual-group0-signer-public-key-and-canonical-funding-source");
    }
    if policy.is_none() {
        missing.push("independently-approved-testnet-genesis-program-profile-and-explicit-limits");
    }
    if deployments.is_none() {
        missing.push("three-exact-compiled-and-funded-unsigned-deployment-transactions");
    }
    if batches.is_none() {
        missing.push(
            "two-real-receipts-and-complete-data-for-actual-factory-domain-and-consecutive-anchors",
        );
    }
    if compiled_operations != 30 {
        missing.push("thirty-independently-reviewed-pinned-compiler-script-artifacts");
    }
    json!({"schema":1,"scope":"offline-prerequisite-report","missing":missing,
        "presenceOnly":true,"contentsValidated":false,"staticPlanFinalized":false,
        "fakeDeploymentIdsEmitted":false,"signable":false,"signingPerformed":false,"deploymentPerformed":false,
        "publicTestnetAccepted":false,"p5_3Accepted":false,
        "remainingBeforeLiveOperation":["explicit-disclosure-signing-funding-fee-approval",
            "fresh-head-funding-capability-for-each-call","canonical-creation-and-parent-confirmation",
            "independent-public-data-retrieval-and-native-reconstruction"]})
}
