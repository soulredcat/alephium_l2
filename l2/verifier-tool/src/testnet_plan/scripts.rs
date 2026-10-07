//! Fixed Ralph syntax; external text never enters identifier/expression positions.
use super::{artifacts::FrozenArtifacts, literal, types::*};
use num_bigint::BigUint;
use serde_json::{Value, json};

pub(super) fn draft(
    kind: &'static str,
    batch: Option<u8>,
    body: String,
    arguments: Value,
    effect: Value,
    limits: OperationLimit,
) -> Result<ScriptDraft, String> {
    let source = format!("TxScript Main {{\n{body}\n}}\n");
    if source.len() > 131_072 {
        return Err("Instantiated script source exceeds planner bound".into());
    }
    let source_sha256 = literal::sha(source.as_bytes());
    let argument_sha256 = literal::hash_value(b"ALPH/L2/testnet-arguments/v1", &arguments)?;
    let expected_effect_sha256 = literal::hash_value(b"ALPH/L2/testnet-effects/v1", &effect)?;
    let policy = json!({"schema":1,"kind":kind,"batch":batch,
        "sourceSha256":hex::encode(source_sha256),"argumentsSha256":hex::encode(argument_sha256),
        "expectedEffectSha256":hex::encode(expected_effect_sha256),"limits":limits.value()});
    let operation_policy_sha256 =
        literal::hash_value(b"ALPH/L2/testnet-operation-policy/v1", &policy)?;
    Ok(ScriptDraft {
        kind,
        batch,
        source,
        source_sha256,
        argument_sha256,
        expected_effect: effect,
        expected_effect_sha256,
        operation_policy_sha256,
        limits,
    })
}

pub(crate) fn prepare_templates(
    artifacts: &FrozenArtifacts,
    policy: &Policy,
    actor: &Actor,
    limits: [OperationLimit; 2],
) -> Result<[ScriptDraft; 2], String> {
    policy.validate(actor)?;
    let caller = literal::caller(actor)?;
    let zero = literal::bytes(&[0; 32]);
    let zero18 = format!("[{}]", ["0"; 18].join(", "));
    let zero12 = format!("[{}]", ["0"; 12].join(", "));
    let zero6 = format!("[{}]", ["0"; 6].join(", "));
    let [proof_limit, data_limit] = limits;
    proof_limit.validate(&policy.minimum_contract_deposit)?;
    data_limit.validate(&policy.minimum_contract_deposit)?;
    let proof_body = format!(
        "    let (imm, mutFields) = Risc0StagedReceiptVerifier.encodeFields!(\n        {}, {}, 0, 0, {}, {}, {}, {}, {}, {}, {})\n    let created = createContract!{{{} -> ALPH: {}}}({}, imm, mutFields)\n    assert!(size!(created) == 32, 1700)",
        crate::cases::FP_MODULUS,
        zero,
        zero18,
        zero18,
        zero12,
        zero12,
        zero12,
        zero6,
        zero,
        caller,
        literal::amount(&proof_limit.deposit)?,
        literal::bytes(&artifacts.proof.bytecode)
    );
    let proof = draft(
        "deploy-proof-template",
        None,
        proof_body,
        json!({"initialStatus":0,"initialCursor":0,"payloadSha256":hex::encode([0;32]),"allArithmeticFieldsZero":true}),
        json!({"operation":"create-contract","contractType":"Risc0StagedReceiptVerifier",
            "expectedCodeHash":hex::encode(artifacts.proof.code_hash),"constructor":"fixed-prime, zero-payload, exact-zero-arithmetic-state",
            "createdOutputIndex":"validated-unsigned-fixed-output-count","actualCreatedIdentityMustMatchPrediction":true}),
        proof_limit,
    )?;
    let data_body = format!(
        "    let (imm, mutFields) = Risc0BatchData.encodeFields!(#00)\n    let created = createContract!{{{} -> ALPH: {}}}({}, imm, mutFields)\n    assert!(size!(created) == 32, 1700)",
        caller,
        literal::amount(&data_limit.deposit)?,
        literal::bytes(&artifacts.data.bytecode)
    );
    let data = draft(
        "deploy-data-template",
        None,
        data_body,
        json!({"templateData":"00"}),
        json!({"operation":"create-contract","contractType":"Risc0BatchData","expectedCodeHash":hex::encode(artifacts.data.code_hash),
            "immutableTemplateDataSha256":hex::encode(literal::sha(&[0])),"mutableFields":0,
            "createdOutputIndex":"validated-unsigned-fixed-output-count","actualCreatedIdentityMustMatchPrediction":true}),
        data_limit,
    )?;
    Ok([proof, data])
}

pub(crate) fn prepare_factory(
    artifacts: &FrozenArtifacts,
    policy: &Policy,
    actor: &Actor,
    proof: &Deployment,
    data: &Deployment,
    limits: OperationLimit,
) -> Result<ScriptDraft, String> {
    policy.validate(actor)?;
    limits.validate(&policy.minimum_contract_deposit)?;
    if proof.kind != "deploy-proof-template"
        || data.kind != "deploy-data-template"
        || proof.expected_code_hash != artifacts.proof.code_hash
        || data.expected_code_hash != artifacts.data.code_hash
    {
        return Err("Template deployment roles/code hashes differ".into());
    }
    for deployment in [proof, data] {
        if deployment.group != 0
            || deployment.contract_id == [0; 32]
            || deployment.caller_public_key_sha256 != literal::sha(&actor.public_key)
            || deployment.funding_source != actor.canonical_source
        {
            return Err("Actual reviewed template deployment identities required".into());
        }
    }
    let args = vec![
        literal::bytes(&proof.contract_id),
        literal::bytes(&artifacts.proof.code_hash),
        literal::bytes(&data.contract_id),
        literal::bytes(&artifacts.data.code_hash),
        literal::bytes(&policy.approved_image),
        "#01".into(),
        literal::bytes(&policy.l1_genesis),
        policy.l2_chain_id.to_string(),
        literal::bytes(&policy.l2_genesis),
        literal::bytes(&policy.execution_profile),
        literal::bytes(&policy.genesis_checkpoint_sha256),
        literal::bytes(&policy.genesis_head),
        literal::bytes(&policy.transport_limits),
        policy.max_future_seconds.to_string(),
        "0".into(),
        literal::bytes(&[0; 80]),
        literal::bytes(&[0; 32]),
    ];
    let body = format!(
        "    let (imm, mutFields) = Risc0BatchSettlementFactory.encodeFields!({})\n    let created = createContract!{{{} -> ALPH: {}}}({}, imm, mutFields)\n    assert!(size!(created) == 32, 1700)",
        args.join(", "),
        literal::caller(actor)?,
        literal::amount(&limits.deposit)?,
        literal::bytes(&artifacts.factory.bytecode)
    );
    draft(
        "deploy-factory",
        None,
        body,
        json!({"canonicalConstructorLiterals":args}),
        json!({"operation":"create-contract","contractType":"Risc0BatchSettlementFactory",
            "expectedCodeHash":hex::encode(artifacts.factory.code_hash),"proofTemplateId":hex::encode(proof.contract_id),
            "dataTemplateId":hex::encode(data.contract_id),"network":1,"group":0,"initialized":0,
            "initialHead":"zero80","initialRoot":"zero32","approvedCheckpointSha256":hex::encode(policy.genesis_checkpoint_sha256),
            "futureDriftSeconds":policy.max_future_seconds,"createdOutputIndex":"validated-unsigned-fixed-output-count",
            "actualCreatedIdentityMustMatchPrediction":true}),
        limits,
    )
}

pub(crate) fn prepare_initialize(
    policy: &Policy,
    actor: &Actor,
    factory: &Deployment,
    limits: OperationLimit,
) -> Result<ScriptDraft, String> {
    policy.validate(actor)?;
    if factory.kind != "deploy-factory"
        || factory.group != 0
        || factory.contract_id == [0; 32]
        || factory.caller_public_key_sha256 != literal::sha(&actor.public_key)
        || factory.funding_source != actor.canonical_source
    {
        return Err("Initialization requires the exact actor's reviewed factory deployment".into());
    }
    limits.validate(&BigUint::from(0_u8))?;
    let root = policy.genesis_root(&factory.contract_id);
    let body = format!(
        "    let result = Risc0BatchSettlementFactory({}).initializeGenesis({})\n    assert!(result == {}, 1701)",
        literal::bytes(&factory.contract_id),
        literal::bytes(&policy.genesis_checkpoint),
        literal::bytes(&root)
    );
    draft(
        "initialize-genesis",
        None,
        body,
        json!({"factory":hex::encode(factory.contract_id),
        "checkpointSha256":hex::encode(policy.genesis_checkpoint_sha256)}),
        json!({"operation":"initialize-canonical-genesis","factory":hex::encode(factory.contract_id),
            "checkpointSha256":hex::encode(policy.genesis_checkpoint_sha256),"acceptedHead":hex::encode(policy.genesis_head),
            "acceptedRoot":hex::encode(root),"initialized":1,"observeExactCanonicalContractState":true}),
        limits,
    )
}
