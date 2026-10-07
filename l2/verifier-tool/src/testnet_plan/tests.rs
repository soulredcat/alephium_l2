//! One pure aggregate over real compiler artifacts and explicitly simulated funding.
//! Prefix/framing fixtures below are not EVM checkpoints or genuine receipts.
#[path = "tests/continuation.rs"]
mod continuation;
#[path = "tests/funding.rs"]
mod funding;
use super::{artifacts::FrozenArtifacts, deployment, literal, plan, scripts, types::*};
use num_bigint::BigUint;
use serde_json::{Value, json};

pub(crate) struct DeploymentVector {
    pub tx_id: [u8; 32],
    pub output_index: u32,
    /// Root supplies an independently computed source-derived expectation.
    /// This is not labelled an upstream hardcoded golden transaction.
    pub expected_contract_id: [u8; 32],
}

pub(crate) fn pure_aggregate(
    artifacts: &FrozenArtifacts,
    policy: &Policy,
    actor: &Actor,
    compiled: &[CompiledScript; 2],
    vector: &DeploymentVector,
) -> Result<Value, String> {
    policy.validate(actor)?;
    let limit = budget(policy.minimum_contract_deposit.clone());
    let templates =
        scripts::prepare_templates(artifacts, policy, actor, [limit.clone(), limit.clone()])?;
    let mut records = Vec::new();
    check(
        &mut records,
        "current-artifacts-code-and-estimated-field-bounds",
        artifacts.proof.bytecode.len() <= 32768
            && artifacts.data.bytecode.len() <= 32768
            && artifacts.factory.bytecode.len() <= 32768
            && 2656 < 3072
            && 609 < 3072
            && 3000 < 3072,
    )?;
    let mut bad_key = actor.public_key;
    bad_key[0] = 0;
    check(
        &mut records,
        "invalid-caller-key-literal",
        literal::caller(&Actor {
            public_key: bad_key,
            canonical_source: actor.canonical_source,
        })
        .is_err(),
    )?;
    let mut foreign = None;
    for tag in 1..=255_u8 {
        let mut key = [tag; 33];
        key[0] = 2;
        if literal::caller(&Actor {
            public_key: key,
            canonical_source: actor.canonical_source,
        })
        .is_err()
        {
            foreign = Some(key);
            break;
        }
    }
    check(&mut records, "foreign-group-key-refused", foreign.is_some())?;
    let injected = b"00); transferAlphToAddress!(@evil, 1) //";
    let encoded = literal::bytes(injected);
    check(
        &mut records,
        "typed-byte-literal-does-not-interpolate-language",
        encoded.starts_with('#')
            && encoded[1..].bytes().all(|byte| byte.is_ascii_hexdigit())
            && !encoded.contains("transferAlph"),
    )?;
    check(
        &mut records,
        "u256-literal-overflow",
        literal::amount(&(BigUint::from(1_u8) << 256)).is_err(),
    )?;
    let pins = ReviewedScriptPins {
        artifact_sha256: compiled[0].artifact_sha256,
        source_sha256: templates[0].source_sha256,
        script_sha256: literal::sha(&[0]),
        compiler_jar_sha256: hex::decode(crate::compiler::JAR_SHA256)
            .map_err(|_| "Compiler pin invalid")?
            .try_into()
            .map_err(|_| "Compiler pin width invalid")?,
    };
    check(
        &mut records,
        "empty-script-refused",
        CompiledScript::from_reviewed_bytes(&templates[0], vec![], &pins).is_err(),
    )?;
    check(
        &mut records,
        "oversized-script-refused",
        CompiledScript::from_reviewed_bytes(&templates[0], vec![0; 32769], &pins).is_err(),
    )?;
    let source_bad = ReviewedScriptPins {
        source_sha256: [5; 32],
        ..pins
    };
    check(
        &mut records,
        "compile-source-rebinding-refused",
        CompiledScript::from_reviewed_bytes(&templates[0], vec![0], &source_bad).is_err(),
    )?;
    let mut too_much = budget(policy.minimum_contract_deposit.clone());
    too_much.gas_amount_max = 5_000_001;
    check(
        &mut records,
        "gas-cap-bound",
        too_much.validate(&policy.minimum_contract_deposit).is_err(),
    )?;
    too_much.gas_amount_max = 19_999;
    check(
        &mut records,
        "below-minimum-gas-cap",
        too_much.validate(&policy.minimum_contract_deposit).is_err(),
    )?;
    too_much.gas_amount_max = 5_000_000;
    too_much.gas_price_max = BigUint::from(99_999_999_999_u64);
    check(
        &mut records,
        "below-minimum-gas-price",
        too_much.validate(&policy.minimum_contract_deposit).is_err(),
    )?;
    too_much.gas_price_max = BigUint::from(10_u8).pow(27);
    check(
        &mut records,
        "exclusive-gas-price-upper-bound",
        too_much.validate(&policy.minimum_contract_deposit).is_err(),
    )?;
    let mut no_deposit = budget(BigUint::from(0_u8));
    check(
        &mut records,
        "exact-deployment-deposit",
        no_deposit
            .validate(&policy.minimum_contract_deposit)
            .is_err(),
    )?;
    no_deposit.request_bytes_max = 1_048_577;
    check(
        &mut records,
        "request-bound",
        no_deposit.validate(&BigUint::from(0_u8)).is_err(),
    )?;
    check(
        &mut records,
        "independent-source-derived-normal-deployment-vector",
        deployment::derive_contract_id(&vector.tx_id, vector.output_index)?
            == vector.expected_contract_id,
    )?;
    check(
        &mut records,
        "signed-int32-index-overflow",
        deployment::derive_contract_id(&vector.tx_id, u32::MAX).is_err(),
    )?;
    let zero = funding::validated(
        &templates[0],
        &compiled[0],
        policy,
        actor,
        1,
        false,
        5_000_000,
        100_000_000_000,
    )?;
    let one = funding::validated(
        &templates[1],
        &compiled[1],
        policy,
        actor,
        2,
        true,
        5_000_000,
        100_000_000_000,
    )?;
    let proof = Deployment::from_unsigned(&templates[0], &compiled[0], &zero, actor, policy)?;
    let data = Deployment::from_unsigned(&templates[1], &compiled[1], &one, actor, policy)?;
    check(
        &mut records,
        "sdk-actual-zero-fixed-output-index",
        zero.fixed_output_count() == 0
            && proof.creation_output_index == 0
            && proof.tx_id() == zero.tx_id().0
            && proof.contract_id() == deployment::derive_contract_id(&proof.tx_id(), 0)?
            && proof.artifact_sha256 == compiled[0].artifact_sha256(),
    )?;
    check(
        &mut records,
        "sdk-actual-one-fixed-output-index",
        one.fixed_output_count() == 1
            && data.creation_output_index == 1
            && data.tx_id() == one.tx_id().0
            && data.contract_id() == deployment::derive_contract_id(&data.tx_id(), 1)?
            && data.artifact_sha256 == compiled[1].artifact_sha256(),
    )?;
    check(
        &mut records,
        "normal-and-child-derivation-distinct",
        deployment::derive_contract_id(&vector.tx_id, 1)?
            != literal::child(&vector.tx_id, b"p5v1/proof/test"),
    )?;
    let small = OperationLimit {
        gas_amount_max: 100_000,
        ..budget(policy.minimum_contract_deposit.clone())
    };
    let narrow = scripts::prepare_templates(artifacts, policy, actor, [small.clone(), small])?;
    let gas_over = funding::validated(
        &narrow[0],
        &compiled[0],
        policy,
        actor,
        3,
        false,
        1_000_000,
        100_000_000_000,
    )?;
    check(
        &mut records,
        "approved-gas-ceiling-cannot-exceed-frozen-draft",
        Deployment::from_unsigned(&narrow[0], &compiled[0], &gas_over, actor, policy).is_err(),
    )?;
    let price_over = funding::validated(
        &templates[0],
        &compiled[0],
        policy,
        actor,
        4,
        false,
        5_000_000,
        200_000_000_000,
    )?;
    check(
        &mut records,
        "approved-price-ceiling-cannot-exceed-frozen-draft",
        Deployment::from_unsigned(&templates[0], &compiled[0], &price_over, actor, policy).is_err(),
    )?;
    check(
        &mut records,
        "initializer-rejects-data-template-role",
        scripts::prepare_initialize(policy, actor, &data, budget(BigUint::from(0_u8))).is_err(),
    )?;
    let factory = scripts::prepare_factory(
        artifacts,
        policy,
        actor,
        &proof,
        &data,
        budget(policy.minimum_contract_deposit.clone()),
    )?;
    check(
        &mut records,
        "factory-script-contains-no-own-predicted-identity",
        !factory.source.contains("selfContractId")
            && !factory.source.contains("predictedContractId"),
    )?;
    let pending = plan::prerequisites(Some(actor), Some(policy), None, None, 2);
    check(
        &mut records,
        "missing-real-funding-and-domain-receipts-never-signable",
        pending["signable"] == false
            && pending["staticPlanFinalized"] == false
            && pending["missing"]
                .as_array()
                .is_some_and(|missing| missing.len() >= 3),
    )?;
    continuation::framing(policy, &mut records)?;
    Ok(
        json!({"scope":"pure-offline-planner-aggregate","passed":true,"checks":records.len(),"results":records,
        "funding":"explicit simulated SDK callbacks only","compilerArtifactInputs":"real independently pinned artifacts",
        "deploymentVector":"source-derived recipe plus independently supplied root expectation; not upstream tx golden",
        "signaturesCreated":false,"networkCalls":0,"vmCalls":0,"genuineReceiptClaims":false,
        "actualFundingEstablished":false,"publicTestnetAccepted":false,"signable":false}),
    )
}

fn budget(deposit: BigUint) -> OperationLimit {
    let fee = BigUint::from(10_000_000_000_000_000_u64);
    OperationLimit {
        gas_amount_max: 5_000_000,
        gas_price_max: BigUint::from(100_000_000_000_u64),
        fee_max: fee.clone(),
        debit_max: &fee + &deposit,
        deposit,
        request_bytes_max: 1_048_576,
        response_bytes_max: 1_048_576,
        connect_timeout_ms: 10_000,
        request_timeout_ms: 10_000,
    }
}

fn check(records: &mut Vec<Value>, name: &'static str, condition: bool) -> Result<(), String> {
    records.push(json!({"name":name,"passed":condition}));
    if condition {
        Ok(())
    } else {
        Err(format!("Offline aggregate invariant failed: {name}"))
    }
}
