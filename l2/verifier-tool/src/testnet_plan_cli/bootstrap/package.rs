//! Private validated unsigned operations; no signature or durable reservation.
use super::super::{io, policy::Inputs};
use super::{approval, funding, limits::Budget};
use crate::{
    p5_env::BootstrapConfig,
    testnet_plan::{CompiledScript, Deployment, ScriptDraft},
};
use alephium_l2_sdk::alephium::{
    ValidatedUnsignedAlephium,
    current_funding::{CurrentFixedFundingObservation, materialize_current_unsigned},
};
use alloy_primitives::B256;
use serde_json::{Value, json};
use std::path::Path;

pub(super) struct Context<'a> {
    pub config: &'a BootstrapConfig,
    pub inputs: &'a Inputs,
    pub budget: &'a Budget,
    pub scope: B256,
}

pub(super) struct PreparedOperation {
    pub unsigned: ValidatedUnsignedAlephium,
    pub deployment: Option<Deployment>,
    pub review: Value,
}

pub(super) fn two(
    output: &Path,
    config: &BootstrapConfig,
    inputs: &Inputs,
    budget: &Budget,
    templates: (&[ScriptDraft; 2], &[CompiledScript; 2]),
    subsets: &[CurrentFixedFundingObservation; 2],
    scope: B256,
) -> Result<Vec<Value>, String> {
    let (drafts, scripts) = templates;
    let first = subsets[0]
        .outputs()
        .first()
        .ok_or("First template funding subset is empty")?
        .reference
        .key;
    if subsets[0].outputs().len() != 1
        || subsets[1].outputs().len() != 1
        || subsets[1].outputs()[0].reference.key == first
    {
        return Err("Template funding subsets require one disjoint current output each".into());
    }
    let context = Context {
        config,
        inputs,
        budget,
        scope,
    };
    let proof = one(
        output,
        "proof-template",
        &context,
        &drafts[0],
        &scripts[0],
        &subsets[0],
    )?;
    let data = one(
        output,
        "data-template",
        &context,
        &drafts[1],
        &scripts[1],
        &subsets[1],
    )?;
    Ok(vec![proof.review, data.review])
}

pub(super) fn one(
    output: &Path,
    name: &str,
    context: &Context<'_>,
    draft: &ScriptDraft,
    script: &CompiledScript,
    subset: &CurrentFixedFundingObservation,
) -> Result<PreparedOperation, String> {
    let is_deployment = match (name, draft.kind()) {
        ("proof-template", "deploy-proof-template")
        | ("data-template", "deploy-data-template")
        | ("factory", "deploy-factory") => true,
        ("initialize", "initialize-genesis") => false,
        _ => {
            return Err("Bootstrap operation role differs from its fixed private directory".into());
        }
    };
    if subset.outputs().len() != 1 {
        return Err("Bootstrap operation requires one selected current input".into());
    }
    let directory = output.join(name);
    let operation = approval::operation(
        context.config,
        context.budget,
        draft,
        script,
        subset.pin(),
        context.scope,
    )?;
    let intent = json!({"schema": 1, "kind": draft.kind(), "operation": approval::metadata(&operation),
        "funding": funding::metadata(subset)?, "scope": "private local unsigned bootstrap construction only",
        "signing": false, "submission": false, "durableInputReservation": false});
    io::write_json(&directory.join("unsigned-intent.json"), &intent)?;
    let unsigned = materialize_current_unsigned(
        &operation,
        subset,
        context.config.max_gas,
        context.config.max_gas_price,
    )
    .map_err(|error| error.to_string())?;
    if unsigned.input_refs().len() != 1
        || unsigned.input_refs()[0] != subset.outputs()[0].reference
        || unsigned.fixed_output_count() != 1
    {
        return Err(
            "Validated unsigned bootstrap differs from its current input and exact change output"
                .into(),
        );
    }
    let request_floor = unsigned
        .unsigned_bytes()
        .len()
        .checked_mul(2)
        .and_then(|length| length.checked_add(4096))
        .ok_or("Bootstrap request size overflows")?;
    if request_floor > draft.limits().request_bytes_max {
        return Err("Unsigned bootstrap request exceeds its frozen byte ceiling".into());
    }
    let deployment = if is_deployment {
        Some(Deployment::from_unsigned(
            draft,
            script,
            &unsigned,
            &context.inputs.actor,
            &context.inputs.policy,
        )?)
    } else {
        None
    };
    let bytes = unsigned.unsigned_bytes();
    io::write(&directory.join("unsigned.bin"), bytes)?;
    let review = json!({"schema": 1, "kind": draft.kind(), "unsignedFile": format!("{name}/unsigned.bin"),
        "unsignedBytes": bytes.len(), "unsignedSha256": hex::encode(io::sha(bytes)),
        "nativeTransactionId": hex::encode(unsigned.tx_id().as_slice()),
        "sourceSha256": hex::encode(draft.source_sha256()), "scriptArtifactSha256": hex::encode(script.artifact_sha256()),
        "scriptSha256": hex::encode(script.script_sha256()), "scriptBlake2b256": hex::encode(script.script_blake2b256()),
        "argumentsSha256": hex::encode(draft.arguments_sha256()),
        "expectedEffectSha256": hex::encode(draft.expected_effect_sha256()), "expectedEffect": draft.expected_effect(),
        "plannerOperationPolicySha256": hex::encode(draft.operation_policy_sha256()), "limits": draft.limits().value(),
        "operation": approval::metadata(&operation), "fundingInputs": funding::metadata(subset)?,
        "inputAmountAtto": unsigned.input_amount().to_string(), "feeAtto": unsigned.fee().to_string(),
        "depositAtto": unsigned.operation().spec().limits.contract_deposit.to_string(),
        "sameOwnerChangeAtto": unsigned.change().to_string(), "fixedOutputCount": unsigned.fixed_output_count(),
        "deployment": deployment.as_ref().map(Deployment::review_metadata),
        "creationIndexAuthority": if is_deployment { "exact validated unsigned fixed-output count, not a guessed zero" } else { "not a contract creation" },
        "selectedInputIdentifiersAreNotDurableReservations": true, "durableInputReservationEstablished": false,
        "fullP2PKHUnsignedEncoding": true, "localExactScriptValidationPassed": true,
        "walletPossessionVerified": false, "independentLiveScriptReviewPending": true,
        "liveSigningApproved": false, "signaturesCreated": false, "submitted": false,
        "actualDeploymentObserved": false, "staticPlanFinalized": false, "signable": false, "p5Complete": false});
    io::write_json(&directory.join("unsigned-review.json"), &review)?;
    Ok(PreparedOperation {
        unsigned,
        deployment,
        review,
    })
}
