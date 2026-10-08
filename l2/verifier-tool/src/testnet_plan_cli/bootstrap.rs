//! Actual configured account, private unsigned bootstrap drafts; never live ops.
mod approval;
mod full;
mod funding;
mod genesis;
mod limits;
mod package;

use super::{artifacts, compile, io, policy};
use crate::{
    p5_env,
    testnet_plan::{prepare_templates, prerequisites},
};
use alephium_l2_sdk::alephium::current_funding::CurrentFundingPolicy;
use alloy_primitives::B256;
use serde_json::{Value, json};
use std::path::Path;

pub(crate) fn run_bootstrap(
    jar: &Path,
    output: &Path,
    env: &Path,
    reviewed_genesis_record: &Path,
    policy_json: &Path,
) -> Result<Value, String> {
    run_inner(
        jar,
        output,
        env,
        reviewed_genesis_record,
        policy_json,
        None,
        false,
    )
}

pub(crate) fn run_bootstrap_with_compiled(
    jar: &Path,
    output: &Path,
    env: &Path,
    reviewed_genesis_record: &Path,
    policy_json: &Path,
    prior_compiled_dir: &Path,
) -> Result<Value, String> {
    run_inner(
        jar,
        output,
        env,
        reviewed_genesis_record,
        policy_json,
        Some(prior_compiled_dir),
        false,
    )
}

pub(crate) fn run_bootstrap_review_full(
    jar: &Path,
    output: &Path,
    env: &Path,
    reviewed_genesis_record: &Path,
    policy_json: &Path,
    prior_compiled_dir: &Path,
) -> Result<Value, String> {
    run_inner(
        jar,
        output,
        env,
        reviewed_genesis_record,
        policy_json,
        Some(prior_compiled_dir),
        true,
    )
}

fn run_inner(
    jar: &Path,
    output: &Path,
    env: &Path,
    reviewed_genesis_record: &Path,
    policy_json: &Path,
    prior_compiled_dir: Option<&Path>,
    full_review: bool,
) -> Result<Value, String> {
    let output = io::fresh_output(output)?;
    let compiler_contexts =
        (if prior_compiled_dir.is_some() { 0 } else { 2 }) + if full_review { 2 } else { 0 };
    let reused_templates = if prior_compiled_dir.is_some() { 2 } else { 0 };
    let operation_count = if full_review { 4 } else { 2 };
    let mut stage = "load_reviewed_configuration";
    let mut network_started = false;
    let result: Result<Value, String> = (|| {
        let env = io::existing(env)?;
        let config = p5_env::load_bootstrap_config(&env)?;
        let selected = genesis::load(reviewed_genesis_record)?;
        let funding_policy = CurrentFundingPolicy {
            minimum_confirmations: config.funding.minimum_confirmations,
            maximum_references: 64,
            maximum_creators: 64,
        };
        let source = funding_policy
            .source_id(&config.funding.origin, selected.pin)
            .map_err(|error| error.to_string())?;
        let original_policy = io::read(policy_json, 65536)?;
        let mut derived_policy = io::json(&original_policy)?;
        if derived_policy["canonicalSource"] != "derive-from-env-current-funding-v4"
            || !derived_policy["simulation"].is_null()
        {
            return Err("Actual bootstrap policy requires explicit SDK-derived source sentinel and simulation=null".into());
        }
        derived_policy
            .as_object_mut()
            .ok_or("Bootstrap policy must be an object")?
            .insert(
                "canonicalSource".into(),
                json!(hex::encode(source.as_slice())),
            );
        stage = "persist_pure_derived_policy";
        let derived_path = output.join("derived-policy.json");
        io::write_json(&derived_path, &derived_policy)?;
        let inputs = policy::load(
            &derived_path,
            &hex::encode(config.funding.caller_public_key),
            &hex::encode(selected.pin.hash.as_slice()),
        )?;
        if inputs.vector.is_some()
            || inputs.vector_sha256.is_some()
            || inputs.actor.canonical_source != source.0
            || inputs.actor.public_key != config.funding.caller_public_key
            || inputs.policy.l1_genesis != selected.pin.hash.0
        {
            return Err("Actual bootstrap policy reused simulated funding or mismatched the configured actor/domain/source".into());
        }
        stage = "reconcile_exact_configured_ceilings";
        let budget = limits::reconcile(&config, &inputs)?;
        let mut scope_bytes = b"ALPH/L2/private-bootstrap-review-scope/v1".to_vec();
        scope_bytes.extend_from_slice(&inputs.policy_sha256);
        scope_bytes.extend_from_slice(&selected.record_sha256);
        scope_bytes.extend_from_slice(&io::sha(&config.funding.caller_public_key));
        if full_review {
            scope_bytes.extend_from_slice(b"conditional-four-operation-subset/v1");
        }
        let scope = B256::from(io::sha(&scope_bytes));
        let intent = json!({"schema": 1, "scope": "actual-account-private-unsigned-bootstrap-draft", "status": "INTENT",
            "inputPolicySha256": hex::encode(io::sha(&original_policy)), "derivedPolicySha256": hex::encode(inputs.policy_sha256),
            "inputCanonicalSource": "derive-from-env-current-funding-v4", "derivedCanonicalSource": hex::encode(source.as_slice()),
            "canonicalSourceDerivation": "pure SDK current fixed funding source v4 from configured origin, selected genesis, three minima and bounded head-window policy",
            "callerPublicKeySha256": hex::encode(io::sha(&config.funding.caller_public_key)),
            "reviewedGenesisRecordSha256": hex::encode(selected.record_sha256), "reviewedGenesisAssociation": selected.association,
            "configuredOrigin": config.funding.origin, "budget": budget.metadata,
            "minimumFundingConfirmations": {"chain": config.funding.minimum_confirmations.chain,
                "fromGroup": config.funding.minimum_confirmations.from_group, "toGroup": config.funding.minimum_confirmations.to_group},
            "publicationScope": hex::encode(scope.as_slice()), "compilerContexts": compiler_contexts,
            "reusedActualCallerTemplates": reused_templates, "fundingObservationBundles": 1,
            "bootstrapOperationCount": operation_count, "fullFourOperationReview": full_review,
            "unchangedPureFixtureAggregateRepeated": false, "automaticRetry": false,
            "walletPossessionVerified": false, "signing": false, "submission": false, "dataUpload": false,
            "staticPlanFinalized": false, "signable": false, "p5Complete": false});
        stage = "persist_intent_before_compiler_or_GET";
        io::write_json(&output.join("bootstrap-intent.json"), &intent)?;
        stage = "load_pinned_compiler_and_artifacts";
        let jar = io::check_jar(jar)?;
        let (frozen, artifact_records) = artifacts::load(&inputs)?;
        let drafts = prepare_templates(
            &frozen,
            &inputs.policy,
            &inputs.actor,
            inputs.limits.clone(),
        )?;
        let (scripts, mut compiler_records) = if let Some(prior) = prior_compiled_dir {
            stage = "revalidate_and_copy_two_prior_actual_caller_templates";
            compile::two_reused(prior, &output, &drafts, &inputs.artifacts)?
        } else {
            stage = "compile_two_actual_caller_templates";
            compile::two_bootstrap(&jar, &output, &drafts, &inputs.artifacts)?
        };
        stage = "single_GET_funding_observation";
        network_started = true;
        let observed = funding::observe(&config, selected.pin, &funding_policy, source)?;
        io::write_json(
            &output.join("funding-observation.json"),
            &funding::metadata(&observed)?,
        )?;
        let (packages, dependencies, pending) = if full_review {
            stage = "construct_four_conditional_unsigned_operations";
            let context = package::Context {
                config: &config,
                inputs: &inputs,
                budget: &budget,
                scope,
            };
            let prepared = full::four(
                &output,
                &jar,
                &frozen,
                &context,
                (&drafts, &scripts),
                &observed,
            )?;
            let pending = prerequisites(
                Some(&inputs.actor),
                Some(&inputs.policy),
                Some(&prepared.deployments),
                None,
                operation_count,
            );
            compiler_records.extend(prepared.new_compiler_records);
            (
                prepared.records,
                Some(prepared.dependencies_and_budget),
                pending,
            )
        } else {
            stage = "select_two_disjoint_adequate_fixed_outputs";
            let subsets = funding::select(&observed, budget.adequate_single_output)?;
            stage = "materialize_two_local_unsigned_templates";
            (
                package::two(
                    &output,
                    &config,
                    &inputs,
                    &budget,
                    (&drafts, &scripts),
                    &subsets,
                    scope,
                )?,
                None,
                prerequisites(
                    Some(&inputs.actor),
                    Some(&inputs.policy),
                    None,
                    None,
                    operation_count,
                ),
            )
        };
        let review = json!({"schema": 1, "scope": "actual-account-private-unsigned-bootstrap-draft", "passed": true,
            "intent": intent, "preservedArtifacts": artifact_records, "compilerOutputs": compiler_records,
            "fundingObservation": funding::metadata(&observed)?, "unsignedTemplateDrafts": packages.iter().take(2).collect::<Vec<_>>(),
            "unsignedBootstrapOperations": packages, "bootstrapOperationCount": operation_count, "bootstrapDependenciesAndBudget": dependencies,
            "compilerContexts": compiler_contexts, "reusedActualCallerTemplates": reused_templates,
            "newCompilerSyntaxRun": prior_compiled_dir.is_none() || full_review, "fundingObservationBundles": 1, "pureFixtureAggregateExecutions": 0,
            "localExactScriptAndFundingValidationPassed": true, "independentLiveCompiledScriptReviewPending": true,
            "currentObservationIsAtomicSnapshot": false, "currentObservationIsAvailabilityAtAfterSnapshot": false,
            "currentFundingSourcePolicy": "SDK current-fixed-funding-source/v4", "maximumCanonicalHeadAdvance": 32,
            "durableInputReservationsEstablished": false,
            "walletPossessionVerified": false, "liveOperatorApprovalGranted": false,
            "publisherHandoffPolicyHash": null, "publisherHandoffPacketFinalized": false,
            "prerequisites": pending, "remaining": ["actual signing and template deployment with refreshed funding and durable intent/reservations",
                "factory deployment and initialization", "two new actual deployed-domain proofs and authenticated public data",
                "full thirty-operation packet, publisher handoff hashes and independent live compiled-script review"],
            "signaturesCreated": false, "submitted": false, "actualDeploymentObserved": false,
            "dataUploaded": false, "staticPlanFinalized": false, "signable": false,
            "publicTestnetAccepted": false, "p5Complete": false});
        stage = "persist_private_review_manifest";
        io::write_json(&output.join("review-manifest.json"), &review)?;
        Ok(
            json!({"scope": "actual-account-private-unsigned-bootstrap-draft", "passed": true,
            "compiledTemplates": 2, "compilerContexts": compiler_contexts, "reusedActualCallerTemplates": reused_templates,
            "unsignedTemplateDrafts": 2, "unsignedBootstrapOperations": operation_count, "fundingObservationBundles": 1,
            "pureFixtureAggregateExecutions": 0, "liveScriptReviewPending": true,
            "walletPossessionVerified": false, "signaturesCreated": false, "submitted": false,
            "actualDeploymentObserved": false, "staticPlanFinalized": false, "signable": false, "p5Complete": false}),
        )
    })();
    if let Err(error) = &result {
        let failure = json!({"schema": 1, "scope": "actual-account-private-unsigned-bootstrap-draft",
            "status": "FAILED/STOPPED", "passed": false, "stage": stage, "failureCategory": error,
            "GETObservationStarted": network_started, "priorPrivateOutputsPreserved": true, "automaticRetry": false,
            "signing": false, "submission": false, "dataUpload": false, "staticPlanFinalized": false,
            "signable": false, "p5Complete": false});
        if io::write_json(&output.join("failure.json"), &failure).is_err() {
            return Err("Bootstrap FAILED/STOPPED; failure report could not be flushed; partial outputs retained".into());
        }
    }
    result
}
