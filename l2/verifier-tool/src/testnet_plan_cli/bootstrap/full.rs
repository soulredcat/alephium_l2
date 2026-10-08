//! Four conditional private operations, preserving typed predictions in memory.
use super::super::{compile, io};
use super::{funding, limits, package};
use crate::testnet_plan::{
    CompiledScript, Deployment, FrozenArtifacts, ScriptDraft, prepare_factory, prepare_initialize,
};
use alephium_l2_sdk::alephium::current_funding::CurrentFixedFundingObservation;
use alloy_primitives::U256;
use serde_json::{Value, json};
use std::path::Path;

pub(super) struct Review {
    pub records: Vec<Value>,
    pub new_compiler_records: Vec<Value>,
    pub dependencies_and_budget: Value,
    pub deployments: [Deployment; 3],
}

pub(super) fn four(
    output: &Path,
    jar: &Path,
    frozen: &FrozenArtifacts,
    context: &package::Context<'_>,
    templates: (&[ScriptDraft; 2], &[CompiledScript; 2]),
    observed: &CurrentFixedFundingObservation,
) -> Result<Review, String> {
    let init_minimum = context
        .budget
        .fee
        .checked_add(context.config.funding.minimum_change_reserve_atto)
        .ok_or("Initialization fee plus change reserve overflows")?;
    let subsets = funding::select_four(
        observed,
        context.budget.adequate_single_output,
        init_minimum,
    )?;
    let (drafts, scripts) = templates;
    let proof = package::one(
        output,
        "proof-template",
        context,
        &drafts[0],
        &scripts[0],
        &subsets[0],
    )?;
    let data = package::one(
        output,
        "data-template",
        context,
        &drafts[1],
        &scripts[1],
        &subsets[1],
    )?;
    let factory_draft = prepare_factory(
        frozen,
        &context.inputs.policy,
        &context.inputs.actor,
        proof
            .deployment
            .as_ref()
            .ok_or("Typed proof deployment is missing")?,
        data.deployment
            .as_ref()
            .ok_or("Typed data deployment is missing")?,
        context.inputs.limits[0].clone(),
    )?;
    let (factory_script, factory_compiler) =
        compile::one_bootstrap(jar, output, &factory_draft, &context.inputs.artifacts)?;
    let factory = package::one(
        output,
        "factory",
        context,
        &factory_draft,
        &factory_script,
        &subsets[2],
    )?;
    let init_limit = limits::initialization_limit(&context.inputs.limits[0])?;
    let init_draft = prepare_initialize(
        &context.inputs.policy,
        &context.inputs.actor,
        factory
            .deployment
            .as_ref()
            .ok_or("Typed factory deployment is missing")?,
        init_limit,
    )?;
    let (init_script, init_compiler) =
        compile::one_bootstrap(jar, output, &init_draft, &context.inputs.artifacts)?;
    let initialize = package::one(
        output,
        "initialize",
        context,
        &init_draft,
        &init_script,
        &subsets[3],
    )?;
    let operations = [proof, data, factory, initialize];
    let mut keys = std::collections::BTreeSet::new();
    let mut fees = U256::ZERO;
    let mut deposits = U256::ZERO;
    for operation in &operations {
        let refs = operation.unsigned.input_refs();
        if refs.len() != 1 || !keys.insert(refs[0].key) {
            return Err("Four bootstrap unsigned transactions reuse an input key".into());
        }
        fees = fees
            .checked_add(operation.unsigned.fee())
            .ok_or("Four-operation fee sum overflows")?;
        deposits = deposits
            .checked_add(
                operation
                    .unsigned
                    .operation()
                    .spec()
                    .limits
                    .contract_deposit,
            )
            .ok_or("Four-operation deposit sum overflows")?;
    }
    let fee_ceiling = context
        .budget
        .fee
        .checked_mul(U256::from(4))
        .ok_or("Four-operation fee ceiling overflows")?;
    let deposit_ceiling = context
        .budget
        .deposit
        .checked_mul(U256::from(3))
        .ok_or("Three-deployment deposit ceiling overflows")?;
    let debit = fees
        .checked_add(deposits)
        .ok_or("Four-operation debit sum overflows")?;
    let debit_ceiling = fee_ceiling
        .checked_add(deposit_ceiling)
        .ok_or("Bootstrap debit ceiling overflows")?;
    if fees != fee_ceiling
        || deposits != deposit_ceiling
        || debit != debit_ceiling
        || fees > context.config.fee_cap_atto
        || deposits > context.config.deposit_cap_atto
        || debit > context.config.debit_cap_atto
        || operations[3].deployment.is_some()
    {
        return Err(
            "Four-operation private package differs from declared bootstrap and full-plan ceilings"
                .into(),
        );
    }
    let dependencies = json!({"schema": 1, "operationCount": 4, "deploymentCount": 3,
        "unsignedFeeAtto": fees.to_string(), "contractDepositAtto": deposits.to_string(), "maximumDebitAtto": debit.to_string(),
        "initializationDepositAtto": "0", "gasMeasured": false, "fourDistinctCurrentInputKeys": true,
        "typedValidatedUnsignedAndDeploymentsRetainedThroughGraphConstruction": true,
        "capabilitiesReconstructedFromJSON": false, "predictedChangeOrFutureOutpointsUsed": false,
        "orderedLiveDependencies": ["proof/data templates canonically created at exact predicted IDs with pinned code and constructor state",
            "factory creation only after canonical template confirmation", "initialization only after canonical factory confirmation and exact uninitialized state"],
        "beforeEachLiveDispatch": ["explicit human scope approval", "fresh eligible funding", "durable intent and reservations",
            "exact script/policy review and distinct publisher handoff policy hash", "dependency confirmation and expected state checks"],
        "conditionalUnsignedDraftsOnly": true, "actualCanonicalDependenciesVerified": false,
        "walletPossessionVerified": false, "liveApprovalGranted": false, "signing": false, "submission": false,
        "staticPlanFinalized": false, "signable": false, "fullThirtyOperationPacketFinalized": false, "p5Complete": false});
    io::write_json(
        &output.join("four-operation-dependencies.json"),
        &dependencies,
    )?;
    let records = operations
        .iter()
        .map(|operation| operation.review.clone())
        .collect();
    let [proof, data, factory, _initialize] = operations;
    let deployments = [
        proof
            .deployment
            .ok_or("Validated proof deployment disappeared")?,
        data.deployment
            .ok_or("Validated data deployment disappeared")?,
        factory
            .deployment
            .ok_or("Validated factory deployment disappeared")?,
    ];
    Ok(Review {
        records,
        new_compiler_records: vec![factory_compiler, init_compiler],
        dependencies_and_budget: dependencies,
        deployments,
    })
}
