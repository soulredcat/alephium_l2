//! Exact configured ceilings; arithmetic is not gas measurement or permission.
use super::super::{io, policy::Inputs};
use crate::p5_env::BootstrapConfig;
use crate::testnet_plan::{OperationLimit, ScriptDraft};
use alloy_primitives::U256;
use num_bigint::BigUint;
use serde_json::{Value, json};

pub(super) struct Budget {
    pub fee: U256,
    pub deposit: U256,
    pub debit: U256,
    pub adequate_single_output: U256,
    pub metadata: Value,
}

pub(super) fn initialization_limit(template: &OperationLimit) -> Result<OperationLimit, String> {
    let mut limit = template.clone();
    limit.deposit = BigUint::from(0_u8);
    limit.debit_max = limit.fee_max.clone();
    limit.validate(&BigUint::from(0_u8))?;
    Ok(limit)
}

pub(super) fn operation_amounts(
    config: &BootstrapConfig,
    budget: &Budget,
    draft: &ScriptDraft,
) -> Result<(U256, U256, U256), String> {
    let limits = draft.limits();
    let required_deposit = match draft.kind() {
        "deploy-proof-template" | "deploy-data-template" | "deploy-factory" => budget.deposit,
        "initialize-genesis" => U256::ZERO,
        _ => return Err("Unsupported private bootstrap operation role".into()),
    };
    let fee = native(&limits.fee_max)?;
    let deposit = native(&limits.deposit)?;
    let debit = native(&limits.debit_max)?;
    let exact_debit = fee
        .checked_add(deposit)
        .ok_or("Bootstrap operation debit overflows")?;
    let role_debit = if required_deposit.is_zero() {
        budget.fee
    } else {
        budget.debit
    };
    if limits.gas_amount_max != config.max_gas
        || native(&limits.gas_price_max)? != config.max_gas_price
        || fee != budget.fee
        || deposit != required_deposit
        || debit != exact_debit
        || debit != role_debit
    {
        return Err(
            "Bootstrap operation differs from exact configured gas/fee/deposit/debit limits".into(),
        );
    }
    limits.validate(&BigUint::from_bytes_be(
        &required_deposit.to_be_bytes::<32>(),
    ))?;
    Ok((fee, deposit, debit))
}

pub(super) fn native(value: &BigUint) -> Result<U256, String> {
    if value.bits() > 256 {
        return Err("Bootstrap amount exceeds U256".into());
    }
    Ok(U256::from_be_slice(&value.to_bytes_be()))
}

pub(super) fn reconcile(config: &BootstrapConfig, inputs: &Inputs) -> Result<Budget, String> {
    let fee = U256::from(config.max_gas)
        .checked_mul(config.max_gas_price)
        .ok_or("Bootstrap per-operation ceiling overflows")?;
    let deposit = native(&inputs.policy.minimum_contract_deposit)?;
    let debit = fee
        .checked_add(deposit)
        .ok_or("Bootstrap template debit overflows")?;
    let full_fee = fee
        .checked_mul(U256::from(30))
        .ok_or("Thirty-operation fee ceiling overflows")?;
    let full_deposit = deposit
        .checked_mul(U256::from(7))
        .ok_or("Seven contract-deposit ceiling overflows")?;
    let full_debit = full_fee
        .checked_add(full_deposit)
        .ok_or("Full bootstrap debit ceiling overflows")?;
    if full_fee != config.fee_cap_atto
        || full_deposit != config.deposit_cap_atto
        || full_debit != config.debit_cap_atto
        || native(&inputs.total.fee_max)? != full_fee
        || native(&inputs.total.deposit_max)? != full_deposit
        || native(&inputs.total.debit_max)? != full_debit
        || inputs.policy.max_future_seconds != config.max_future_seconds
        || inputs.policy.confirmations != config.publisher_confirmations
    {
        return Err("Private policy differs from exact configured thirty-operation ceilings or time/confirmation policy".into());
    }
    for limit in &inputs.limits {
        if limit.gas_amount_max != config.max_gas
            || native(&limit.gas_price_max)? != config.max_gas_price
            || native(&limit.fee_max)? != fee
            || native(&limit.deposit)? != deposit
            || native(&limit.debit_max)? != debit
        {
            return Err("Template policy gas/fee/deposit/debit differs from the configured bootstrap ceiling".into());
        }
    }
    let adequate_single_output = debit
        .checked_add(config.funding.minimum_change_reserve_atto)
        .ok_or("Template debit plus one minimum change reserve overflows")?;
    let outbox = config
        .outbox_directory
        .to_str()
        .ok_or("Configured outbox path must be UTF-8")?;
    let metadata = json!({"gasAmountCeiling": config.max_gas, "gasPriceCeilingAtto": config.max_gas_price.to_string(),
        "templateFeeAtto": fee.to_string(), "templateDepositAtto": deposit.to_string(), "templateDebitAtto": debit.to_string(),
        "templateRequiredSingleOutputAtto": adequate_single_output.to_string(),
        "operationCountCeiling": 30, "contractDepositCountCeiling": 7,
        "fullFeeCeilingAtto": full_fee.to_string(), "fullDepositCeilingAtto": full_deposit.to_string(),
        "fullDebitCeilingAtto": full_debit.to_string(), "maxFutureSeconds": config.max_future_seconds,
        "publisherConfirmations": config.publisher_confirmations,
        "configuredOutboxDirectorySha256": hex::encode(io::sha(outbox.as_bytes())),
        "gasMeasured": false, "fullThirtyOperationPacketFinalized": false, "liveSpendingApproved": false});
    Ok(Budget {
        fee,
        deposit,
        debit,
        adequate_single_output,
        metadata,
    })
}
