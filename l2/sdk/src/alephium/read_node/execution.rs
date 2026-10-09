//! Pure ordinary-v0 execution decoding. No effects, approval, signing or reads.
use super::{
    GenesisProvenance, NodeVersion, TransactionDetailsObservation, TransactionOutcome,
    execution_outputs as fields, execution_types::*,
};
use crate::alephium::{
    MAX_UNSIGNED_BYTES, alephium_hash, current_funding::execution_unsigned,
    publisher_address_from_public_key,
};
use alloy_primitives::B256;

type Error = ExecutedTransactionError;
const MAX_EXECUTED_SCRIPT_BYTES: usize = 32_768;

/// Decode only already block/index/status-correlated transaction details.
/// The narrow bootstrap profile has one full P2PKH owner-zero input, one plain
/// same-owner fixed change output, and a complete nonempty serialized script.
/// Script semantics/permission and generated effects remain the caller's work.
pub fn decode_executed_transaction(
    observed: &TransactionDetailsObservation,
    frozen_unsigned: &[u8],
) -> Result<ExecutedTransactionEvidence, Error> {
    if frozen_unsigned.is_empty() || frozen_unsigned.len() > MAX_UNSIGNED_BYTES {
        return Err(Error::Bounds);
    }
    let observation = observed.observation();
    let identity = &observation.identity;
    if identity.network_id != 1
        || identity.groups != 4
        || identity.source_id == B256::ZERO
        || identity.chain_0_0_genesis.hash == B256::ZERO
        || identity.chain_0_0_genesis.provenance != GenesisProvenance::Independent
        || !matches!(identity.version, NodeVersion::V4_7_0 | NodeVersion::V4_7_1)
    {
        return Err(Error::Identity);
    }
    let (outcome, inclusion, header) = match &observation.outcome {
        TransactionOutcome::ScriptSucceeded { inclusion, header } => {
            (ExecutedOutcome::Succeeded, inclusion, header)
        }
        TransactionOutcome::ScriptFailed { inclusion, header } => {
            (ExecutedOutcome::Failed, inclusion, header)
        }
        _ => return Err(Error::Unconfirmed),
    };
    if inclusion.block_hash == B256::ZERO
        || inclusion.block_hash != header.hash
        || inclusion.transaction_index >= 4096
        || header.timestamp_ms > i64::MAX as u64
    {
        return Err(Error::Inclusion);
    }
    let details = fields::object(
        observed.details().ok_or(Error::Unconfirmed)?,
        &[
            "unsigned",
            "scriptExecutionOk",
            "contractInputs",
            "generatedOutputs",
            "inputSignatures",
            "scriptSignatures",
        ],
    )?;
    if details["scriptExecutionOk"].as_bool() != Some(outcome == ExecutedOutcome::Succeeded) {
        return Err(Error::Outcome);
    }
    let tx_id = alephium_hash(frozen_unsigned);
    if tx_id != observation.transaction_id {
        return Err(Error::Unsigned);
    }
    let unsigned = details["unsigned"].as_object().ok_or(Error::Format)?;
    let script = fields::bytes(
        unsigned.get("scriptOpt").ok_or(Error::Script)?,
        MAX_EXECUTED_SCRIPT_BYTES,
    )?;
    if script.is_empty() {
        return Err(Error::Script);
    }
    let inputs = fields::list(unsigned.get("inputs").ok_or(Error::Format)?, 1)?;
    let fixed = fields::list(unsigned.get("fixedOutputs").ok_or(Error::Format)?, 1)?;
    if inputs.len() != 1 || fixed.len() != 1 {
        return Err(Error::Profile);
    }
    let input = fields::object(&inputs[0], &["outputRef", "unlockScript"])?;
    let unlock = fields::bytes(&input["unlockScript"], 34)?;
    if unlock.len() != 34 || unlock[0] != 0 {
        return Err(Error::Profile);
    }
    let key: [u8; 33] = unlock[1..].try_into().map_err(|_| Error::Profile)?;
    let owner = publisher_address_from_public_key(&key).map_err(|_| Error::Profile)?;
    if owner.group() != 0 {
        return Err(Error::Profile);
    }
    let (reencoded, fixed_outputs) = execution_unsigned(
        observed.details().ok_or(Error::Unconfirmed)?,
        tx_id,
        Some(&script),
    )
    .map_err(|_| Error::Unsigned)?;
    if reencoded != frozen_unsigned
        || fixed_outputs.len() != 1
        || fixed_outputs[0].locking_script.get(1..) != Some(owner.hash().as_slice())
    {
        return Err(Error::Unsigned);
    }
    signatures(&details["inputSignatures"], &details["scriptSignatures"])?;
    let contract_inputs = fields::contract_inputs(&details["contractInputs"])?;
    let generated_outputs = fields::generated_outputs(&details["generatedOutputs"], tx_id, 1)?;
    Ok(ExecutedTransactionEvidence {
        identity: identity.clone(),
        inclusion: inclusion.clone(),
        header: header.clone(),
        transaction_id: tx_id,
        script_hash: alephium_hash(&script),
        script,
        fixed_output_count: 1,
        outcome,
        contract_inputs,
        generated_outputs,
    })
}

fn signatures(inputs: &serde_json::Value, scripts: &serde_json::Value) -> Result<(), Error> {
    let inputs = fields::list(inputs, 1)?;
    if inputs.len() != 1 || !fields::list(scripts, 0)?.is_empty() {
        return Err(Error::Signatures);
    }
    if fields::bytes(&inputs[0], 64)?.len() != 64 {
        return Err(Error::Signatures);
    }
    // Consensus validation is trusted here; this does not verify or authorize a signature.
    Ok(())
}
