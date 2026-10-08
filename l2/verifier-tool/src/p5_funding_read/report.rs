//! Allowlisted private observation metadata; opaque capabilities stay opaque.
use crate::p5_env::FundingReadConfig;
use alephium_l2_sdk::alephium::{
    current_funding::CurrentFixedFundingObservation,
    read_node::{GenesisPin, NodeVersion},
};
use alloy_primitives::{B256, U256};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub(super) fn intent(config: &FundingReadConfig, genesis: GenesisPin, source: B256) -> Value {
    json!({"schema": 1, "mode": "GET-only-p5-funding-observation", "status": "INTENT",
        "sourceId": hex::encode(source.as_slice()), "configuredOrigin": config.origin,
        "callerPublicKeySha256": hex::encode(Sha256::digest(config.caller_public_key)),
        "chain0To0Genesis": hex::encode(genesis.hash.as_slice()),
        "genesisProvenance": "caller-supplied independent trusted configuration; not automatically discovered",
        "sourceTrust": "configured consensus node; no independent consensus or light-client proof",
        "networkId": 1, "group": 0, "groups": 4, "model": "CanonicalFixedCurrentV1",
        "sourcePolicyVersion": 4, "creatorChains": [[0,0],[1,0],[2,0],[3,0]],
        "nativeOutputLockRule": "max(committed lock, same canonical creator timestamp); require a concrete published projection",
        "ownerHeadProgressPolicy": "equal or canonical descendant, at most 32 owner-chain blocks",
        "minimumConfirmations": {"chain": config.minimum_confirmations.chain,
            "fromGroup": config.minimum_confirmations.from_group, "toGroup": config.minimum_confirmations.to_group},
        "maximumSelectedReferences": 64, "maximumCreators": 64,
        "totalDebitCapAtto": config.total_debit_cap_atto.to_string(),
        "minimumChangeReserveAtto": config.minimum_change_reserve_atto.to_string(),
        "requiredBalanceAtto": config.required_balance_atto.to_string(),
        "budgetScope": "configured total debit cap plus one change reserve; no measured thirty-operation budget",
        "creatorScriptPolicy": "script-free creators only; no stateful creator script approval",
        "automaticRetry": false, "genesisDiscovery": false, "signing": false,
        "builder": false, "submission": false, "faucet": false, "p5Complete": false,
        "filePersistence": "create-new files with sync_all; directory-entry/power-loss durability not qualified",
        "directoryPrivacyAndWindowsACL": "caller provisioned; not independently verified by this driver"})
}

pub(super) fn observation(
    observed: &CurrentFixedFundingObservation,
    total: U256,
    initial_latest_count: usize,
) -> Value {
    let pin = observed.pin();
    let before = observed.head_before();
    let after = observed.head_after();
    let version = match before.identity.version {
        NodeVersion::V4_7_0 => "v4.7.0",
        NodeVersion::V4_7_1 => "v4.7.1",
    };
    let records: Vec<Value> = observed.outputs().iter().zip(observed.provenance()).map(|(output, provenance)| {
        json!({"reference": {"hint": output.reference.hint, "key": hex::encode(output.reference.key.as_slice())},
            "amountAtto": output.amount.to_string(), "lockTimeMs": output.lock_time_ms,
            "committedLockTimeMs": provenance.committed_lock_time_ms,
            "creatorBlockTimestampMs": provenance.creator_block_timestamp_ms,
            "effectiveLockTimeMs": provenance.effective_lock_time_ms,
            "initialObservedLockRepresentation": provenance.initial_lock_time_projection.map(|value| format!("{value:?}")),
            "finalObservedLockRepresentation": provenance.final_lock_time_projection.map(|value| format!("{value:?}")),
            "creatorTransactionId": hex::encode(provenance.creator_transaction_id.as_slice()),
            "fixedOutputIndex": provenance.fixed_output_index, "creatorBlockHeight": provenance.creator_block_height,
            "creatorChainFrom": provenance.creator_chain_from, "creatorChainTo": provenance.creator_chain_to,
            "creatorBlockHash": hex::encode(provenance.inclusion.block_hash.as_slice()),
            "creatorTransactionIndex": provenance.inclusion.transaction_index,
            "confirmations": {"chain": provenance.inclusion.confirmations.chain,
                "fromGroup": provenance.inclusion.confirmations.from_group, "toGroup": provenance.inclusion.confirmations.to_group}})
    }).collect();
    json!({"sourceId": hex::encode(pin.source_id.as_slice()), "networkId": pin.network_id,
        "networkGenesis": hex::encode(pin.network_genesis_id.as_slice()), "reportedNodeVersion": version,
        "head": {"hash": hex::encode(pin.head_hash.as_slice()), "height": pin.head_height, "timestampMs": pin.timestamp_ms},
        "bracketingHeadsEqual": before.identity == after.identity && before.header == after.header,
        "currentWindow": observed.is_current_window(), "ownerHeadAdvance": observed.head_advance(),
        "ownerCanonicalHeadLineage": observed.head_lineage().iter().map(|header| json!({
            "hash": hex::encode(header.hash.as_slice()), "height": header.height,
            "timestampMs": header.timestamp_ms, "parent": header.parent().map(|hash| hex::encode(hash.as_slice()))
        })).collect::<Vec<_>>(),
        "initialLatestOutputCount": initial_latest_count, "selectedReferenceCount": records.len(),
        "matchedConfirmedFixedOutputCount": records.len(), "totalMatchedAtto": total.to_string(), "outputs": records,
        "availabilityView": "latest including mempool, unanchored; each selected confirmed fixed output matched",
        "atomicOrHistoricalSnapshot": false, "raceEliminatedByEqualHeads": false,
        "fundingAtAfterHeaderOrReservationProven": false,
        "afterPinMeaning": "independently captured owner head within the bounded observation window; final creator/availability checks remain non-atomic",
        "cryptographicConsensusOrUTXOProof": false,
        "fullTransactionDetailsSignaturesAddressesPublicKeysAndScriptsSerialized": false})
}

pub(super) fn success(intent: &Value, observed: &Value) -> Value {
    json!({"schema": 1, "mode": "GET-only-p5-funding-observation", "status": "PASS", "passed": true,
        "intentMetadata": intent, "observation": observed, "configuredCapPlusOneChangeGatePassed": true,
        "thirtyOperationBudgetMeasuredOrApproved": false, "independentGenesisSourceVerifiedByDriver": false,
        "liveOperationAuthorityGranted": false, "signing": false, "builder": false,
        "submission": false, "faucet": false, "automaticRetry": false, "p5Complete": false})
}

pub(super) fn failure(
    stage: &str,
    error: &str,
    intent: Option<&Value>,
    observed: Option<&Value>,
) -> Value {
    json!({"schema": 1, "mode": "GET-only-p5-funding-observation", "status": "FAILED/STOPPED", "passed": false,
        "stage": stage, "failureCategory": error, "intentMetadata": intent, "completedObservationMetadata": observed,
        "priorOutputsPreserved": true, "automaticRetry": false, "signing": false,
        "builder": false, "submission": false, "faucet": false, "p5Complete": false})
}
