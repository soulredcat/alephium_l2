//! One bounded GET observation; disjoint subsets retain the same sealed evidence.
use super::super::io;
use crate::p5_env::BootstrapConfig;
use alephium_l2_sdk::alephium::{
    current_funding::{
        CurrentFixedFundingObservation, CurrentFundingPolicy, ScriptFreeCreators,
        observe_current_fixed_funding_current,
    },
    read_node::{FundingView, GenesisPin, ReadNode, ReadNodeConfig},
};
use alloy_primitives::{B256, U256};
use serde_json::{Value, json};

pub(super) fn observe(
    config: &BootstrapConfig,
    genesis: GenesisPin,
    policy: &CurrentFundingPolicy,
    source_id: B256,
) -> Result<CurrentFixedFundingObservation, String> {
    let mut node = ReadNode::new(ReadNodeConfig {
        origin: config.funding.origin.clone(),
        source_id,
        chain_0_0_genesis: genesis,
    })
    .map_err(|error| error.to_string())?;
    let identity = node.handshake().map_err(|error| error.to_string())?;
    let latest = node
        .unanchored_utxos(&config.funding.owner)
        .map_err(|error| error.to_string())?;
    if latest.identity != identity
        || latest.owner != config.funding.owner
        || latest.view != FundingView::LatestIncludingMempoolUnanchored
        || latest.outputs.is_empty()
        || latest.outputs.len() > 64
    {
        return Err(
            "Bootstrap initial owner/latest identity or all-reference count is unsupported".into(),
        );
    }
    let references: Vec<_> = latest
        .outputs
        .iter()
        .map(|output| output.reference)
        .collect();
    let observed = observe_current_fixed_funding_current(
        &config.funding.caller_public_key,
        &references,
        &node,
        policy,
        &ScriptFreeCreators,
    )
    .map_err(|error| error.to_string())?;
    if observed.outputs().len() != references.len()
        || observed.provenance().len() != references.len()
        || !observed.is_current_window()
        || observed.head_advance() > 32
        || observed.pin().head_hash != observed.head_after().header.hash
        || observed.pin().head_height != observed.head_after().header.height
    {
        return Err("Sealed bootstrap observation omitted selected fixed outputs".into());
    }
    let total = total(&observed)?;
    if total < config.funding.required_balance_atto {
        return Err("Confirmed fixed funds do not cover the configured full debit ceiling plus one minimum change reserve".into());
    }
    Ok(observed)
}

fn total(observed: &CurrentFixedFundingObservation) -> Result<U256, String> {
    observed
        .outputs()
        .iter()
        .try_fold(U256::ZERO, |sum, output| {
            sum.checked_add(output.amount)
                .ok_or_else(|| "Bootstrap confirmed fixed-output sum overflows U256".into())
        })
}

pub(super) fn select(
    observed: &CurrentFixedFundingObservation,
    minimum: U256,
) -> Result<[CurrentFixedFundingObservation; 2], String> {
    let mut adequate: Vec<_> = observed
        .outputs()
        .iter()
        .filter(|output| output.amount >= minimum)
        .collect();
    adequate.sort_by_key(|output| output.reference);
    let first = adequate
        .first()
        .ok_or("No adequate confirmed fixed output for first template")?
        .reference;
    let second = adequate
        .iter()
        .find(|output| output.reference.key != first.key)
        .ok_or("Two disjoint adequate confirmed fixed outputs are required")?
        .reference;
    let proof = observed
        .select_references(&[first])
        .map_err(|error| error.to_string())?;
    let data = observed
        .select_references(&[second])
        .map_err(|error| error.to_string())?;
    Ok([proof, data])
}

pub(super) fn select_four(
    observed: &CurrentFixedFundingObservation,
    deployment_minimum: U256,
    initialization_minimum: U256,
) -> Result<[CurrentFixedFundingObservation; 4], String> {
    let mut outputs: Vec<_> = observed.outputs().iter().collect();
    outputs.sort_by_key(|output| output.reference);
    let mut keys = std::collections::BTreeSet::new();
    let mut references = Vec::new();
    for minimum in [
        deployment_minimum,
        deployment_minimum,
        deployment_minimum,
        initialization_minimum,
    ] {
        let output = outputs.iter().find(|output| output.amount >= minimum && !keys.contains(&output.reference.key))
            .ok_or("Four disjoint current outputs must cover three deployments and zero-deposit initialization")?;
        keys.insert(output.reference.key);
        references.push(output.reference);
    }
    let select = |index: usize| {
        observed
            .select_references(&[references[index]])
            .map_err(|error| error.to_string())
    };
    Ok([select(0)?, select(1)?, select(2)?, select(3)?])
}

pub(super) fn metadata(observed: &CurrentFixedFundingObservation) -> Result<Value, String> {
    let rows: Vec<_> = observed.outputs().iter().zip(observed.provenance()).map(|(output, origin)| json!({
        "referenceHint": output.reference.hint, "referenceKey": hex::encode(output.reference.key.as_slice()),
        "amountAtto": output.amount.to_string(), "lockTimeMs": output.lock_time_ms,
        "committedLockTimeMs": origin.committed_lock_time_ms,
        "creatorBlockTimestampMs": origin.creator_block_timestamp_ms,
        "effectiveLockTimeMs": origin.effective_lock_time_ms,
        "initialObservedLockRepresentation": origin.initial_lock_time_projection.map(|value| format!("{value:?}")),
        "finalObservedLockRepresentation": origin.final_lock_time_projection.map(|value| format!("{value:?}")),
        "creatorTransactionId": hex::encode(origin.creator_transaction_id.as_slice()), "fixedOutputIndex": origin.fixed_output_index,
        "creatorFromGroup": origin.creator_chain_from, "creatorToGroup": origin.creator_chain_to,
        "creatorBlockHash": hex::encode(origin.inclusion.block_hash.as_slice()), "creatorBlockHeight": origin.creator_block_height,
        "creatorTransactionIndex": origin.inclusion.transaction_index,
        "confirmations": {"chain": origin.inclusion.confirmations.chain, "fromGroup": origin.inclusion.confirmations.from_group,
            "toGroup": origin.inclusion.confirmations.to_group}})).collect();
    let pin = observed.pin();
    let before = observed.head_before();
    let after = observed.head_after();
    Ok(
        json!({"sourceId": hex::encode(pin.source_id.as_slice()), "fundingModel": "CanonicalFixedCurrentV1",
        "headHash": hex::encode(pin.head_hash.as_slice()), "headHeight": pin.head_height, "headTimestampMs": pin.timestamp_ms,
        "headChain": "0->0", "matchedFixedOutputs": rows.len(), "totalMatchedAtto": total(observed)?.to_string(), "outputs": rows,
        "bracketingHeadsEqual": before.identity == after.identity && before.header == after.header,
        "headBefore": {"hash": hex::encode(before.header.hash.as_slice()), "height": before.header.height},
        "headAfter": {"hash": hex::encode(after.header.hash.as_slice()), "height": after.header.height},
        "currentWindow": observed.is_current_window(), "canonicalHeadAdvance": observed.head_advance(), "maximumHeadAdvance": 32,
        "headLineage": observed.head_lineage().iter().map(|header| json!({"hash": hex::encode(header.hash.as_slice()),
            "height": header.height, "timestampMs": header.timestamp_ms})).collect::<Vec<_>>(),
        "sealedFundingPinAtAfter": pin.head_hash == after.header.hash && pin.head_height == after.header.height,
        "inputRecordsSha256": hex::encode(io::sha(&serde_json::to_vec(&rows).map_err(|_| "Cannot encode private fixed-output metadata")?)),
        "availability": "windowed trusted-node latest facts, matched confirmed fixed outputs with bounded canonical head advance; non-atomic",
        "availabilityAtAfterSnapshotEstablished": false,
        "newObservationOrReservationCreatedBySubsetSelection": false, "raceEliminatedByMatchingHeads": false,
        "cryptographicConsensusOrUTXOProof": false, "sourcePolicy": "SDK current-fixed-funding-source/v4",
        "acceptedCreatorChains": "0..3->0", "scriptFreeCreatorsOnly": true}),
    )
}
