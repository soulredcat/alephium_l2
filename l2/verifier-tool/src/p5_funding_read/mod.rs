//! One GET-only funding observation. No operation, approval or transaction built.
mod io;
mod report;

use alephium_l2_sdk::alephium::{
    current_funding::{
        CurrentFundingPolicy, ScriptFreeCreators, observe_current_fixed_funding_current,
    },
    read_node::{FundingView, GenesisPin, GenesisProvenance, ReadNode, ReadNodeConfig},
};
use alloy_primitives::{B256, U256};
use serde_json::Value;
use std::path::Path;

pub(crate) fn run(
    env: &Path,
    independent_genesis_hex: &str,
    fresh_output: &Path,
) -> Result<(), String> {
    let output = io::fresh_output(fresh_output)?;
    let mut stage = "configuration";
    let mut intent: Option<Value> = None;
    let mut observation: Option<Value> = None;
    let result: Result<(), String> = (|| {
        io::reject_links(env)?;
        let config = crate::p5_env::load_funding_read_config(env)?;
        let genesis = genesis(independent_genesis_hex)?;
        let policy = CurrentFundingPolicy {
            minimum_confirmations: config.minimum_confirmations,
            maximum_references: 64,
            maximum_creators: 64,
        };
        let source = policy
            .source_id(&config.origin, genesis)
            .map_err(|error| error.to_string())?;
        let document = report::intent(&config, genesis, source);
        stage = "persist_intent_before_GET";
        io::write_json(&output, "intent.json", &document)?;
        intent = Some(document);
        let mut node = ReadNode::new(ReadNodeConfig {
            origin: config.origin.clone(),
            source_id: source,
            chain_0_0_genesis: genesis,
        })
        .map_err(|error| error.to_string())?;
        stage = "identity_handshake";
        let identity = node.handshake().map_err(|error| error.to_string())?;
        stage = "initial_latest_owner_UTXOs";
        let current = node
            .unanchored_utxos(&config.owner)
            .map_err(|error| error.to_string())?;
        if current.identity != identity
            || current.owner != config.owner
            || current.view != FundingView::LatestIncludingMempoolUnanchored
        {
            return Err("Initial latest owner view identity differs".into());
        }
        stage = "select_all_bounded_references";
        if current.outputs.is_empty() || current.outputs.len() > 64 {
            return Err("Latest output count is outside the one-to-64 all-reference bound".into());
        }
        let references: Vec<_> = current
            .outputs
            .iter()
            .map(|output| output.reference)
            .collect();
        stage = "confirmed_fixed_creator_and_latest_availability";
        let matched = observe_current_fixed_funding_current(
            &config.caller_public_key,
            &references,
            &node,
            &policy,
            &ScriptFreeCreators,
        )
        .map_err(|error| error.to_string())?;
        if matched.outputs().len() != references.len()
            || matched.provenance().len() != references.len()
        {
            return Err("Matched fixed-output metadata omits selected references".into());
        }
        stage = "exact_matched_balance";
        let mut total = U256::ZERO;
        for fixed in matched.outputs() {
            total = total
                .checked_add(fixed.amount)
                .ok_or("Matched fixed-output amount exceeds U256")?;
        }
        observation = Some(report::observation(&matched, total, current.outputs.len()));
        stage = "configured_cap_plus_one_change_gate";
        if total < config.required_balance_atto {
            return Err("Matched confirmed fixed outputs do not cover the configured debit cap plus one change reserve".into());
        }
        stage = "persist_success";
        let success = report::success(
            intent.as_ref().ok_or("Funding intent is missing")?,
            observation
                .as_ref()
                .ok_or("Funding observation metadata is missing")?,
        );
        io::write_json(&output, "success.json", &success)?;
        println!(
            "P5 funding observation: PASS matched_fixed_outputs={} total_atto={} required_atto={}; GET-only, P5 incomplete",
            references.len(),
            total,
            config.required_balance_atto
        );
        Ok(())
    })();
    if let Err(error) = &result {
        let failure = report::failure(stage, error, intent.as_ref(), observation.as_ref());
        if io::write_json(&output, "failure.json", &failure).is_err() {
            return Err("Funding observation FAILED/STOPPED; failure report could not be flushed; prior outputs retained".into());
        }
        println!(
            "P5 funding observation: FAILED/STOPPED stage={stage}; no retry, signing, builder, submission or faucet"
        );
    }
    result
}

fn genesis(text: &str) -> Result<GenesisPin, String> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("Independent genesis requires exactly 32 lowercase hexadecimal bytes".into());
    }
    let bytes = hex::decode(text).map_err(|_| "Independent genesis encoding is invalid")?;
    let hash = B256::from_slice(&bytes);
    if hash == B256::ZERO {
        return Err("Independent genesis must be nonzero".into());
    }
    // The caller supplies the independent trust association. Labelling it here
    // is not a consensus proof and never promotes a node-discovered diagnostic.
    Ok(GenesisPin {
        hash,
        provenance: GenesisProvenance::Independent,
    })
}
