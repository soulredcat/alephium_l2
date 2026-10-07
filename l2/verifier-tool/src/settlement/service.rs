//! One proof reuse, exact carried VM states, and explicit foreign-domain refusal.
use super::{
    Prepared, cases, flow, layout,
    state::{self, Run, bytes},
};
use crate::{compiler::Compiled, transport::ReadOnlyNode};
use serde_json::{Value, json};

pub(super) const FUTURE_SECONDS: u64 = 60;
const FACTORY_REQUESTS: usize = 39;
const CHILD_REQUESTS: usize = 12;

pub(crate) fn execute(
    node: &ReadOnlyNode,
    factory: &Compiled,
    proof: &Compiled,
    data: &Compiled,
    report: &mut Value,
    prepared: Prepared,
) -> Result<(), String> {
    let native = cases::native(&prepared.journal, &prepared.bootstrap)?;
    let (root, templates) = layout::build(factory, proof, data, &prepared)?;
    let source_fields = state::field_bytes(
        root["immFields"]
            .as_array()
            .ok_or("Missing factory immutable fields")?,
    )? + state::field_bytes(
        root["mutFields"]
            .as_array()
            .ok_or("Missing factory mutable fields")?,
    )?;
    report["actualReceipt"] = prepared.actual_evidence.clone();
    report["nativeBoundary"] =
        json!({"passed": true, "executedCases": native.len(), "results": native});
    report["sourceBounds"] = json!([
        {"name": "exact-compiled-public-abi", "passed": true},
        {"name": "executable-and-combined-field-bounds", "passed": true}
    ]);
    report["settlement"] = json!({"scope": "native policy and canonical synthetic VM; not public settlement",
        "journalBytes": prepared.journal.bytes.len(), "dataBytes": prepared.bootstrap.data.len(),
        "capacity": {"blockGas": prepared.bootstrap.capacity[0], "blockBytes": prepared.bootstrap.capacity[1],
            "maxPending": prepared.bootstrap.capacity[2]},
        "genesisCheckpointBytes": prepared.bootstrap.checkpoint.len(), "factoryFieldBytes": source_fields,
        "maximumInlineDataBytes": 3000, "strictContractFieldMaximum": 3072,
        "maximumExecutableBytes": 32768, "maximumCallGas": 5000000,
        "maximumRequests": super::MAX_REQUESTS, "futureDriftSeconds": FUTURE_SECONDS,
        "sourceAbiAndFieldBoundsPassed": true, "actualReceiptReproved": false,
        "expectedMatchingDomainFactoryRequests": FACTORY_REQUESTS,
        "expectedMatchingDomainChildRequests": CHILD_REQUESTS,
        "canonicalSyntheticAccepted": false, "publicTestnetAccepted": false,
        "p5Complete": false, "deployed": false, "signed": false});
    if node.identity["reportedNetworkId"].as_u64() != Some(0)
        || node.identity["reportedSynced"].as_bool() != Some(true)
    {
        return Err(
            "Settlement synthetic adapter requires the verified network-zero read-only route"
                .into(),
        );
    }
    let compatible = prepared.journal.network == 0 && prepared.journal.factory[31] == 0;
    report["settlement"]["actualReceiptDomainCompatible"] = json!(compatible);
    if !compatible {
        // This is an expected authority refusal, not a relabelled positive flow.
        // No root/child state is sent to the VM under an incompatible identity.
        report["results"] = json!([{"name": "foreign-receipt-domain-refused-before-vm", "passed": true,
            "scope": "native-authority-boundary", "vmRequests": 0}]);
        report["settlement"]["status"] = json!("MATCHED_DOMAIN_PROOF_REQUIRED");
        report["executedCases"] = json!(cases::NATIVE_CASES + 3);
        report["passed"] = json!(true);
        return Ok(());
    }
    let timestamp_ms = prepared
        .journal
        .head
        .timestamp
        .checked_mul(1000)
        .ok_or("L2 timestamp exceeds millisecond boundary")?;
    let mut run = Run {
        node,
        compiled: factory,
        root,
        records: Vec::new(),
        timestamp_ms,
    };
    let result = flow::execute(&mut run, proof, data, &templates, &prepared, report);
    report["results"] = json!(run.records);
    report["executedCases"] = json!(
        cases::NATIVE_CASES
            + 2
            + run.records.len()
            + report["canonicalChildLifecycle"]["executedCases"]
                .as_u64()
                .unwrap_or(0) as usize
    );
    result?;
    if run.records.len() != FACTORY_REQUESTS {
        return Err("Settlement factory case inventory differs".into());
    }
    report["settlement"]["canonicalSyntheticAccepted"] = json!(true);
    report["settlement"]["status"] = json!("MATCHED_DOMAIN_SYNTHETIC_FLOW_PASSED");
    report["actualReceipt"]["canonicalTargetAccepted"] = json!(true);
    report["passed"] = json!(true);
    Ok(())
}

pub(super) fn candidate_args(p: &Prepared, auxiliary: &[u8; 32], data: &[u8]) -> Vec<Value> {
    vec![
        bytes(&p.journal.bytes),
        bytes(&p.seal_hash),
        bytes(auxiliary),
        bytes(data),
    ]
}
pub(super) fn finalize_args(p: &Prepared, auxiliary: &[u8; 32]) -> Vec<Value> {
    vec![
        bytes(&p.journal.bytes),
        bytes(&p.seal_hash),
        bytes(auxiliary),
    ]
}
