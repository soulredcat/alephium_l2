//! Genuine receipt pairing and exact consecutive batch planning, never proving.
use super::{artifacts::Hash, da, literal, scripts, types::*};
use crate::{actual_receipt, settlement::journal::Journal};
use num_bigint::BigUint;
use serde_json::json;
use std::path::Path;

// Full actual-domain planning is intentionally unavailable to the draft CLI
// until genuine receipts and deployment/funding pins have been supplied.
#[allow(dead_code)]
pub(crate) struct BatchInput<'a> {
    pub receipt: &'a actual_receipt::Input,
    pub data_path: &'a Path,
}

pub(crate) struct PreparedBatch {
    pub(super) journal: Journal,
    pub(super) data: da::DataBoundary,
    pub(super) begin: [Vec<u8>; 4],
    pub(super) seal_hash: Hash,
    pub(super) auxiliary_hash: Hash,
    pub(super) key: Hash,
    pub(super) proof_id: Hash,
    pub(super) data_id: Hash,
    pub(super) payload: Hash,
    pub(super) statement: Hash,
}

#[allow(dead_code)]
pub(crate) fn prepare_batches(
    inputs: [BatchInput<'_>; 2],
    policy: &Policy,
    actor: &Actor,
    factory: &Deployment,
) -> Result<[PreparedBatch; 2], String> {
    policy.validate(actor)?;
    if factory.group != 0
        || factory.contract_id == [0; 32]
        || factory.caller_public_key_sha256 != literal::sha(&actor.public_key)
    {
        return Err("Actual funding-derived factory identity required".into());
    }
    let [first, second] = inputs;
    let one = prepare(first, policy, factory, true)?;
    let two = prepare(second, policy, factory, false)?;
    if one.journal.parent.bytes != policy.genesis_head
        || one.journal.old_root != policy.genesis_root(&factory.contract_id)
        || two.journal.parent != one.journal.head
        || two.journal.old_root != one.journal.new_root
    {
        return Err("Two actual batches do not extend the exact accepted predecessor".into());
    }
    Ok([one, two])
}

fn prepare(
    input: BatchInput<'_>,
    policy: &Policy,
    factory: &Deployment,
    first: bool,
) -> Result<PreparedBatch, String> {
    let actual = actual_receipt::prepare_for_child(input.receipt, &[0; 32])?;
    let journal = Journal::decode(actual.journal)?;
    if journal.network != 1
        || journal.factory != factory.contract_id
        || journal.l1_genesis != policy.l1_genesis
        || journal.chain_id != policy.l2_chain_id
        || journal.genesis != policy.l2_genesis
        || journal.profile != policy.execution_profile
    {
        return Err("Receipt domain/program profile cannot be relabelled for deployment".into());
    }
    let mut arguments = Vec::with_capacity(4);
    for argument in &actual.fixture.begin_args {
        if argument["type"] != "ByteVec" {
            return Err("Verified begin argument is not ByteVec".into());
        }
        arguments.push(
            hex::decode(
                argument["value"]
                    .as_str()
                    .ok_or("Missing checked begin argument")?,
            )
            .map_err(|_| "Invalid checked begin argument")?,
        );
    }
    let begin: [Vec<u8>; 4] = arguments
        .try_into()
        .map_err(|_| "Begin requires four exact vectors")?;
    if begin[1] != policy.approved_image || begin[2] != journal.digest {
        return Err("Receipt image/journal differs from independently approved policy".into());
    }
    let data = da::read(input.data_path, &journal, policy, first)?;
    let seal_hash = literal::sha(&begin[0]);
    let auxiliary_hash = literal::sha(&begin[3]);
    let key = literal::session(
        &factory.contract_id,
        &policy.approved_image,
        &journal.digest,
        &seal_hash,
        &auxiliary_hash,
    );
    let mut proof_path = b"p5v1/proof/".to_vec();
    proof_path.extend(key);
    let mut data_path = b"p5v1/data/".to_vec();
    data_path.extend(key);
    let proof_id = literal::child(&factory.contract_id, &proof_path);
    let data_id = literal::child(&factory.contract_id, &data_path);
    let payload = literal::payload(
        &policy.approved_image,
        &journal.digest,
        &seal_hash,
        &auxiliary_hash,
    );
    let statement = literal::statement(
        &proof_id,
        &policy.approved_image,
        &journal.digest,
        &seal_hash,
        &auxiliary_hash,
    );
    Ok(PreparedBatch {
        journal,
        data,
        begin,
        seal_hash,
        auxiliary_hash,
        key,
        proof_id,
        data_id,
        payload,
        statement,
    })
}

#[allow(dead_code)]
pub(crate) fn calls(
    batch: &PreparedBatch,
    number: u8,
    policy: &Policy,
    actor: &Actor,
    limits: [OperationLimit; 13],
) -> Result<Vec<ScriptDraft>, String> {
    let mut output = Vec::with_capacity(13);
    let mut budgets = limits.into_iter();
    let limit = budgets.next().ok_or("Missing candidate budget")?;
    limit.validate(&(&policy.minimum_contract_deposit * BigUint::from(2_u8)))?;
    let body = format!(
        "    let (key, proof, data) = Risc0BatchSettlementFactory({}).createCandidate{{{} -> ALPH: {}}}({}, {}, {}, {})\n    assert!(key == {} && proof == {} && data == {}, 1702)",
        literal::bytes(&batch.journal.factory),
        literal::caller(actor)?,
        literal::amount(&limit.deposit)?,
        literal::bytes(&batch.journal.bytes),
        literal::bytes(&batch.seal_hash),
        literal::bytes(&batch.auxiliary_hash),
        literal::bytes(&batch.data.bytes),
        literal::bytes(&batch.key),
        literal::bytes(&batch.proof_id),
        literal::bytes(&batch.data_id)
    );
    output.push(scripts::draft("create-candidate",Some(number),body,
        json!({"journalSha256":hex::encode(batch.journal.digest),"sealSha256":hex::encode(batch.seal_hash),
            "auxiliarySha256":hex::encode(batch.auxiliary_hash),"dataSha256":hex::encode(batch.journal.data_hash)}),
        json!({"operation":"canonical-candidate-created","factory":hex::encode(batch.journal.factory),
            "candidateKey":hex::encode(batch.key),"proofChild":hex::encode(batch.proof_id),"dataChild":hex::encode(batch.data_id),
            "immutablePayload":hex::encode(batch.payload),"dataSha256":hex::encode(batch.journal.data_hash),
            "initialProofStatus":0,"initialProofCursor":0,"acceptedHeadUnchanged":hex::encode(batch.journal.parent.bytes),
            "acceptedRootUnchanged":hex::encode(batch.journal.old_root)}),limit)?);
    let args = batch
        .begin
        .iter()
        .map(|value| literal::bytes(value))
        .collect::<Vec<_>>()
        .join(", ");
    output.push(arithmetic(
        batch,
        number,
        "begin-proof",
        format!("begin({args})"),
        format!("result == {}", literal::bytes(&batch.statement)),
        1,
        65,
        budgets.next().ok_or("Missing begin budget")?,
    )?);
    let mut cursor = 65_u64;
    for _ in 0..9 {
        let next = cursor.saturating_sub(8);
        output.push(arithmetic(
            batch,
            number,
            "advance-proof",
            format!("advance({}, {cursor})", literal::bytes(&batch.statement)),
            format!("result == {next}"),
            if next == 0 { 2 } else { 1 },
            next,
            budgets.next().ok_or("Missing advance budget")?,
        )?);
        cursor = next;
    }
    output.push(arithmetic(
        batch,
        number,
        "finish-proof",
        format!("finish({})", literal::bytes(&batch.statement)),
        format!("result == {}", literal::bytes(&batch.statement)),
        3,
        0,
        budgets.next().ok_or("Missing finish budget")?,
    )?);
    let limit = budgets.next().ok_or("Missing finalize budget")?;
    limit.validate(&BigUint::from(0_u8))?;
    let body = format!(
        "    let result = Risc0BatchSettlementFactory({}).finalize({}, {}, {})\n    assert!(result == {}, 1704)",
        literal::bytes(&batch.journal.factory),
        literal::bytes(&batch.journal.bytes),
        literal::bytes(&batch.seal_hash),
        literal::bytes(&batch.auxiliary_hash),
        literal::bytes(&batch.journal.new_root)
    );
    output.push(scripts::draft("finalize-batch",Some(number),body,json!({"journalSha256":hex::encode(batch.journal.digest)}),
        json!({"operation":"consume-canonical-batch","factory":hex::encode(batch.journal.factory),
            "parentHead":hex::encode(batch.journal.parent.bytes),"oldRoot":hex::encode(batch.journal.old_root),
            "acceptedHead":hex::encode(batch.journal.head.bytes),"acceptedRoot":hex::encode(batch.journal.new_root),
            "statement":hex::encode(batch.statement),"dataSha256":hex::encode(batch.journal.data_hash)}),limit)?);
    Ok(output)
}

#[allow(clippy::too_many_arguments)]
fn arithmetic(
    batch: &PreparedBatch,
    number: u8,
    kind: &'static str,
    call: String,
    assertion: String,
    status: u8,
    cursor: u64,
    limit: OperationLimit,
) -> Result<ScriptDraft, String> {
    limit.validate(&BigUint::from(0_u8))?;
    let body = format!(
        "    let result = Risc0StagedReceiptVerifier({}).{}\n    assert!({}, 1703)",
        literal::bytes(&batch.proof_id),
        call,
        assertion
    );
    scripts::draft(
        kind,
        Some(number),
        body,
        json!({"child":hex::encode(batch.proof_id),"statement":hex::encode(batch.statement),"expectedCursorAfter":cursor}),
        json!({"operation":"canonical-proof-state","child":hex::encode(batch.proof_id),
            "immutablePayload":hex::encode(batch.payload),"statement":hex::encode(batch.statement),"status":status,"cursor":cursor}),
        limit,
    )
}
