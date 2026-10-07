//! Constructor and source/field policy; all initial values derive from proven bytes.
use super::{
    Prepared,
    service::FUTURE_SECONDS,
    state::{self, bytes, word},
};
use crate::{
    compiler::Compiled,
    factory_state::{self, fixture_id},
    staged_cases,
};
use serde_json::Value;

pub(super) struct Templates {
    pub proof: Value,
    pub data: Value,
    pub proof_id: [u8; 32],
}
pub(super) fn build(
    factory: &Compiled,
    proof: &Compiled,
    data: &Compiled,
    p: &Prepared,
) -> Result<(Value, Templates), String> {
    for (compiled, names) in [
        (
            factory,
            vec![
                "initializeGenesis",
                "createCandidate",
                "finalize",
                "getAnchor",
            ],
        ),
        (
            proof,
            vec!["begin", "advance", "finish", "getAcceptance", "getBinding"],
        ),
        (data, vec!["getHash", "getLength", "getData"]),
    ] {
        state::validate_code(compiled)?;
        if compiled.public_methods.len() != names.len()
            || names
                .iter()
                .any(|name| !compiled.public_methods.contains_key(*name))
        {
            return Err("Settlement source public ABI differs from the fixed inventory".into());
        }
    }
    let proof_id = fixture_id(b"ALPH/L2/p5/proof-template/v1");
    let data_id = fixture_id(b"ALPH/L2/p5/data-template/v1");
    let proof_template = factory_state::child_state(
        proof,
        &proof_id,
        staged_cases::initial_fields(),
        &"00".repeat(32),
    );
    let data_template = state::contract(data, &data_id, vec![bytes(&[])], vec![])?;
    let code_hash = |compiled: &Compiled| -> Result<Value, String> {
        Ok(staged_cases::bytes(
            compiled.evidence["productionCodeHash"]
                .as_str()
                .ok_or("Missing template code hash")?,
        ))
    };
    let j = &p.journal;
    let imm = vec![
        bytes(&proof_id),
        code_hash(proof)?,
        bytes(&data_id),
        code_hash(data)?,
        bytes(&p.image),
        bytes(&[j.network]),
        bytes(&j.l1_genesis),
        word(j.chain_id),
        bytes(&j.genesis),
        bytes(&j.profile),
        bytes(&p.bootstrap.checkpoint_hash),
        bytes(&j.parent.bytes),
        bytes(&p.bootstrap.limits),
        word(FUTURE_SECONDS),
    ];
    let root = state::contract(
        factory,
        &j.factory,
        imm,
        vec![word(0), bytes(&[0; 80]), bytes(&[0; 32])],
    )?;
    // Preserve the independent staged-child field bound as well as the new ones.
    let total = state::field_bytes(
        proof_template["immFields"]
            .as_array()
            .ok_or("Missing proof fields")?,
    )? + state::field_bytes(
        proof_template["mutFields"]
            .as_array()
            .ok_or("Missing proof fields")?,
    )?;
    if total >= 3072 {
        return Err("Existing proof child exceeds strict field bound".into());
    }
    Ok((
        root,
        Templates {
            proof: proof_template,
            data: data_template,
            proof_id,
        },
    ))
}
