//! Bounded target checks for immutable intended-input and canonical-origin binding.
use crate::{
    compiler::Compiled,
    factory_service::Run as FactoryRun,
    staged_cases::{self, Fixture, bytes},
    staged_state::Run,
    transport::ReadOnlyNode,
};
use serde_json::{Value, json};

pub(crate) const REQUESTS: usize = 5;

/// All rejected claims start at the intended immutable binding and zero state.
/// The caller then uses that same genuine creation result for the valid flow.
pub(crate) fn reject_hijacks(
    node: &ReadOnlyNode,
    compiled: &Compiled,
    report: &mut Value,
    fixture: &Fixture,
    initial: &Value,
) -> Result<(), String> {
    let begin = *compiled
        .public_methods
        .get("begin")
        .ok_or("Missing begin")?;
    let fields = crate::staged_state::canonical_child_fields(initial, compiled, fixture)?;
    let mut run = Run::new(node, compiled, fixture, report);
    for (name, args) in [
        ("hijack-image", fixture.wrong_image_args.clone()),
        ("hijack-journal", fixture.wrong_journal_args.clone()),
        ("hijack-seal", changed_arg(fixture, 0)?),
        ("hijack-auxiliary", changed_arg(fixture, 3)?),
    ] {
        run.reject(name, begin, args, &fields, 1503)?;
    }
    let mut malformed = run.request(begin, fixture.begin_args.clone(), &fields);
    malformed["initialImmFields"][1] = bytes("00");
    run.reject_request("malformed-child-binding", malformed, &fields, 1503)?;
    if run.records.len() != REQUESTS {
        return Err("Session binding checks differ from the fixed request inventory".into());
    }
    run.report["executedCases"] = json!(REQUESTS);
    run.report["scope"] = json!("synthetic intended-input guards; unchanged canonical zero origin");
    run.report["passed"] = json!(true);
    Ok(())
}

pub(crate) fn reject_factory_binding(
    run: &mut FactoryRun<'_>,
    create: usize,
    accepted: usize,
    fixture: &Fixture,
    template: &Value,
    created: &Value,
) -> Result<(), String> {
    // Deliberately supplied adversarial state is never used as positive origin.
    let mut wrong_binding = created.clone();
    wrong_binding["immFields"][1] = bytes(&staged_cases::different_id(&fixture.payload_id)?);
    run.reject(
        "canonical-address-wrong-binding",
        accepted,
        vec![bytes(&fixture.statement_id)],
        &[wrong_binding],
        1515,
    )?;
    let mut malformed = run.request(create, Vec::new(), std::slice::from_ref(template));
    malformed["initialImmFields"][3] = bytes("00");
    run.reject_request("factory-malformed-binding", malformed, 1510)
}

fn changed_arg(fixture: &Fixture, index: usize) -> Result<Vec<Value>, String> {
    let mut args = fixture.begin_args.clone();
    let encoded = args[index]["value"].as_str().ok_or("Missing claim bytes")?;
    let mut decoded = hex::decode(encoded).map_err(|_| "Malformed claim hex")?;
    let last = decoded.last_mut().ok_or("Empty claim bytes")?;
    *last ^= 1;
    args[index] = bytes(&hex::encode(decoded));
    Ok(args)
}

pub(crate) fn forged_clone_view(
    run: &mut FactoryRun<'_>,
    child: &Compiled,
    clone: &Value,
    statement: &str,
) -> Result<(), String> {
    let view = child
        .public_methods
        .get("getAcceptance")
        .ok_or("Missing child acceptance view")?;
    let request = json!({"group": 0, "address": clone["address"], "bytecode": child.bytecode,
        "initialImmFields": clone["immFields"], "initialMutFields": clone["mutFields"],
        "initialAsset": crate::staged_state::asset(), "methodIndex": view, "args": [],
        "existingContracts": [], "inputAssets": []});
    let response = run.success("forged-clone-claims-final-view", &request)?;
    let checked = crate::factory_state::checked_states(&response, &[clone]);
    run.record(json!({"name": "forged-clone-claims-final-view",
        "passed": crate::factory_state::envelope(&response, clone) && checked.is_ok()
            && response["events"] == json!([])
            && response["returns"] == json!([crate::cases::word("3"), bytes(statement)]),
        "outcome": "vm-success", "gasUsed": response["gasUsed"],
        "syntheticallyForgedAttackState": true, "canonicalOriginEvidence": false,
        "stateValidationError": checked.as_ref().err()}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded() -> Vec<String> {
        let mut seal = vec![0_u8; 260];
        seal[..4].copy_from_slice(&[0x73, 0xc4, 0x57, 0xba]);
        let mut auxiliary = vec![0_u8; 577];
        auxiliary[0] = 1;
        vec![
            hex::encode(seal),
            hex::encode([1_u8; 32]),
            hex::encode([2_u8; 32]),
            hex::encode(auxiliary),
        ]
    }

    #[test]
    fn payload_can_be_pinned_before_deployment_but_statement_binds_child() {
        let fixture = Fixture::from_encoded(&[0; 32], &encoded()).unwrap();
        // Independent SHA256 vectors generated with .NET SHA256, not this codec.
        assert_eq!(
            fixture.payload_id,
            "91d90dcfb22517173b92b53271a5c6b92c08871970313cb55c160df4f79d87b2"
        );
        assert_eq!(
            fixture.statement_id,
            "e7e3505ca8b30e467512ab084f5743c884e3939fbd6dc764e154050fe9c85023"
        );
        let mut other_child = [0_u8; 32];
        other_child[0] = 1;
        let other = Fixture::from_encoded(&other_child, &encoded()).unwrap();
        assert_eq!(fixture.payload_id, other.payload_id);
        assert_ne!(fixture.statement_id, other.statement_id);
        for index in 0..4 {
            let args = changed_arg(&fixture, index).unwrap();
            let changed = Fixture::from_args(&fixture.contract_id, &args).unwrap();
            assert_ne!(fixture.payload_id, changed.payload_id);
            assert_ne!(fixture.statement_id, changed.statement_id);
        }
    }

    #[test]
    fn binding_codec_rejects_noncanonical_width_selector_and_version() {
        for index in 0..4 {
            let mut args = encoded();
            args[index].push_str("00");
            assert!(Fixture::from_encoded(&[0; 32], &args).is_err());
        }
        for index in [0, 3] {
            let mut args = encoded();
            args[index].replace_range(..2, "00");
            assert!(Fixture::from_encoded(&[0; 32], &args).is_err());
        }
    }
}
