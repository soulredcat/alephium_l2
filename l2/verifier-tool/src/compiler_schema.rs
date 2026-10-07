//! Exact field and public-method schemas, including staged state transitions.
use crate::input::Suite;
use serde_json::{Value, json};
use std::collections::BTreeMap;

type MethodSchema<'a> = (&'a str, Vec<&'a str>, Vec<&'a str>, Vec<&'a str>, bool);

pub fn validate(artifact: &Value, suite: Suite) -> Result<BTreeMap<String, usize>, String> {
    if matches!(
        suite,
        Suite::SettlementFactoryCompile | Suite::SettlementFactoryFlow | Suite::SettlementData
    ) {
        return crate::settlement_schema::validate(artifact, suite);
    }
    let fields = &artifact["fieldsSig"];
    let staged = matches!(suite, Suite::StagedReceipt);
    let factory = matches!(suite, Suite::StagedFactory | Suite::StagedFactoryFlow);
    let (names, types, mutable) = if staged {
        (
            json!([
                "fpModulus",
                "expectedPayloadId",
                "stateStatus",
                "stateCursor",
                "statePairs",
                "statePoints",
                "stateRootInverse",
                "stateRoot",
                "stateAccumulator",
                "stateCorrection",
                "stateStatementId"
            ]),
            json!([
                "U256",
                "ByteVec",
                "U256",
                "U256",
                "[U256;18]",
                "[U256;18]",
                "[U256;12]",
                "[U256;12]",
                "[U256;12]",
                "[U256;6]",
                "ByteVec"
            ]),
            json!([
                false, false, true, true, true, true, true, true, true, true, true
            ]),
        )
    } else if factory {
        (
            json!([
                "templateContractId",
                "expectedTemplateCodeHash",
                "fpModulus",
                "expectedPayloadId"
            ]),
            json!(["ByteVec", "ByteVec", "U256", "ByteVec"]),
            json!([false, false, false, false]),
        )
    } else {
        (json!(["fpModulus"]), json!(["U256"]), json!([false]))
    };
    if fields["names"] != names || fields["types"] != types || fields["isMutable"] != mutable {
        return Err("Compiler fields differ from the exact selected layout".into());
    }
    if artifact["eventsSig"] != json!([]) {
        return Err("Selected verifier artifact has an unexpected event interface".into());
    }
    let functions = artifact["functions"]
        .as_array()
        .ok_or("Missing compiler function ABI")?;
    let expected: Vec<MethodSchema<'_>> = if staged {
        vec![
            (
                "begin",
                vec!["seal", "imageId", "journalDigest", "auxiliary"],
                vec!["ByteVec"; 4],
                vec!["ByteVec"],
                false,
            ),
            (
                "advance",
                vec!["expectedStatement", "expectedCursor"],
                vec!["ByteVec", "U256"],
                vec!["U256"],
                false,
            ),
            (
                "finish",
                vec!["expectedStatement"],
                vec!["ByteVec"],
                vec!["ByteVec"],
                false,
            ),
            (
                "getAcceptance",
                vec![],
                vec![],
                vec!["U256", "ByteVec"],
                false,
            ),
            ("getBinding", vec![], vec![], vec!["U256", "ByteVec"], false),
        ]
    } else if factory {
        vec![
            ("create", vec![], vec![], vec!["ByteVec"], true),
            (
                "accepted",
                vec!["expectedStatement"],
                vec!["ByteVec"],
                vec!["ByteVec"],
                false,
            ),
        ]
    } else {
        // Component schemas are dynamic only in their fixed names/types list.
        return component(functions, suite);
    };
    if functions.iter().filter(|f| f["isPublic"] == true).count() != expected.len() {
        return Err("Unexpected public method in selected verifier artifact".into());
    }
    let mut methods = BTreeMap::new();
    for (name, params, types, returns, approved) in expected {
        let (index, function) = functions
            .iter()
            .enumerate()
            .find(|(_, f)| f["name"] == name)
            .ok_or("Missing selected public method")?;
        if function["isPublic"] != true
            || function["paramNames"] != json!(params)
            || function["paramTypes"] != json!(types)
            || function["returnTypes"] != json!(returns)
            || function["usePreapprovedAssets"] != approved
            || function["useAssetsInContract"] != false
        {
            return Err(format!(
                "Compiler ABI/assets differ for selected method {name}"
            ));
        }
        methods.insert(name.into(), index);
    }
    Ok(methods)
}

fn component(functions: &[Value], suite: Suite) -> Result<BTreeMap<String, usize>, String> {
    let (index, function) = functions
        .iter()
        .enumerate()
        .find(|(_, f)| f["name"] == suite.entry())
        .ok_or("Missing component public entry")?;
    if function["isPublic"] != true
        || function["paramNames"] != json!(suite.param_names())
        || function["paramTypes"] != json!(suite.param_types())
        || function["returnTypes"] != json!(suite.return_types())
        || function["usePreapprovedAssets"] != false
        || function["useAssetsInContract"] != false
        || functions.iter().filter(|f| f["isPublic"] == true).count() != 1
    {
        return Err("Compiler component ABI or asset privileges differ".into());
    }
    Ok(BTreeMap::from([(suite.entry().into(), index)]))
}
