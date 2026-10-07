//! Exact ABI and field privileges for canonical settlement and immutable data.
use crate::input::Suite;
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub(crate) fn validate(artifact: &Value, suite: Suite) -> Result<BTreeMap<String, usize>, String> {
    let data = matches!(suite, Suite::SettlementData);
    let (names, types, mutable) = if data {
        (json!(["data"]), json!(["ByteVec"]), json!([false]))
    } else {
        (
            json!([
                "proofTemplateId",
                "proofTemplateCodeHash",
                "dataTemplateId",
                "dataTemplateCodeHash",
                "approvedImageId",
                "l1Network",
                "l1GenesisId",
                "l2ChainId",
                "l2GenesisId",
                "executionProfile",
                "genesisCheckpointSha256",
                "genesisHead",
                "transportLimits",
                "maxFutureSeconds",
                "initialized",
                "acceptedHead",
                "acceptedRoot"
            ]),
            json!([
                "ByteVec", "ByteVec", "ByteVec", "ByteVec", "ByteVec", "ByteVec", "ByteVec",
                "U256", "ByteVec", "ByteVec", "ByteVec", "ByteVec", "ByteVec", "U256", "U256",
                "ByteVec", "ByteVec"
            ]),
            json!([
                false, false, false, false, false, false, false, false, false, false, false, false,
                false, false, true, true, true
            ]),
        )
    };
    let fields = &artifact["fieldsSig"];
    if fields["names"] != names || fields["types"] != types || fields["isMutable"] != mutable {
        return Err("Settlement artifact field schema differs".into());
    }
    type Method<'a> = (&'a str, Vec<&'a str>, Vec<&'a str>, Vec<&'a str>, bool);
    let expected: Vec<Method<'_>> = if data {
        vec![
            ("getHash", vec![], vec![], vec!["ByteVec"], false),
            ("getLength", vec![], vec![], vec!["U256"], false),
            ("getData", vec![], vec![], vec!["ByteVec"], false),
        ]
    } else {
        vec![
            (
                "initializeGenesis",
                vec!["checkpoint"],
                vec!["ByteVec"],
                vec!["ByteVec"],
                false,
            ),
            (
                "createCandidate",
                vec!["journal", "sealDigest", "auxiliaryDigest", "data"],
                vec!["ByteVec"; 4],
                vec!["ByteVec"; 3],
                true,
            ),
            (
                "finalize",
                vec!["journal", "sealDigest", "auxiliaryDigest"],
                vec!["ByteVec"; 3],
                vec!["ByteVec"],
                false,
            ),
            (
                "getAnchor",
                vec![],
                vec![],
                vec!["U256", "ByteVec", "ByteVec"],
                false,
            ),
        ]
    };
    let methods = artifact["functions"]
        .as_array()
        .ok_or("Missing settlement functions")?;
    if methods
        .iter()
        .filter(|method| method["isPublic"] == true)
        .count()
        != expected.len()
    {
        return Err("Settlement public entry inventory differs".into());
    }
    let mut indices = BTreeMap::new();
    for (name, params, args, returns, preapproved) in expected {
        let (index, method) = methods
            .iter()
            .enumerate()
            .find(|(_, method)| method["name"] == name)
            .ok_or("Missing settlement public entry")?;
        if method["isPublic"] != true
            || method["paramNames"] != json!(params)
            || method["paramTypes"] != json!(args)
            || method["returnTypes"] != json!(returns)
            || method["usePreapprovedAssets"] != preapproved
            || method["useAssetsInContract"] != false
        {
            return Err("Settlement public ABI or asset privileges differ".into());
        }
        indices.insert(name.into(), index);
    }
    Ok(indices)
}
