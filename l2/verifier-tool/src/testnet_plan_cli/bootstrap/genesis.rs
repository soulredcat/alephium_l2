//! Reviewed pre-node source association, explicitly retained as trusted config.
use super::super::io;
use alephium_l2_sdk::alephium::read_node::{GenesisPin, GenesisProvenance};
use alloy_primitives::B256;
use serde_json::{Value, json};
use std::path::Path;

const SOURCE_URL: &str = "https://backend.testnet.alephium.org/blocks?limit=16&page=1&reverse=true";

pub(super) struct Selection {
    pub pin: GenesisPin,
    pub record_sha256: [u8; 32],
    pub association: Value,
}

pub(super) fn load(path: &Path) -> Result<Selection, String> {
    let bytes = io::read(path, 16384)?;
    let value = io::json(&bytes)?;
    io::object(
        &value,
        &[
            "schema",
            "networkId",
            "groups",
            "fromGroup",
            "toGroup",
            "height",
            "genesisHash",
            "sourceUrl",
            "provenance",
            "reviewed",
            "independentOfNodeDiscovery",
            "organizationallyIndependent",
            "cryptographicConsensusProof",
        ],
    )?;
    if value["schema"] != 1
        || value["networkId"] != 1
        || value["groups"] != 4
        || value["fromGroup"] != 0
        || value["toGroup"] != 0
        || value["height"] != 0
        || value["sourceUrl"] != SOURCE_URL
        || value["provenance"] != "explorer-selected-before-node"
        || value["reviewed"] != true
        || value["independentOfNodeDiscovery"] != true
        || value["organizationallyIndependent"] != false
        || value["cryptographicConsensusProof"] != false
    {
        return Err(
            "Reviewed genesis selection differs from the explicit pre-node source association"
                .into(),
        );
    }
    let hash = io::hash(&value, "genesisHash")?;
    if hash == [0; 32] {
        return Err("Reviewed genesis must be nonzero".into());
    }
    let pin = GenesisPin {
        hash: B256::from(hash),
        provenance: GenesisProvenance::Independent,
    };
    Ok(Selection {
        pin,
        record_sha256: io::sha(&bytes),
        association: json!({
        "networkId": 1, "groups": 4, "fromGroup": 0, "toGroup": 0, "height": 0,
        "genesisHash": hex::encode(hash), "sourceUrl": SOURCE_URL,
        "provenance": "explorer-selected-before-node", "reviewed": true,
        "independentOfNodeDiscovery": true, "organizationallyIndependent": false,
        "cryptographicConsensusProof": false, "sourceOriginVerifiedByDriver": false,
        "assertionScope": "caller-reviewed trusted configuration association, not independently proved consensus"}),
    })
}
