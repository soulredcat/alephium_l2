use super::{IdentityObservation, NodeVersion, ReadNodeConfig, ReadNodeError as Error};
use serde::Deserialize;

#[derive(Deserialize)]
pub(super) struct Version {
    pub version: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ChainParams {
    pub network_id: i32,
    pub groups: i32,
    pub group_num_per_broker: i32,
    pub num_zeros_at_least_in_hash: i32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Clique {
    pub self_ready: bool,
    pub synced: bool,
}

pub(super) fn validate(
    config: &ReadNodeConfig,
    origin: &str,
    version: Version,
    params: ChainParams,
    clique: Clique,
) -> Result<IdentityObservation, Error> {
    let version = match version.version.as_str() {
        "v4.7.0" => NodeVersion::V4_7_0,
        "v4.7.1" => NodeVersion::V4_7_1,
        _ => return Err(Error::UnsupportedVersion),
    };
    if params.network_id != 1
        || params.groups != 4
        || !(1..=4).contains(&params.group_num_per_broker)
        || 4 % params.group_num_per_broker != 0
        || !(0..=256).contains(&params.num_zeros_at_least_in_hash)
    {
        return Err(Error::WrongNetwork);
    }
    if !clique.self_ready || !clique.synced {
        return Err(Error::NotReady);
    }
    Ok(IdentityObservation {
        source_id: config.source_id,
        origin: origin.into(),
        version,
        network_id: 1,
        groups: 4,
        group_num_per_broker: params.group_num_per_broker as u8,
        num_zeros_at_least_in_hash: params.num_zeros_at_least_in_hash as u32,
        chain_0_0_genesis: config.chain_0_0_genesis,
    })
}
