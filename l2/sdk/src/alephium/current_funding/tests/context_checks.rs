//! Public context preconditions and parity, without DNS or HTTP requests.
use super::fixture;
use crate::alephium::{
    FundingModel,
    current_funding::{
        CurrentFundingError as Error, ScriptFreeCreators, observe_current_fixed_funding,
        observe_current_fixed_funding_context,
    },
    read_node::{ReadNode, ReadNodeConfig, ReadNodeError},
};
use alloy_primitives::B256;

pub(super) fn run_checks() -> usize {
    let f = fixture::build(None);
    let pin = f.observation.pin();
    let key = &f.operation.spec().caller_public_key;
    let references = [f.fixed[1].reference];
    let policy = f.observation.policy();
    // Construction performs no requests. No handshake is performed; all valid
    // contexts stop at HandshakeRequired before the reader can send a GET.
    let node = ReadNode::new(ReadNodeConfig::official_testnet(
        pin.source_id,
        f.observation.head_before().identity.chain_0_0_genesis,
    ))
    .unwrap();
    let mut count = 0;
    let mut check = |ok: bool| {
        assert!(ok, "Funding read-context check failed; payload suppressed");
        count += 1;
    };
    check(matches!(
        observe_current_fixed_funding(
            &f.operation,
            &references,
            &node,
            policy,
            &ScriptFreeCreators
        ),
        Err(Error::Read(ReadNodeError::HandshakeRequired))
    ));
    check(matches!(
        observe_current_fixed_funding_context(
            pin,
            key,
            &references,
            &node,
            policy,
            &ScriptFreeCreators
        ),
        Err(Error::Read(ReadNodeError::HandshakeRequired))
    ));
    let mut noncanonical_key = *key;
    noncanonical_key[0] = 4;
    for invalid_key in [
        [0; 33],
        noncanonical_key,
        fixture::public_point_for_group(1),
    ] {
        check(matches!(
            observe_current_fixed_funding_context(
                pin,
                &invalid_key,
                &references,
                &node,
                policy,
                &ScriptFreeCreators
            ),
            Err(Error::InvalidPublisher)
        ));
    }
    for mutation in 0..4 {
        let mut invalid = pin.clone();
        match mutation {
            0 => invalid.source_id = B256::ZERO,
            1 => invalid.network_genesis_id = B256::ZERO,
            2 => invalid.head_hash = B256::ZERO,
            _ => invalid.timestamp_ms = u64::MAX,
        }
        check(matches!(
            observe_current_fixed_funding_context(
                &invalid,
                key,
                &references,
                &node,
                policy,
                &ScriptFreeCreators
            ),
            Err(Error::InvalidPolicy)
        ));
    }
    for mutation in 0..3 {
        let mut invalid = pin.clone();
        match mutation {
            0 => invalid.network_id = 0,
            1 => invalid.group = 1,
            _ => invalid.group_count = 3,
        }
        check(matches!(
            observe_current_fixed_funding_context(
                &invalid,
                key,
                &references,
                &node,
                policy,
                &ScriptFreeCreators
            ),
            Err(Error::InvalidPolicy)
        ));
    }
    let mut snapshot = pin.clone();
    snapshot.model = FundingModel::ExactHeadSnapshotV1;
    check(matches!(
        observe_current_fixed_funding_context(
            &snapshot,
            key,
            &references,
            &node,
            policy,
            &ScriptFreeCreators
        ),
        Err(Error::WrongFundingModel)
    ));
    count
}
