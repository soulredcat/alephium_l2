//! AFTER pinning is a new approval context, never renewal of a previous intent.
use super::fixture;
use crate::alephium::{
    current_funding::{
        CurrentFundingError, ScriptFreeCreators, observe_current_fixed_funding_current,
        validate_current_unsigned,
    },
    read_node::{ReadNode, ReadNodeConfig, ReadNodeError},
};
use alloy_primitives::B256;

pub(super) fn run_checks() -> usize {
    let mut f = fixture::build(None);
    let mut count = 0;
    let mut check = |ok: bool| {
        assert!(
            ok,
            "Funding head capability check failed; payload suppressed"
        );
        count += 1;
    };
    // Simulated canonical lineage; no RPC/consensus validation is claimed here.
    let before = f.observation.before.header.clone();
    let mut after = before.clone();
    after.height += 1;
    after.timestamp_ms += 1;
    after.hash = B256::repeat_byte(90);
    after.dependencies[3] = before.hash;
    f.observation.after.header = after.clone();
    f.observation.current_window = true;
    f.observation.head_lineage = vec![before, after.clone()];
    f.observation.funding.pin.head_hash = after.hash;
    f.observation.funding.pin.head_height = after.height;
    f.observation.funding.pin.timestamp_ms = after.timestamp_ms;
    check(f.observation.is_current_window() && f.observation.head_advance() == 1);
    check(validate_current_unsigned(&f.operation, &f.observation, &f.spend).is_err());
    // Model a separate fresh local approval, without signing or submission.
    f.operation.spec.funding = f.observation.pin().clone();
    f.operation.spec.intent_id = B256::repeat_byte(91);
    check(validate_current_unsigned(&f.operation, &f.observation, &f.spend).is_ok());
    f.observation.head_lineage.pop();
    check(validate_current_unsigned(&f.operation, &f.observation, &f.spend).is_err());
    f.observation.head_lineage.push(after);
    f.observation.current_window = false;
    check(validate_current_unsigned(&f.operation, &f.observation, &f.spend).is_err());
    f.observation.current_window = true;
    f.observation.funding.pin.head_height -= 1;
    f.operation.spec.funding = f.observation.pin().clone();
    check(validate_current_unsigned(&f.operation, &f.observation, &f.spend).is_err());
    let equal = fixture::build(None);
    check(!equal.observation.is_current_window() && equal.observation.head_advance() == 0);
    check(validate_current_unsigned(&equal.operation, &equal.observation, &equal.spend).is_ok());
    let node = ReadNode::new(ReadNodeConfig::official_testnet(
        equal.observation.pin().source_id,
        equal.observation.head_before().identity.chain_0_0_genesis,
    ))
    .unwrap();
    let refs = [equal.fixed[1].reference];
    check(matches!(
        observe_current_fixed_funding_current(
            &equal.operation.spec().caller_public_key,
            &refs,
            &node,
            equal.observation.policy(),
            &ScriptFreeCreators,
        ),
        Err(CurrentFundingError::Read(ReadNodeError::HandshakeRequired))
    ));
    check(matches!(
        observe_current_fixed_funding_current(
            &[0; 33],
            &refs,
            &node,
            equal.observation.policy(),
            &ScriptFreeCreators,
        ),
        Err(CurrentFundingError::InvalidPublisher)
    ));
    count
}
