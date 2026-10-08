//! Derived lock evidence stays bound to the exact canonical creator observation.
use super::fixture;
use crate::alephium::{
    current_funding::{checks, lock_time, validate_current_unsigned},
    read_node::ChainHeader,
};
use alloy_primitives::B256;

pub(super) fn run_checks() -> usize {
    let f = fixture::build(None);
    let fact = &f.observation.provenance()[0];
    let mut count = 0;
    let mut check = |ok: bool| {
        assert!(ok, "Lock evidence binding failed; payload suppressed");
        count += 1;
    };
    let header = ChainHeader {
        hash: fact.inclusion.block_hash,
        height: fact.creator_block_height,
        timestamp_ms: fact.creator_block_timestamp_ms,
        dependencies: [B256::repeat_byte(44); 7],
    };
    check(lock_time::rechecked(fact, &f.fixed[1], &header).is_ok());
    for mutation in 0..3 {
        let mut changed = header.clone();
        match mutation {
            0 => changed.hash = B256::repeat_byte(99),
            1 => changed.height += 1,
            _ => changed.timestamp_ms += 1,
        }
        check(lock_time::rechecked(fact, &f.fixed[1], &changed).is_err());
    }
    let mut requested_future = f.fixed[1].clone();
    requested_future.lock_time_ms = 9_000;
    let mut future_fact = fact.clone();
    future_fact.committed_lock_time_ms = 9_000;
    future_fact.effective_lock_time_ms = 9_000;
    check(lock_time::rechecked(&future_fact, &requested_future, &header).is_ok());
    let mut reincluded = header.clone();
    reincluded.timestamp_ms += 1;
    // Both timestamps yield the same effective value. Exact creator T is still
    // required; max equality alone must not approve changed inclusion facts.
    check(lock_time::rechecked(&future_fact, &requested_future, &reincluded).is_err());

    for mutation in 0..6 {
        let mut changed = fixture::build(None);
        match mutation {
            0 => changed.observation.funding.outputs[0].lock_time_ms = 0,
            1 => changed.observation.provenance[0].creator_block_timestamp_ms += 1,
            2 => changed.observation.provenance[0].effective_lock_time_ms += 1,
            3 => changed.observation.provenance[0].committed_lock_time_ms = u64::MAX,
            4 => changed.observation.provenance[0].reference.key = B256::repeat_byte(99),
            _ => changed.observation.provenance.clear(),
        }
        check(
            validate_current_unsigned(&changed.operation, &changed.observation, &changed.spend)
                .is_err(),
        );
    }
    let mut future = fixture::build(None);
    let lock = future.observation.pin().timestamp_ms + 1;
    future.observation.provenance[0].committed_lock_time_ms = lock;
    future.observation.provenance[0].effective_lock_time_ms = lock;
    future.observation.funding.outputs[0].lock_time_ms = lock;
    check(future.observation.validate_lock_evidence().is_ok());
    check(
        validate_current_unsigned(&future.operation, &future.observation, &future.spend).is_err(),
    );

    let owner = crate::alephium::alephium_hash(&f.operation.spec().caller_public_key);
    for mutation in 0..3 {
        let mut changed = f.observation.outputs()[0].clone();
        match mutation {
            0 => changed.locking_script[0] = 3,
            1 => {
                changed.locking_script.pop();
            }
            _ => changed.locking_script[1] ^= 1,
        }
        check(
            checks::latest(
                &changed,
                &f.latest,
                fact,
                owner,
                f.observation.pin().timestamp_ms,
            )
            .is_err(),
        );
    }
    count
}
