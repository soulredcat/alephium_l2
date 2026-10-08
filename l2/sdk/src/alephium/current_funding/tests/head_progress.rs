//! Simulated owner-chain lineage checks in the existing aggregate, not PoW proof.
use super::super::{CurrentFundingError as Error, MAX_OWNER_HEAD_ADVANCE, checks};
use crate::alephium::read_node::ChainHeader;
use alloy_primitives::B256;

fn chain(advance: u32) -> Vec<ChainHeader> {
    assert!(advance <= 33, "Synthetic lineage bound exceeded");
    (0..=advance)
        .map(|index| {
            let mut dependencies = [B256::repeat_byte(200 + index as u8); 7];
            dependencies[3] = if index == 0 {
                B256::repeat_byte(199)
            } else {
                B256::repeat_byte(index as u8)
            };
            ChainHeader {
                hash: B256::repeat_byte(index as u8 + 1),
                height: 100 + u64::from(index),
                timestamp_ms: 1_000 + u64::from(index),
                dependencies,
            }
        })
        .collect()
}

pub(super) fn run_checks() -> usize {
    let mut count = 0;
    let mut check = |ok: bool| {
        assert!(ok, "Owner-head progress check failed; payload suppressed");
        count += 1;
    };
    let stationary = chain(0);
    let before = &stationary[0];
    check(checks::head_advance(before, before) == Ok(0));
    check(checks::head_lineage(before, before, &stationary).is_ok());
    let one = chain(1);
    check(checks::head_advance(&one[0], &one[1]) == Ok(1));
    check(checks::head_lineage(&one[0], &one[1], &one).is_ok());
    let maximum = chain(32);
    let last = maximum.last().unwrap();
    check(checks::head_advance(&maximum[0], last) == Ok(32));
    check(checks::head_lineage(&maximum[0], last, &maximum).is_ok());
    let oversized = chain(33);
    let last = oversized.last().unwrap();
    let too_large = Error::HeadProgressTooLarge {
        observed: 33,
        maximum: MAX_OWNER_HEAD_ADVANCE,
    };
    check(checks::head_advance(&oversized[0], last).err() == Some(too_large));
    check(checks::head_lineage(&oversized[0], last, &oversized).err() == Some(too_large));
    check(checks::head_advance(&one[1], &one[0]).err() == Some(Error::HeadChanged));
    check(checks::head_lineage(&one[1], &one[0], &one).err() == Some(Error::HeadChanged));

    for index in 0..2 {
        let mut changed = one.clone();
        changed[index].hash = B256::ZERO;
        check(checks::head_advance(&changed[0], &changed[1]).err() == Some(Error::HeadChanged));
        check(checks::head_lineage(&changed[0], &changed[1], &changed).is_err());
    }
    let mut backwards_time = one.clone();
    backwards_time[1].timestamp_ms = backwards_time[0].timestamp_ms - 1;
    check(checks::head_advance(&backwards_time[0], &backwards_time[1]).is_err());
    check(checks::head_lineage(&backwards_time[0], &backwards_time[1], &backwards_time).is_err());
    for mutation in 0..3 {
        let mut changed = before.clone();
        match mutation {
            0 => changed.hash = B256::repeat_byte(99),
            1 => changed.dependencies[0] = B256::repeat_byte(99),
            _ => changed.timestamp_ms += 1,
        }
        check(checks::head_advance(before, &changed).err() == Some(Error::HeadChanged));
        check(checks::head_lineage(before, &changed, &stationary).is_err());
    }

    let original = chain(3);
    let before = &original[0];
    let after = &original[3];
    check(checks::head_lineage(before, after, &[]).is_err());
    check(checks::head_lineage(before, after, &original[1..]).is_err());
    check(checks::head_lineage(before, after, &original[..3]).is_err());
    let mut missing = original.clone();
    missing.remove(1);
    check(checks::head_lineage(before, after, &missing).is_err());
    for mutation in 0..7 {
        let mut changed = original.clone();
        match mutation {
            0 => changed[2] = changed[1].clone(),
            1 => changed[1].height += 1,
            2 => changed.swap(1, 2),
            3 => changed[2].dependencies[3] = B256::repeat_byte(99),
            4 => changed[2].timestamp_ms = changed[1].timestamp_ms - 1,
            5 => changed[1].hash = B256::ZERO,
            _ => {
                // A repeated hash remains invalid even if heights increase and
                // all parent links are adjusted to agree with the duplicate.
                changed[1].hash = changed[0].hash;
                changed[2].dependencies[3] = changed[1].hash;
            }
        }
        check(checks::head_lineage(before, after, &changed).is_err());
    }
    for index in [0, 3] {
        let mut changed = original.clone();
        changed[index].dependencies[6] = B256::repeat_byte(99);
        check(checks::head_lineage(before, after, &changed).is_err());
    }
    let mut mixed_dependencies = original.clone();
    for header in &mut mixed_dependencies[1..3] {
        for index in [0, 1, 2, 4, 5, 6] {
            header.dependencies[index] = B256::repeat_byte(77 + index as u8);
        }
    }
    check(checks::head_lineage(before, after, &mixed_dependencies).is_ok());
    let mut equal_times = original.clone();
    for header in &mut equal_times {
        header.timestamp_ms = before.timestamp_ms;
    }
    check(checks::head_lineage(&equal_times[0], &equal_times[3], &equal_times).is_ok());
    count
}
