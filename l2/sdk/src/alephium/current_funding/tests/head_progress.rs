//! Simulated owner-chain lineage checks in the existing aggregate, not PoW proof.
use super::super::{
    CurrentFundingError as Error, HeadChangeReason as Reason, MAX_OWNER_HEAD_ADVANCE, checks,
};
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

fn changed(reason: Reason, expected: (u64, u64), observed: (u64, u64)) -> Error {
    Error::HeadChanged {
        reason,
        expected_height: expected.0,
        observed_height: observed.0,
        expected_timestamp_ms: expected.1,
        observed_timestamp_ms: observed.1,
    }
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
        before_height: 100,
        after_height: 133,
    };
    check(
        checks::head_advance(&oversized[0], last).err() == Some(too_large)
            && too_large.to_string()
                == "Current fixed-output funding refused: HeadProgressTooLarge { observed: 33, maximum: 32, before_height: 100, after_height: 133 }",
    );
    check(checks::head_lineage(&oversized[0], last, &oversized).err() == Some(too_large));
    let backwards = changed(Reason::HeightRegression, (101, 1_001), (100, 1_000));
    check(
        checks::head_advance(&one[1], &one[0]).err() == Some(backwards)
            && backwards.to_string()
                == "Current fixed-output funding refused: HeadChanged { reason: HeightRegression, expected_height: 101, observed_height: 100, expected_timestamp_ms: 1001, observed_timestamp_ms: 1000 }",
    );
    check(checks::head_lineage(&one[1], &one[0], &one).err() == Some(backwards));

    for index in 0..2 {
        let mut altered = one.clone();
        altered[index].hash = B256::ZERO;
        let expected = changed(Reason::ZeroHeaderHash, (100, 1_000), (101, 1_001));
        check(checks::head_advance(&altered[0], &altered[1]).err() == Some(expected));
        check(checks::head_lineage(&altered[0], &altered[1], &altered).err() == Some(expected));
    }
    let mut backwards_time = one.clone();
    backwards_time[1].timestamp_ms = backwards_time[0].timestamp_ms - 1;
    let expected = changed(Reason::TimestampRegression, (100, 1_000), (101, 999));
    check(checks::head_advance(&backwards_time[0], &backwards_time[1]).err() == Some(expected));
    check(
        checks::head_lineage(&backwards_time[0], &backwards_time[1], &backwards_time).err()
            == Some(expected),
    );
    for mutation in 0..3 {
        let mut altered = before.clone();
        let expected = match mutation {
            0 => {
                altered.hash = B256::repeat_byte(99);
                changed(Reason::SameHeightFork, (100, 1_000), (100, 1_000))
            }
            1 => {
                altered.dependencies[0] = B256::repeat_byte(99);
                changed(Reason::SameHeightHeader, (100, 1_000), (100, 1_000))
            }
            _ => {
                altered.timestamp_ms += 1;
                changed(Reason::SameHeightHeader, (100, 1_000), (100, 1_001))
            }
        };
        check(checks::head_advance(before, &altered).err() == Some(expected));
        check(checks::head_lineage(before, &altered, &stationary).err() == Some(expected));
    }

    let original = chain(3);
    let before = &original[0];
    let after = &original[3];
    let length_error = changed(Reason::LineageLength, (100, 1_000), (103, 1_003));
    check(checks::head_lineage(before, after, &[]).err() == Some(length_error));
    check(checks::head_lineage(before, after, &original[1..]).err() == Some(length_error));
    check(checks::head_lineage(before, after, &original[..3]).err() == Some(length_error));
    let mut missing = original.clone();
    missing.remove(1);
    check(checks::head_lineage(before, after, &missing).err() == Some(length_error));
    for mutation in 0..7 {
        let mut altered = original.clone();
        let expected = match mutation {
            0 => {
                altered[2] = altered[1].clone();
                changed(Reason::LineageDuplicate, (100, 1_000), (101, 1_001))
            }
            1 => {
                altered[1].height += 1;
                changed(Reason::LineageHeight, (101, 1_000), (102, 1_001))
            }
            2 => {
                altered.swap(1, 2);
                changed(Reason::LineageHeight, (101, 1_000), (102, 1_002))
            }
            3 => {
                altered[2].dependencies[3] = B256::repeat_byte(99);
                changed(Reason::LineageParent, (102, 1_001), (102, 1_002))
            }
            4 => {
                altered[2].timestamp_ms = altered[1].timestamp_ms - 1;
                changed(Reason::LineageTimestamp, (102, 1_001), (102, 1_000))
            }
            5 => {
                altered[1].hash = B256::ZERO;
                changed(Reason::ZeroHeaderHash, (100, 1_000), (101, 1_001))
            }
            _ => {
                // A repeated hash remains invalid even if heights increase and
                // all parent links are adjusted to agree with the duplicate.
                altered[1].hash = altered[0].hash;
                altered[2].dependencies[3] = altered[1].hash;
                changed(Reason::LineageDuplicate, (100, 1_000), (101, 1_001))
            }
        };
        check(checks::head_lineage(before, after, &altered).err() == Some(expected));
    }
    for index in [0, 3] {
        let mut altered = original.clone();
        altered[index].dependencies[6] = B256::repeat_byte(99);
        let expected = if index == 0 {
            changed(Reason::LineageStart, (100, 1_000), (100, 1_000))
        } else {
            changed(Reason::LineageEnd, (103, 1_003), (103, 1_003))
        };
        check(checks::head_lineage(before, after, &altered).err() == Some(expected));
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
