//! Pure native lock-time rules within the existing aggregate; simulated facts.
use super::fixture;
use crate::alephium::{
    alephium_hash,
    current_funding::{CurrentFundingError as Error, LockTimeProjection, creator, lock_time},
};
use serde_json::json;

pub(super) fn run_checks() -> usize {
    let fixture = fixture::build(None);
    let base = &fixture.fixed[1];
    let maximum = i64::MAX as u64;
    let mut count = 0;
    let mut check = |ok: bool| {
        assert!(ok, "Native lock-time check failed; payload suppressed");
        count += 1;
    };

    for (committed, timestamp, expected) in [
        (0, 0, 0),
        (0, 6_000, 6_000),
        (1_000, 6_000, 6_000),
        (6_000, 6_000, 6_000),
        (9_000, 6_000, 9_000),
        (maximum, 0, maximum),
        (0, maximum, maximum),
        (maximum, maximum, maximum),
    ] {
        let mut original = base.clone();
        original.lock_time_ms = committed;
        let effective = lock_time::effective_output(&original, timestamp).unwrap();
        check(effective.lock_time_ms == expected);
        check(
            original.lock_time_ms == committed
                && effective.reference == original.reference
                && effective.amount == original.amount
                && effective.locking_script == original.locking_script
                && effective.tokens == original.tokens
                && effective.additional_data == original.additional_data,
        );
    }
    let earlier = lock_time::effective_output(base, 6_000).unwrap();
    let later = lock_time::effective_output(base, 7_000).unwrap();
    check(earlier.lock_time_ms == 6_000 && later.lock_time_ms == 7_000);

    for (committed, timestamp) in [
        (maximum + 1, 0),
        (0, maximum + 1),
        (u64::MAX, maximum),
        (maximum, u64::MAX),
    ] {
        let mut original = base.clone();
        original.lock_time_ms = committed;
        check(
            lock_time::effective_output(&original, timestamp).err() == Some(Error::CreatorMismatch),
        );
    }

    check(matches!(
        lock_time::projection(0, 6_000, Some(0), 6_000),
        Ok(LockTimeProjection::Committed)
    ));
    check(matches!(
        lock_time::projection(0, 6_000, Some(6_000), 6_000),
        Ok(LockTimeProjection::Effective)
    ));
    check(matches!(
        lock_time::projection(6_000, 6_000, Some(6_000), 6_000),
        Ok(LockTimeProjection::Coincident)
    ));
    check(matches!(
        lock_time::projection(0, 0, Some(0), 0),
        Ok(LockTimeProjection::Coincident)
    ));
    check(matches!(
        lock_time::projection(maximum, maximum, Some(maximum), maximum),
        Ok(LockTimeProjection::Coincident)
    ));
    check(matches!(
        lock_time::projection(0, maximum, Some(0), maximum),
        Ok(LockTimeProjection::Committed)
    ));
    check(matches!(
        lock_time::projection(0, maximum, Some(maximum), maximum),
        Ok(LockTimeProjection::Effective)
    ));

    for (committed, effective, observed, maturity) in [
        (0, 6_000, 0, 5_999),
        (0, 6_000, 6_000, 5_999),
        (9_000, 9_000, 9_000, 8_999),
        (9_000, 12_000, 9_000, 11_999),
        (9_000, 12_000, 12_000, 11_999),
    ] {
        check(
            lock_time::projection(committed, effective, Some(observed), maturity).err()
                == Some(Error::AvailabilityImmature),
        );
    }
    check(
        lock_time::projection(0, 6_000, None, 6_000).err()
            == Some(Error::AvailabilityLockTimeMissing),
    );
    for observed in [1, 5_999, 6_001, u64::MAX] {
        check(
            lock_time::projection(0, 6_000, Some(observed), 10_000).err()
                == Some(Error::AvailabilityLockTimeMismatch),
        );
    }
    for (committed, effective) in [
        (6_001, 6_000),
        (0, maximum + 1),
        (maximum + 1, maximum + 1),
        (u64::MAX, u64::MAX),
    ] {
        check(
            lock_time::projection(committed, effective, Some(effective), u64::MAX).err()
                == Some(Error::CreatorMismatch),
        );
    }

    // Deriving a stored timestamp must not rewrite the hash-authenticated body.
    let original = creator::fixed_outputs(&fixture.details, fixture.creator_id, None).unwrap();
    check(original[1].lock_time_ms == 0);
    let effective = lock_time::effective_output(&original[1], 6_000).unwrap();
    check(effective.lock_time_ms == 6_000);
    check(
        fixture.details["unsigned"]["fixedOutputs"][1]["lockTime"] == json!(0)
            && alephium_hash(&fixture.creator_raw) == fixture.creator_id,
    );
    let reread = creator::fixed_outputs(&fixture.details, fixture.creator_id, None).unwrap();
    check(reread[1].lock_time_ms == 0 && reread[1].reference == original[1].reference);
    let mut changed_time = fixture.details.clone();
    changed_time["unsigned"]["fixedOutputs"][1]["lockTime"] = json!(6_000);
    check(
        creator::fixed_outputs(&changed_time, fixture.creator_id, None).err()
            == Some(Error::CreatorMismatch),
    );
    let mut changed_amount = fixture.details.clone();
    changed_amount["unsigned"]["fixedOutputs"][1]["attoAlphAmount"] = json!("2000000000000000001");
    check(
        creator::fixed_outputs(&changed_amount, fixture.creator_id, None).err()
            == Some(Error::CreatorMismatch),
    );
    count
}
