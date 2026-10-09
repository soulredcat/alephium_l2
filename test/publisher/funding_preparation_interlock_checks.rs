//! One fail-closed interlock aggregate; no keys, files, client or effects.
use super::*;

#[test]
fn p5_funding_preparation_interlock_bulk() {
    assert!(submission_interlock(Some("1"), true).is_ok());
    for (value, enabled) in [
        (None, true),
        (Some("0"), true),
        (Some("1"), false),
        (Some("true"), true),
        (Some("01"), true),
        (Some("1 "), true),
    ] {
        assert!(submission_interlock(value, enabled) == Err(Error::Disabled));
    }
    println!(
        "Funding preparation submission interlock aggregate: PASS checks=7; no keys or clients"
    );
}
