//! One aggregate for the newly implemented read/funding responsibility only.
//! Source observations are simulated; no live RPC, signing or submission runs.

#[test]
#[ignore = "Requires explicitly supplied, independently compiled and pinned project-drive script fixture"]
fn p5_read_node_and_current_fixed_funding_aggregate() {
    let reader_checks = super::read_node::tests::run_checks();
    let funding_checks = super::current_funding::tests::run_checks();
    assert!(reader_checks > 0 && funding_checks > 0);
    println!(
        "P5 read/funding aggregate: PASS reader_checks={reader_checks} funding_checks={funding_checks}; simulated facts, no live operations"
    );
}
