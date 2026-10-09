#[test]
fn p5_publisher_native_adapters_bulk() {
    let signer_checks = super::configured_signer::run_configured_signer_checks();
    let submitter_checks = super::http_submitter::pure_checks();
    assert!(signer_checks > 0 && submitter_checks > 0);
    println!(
        "P5 native adapter aggregate: PASS signer_checks={signer_checks} submitter_checks={submitter_checks}; synthetic only, no network"
    );
}
