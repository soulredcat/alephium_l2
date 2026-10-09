//! One real-Store serial dispatch/recovery bundle; synthetic source and callbacks.
#[path = "serial_dispatch_context.rs"]
mod context;
#[path = "serial_dispatch_faults.rs"]
mod faults;
#[allow(dead_code)]
#[path = "../../l2/node/tests/support/publisher_fixture.rs"]
mod fixture;
#[path = "serial_dispatch_lifecycle.rs"]
mod lifecycle;

use std::{fs, path::PathBuf};

#[test]
#[ignore = "Requires fresh private project output and independently pinned compiled script"]
fn serial_dispatch_durable_bulk() {
    let output = PathBuf::from(
        std::env::var_os("L2_SERIAL_BULK_OUTPUT").expect("Set fresh private serial output"),
    );
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("Repository root")
        .to_path_buf();
    let allowed = fs::canonicalize(repository.join("test/private"))
        .expect("Private test parent must already exist");
    let parent = fs::canonicalize(output.parent().expect("Output parent"))
        .expect("Output parent must already exist");
    assert!(
        fixture::on_project_drive(&output) && parent.starts_with(&allowed) && !output.exists(),
        "Use fresh output under the main repository test/private directory"
    );
    fs::create_dir(&output).expect("Create fresh serial output");
    let started = std::time::Instant::now();
    let lifecycle_checks = lifecycle::run(&output.join("lifecycle"))
        + lifecycle::regressed_confirmation(&output.join("lower-head"));
    let fault_checks = faults::run(&output);
    let checks = lifecycle_checks + fault_checks;
    let report = serde_json::json!({
        "schema": 1, "passed": true, "checks": checks,
        "lifecycleChecks": lifecycle_checks, "faultChecks": fault_checks,
        "elapsedMillis": started.elapsed().as_millis(),
        "realStoreReopen": true, "serialRoles": 4,
        "sourceAndCallbacks": "synthetic development fixture",
        "faultModel": "repository return before/after actual SyncAll; not power loss",
        "networkCalls": 0, "liveSigning": false, "liveSubmission": false,
        "allStoresDropped": true
    });
    fs::write(
        output.join("summary.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .expect("Write metadata-only aggregate summary");
    println!("Serial dispatch bulk: PASS checks={checks}; synthetic callbacks, no network");
}
