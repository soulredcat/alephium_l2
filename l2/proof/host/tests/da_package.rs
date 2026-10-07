//! One cohesive offline DA package/corruption/recovery bundle; no live app.
#[path = "support/da_reconstruction.rs"]
mod core_checks;

use alephium_l2_transition_prover::da::{export_package, read_candidate, reconstruct_package};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fs, path::Path};

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn copy_package(source: &Path, target: &Path) {
    fs::create_dir(target).unwrap();
    for name in [
        "data.bin",
        "candidate-journal.json",
        "retention.json",
        "report.json",
        "manifest.json",
    ] {
        fs::copy(source.join(name), target.join(name)).unwrap();
    }
}

#[test]
fn bulk_da_package_reconstruction_and_fail_closed_retention() {
    let input =
        std::env::var_os("L2_DA_INPUT").expect("explicit retained private fixture required");
    let output =
        std::env::var_os("L2_DA_OUTPUT").expect("explicit fresh project-drive output required");
    let input = Path::new(&input);
    let output = Path::new(&output);
    assert!(
        !output.exists(),
        "fresh output required; previous evidence is preserved"
    );
    fs::create_dir(output).unwrap();
    let fixture = core_checks::fixture_and_core_checks(input);
    let package = output.join("package");
    let report = export_package(input, &package).expect("native DA export");
    assert!(report.native_reconstruction_verified);
    assert!(!report.proof_accepted && !report.settlement_eligible && !report.public_data_available);
    assert_eq!(report.executed_transactions, 1000);
    assert_eq!(report.blocks, 8);
    assert_eq!(report.data_bytes, fixture.bytes.len());
    assert_eq!(
        report.da_commitment,
        fixture.journal.da_commitment.to_string()
    );
    assert!(
        fs::read(package.join("data.bin")).unwrap() == fixture.bytes,
        "canonical DA package bytes differ; private payload suppressed"
    );
    let expected_json = serde_json::to_vec_pretty(&fixture.journal).unwrap();
    let expected_file = output.join("independently-pinned-candidate.json");
    fs::write(&expected_file, &expected_json).unwrap();
    let expected = read_candidate(&expected_file, &sha(&expected_json)).unwrap();
    assert!(read_candidate(&expected_file, &"00".repeat(32)).is_err());
    let restored = output.join("clean-reconstruction");
    let restored_report = reconstruct_package(
        &package,
        &expected,
        fixture.bundle.checkpoint.capacity,
        &restored,
    )
    .unwrap();
    assert!(restored_report.native_reconstruction_verified);
    assert!(!restored_report.proof_accepted && !restored_report.settlement_eligible);
    assert!(
        fs::read(restored.join("checkpoint.bin")).unwrap() == fixture.checkpoint_bytes,
        "reconstructed checkpoint differs; private payload suppressed"
    );
    assert!(
        fs::read(restored.join("journal.bin")).unwrap() == fixture.journal.encode().unwrap(),
        "reconstructed journal bytes differ; payload suppressed"
    );
    assert!(
        export_package(input, &package).is_err(),
        "existing package is never overwritten"
    );

    let mut package_checks = 7usize;
    for missing in ["manifest.json", "retention.json", "data.bin"] {
        let damaged = output.join(format!("missing-{missing}"));
        copy_package(&package, &damaged);
        fs::remove_file(damaged.join(missing)).unwrap();
        let rejected = output.join(format!("rejected-missing-{missing}"));
        assert!(
            reconstruct_package(
                &damaged,
                &expected,
                fixture.bundle.checkpoint.capacity,
                &rejected
            )
            .is_err()
        );
        assert!(
            !rejected.exists(),
            "invalid packages produce no state output"
        );
        package_checks += 1;
    }
    for (name, field, value) in [
        ("manifest.json", "schema", Value::from(2)),
        ("manifest.json", "data_file", Value::from("../outside.bin")),
        (
            "manifest.json",
            "data_bytes",
            Value::from(report.data_bytes + 1),
        ),
        ("manifest.json", "da_commitment", Value::from("0x00")),
        (
            "manifest.json",
            "candidate_journal_sha256",
            Value::from("00".repeat(32)),
        ),
        ("retention.json", "pruning_allowed", Value::from(true)),
        ("retention.json", "policy", Value::from("expired")),
        (
            "retention.json",
            "candidate_journal_sha256",
            Value::from("00".repeat(32)),
        ),
    ] {
        let damaged = output.join(format!("altered-{name}-{field}"));
        copy_package(&package, &damaged);
        let mut metadata: Value =
            serde_json::from_slice(&fs::read(damaged.join(name)).unwrap()).unwrap();
        metadata[field] = value;
        fs::write(damaged.join(name), serde_json::to_vec(&metadata).unwrap()).unwrap();
        let rejected = output.join(format!("rejected-{name}-{field}"));
        assert!(
            reconstruct_package(
                &damaged,
                &expected,
                fixture.bundle.checkpoint.capacity,
                &rejected
            )
            .is_err()
        );
        assert!(!rejected.exists());
        package_checks += 1;
    }
    for mode in ["altered", "truncated", "extended"] {
        let damaged = output.join(format!("data-{mode}"));
        copy_package(&package, &damaged);
        let mut bytes = fs::read(damaged.join("data.bin")).unwrap();
        match mode {
            "altered" => {
                *bytes.last_mut().unwrap() ^= 1;
            }
            "truncated" => {
                bytes.pop();
            }
            _ => bytes.push(0),
        }
        fs::write(damaged.join("data.bin"), bytes).unwrap();
        let rejected = output.join(format!("rejected-data-{mode}"));
        assert!(
            reconstruct_package(
                &damaged,
                &expected,
                fixture.bundle.checkpoint.capacity,
                &rejected
            )
            .is_err()
        );
        assert!(!rejected.exists());
        package_checks += 1;
    }
    let summary = serde_json::json!({
        "schema":1,"scope":"one-bulk-local-native-DA-foundation", "passed":true,
        "core_checks":fixture.checks,"package_checks":package_checks,
        "data_bytes":report.data_bytes,"da_commitment":report.da_commitment,
        "candidate_journal_sha256":report.candidate_journal_sha256,
        "checkpoint_bytes":report.checkpoint_bytes,"checkpoint_sha256":report.checkpoint_sha256,
        "blocks":8,"transactions":1000,"private_database_used":false,
        "node_started":false,"prover_started":false,"GPU_run":false,"RPC_used":false,
        "proof_accepted":false,"settlement_eligible":false,"public_data_available":false,
        "all_application_processes_owned_by_single_harness":true
    });
    fs::write(
        output.join("bulk-result.json"),
        serde_json::to_vec_pretty(&summary).unwrap(),
    )
    .unwrap();
}
