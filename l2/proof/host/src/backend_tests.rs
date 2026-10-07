use super::*;
use serde_json::{Value, json};

fn manifest() -> Value {
    json!({"schema":2,"sdk_version":cli::SDK_VERSION,"sdk_revision":cli::SDK_REVISION,
        "sdk_patches":SdkPatch::reviewed(),
        "dependency_patches":DependencyPatch::reviewed(),
        "prover_sha256":"11".repeat(32),"backend":"cuda","cargo_features":["cuda"],
        "default_features":false,"circuit_debug":false,"groth16_component":{
            "component":"Risc0Groth16","version":"0.1.0",
            "component_directory":if cfg!(windows) { "E:/groth16" } else { "/groth16" },
            "files_sha256":{"preprocessed_coeffs.bin":"22".repeat(32),
                "fuzzed_msm_results.bin":"33".repeat(32),"stark_verify_final.zkey":"44".repeat(32),
                "stark_verify_graph.bin":"55".repeat(32)}}})
}

fn accepted(value: Value) -> bool {
    let bytes = serde_json::to_vec(&value).unwrap();
    match_manifest(&bytes, Sha256::digest(&bytes).into(), [0x11; 32]).is_ok()
}

#[test]
fn selection_and_cpu_evidence_do_not_claim_cuda() {
    assert_eq!(Backend::default(), Backend::Cpu);
    assert_eq!(Backend::parse(OsStr::new("cuda")), Ok(Backend::Cuda));
    assert!(Backend::parse(OsStr::new("CUDA")).is_err());
    let evidence = validate(Backend::Cpu, None, None, [0; 32]).unwrap();
    assert_eq!(evidence.requested_backend, "cpu");
    assert_eq!(evidence.runtime_cuda_qualification, "not-requested");
    assert!(evidence.sdk_base_version.is_none());
    assert!(evidence.sdk_base_revision.is_none());
    assert!(evidence.sdk_patches.is_none());
    assert!(evidence.dependency_patches.is_none());
    assert!(
        serde_json::to_value(evidence)
            .unwrap()
            .get("sdk_patches")
            .is_none()
    );
    assert!(validate(Backend::Cpu, None, Some([0; 32]), [0; 32]).is_err());
    assert!(validate(Backend::Cuda, None, Some([0; 32]), [0; 32]).is_err());
    assert!(validate(Backend::Cuda, Some(Path::new("missing")), None, [0; 32]).is_err());
}

#[test]
fn cuda_requires_exact_reviewed_patch_declaration() {
    let mut value = manifest();
    value.as_object_mut().unwrap().remove("sdk_patches");
    assert!(!accepted(value));
    let reviewed = serde_json::to_value(SdkPatch::reviewed()).unwrap();
    let patches = reviewed.as_array().unwrap();
    let count = patches.len();
    let mut reordered = patches.clone();
    reordered.swap(count - 2, count - 1);
    let mut duplicated = patches.clone();
    duplicated[count - 1] = patches[0].clone();
    let mut extra = patches.clone();
    extra.push(patches[0].clone());
    for patches in [
        json!(null),
        json!(reordered),
        json!(duplicated),
        json!(extra),
    ] {
        let mut value = manifest();
        value["sdk_patches"] = patches;
        assert!(!accepted(value));
    }
    // Every shorter prefix is a stale manifest, including former patch profiles.
    for retained in 0..count {
        let mut value = manifest();
        value["sdk_patches"] = json!(&patches[..retained]);
        assert!(!accepted(value));
    }
    for index in 0..count {
        let mut missing = manifest();
        missing["sdk_patches"].as_array_mut().unwrap().remove(index);
        assert!(!accepted(missing));
        for field in [
            "patch_path",
            "patch_sha256",
            "source_path",
            "original_source_sha256",
            "patched_source_sha256",
        ] {
            let mut value = manifest();
            value["sdk_patches"][index][field] = json!("unreviewed");
            assert!(!accepted(value));
        }
    }
    let mut value = manifest();
    value["sdk_patches"][count - 1]["unknown"] = json!(true);
    assert!(!accepted(value));
    let mut value = manifest();
    value["sdk_patches"][count - 1]
        .as_object_mut()
        .unwrap()
        .remove("patched_source_sha256");
    assert!(!accepted(value));
}

#[test]
fn every_build_constraint_and_executable_pin_is_required() {
    assert!(accepted(manifest()));
    for (field, wrong) in [
        ("schema", json!(1)),
        ("sdk_version", json!("3.0.2")),
        ("sdk_revision", json!("14b5d58")),
        ("prover_sha256", json!("ff".repeat(32))),
        ("backend", json!("cpu")),
        ("cargo_features", json!(["cuda", "circuit_debug"])),
        ("cargo_features", json!(["cuda", "cuda"])),
        ("default_features", json!(true)),
        ("circuit_debug", json!(true)),
    ] {
        let mut value = manifest();
        value[field] = wrong;
        assert!(!accepted(value));
    }
}

#[test]
fn component_identity_paths_pins_and_strict_fields_are_required() {
    for (field, wrong) in [
        ("component", json!("risc0-groth16")),
        ("version", json!("^0.1.0")),
        ("component_directory", json!("relative")),
        ("component_directory", json!("/a/../b")),
    ] {
        let mut value = manifest();
        value["groth16_component"][field] = wrong;
        assert!(!accepted(value));
    }
    let mut value = manifest();
    value["unknown"] = json!(true);
    assert!(!accepted(value));
    let mut value = manifest();
    value["groth16_component"]["files_sha256"]["extra"] = json!("00".repeat(32));
    assert!(!accepted(value));
    let mut value = manifest();
    value["groth16_component"]["files_sha256"]["stark_verify_final.zkey"] = json!("AA".repeat(32));
    assert!(!accepted(value));
    let bytes = serde_json::to_string(&manifest())
        .unwrap()
        .replace("\"schema\":2", "\"schema\":2,\"schema\":2")
        .into_bytes();
    assert!(match_manifest(&bytes, Sha256::digest(&bytes).into(), [0x11; 32]).is_err());
    let bytes = serde_json::to_vec(&manifest()).unwrap();
    assert!(match_manifest(&bytes, [0; 32], [0x11; 32]).is_err());
    assert!(sdk_root(Some("relative".into()), Some("/home".into())).is_err());
    assert!(sdk_root(Some("/root".into()), None).is_err());
}

#[test]
fn cuda_requires_exact_reviewed_dependency_patch_declaration() {
    let mut value = manifest();
    value.as_object_mut().unwrap().remove("dependency_patches");
    assert!(!accepted(value));
    let reviewed = serde_json::to_value(DependencyPatch::reviewed()).unwrap();
    let mut duplicated = reviewed.as_array().unwrap().clone();
    duplicated.push(duplicated[0].clone());
    for patches in [json!(null), json!([]), json!(duplicated)] {
        let mut value = manifest();
        value["dependency_patches"] = patches;
        assert!(!accepted(value));
    }
    for field in [
        "package",
        "version",
        "registry_source",
        "package_checksum",
        "patch_path",
        "patch_sha256",
        "source_path",
        "original_source_sha256",
        "patched_source_sha256",
    ] {
        let mut value = manifest();
        value["dependency_patches"][0][field] = json!("unreviewed");
        assert!(!accepted(value));
        let mut value = manifest();
        value["dependency_patches"][0]
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert!(!accepted(value));
    }
    let mut value = manifest();
    value["dependency_patches"][0]["unknown"] = json!(true);
    assert!(!accepted(value));
}
