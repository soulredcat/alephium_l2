//! One cohesive publisher/real-Store fault and recovery bundle. No HTTP or GPU.
#[path = "support/publisher_fixture.rs"]
mod fixture;
#[path = "support/publisher_head_advance.rs"]
mod head_advance;
#[path = "support/publisher_late_receipt.rs"]
mod late_receipt;
#[path = "support/publisher_scenarios.rs"]
mod scenarios;
use alephium_l2_node::{development, publisher::*, storage::Store};
use fixture::*;
use std::{
    cell::{Cell, RefCell},
    fs,
    path::{Path, PathBuf},
    rc::Rc,
};

#[test]
#[ignore = "Requires fresh owned project-drive publisher output and independently pinned compiled script fixture"]
fn publisher_bulk_durability_fencing_ambiguity_and_reorg() {
    let root = PathBuf::from(
        std::env::var_os("L2_PUBLISHER_OUTPUT").expect("set fresh project-drive publisher output"),
    );
    assert!(
        root.is_absolute() && !root.exists(),
        "preserve prior evidence; use a fresh project-drive path"
    );
    assert!(
        fixture::on_project_drive(&root),
        "publisher artifacts must stay on E: or /mnt/e"
    );
    fs::create_dir(&root).unwrap();
    let started = std::time::Instant::now();
    let mut cases = 0_u64;
    // Before/after durable return at every signing/submission marker/response gap.
    for boundary in [4, 5, 6, 7] {
        for after in [false, true] {
            persistence_gap(
                &root.join(format!("gap-{boundary}-{after}")),
                boundary,
                after,
            );
            cases += 1;
        }
    }
    for boundary in [4, 5] {
        fencing_gap(&root.join(format!("fence-{boundary}")), boundary);
        cases += 1;
    }
    cases += scenarios::lifecycle(&root.join("lifecycle"));
    cases += scenarios::abandonment(&root.join("abandonment"));
    cases += scenarios::signature_failure(&root.join("invalid-signature"));
    cases += head_advance::exercise(&root.join("head-advance"));
    cases += late_receipt::exercise(&root.join("late-receipt"));
    let report = serde_json::json!({"passed": true, "bulkCases": cases,
        "elapsedMillis": started.elapsed().as_millis(), "liveSigning": false,
        "liveSubmission": false, "publicSettlement": false, "runtimeHttpStarted": false,
        "gpuWorkloadStarted": false, "developmentDetachedSignaturesOnly": true,
        "canonicalObservations": "configured simulated source; not cryptographic L1 proof",
        "barrierFaults": "repository return before/after actual Store SyncAll; not power-loss qualification",
        "allStoresDroppedAndReopened": true});
    fs::write(
        root.join("summary.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    println!("publisher bulk: PASS cases={cases}; no live operations");
}

fn initialized(
    path: &Path,
) -> (
    Publisher<FaultRepository>,
    Scope,
    Source,
    Script,
    Rc<Control>,
) {
    let (mut service, scope, mut source, script, control) = fixture::open(path);
    let token = service.acquire(service.token().unwrap(), 10_000).unwrap();
    let token = service.refresh_head(token, &mut source).unwrap();
    let unsigned = unsigned(&scope, &script, 1, 1001, 100_000, source.head);
    service
        .register(token, &unsigned, plan(None, id(500)), 10_000)
        .unwrap();
    assert!(control.calls.get() == 3);
    (service, scope, source, script, control)
}

fn callbacks(control: &Rc<Control>) -> (Signer, Submitter) {
    (
        Signer {
            mode: Mode::Success,
            calls: Rc::new(Cell::new(0)),
            recovered: Rc::new(RefCell::new(None)),
            durable: control.durable.clone(),
        },
        Submitter {
            mode: Mode::Success,
            calls: Rc::new(Cell::new(0)),
            durable: control.durable.clone(),
        },
    )
}

fn persistence_gap(path: &Path, boundary: u64, after: bool) {
    let (mut service, scope, source, script, control) = initialized(path);
    if after {
        control.after.set(Some(boundary));
    } else {
        control.before.set(Some(boundary));
    }
    let (mut signer, mut submitter) = callbacks(&control);
    let result = service.sign(
        service.token().unwrap(),
        unsigned(&scope, &script, 1, 1001, 100_000, source.head),
        &mut signer,
        10_000,
    );
    if boundary <= 5 {
        assert!(matches!(result, Err(PublisherError::Storage)));
    } else {
        let (token, signed) = result.unwrap();
        assert!(matches!(
            service.submit(token, &signed, &mut submitter, 10_000),
            Err(PublisherError::Storage)
        ));
    }
    assert!(signer.calls.get() == u32::from(boundary >= 5));
    assert!(submitter.calls.get() == u32::from(boundary == 7));
    drop(service);
    let store = Store::open_existing(path, &development::genesis()).unwrap();
    let state = store.publisher_load(&scope).unwrap().unwrap();
    let phase = state.records[0].phase;
    let expected = match (boundary, after) {
        (4, false) => Phase::Intent,
        (4, true) | (5, false) => Phase::SignAttempted,
        (5, true) | (6, false) => Phase::Signed,
        (6, true) | (7, false) => Phase::SubmitAttempted,
        (7, true) => Phase::Submitted,
        _ => unreachable!(),
    };
    assert!(phase == expected);
    let repo = FaultRepository {
        store,
        control: Rc::new(Control::default()),
    };
    let mut restarted = Publisher::open(repo, scope.clone()).unwrap();
    let token = restarted
        .acquire(restarted.token().unwrap(), 10_001)
        .unwrap();
    assert!(signer.calls.get() == u32::from(boundary >= 5));
    assert!(submitter.calls.get() == u32::from(boundary == 7));
    if state.records[0].sign_attempts == 1 {
        assert!(matches!(
            restarted.sign(
                token,
                unsigned(&scope, &script, 1, 1001, 100_000, source.head),
                &mut signer,
                10_001
            ),
            Err(PublisherError::InvalidTransition)
        ));
    }
    drop(restarted);
}

fn fencing_gap(path: &Path, boundary: u64) {
    let (mut service, scope, source, script, control) = initialized(path);
    control.steal_fence.set(Some(boundary));
    let (mut signer, _) = callbacks(&control);
    let result = service.sign(
        service.token().unwrap(),
        unsigned(&scope, &script, 1, 1001, 100_000, source.head),
        &mut signer,
        10_000,
    );
    assert!(matches!(
        result,
        Err(PublisherError::Conflict | PublisherError::StaleFence)
    ));
    assert!(signer.calls.get() == u32::from(boundary == 5));
    drop(service);
    let store = Store::open_existing(path, &development::genesis()).unwrap();
    let state = store.publisher_load(&scope).unwrap().unwrap();
    assert!(state.fencing_epoch == 2 && state.records[0].sign_attempts == u8::from(boundary == 5));
}
