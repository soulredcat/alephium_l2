use crate::{callbacks, fixture::*, initialized};
use alephium_l2_node::{development, publisher::*, storage::Store};
use alephium_l2_sdk::alephium::validate_detached_signature;
use std::path::Path;

pub fn lifecycle(path: &Path) -> u64 {
    let (mut service, scope, mut source, script, control) = initialized(path);
    let token = service.token().unwrap();
    let loads = control.loads.get();
    assert!(service.snapshot(token).unwrap().token() == token && control.loads.get() == loads);
    let mut stale = token;
    stale.canonical_head = id(999);
    assert!(matches!(
        service.snapshot(stale),
        Err(PublisherError::Conflict)
    ));
    let mut disabled = DisabledExternal;
    assert!(matches!(
        service.sign(
            token,
            unsigned(&scope, &script, 1, 1001, 100_000, source.head),
            &mut disabled,
            10_000
        ),
        Err(PublisherError::Disabled)
    ));
    assert!(service.token().unwrap() == token);
    let mut wrong_scope = scope.clone();
    wrong_scope.factory = id(999);
    let wrong_script = script.for_scope(&wrong_scope);
    let wrong = unsigned(&wrong_scope, &wrong_script, 9, 1009, 100_000, source.head);
    assert!(matches!(
        service.register(token, &wrong, plan(None, id(500)), 10_000),
        Err(PublisherError::InvalidInput)
    ));
    let (mut signer, mut submitter) = callbacks(&control);
    let (token, signed) = service
        .sign(
            token,
            unsigned(&scope, &script, 1, 1001, 100_000, source.head),
            &mut signer,
            10_000,
        )
        .unwrap();
    submitter.mode = Mode::Timeout;
    assert!(matches!(
        service.submit(token, &signed, &mut submitter, 10_000),
        Err(PublisherError::Ambiguous)
    ));
    let mut token = service.token().unwrap();
    assert!(matches!(
        service.submit(token, &signed, &mut submitter, 10_000),
        Err(PublisherError::InvalidTransition)
    ));
    assert!(signer.calls.get() == 1 && submitter.calls.get() == 1);
    assert!(service.reconcile(token, id(1), &mut source).unwrap() == token);
    source.include(&scope, signed.unsigned(), id(500));
    let original = source.receipts[&signed.tx_id()];
    for mutation in 0..6 {
        let receipt = source.receipts.get_mut(&signed.tx_id()).unwrap();
        *receipt = original;
        match mutation {
            0 => receipt.tx_id = id(999),
            1 => receipt.block = id(999),
            2 => receipt.factory = id(999),
            3 => receipt.script_hash = id(999),
            4 => receipt.effect_digest = id(999),
            _ => receipt.execution = ExecutionOutcome::Failed,
        }
        assert!(matches!(
            service.reconcile(token, id(1), &mut source),
            Err(PublisherError::InvalidObservation)
        ));
        assert!(service.token().unwrap() == token);
    }
    source.receipts.insert(signed.tx_id(), original);
    let network = source.head.network;
    source.head.network = 2;
    assert!(matches!(
        service.reconcile(token, id(1), &mut source),
        Err(PublisherError::InvalidObservation)
    ));
    source.head.network = network;
    let source_id = source.source_id;
    source.source_id = id(999);
    assert!(matches!(
        service.reconcile(token, id(1), &mut source),
        Err(PublisherError::InvalidObservation)
    ));
    source.source_id = source_id;
    token = service.reconcile(token, id(1), &mut source).unwrap();
    assert!(service.snapshot(token).unwrap().records[0].phase == Phase::Included);
    source.advance();
    token = service.refresh_head(token, &mut source).unwrap();
    token = service.reconcile(token, id(1), &mut source).unwrap();
    assert!(service.snapshot(token).unwrap().records[0].phase == Phase::Confirmed);
    let child = unsigned(&scope, &script, 2, 2001, 100_000, source.head);
    let mut child_plan = plan(Some(id(1)), id(501));
    child_plan.review_after_ms = 20_000;
    token = service
        .register(token, &child, child_plan, source.head.timestamp_ms)
        .unwrap();
    let (next, child) = service
        .sign(token, child, &mut signer, source.head.timestamp_ms)
        .unwrap();
    submitter.mode = Mode::Success;
    token = service
        .submit(next, &child, &mut submitter, source.head.timestamp_ms)
        .unwrap();
    source.include(&scope, child.unsigned(), id(501));
    source.advance();
    token = service.refresh_head(token, &mut source).unwrap();
    token = service.reconcile(token, id(2), &mut source).unwrap();
    assert!(service.snapshot(token).unwrap().records[1].phase == Phase::Confirmed);
    for height in 7..=source.head.height {
        source.hashes.insert(height, id(9000 + height));
    }
    source.head.hash = source.hashes[&source.head.height];
    source.head.parent = source.hashes[&(source.head.height - 1)];
    source.receipts.clear();
    token = service.refresh_head(token, &mut source).unwrap();
    let orphaned = service.snapshot(token).unwrap();
    assert!(
        orphaned
            .records
            .iter()
            .all(|row| row.phase == Phase::Orphaned && row.reservations_retained)
    );
    assert!(orphaned.history.iter().any(|event| event.kind == AuditKind::CanonicalObservation && event.inclusion.is_some()));
    let fresh = unsigned(&scope, &script, 3, 3001, 100_000, source.head);
    let mut fresh_plan = plan(None, id(502));
    fresh_plan.review_after_ms = 20_000;
    token = service
        .register(token, &fresh, fresh_plan, source.head.timestamp_ms)
        .unwrap();
    let unchanged = service.snapshot(token).unwrap();
    let mut forged = unchanged.clone();
    forged.revision += 1;
    let row = &mut forged.records[2];
    row.phase = Phase::Confirmed;
    row.sign_attempts = 1;
    row.submit_attempts = 1;
    row.signature = Some(vec![0; 64]);
    row.inclusion = Some(Inclusion {
        block: source.head.hash,
        height: source.head.height,
        canonical_head: source.head.hash,
    });
    forged.history.push(AuditEntry {
        revision: forged.revision,
        fencing_epoch: forged.fencing_epoch,
        intent_id: Some(id(3)),
        kind: AuditKind::CanonicalObservation,
        at_ms: source.head.timestamp_ms,
        canonical_head: source.head.hash,
        inclusion: row.inclusion.clone(),
    });
    let mut repository = service.into_repository();
    assert!(
        repository
            .publisher_cas(token.revision, token.fencing_epoch, &forged)
            .is_err()
    );
    assert!(repository.publisher_load(&scope).unwrap().unwrap() == unchanged);
    drop(repository);
    let store = Store::open_existing(path, &development::genesis()).unwrap();
    assert!(store.publisher_load(&scope).unwrap().unwrap() == unchanged);
    18
}

pub fn abandonment(path: &Path) -> u64 {
    let (mut service, scope, mut source, script, control) = initialized(path);
    let (mut signer, _) = callbacks(&control);
    signer.mode = Mode::Timeout;
    assert!(matches!(
        service.sign(
            service.token().unwrap(),
            unsigned(&scope, &script, 1, 1001, 100_000, source.head),
            &mut signer,
            10_000
        ),
        Err(PublisherError::Ambiguous)
    ));
    let token = service.token().unwrap();
    assert!(matches!(
        service.abandon(token, id(1), &mut source),
        Err(PublisherError::InvalidTransition)
    ));
    source.advance();
    let token = service.refresh_head(token, &mut source).unwrap();
    let token = service.abandon(token, id(1), &mut source).unwrap();
    assert!(service.snapshot(token).unwrap().records[0].reservations_retained);
    // A canonical-source claim cannot promote an abandoned signing-only
    // attempt: this publisher never persisted a submission for it.
    let unsubmitted = unsigned(&scope, &script, 1, 1001, 100_000, source.head);
    source.include(&scope, &unsubmitted, id(500));
    assert!(matches!(
        service.reconcile(token, id(1), &mut source),
        Err(PublisherError::InvalidTransition)
    ));
    source.receipts.remove(&unsubmitted.tx_id());
    let conflict = unsigned(&scope, &script, 2, 1001, 100_001, source.head);
    let mut reviewed = plan(None, id(501));
    reviewed.review_after_ms = 12_000;
    assert!(
        service
            .register(token, &conflict, reviewed, 11_000)
            .is_err()
    );
    let fresh = unsigned(&scope, &script, 2, 2001, 100_000, source.head);
    let mut reviewed = plan(None, id(501));
    reviewed.review_after_ms = 12_000;
    let token = service.register(token, &fresh, reviewed, 11_000).unwrap();
    source.advance();
    let token = service.refresh_head(token, &mut source).unwrap();
    let token = service.abandon(token, id(2), &mut source).unwrap();
    assert!(!service.snapshot(token).unwrap().records[1].reservations_retained);
    let replacement = unsigned(&scope, &script, 3, 2001, 100_001, source.head);
    let mut reviewed = plan(None, id(502));
    reviewed.review_after_ms = 13_000;
    let token = service
        .register(token, &replacement, reviewed, 12_000)
        .unwrap();
    assert!(service.snapshot(token).unwrap().records.len() == 3 && signer.calls.get() == 1);
    drop(service);
    assert!(
        Store::open_existing(path, &development::genesis())
            .unwrap()
            .publisher_load(&scope)
            .unwrap()
            .is_some()
    );
    5
}

pub fn signature_failure(path: &Path) -> u64 {
    let (mut service, scope, source, script, control) = initialized(path);
    let (mut signer, mut submitter) = callbacks(&control);
    signer.mode = Mode::Invalid;
    assert!(matches!(
        service.sign(
            service.token().unwrap(),
            unsigned(&scope, &script, 1, 1001, 100_000, source.head),
            &mut signer,
            10_000
        ),
        Err(PublisherError::InvalidSignature)
    ));
    let token = service.token().unwrap();
    let signed = validate_detached_signature(
        unsigned(&scope, &script, 1, 1001, 100_000, source.head),
        signer.recovered.borrow().as_ref().unwrap(),
    )
    .unwrap();
    let token = service.record_signed(token, &signed, 10_000).unwrap();
    submitter.mode = Mode::Invalid;
    assert!(matches!(
        service.submit(token, &signed, &mut submitter, 10_000),
        Err(PublisherError::Ambiguous)
    ));
    let token = service.token().unwrap();
    assert!(service.snapshot(token).unwrap().records[0].phase == Phase::SubmitAmbiguous);
    assert!(matches!(
        service.submit(token, &signed, &mut submitter, 10_000),
        Err(PublisherError::InvalidTransition)
    ));
    assert!(signer.calls.get() == 1 && submitter.calls.get() == 1);
    drop(service);
    assert!(
        Store::open_existing(path, &development::genesis())
            .unwrap()
            .publisher_load(&scope)
            .unwrap()
            .is_some()
    );
    3
}
