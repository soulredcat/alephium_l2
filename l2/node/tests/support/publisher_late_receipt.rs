//! Abandonment stops dispatch but cannot erase a transaction already submitted.
use crate::{callbacks, fixture::*, initialized};
use alephium_l2_node::{development, publisher::*, storage::Store};
use alephium_l2_sdk::alephium::validate_detached_signature;
use std::path::Path;

pub fn exercise(path: &Path) -> u64 {
    let (mut service, scope, mut source, script, control) = initialized(path);
    let (mut signer, mut submitter) = callbacks(&control);
    let (token, signed) = service
        .sign(
            service.token().unwrap(),
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
    source.advance();
    let token = service
        .refresh_head(service.token().unwrap(), &mut source)
        .unwrap();
    let token = service.abandon(token, id(1), &mut source).unwrap();
    let abandoned = service.snapshot(token).unwrap();
    assert!(
        abandoned.records[0].phase == Phase::Abandoned
            && abandoned.records[0].reservations_retained
    );
    let fresh = validate_detached_signature(
        unsigned(&scope, &script, 1, 1001, 100_000, source.head),
        signed.signature(),
    )
    .unwrap();
    assert!(matches!(
        service.submit(token, &fresh, &mut submitter, source.head.timestamp_ms),
        Err(PublisherError::InvalidTransition)
    ));
    assert!(matches!(
        service.sign(
            token,
            unsigned(&scope, &script, 1, 1001, 100_000, source.head),
            &mut signer,
            source.head.timestamp_ms
        ),
        Err(PublisherError::InvalidTransition)
    ));
    let child = unsigned(&scope, &script, 2, 2001, 100_000, source.head);
    let mut child_plan = plan(Some(id(1)), id(501));
    child_plan.review_after_ms = 20_000;
    assert!(matches!(
        service.register(token, &child, child_plan, source.head.timestamp_ms),
        Err(PublisherError::InvalidTransition)
    ));
    assert!(signer.calls.get() == 1 && submitter.calls.get() == 1);

    source.include(&scope, signed.unsigned(), id(999));
    assert!(matches!(
        service.reconcile(token, id(1), &mut source),
        Err(PublisherError::InvalidObservation)
    ));
    assert!(service.snapshot(token).unwrap() == abandoned);
    source.include(&scope, signed.unsigned(), id(500));
    let token = service.reconcile(token, id(1), &mut source).unwrap();
    let included = service.snapshot(token).unwrap();
    assert!(
        included.records[0].phase == Phase::Included && included.records[0].reservations_retained
    );
    assert!(included.history.starts_with(&abandoned.history));
    assert!(
        included
            .history
            .iter()
            .any(|event| event.kind == AuditKind::Abandon)
    );

    source.advance();
    let token = service.refresh_head(token, &mut source).unwrap();
    let token = service.reconcile(token, id(1), &mut source).unwrap();
    assert!(service.snapshot(token).unwrap().records[0].phase == Phase::Confirmed);
    let child = unsigned(&scope, &script, 2, 2001, 100_000, source.head);
    let mut child_plan = plan(Some(id(1)), id(501));
    child_plan.review_after_ms = 20_000;
    let token = service
        .register(token, &child, child_plan, source.head.timestamp_ms)
        .unwrap();
    let state = service.snapshot(token).unwrap();
    assert!(state.records[1].intent.parent == Some(id(1)));
    assert!(state.records[0].intent == abandoned.records[0].intent);
    assert!(state.records[0].signature == abandoned.records[0].signature);
    assert!(state.records[0].sign_attempts == 1 && state.records[0].submit_attempts == 1);
    assert!(
        state.records[0].reservations_retained
            && signer.calls.get() == 1
            && submitter.calls.get() == 1
    );
    drop(service);
    assert!(
        Store::open_existing(path, &development::genesis())
            .unwrap()
            .publisher_load(&scope)
            .unwrap()
            .unwrap()
            == state
    );
    5
}
