//! Fresh funding capabilities for unchanged bytes; never another signer call.
use crate::{callbacks, fixture::*, initialized};
use alephium_l2_node::{development, publisher::*, storage::Store};
use alephium_l2_sdk::alephium::validate_detached_signature;
use alloy_signer::SignerSync;
use std::path::Path;

pub fn exercise(path: &Path) -> u64 {
    let (mut service, scope, mut source, script, control) = initialized(path);
    let original = unsigned(&scope, &script, 1, 1001, 100_000, source.head);
    let original_bytes = original.unsigned_bytes().to_vec();
    let original_intent = service.snapshot(service.token().unwrap()).unwrap().records[0]
        .intent
        .clone();
    let (mut signer, mut submitter) = callbacks(&control);
    source.advance();
    let token = service
        .refresh_head(service.token().unwrap(), &mut source)
        .unwrap();
    assert!(matches!(
        service.sign(token, original, &mut signer, source.head.timestamp_ms),
        Err(PublisherError::InvalidInput)
    ));
    assert!(signer.calls.get() == 0 && service.token().unwrap() == token);

    let signed_head = source.head;
    signer.mode = Mode::Timeout;
    assert!(matches!(
        service.sign(
            token,
            unsigned(&scope, &script, 1, 1001, 100_000, signed_head),
            &mut signer,
            signed_head.timestamp_ms
        ),
        Err(PublisherError::Ambiguous)
    ));
    let signature = signer.recovered.borrow().as_ref().unwrap().clone();
    let stale_response = validate_detached_signature(
        unsigned(&scope, &script, 1, 1001, 100_000, signed_head),
        &signature,
    )
    .unwrap();
    source.advance();
    let token = service
        .refresh_head(service.token().unwrap(), &mut source)
        .unwrap();
    assert!(matches!(
        service.record_signed(token, &stale_response, source.head.timestamp_ms),
        Err(PublisherError::InvalidInput)
    ));
    assert!(service.token().unwrap() == token && signer.calls.get() == 1);

    // Adversarial fixture only: a valid signature for different bytes still
    // cannot replace the already durable intent. This is no signer dispatch.
    let changed = unsigned(&scope, &script, 1, 1001, 100_001, source.head);
    let changed_signature = dev_signer().sign_hash_sync(&changed.tx_id()).unwrap();
    let mut changed_bytes = changed_signature.r().to_be_bytes::<32>().to_vec();
    changed_bytes.extend(changed_signature.s().to_be_bytes::<32>());
    let changed = validate_detached_signature(changed, &changed_bytes).unwrap();
    assert!(matches!(
        service.record_signed(token, &changed, source.head.timestamp_ms),
        Err(PublisherError::InvalidInput)
    ));
    assert!(service.token().unwrap() == token);

    let fresh_response = validate_detached_signature(
        unsigned(&scope, &script, 1, 1001, 100_000, source.head),
        &signature,
    )
    .unwrap();
    assert!(
        fresh_response.unsigned_bytes() == original_bytes
            && fresh_response.signature().as_slice() == signature
    );
    let token = service
        .record_signed(token, &fresh_response, source.head.timestamp_ms)
        .unwrap();
    assert!(
        signer.calls.get() == 1
            && service.snapshot(token).unwrap().records[0].intent == original_intent
    );

    source.advance();
    let token = service.refresh_head(token, &mut source).unwrap();
    assert!(matches!(
        service.submit(
            token,
            &fresh_response,
            &mut submitter,
            source.head.timestamp_ms
        ),
        Err(PublisherError::InvalidInput)
    ));
    assert!(submitter.calls.get() == 0 && service.token().unwrap() == token);
    let refreshed = validate_detached_signature(
        unsigned(&scope, &script, 1, 1001, 100_000, source.head),
        &signature,
    )
    .unwrap();
    assert!(
        refreshed.unsigned_bytes() == original_bytes
            && refreshed.signature().as_slice() == signature
    );
    let token = service
        .submit(token, &refreshed, &mut submitter, source.head.timestamp_ms)
        .unwrap();
    let state = service.snapshot(token).unwrap();
    assert!(
        state.records[0].phase == Phase::Submitted && state.records[0].intent == original_intent
    );
    assert!(state.records[0].sign_attempts == 1 && state.records[0].submit_attempts == 1);
    assert!(signer.calls.get() == 1 && submitter.calls.get() == 1);
    drop(service);
    assert!(
        Store::open_existing(path, &development::genesis())
            .unwrap()
            .publisher_load(&scope)
            .unwrap()
            .unwrap()
            == state
    );
    6
}
