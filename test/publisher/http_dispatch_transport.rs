//! One integration aggregate through the real submitter and Publisher service.
//! Public development scalars and simulated funding; no env, Store or HTTP.
#[path = "http_dispatch_fixture.rs"]
mod fixture;
use alephium_l2_node::publisher::{
    http_submitter::{
        ApprovedHttpSubmitter, MAX_RESPONSE_BYTES, SubmissionRequest, SubmissionResponse,
        SubmissionTransport,
    },
    *,
};
use alephium_l2_sdk::alephium::{ValidatedSignedAlephium, read_node::OFFICIAL_TESTNET_ORIGIN};
use alloy_primitives::B256;
use fixture::{fixture, publisher};
use serde_json::json;
use std::{cell::Cell, rc::Rc};
#[derive(Clone, Copy)]
enum Mode {
    Ack,
    Timeout,
    Unavailable,
    Malformed,
    WrongAck,
    DeclaredOversize,
    BodyOversize,
    Status,
}
struct Transport {
    mode: Mode,
    calls: Rc<Cell<usize>>,
    expected: Vec<u8>,
    tx: B256,
}
impl SubmissionTransport for Transport {
    fn post(&mut self, request: &SubmissionRequest) -> Result<SubmissionResponse, ExternalFailure> {
        self.calls.set(self.calls.get() + 1);
        assert!(
            request.origin() == OFFICIAL_TESTNET_ORIGIN
                && request.url().origin().ascii_serialization() == OFFICIAL_TESTNET_ORIGIN
                && request.url().path() == "/transactions/submit"
                && request.url().query().is_none()
                && request.body() == self.expected.as_slice()
                && request.maximum_response_bytes() == MAX_RESPONSE_BYTES,
            "Exact pinned request differs; private body suppressed"
        );
        let mut body =
            serde_json::to_vec(&json!({"txId":hex::encode(self.tx),"fromGroup":0,"toGroup":0}))
                .unwrap();
        let mut length = None;
        let mut status = 200;
        match self.mode {
            Mode::Ack => {}
            Mode::Timeout => return Err(ExternalFailure::Timeout),
            Mode::Unavailable => return Err(ExternalFailure::Unavailable),
            Mode::Malformed => body = b"{".to_vec(),
            Mode::WrongAck => {
                body = serde_json::to_vec(
                    &json!({"txId":hex::encode(B256::ZERO),"fromGroup":0,"toGroup":0}),
                )
                .unwrap()
            }
            Mode::DeclaredOversize => length = Some(MAX_RESPONSE_BYTES as u64 + 1),
            Mode::BodyOversize => body = vec![0; MAX_RESPONSE_BYTES + 1],
            Mode::Status => status = 503,
        }
        SubmissionResponse::from_parts(status, length, body)
    }
}
fn transport(mode: Mode, signed: &ValidatedSignedAlephium) -> (Transport, Rc<Cell<usize>>) {
    let calls = Rc::new(Cell::new(0));
    let expected = serde_json::to_vec(&json!({"unsignedTx":hex::encode(signed.unsigned_bytes()),
        "signature":hex::encode(signed.signature())}))
    .unwrap();
    (
        Transport {
            mode,
            calls: calls.clone(),
            expected,
            tx: signed.tx_id(),
        },
        calls,
    )
}

#[test]
fn http_dispatch_transport_bulk() {
    let (scope, signed) = fixture();
    let mut checks = 0;
    for mode in [
        Mode::Ack,
        Mode::Timeout,
        Mode::Unavailable,
        Mode::Malformed,
        Mode::WrongAck,
        Mode::DeclaredOversize,
        Mode::BodyOversize,
        Mode::Status,
    ] {
        let (backend, calls) = transport(mode, &signed);
        let mut submitter = ApprovedHttpSubmitter::with_transport(
            OFFICIAL_TESTNET_ORIGIN,
            scope.clone(),
            true,
            backend,
        )
        .unwrap();
        let mut service = publisher(&scope, &signed);
        let token = service.acquire(service.token().unwrap(), 2000).unwrap();
        let result = service.submit(token, &signed, &mut submitter, 2001);
        let ack = matches!(mode, Mode::Ack);
        assert!(if ack {
            result.is_ok()
        } else {
            matches!(result, Err(PublisherError::Ambiguous))
        });
        checks += 1;
        let token = service.token().unwrap();
        let state = service.snapshot(token).unwrap();
        let row = &state.records[0];
        assert!(
            row.phase
                == if ack {
                    Phase::Submitted
                } else {
                    Phase::SubmitAmbiguous
                }
        );
        checks += 1;
        assert!(
            row.phase != Phase::Confirmed
                && row.inclusion.is_none()
                && row.reservations_retained
                && row.sign_attempts == 1
                && row.submit_attempts == 1
                && calls.get() == 1
        );
        checks += 1;
        assert!(
            matches!(
                service.submit(token, &signed, &mut submitter, 2002),
                Err(PublisherError::InvalidTransition)
            ) && calls.get() == 1
        );
        checks += 1;
        assert!(
            matches!(
                submitter.submit(token, &signed),
                Err(ExternalFailure::Rejected)
            ) && calls.get() == 1
        );
        checks += 1;
    }
    for disabled in [true, false] {
        let (backend, calls) = transport(Mode::Ack, &signed);
        let mut configured = scope.clone();
        if !disabled {
            configured.factory = B256::repeat_byte(20);
        }
        let mut submitter = ApprovedHttpSubmitter::with_transport(
            OFFICIAL_TESTNET_ORIGIN,
            configured,
            !disabled,
            backend,
        )
        .unwrap();
        let token = Token {
            revision: 6,
            fencing_epoch: 1,
            canonical_head: signed.unsigned().operation().spec().funding.head_hash,
        };
        assert!(submitter.submit(token, &signed).is_err() && calls.get() == 0);
        checks += 1;
    }
    let (backend, calls) = transport(Mode::Ack, &signed);
    let mut submitter = ApprovedHttpSubmitter::with_transport(
        OFFICIAL_TESTNET_ORIGIN,
        scope.clone(),
        true,
        backend,
    )
    .unwrap();
    assert!(
        submitter
            .submit(
                Token {
                    revision: 0,
                    fencing_epoch: 0,
                    canonical_head: B256::ZERO
                },
                &signed
            )
            .is_err()
            && calls.get() == 0
    );
    checks += 1;
    for origin in [
        "http://node.testnet.alephium.org",
        "https://node.mainnet.alephium.org",
        "https://node.testnet.alephium.org/other",
    ] {
        let (backend, calls) = transport(Mode::Ack, &signed);
        assert!(
            ApprovedHttpSubmitter::with_transport(origin, scope.clone(), true, backend).is_err()
                && calls.get() == 0
        );
        checks += 1;
    }
    println!(
        "HTTP dispatch transport aggregate: PASS checks={checks}; simulated transport, network_calls=0, no env or Store"
    );
}
