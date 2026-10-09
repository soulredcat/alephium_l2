use crate::{context::*, fixture::*};
use alephium_l2_node::publisher::{serial_dispatch::ResumeDecision, *};
use std::path::Path;

fn registered(path: &Path) -> (Service, Context) {
    let (mut service, context) = Context::open(path);
    let unsigned = context.unsigned(0);
    service
        .register(
            service.token().unwrap(),
            &unsigned,
            plan(None, id(500)),
            10_000,
        )
        .unwrap();
    assert!(
        context.control.calls.get() == 3,
        "Unexpected fixture persistence boundary"
    );
    (service, context)
}

fn refuse_dispatch(service: &mut Service, context: &mut Context, count: &mut usize) {
    let before = snapshot(service);
    let calls = context.counts();
    check(
        context.plan.check_existing(&before).is_ok()
            && matches!(
                context.plan.decision(&before, 0),
                Ok(ResumeDecision::ReconcileOnly)
            ),
        count,
    );
    check(context.dispatch(service, 0).is_err(), count);
    check(context.dispatch(service, 1).is_err(), count);
    check(
        context.counts() == calls && snapshot(service) == before,
        count,
    );
}

fn ambiguous_write(path: &Path, submit: bool, after: bool) -> usize {
    let (mut service, mut context) = registered(path);
    let mut count = 0;
    let boundary = if submit { 7 } else { 5 };
    if after {
        context.control.after.set(Some(boundary));
    } else {
        context.control.before.set(Some(boundary));
    }
    if submit {
        context.submitter.mode = Mode::Timeout;
    } else {
        context.signer.mode = Mode::Timeout;
    }
    let unsigned = context.unsigned(0);
    let result = service.sign(
        service.token().unwrap(),
        unsigned,
        &mut context.signer,
        10_000,
    );
    let error = if submit {
        let (token, signed) = result.unwrap();
        service
            .submit(token, &signed, &mut context.submitter, 10_000)
            .err()
    } else {
        result.err()
    };
    check(matches!(error, Some(PublisherError::Storage)), &mut count);
    check(context.counts() == (1, u32::from(submit)), &mut count);
    service = context.reopen(service);
    let state = snapshot(&mut service);
    let expected = match (submit, after) {
        (false, false) => Phase::SignAttempted,
        (false, true) => Phase::SignAmbiguous,
        (true, false) => Phase::SubmitAttempted,
        (true, true) => Phase::SubmitAmbiguous,
    };
    let row = &state.records[0];
    check(
        row.phase == expected
            && row.reservations_retained
            && row.sign_attempts == 1
            && row.submit_attempts == u8::from(submit)
            && row.signature.is_some() == submit,
        &mut count,
    );
    refuse_dispatch(&mut service, &mut context, &mut count);
    if submit {
        // A lost ACK is recoverable only through positive canonical observation.
        let tx = context.unsigned(0);
        context.source.include(&context.scope, &tx, id(500));
        context.source.advance();
        let token = service.token().unwrap();
        service.refresh_head(token, &mut context.source).unwrap();
        context.observe(&mut service, 0).unwrap();
        check(
            snapshot(&mut service).records[0].phase == Phase::Confirmed
                && context.counts() == (1, 1),
            &mut count,
        );
    } else if after {
        context.source.advance();
        let token = service.token().unwrap();
        let token = service.refresh_head(token, &mut context.source).unwrap();
        service.abandon(token, id(1), &mut context.source).unwrap();
        service = context.reopen(service);
        check(
            snapshot(&mut service).records[0].phase == Phase::Abandoned
                && snapshot(&mut service).records[0].reservations_retained,
            &mut count,
        );
        refuse_dispatch(&mut service, &mut context, &mut count);
    }
    drop(service);
    count
}

fn submit_fence(path: &Path, boundary: u64) -> usize {
    let (mut service, mut context) = registered(path);
    let mut count = 0;
    let unsigned = context.unsigned(0);
    let (token, signed) = service
        .sign(
            service.token().unwrap(),
            unsigned,
            &mut context.signer,
            10_000,
        )
        .unwrap();
    context.control.steal_fence.set(Some(boundary));
    check(
        matches!(
            service.submit(token, &signed, &mut context.submitter, 10_000),
            Err(PublisherError::Conflict | PublisherError::StaleFence)
        ),
        &mut count,
    );
    check(
        context.counts() == (1, u32::from(boundary == 7)),
        &mut count,
    );
    service = context.reopen(service);
    let state = snapshot(&mut service);
    check(
        state.fencing_epoch == 3
            && state.records[0].phase
                == if boundary == 6 {
                    Phase::Signed
                } else {
                    Phase::SubmitAttempted
                }
            && state.records[0].reservations_retained
            && state.records[0].submit_attempts == u8::from(boundary == 7),
        &mut count,
    );
    refuse_dispatch(&mut service, &mut context, &mut count);
    drop(service);
    count
}

pub fn run(root: &Path) -> usize {
    let mut count = 0;
    for submit in [false, true] {
        for after in [false, true] {
            count += ambiguous_write(
                &root.join(format!("ambiguous-{submit}-{after}")),
                submit,
                after,
            );
        }
    }
    for boundary in [6, 7] {
        count += submit_fence(&root.join(format!("submit-fence-{boundary}")), boundary);
    }
    let (service, mut context) = registered(&root.join("intent-reopen"));
    let mut service = context.reopen(service);
    check(
        snapshot(&mut service).records[0].phase == Phase::Intent,
        &mut count,
    );
    refuse_dispatch(&mut service, &mut context, &mut count);
    check(context.counts() == (0, 0), &mut count);
    drop(service);
    count
}
