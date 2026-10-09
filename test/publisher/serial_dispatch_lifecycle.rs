use crate::{context::*, fixture::*};
use alephium_l2_node::publisher::{serial_dispatch::ResumeDecision, *};
use std::path::Path;

pub fn run(path: &Path) -> usize {
    let (mut service, mut context) = Context::open(path);
    let mut count = 0;
    for index in 0..4 {
        check(
            matches!(
                context.plan.decision(&snapshot(&mut service), index),
                Ok(ResumeDecision::Fresh)
            ),
            &mut count,
        );
        context.dispatch(&mut service, index).unwrap();
        let sent = snapshot(&mut service);
        check(
            sent.records.len() == index + 1
                && sent.records[index].phase == Phase::Submitted
                && sent.records[index].sign_attempts == 1
                && sent.records[index].submit_attempts == 1
                && sent.records[index].reservations_retained
                && context.counts() == (index as u32 + 1, index as u32 + 1),
            &mut count,
        );
        service = context.reopen(service);
        check(
            matches!(
                context.plan.decision(&snapshot(&mut service), index),
                Ok(ResumeDecision::ReconcileOnly)
            ) && context.dispatch(&mut service, index).is_err()
                && context.counts() == (index as u32 + 1, index as u32 + 1),
            &mut count,
        );
        let sent = snapshot(&mut service);
        check(context.observe(&mut service, index).is_err(), &mut count);
        check(snapshot(&mut service) == sent, &mut count);
        if index < 3 {
            check(
                context.dispatch(&mut service, index + 1).is_err(),
                &mut count,
            );
            check(
                context.counts() == (index as u32 + 1, index as u32 + 1),
                &mut count,
            );
        }
        let tx = context.unsigned(index);
        context
            .source
            .include(&context.scope, &tx, id(index as u64 + 500));
        check(context.observe(&mut service, index).is_err(), &mut count);
        check(
            snapshot(&mut service).records[index].phase != Phase::Confirmed,
            &mut count,
        );
        service = context.reopen(service);
        check(
            matches!(
                context.plan.decision(&snapshot(&mut service), index),
                Ok(ResumeDecision::ReconcileOnly)
            ) && context.dispatch(&mut service, index).is_err()
                && context.counts() == (index as u32 + 1, index as u32 + 1),
            &mut count,
        );
        context.source.advance();
        let token = service.token().unwrap();
        service.refresh_head(token, &mut context.source).unwrap();
        context.observe(&mut service, index).unwrap();
        check(
            snapshot(&mut service).records[index].phase == Phase::Confirmed,
            &mut count,
        );

        service = context.reopen(service);
        let reopened = snapshot(&mut service);
        check(
            context.plan.check_existing(&reopened).is_ok()
                && matches!(
                    context.plan.decision(&reopened, index),
                    Ok(ResumeDecision::RecheckConfirmed)
                ),
            &mut count,
        );
        let receipt = context.source.receipts.remove(&tx.tx_id()).unwrap();
        check(context.observe(&mut service, index).is_err(), &mut count);
        if index < 3 {
            check(
                context.dispatch(&mut service, index + 1).is_err(),
                &mut count,
            );
        }
        check(
            context.counts() == (index as u32 + 1, index as u32 + 1)
                && snapshot(&mut service).records.len() == index + 1,
            &mut count,
        );
        context.source.receipts.insert(tx.tx_id(), receipt);
        context.observe(&mut service, index).unwrap();
        check(context.dispatch(&mut service, index).is_err(), &mut count);
        check(
            context.counts() == (index as u32 + 1, index as u32 + 1),
            &mut count,
        );
    }

    let accepted = snapshot(&mut service);
    for index in 0..4 {
        for mutation in 0..3 {
            let mut altered = accepted.clone();
            let intent = &mut altered.records[index].intent;
            match mutation {
                0 => intent.parent = if index == 0 { Some(id(999)) } else { None },
                1 => intent.expected_effect = id(999),
                _ => intent.confirmations += 1,
            }
            check(context.plan.check_existing(&altered).is_err(), &mut count);
        }
    }
    check(context.plan.decision(&accepted, 4).is_err(), &mut count);

    // Only the first inclusion is removed. The other three retain their own
    // canonical block hashes, so orphaning all four proves descendant invalidation.
    context.source.hashes.insert(7, id(9007));
    context.source.receipts.clear();
    let token = service.token().unwrap();
    service.refresh_head(token, &mut context.source).unwrap();
    let orphaned = snapshot(&mut service);
    check(
        orphaned.records.len() == 4
            && orphaned.records.iter().all(|row| {
                row.phase == Phase::Orphaned
                    && row.reservations_retained
                    && row.sign_attempts == 1
                    && row.submit_attempts == 1
            })
            && orphaned
                .history
                .iter()
                .any(|entry| entry.kind == AuditKind::Reorg),
        &mut count,
    );
    service = context.reopen(service);
    for index in 0..4 {
        check(
            matches!(
                context.plan.decision(&snapshot(&mut service), index),
                Ok(ResumeDecision::ReconcileOnly)
            ),
            &mut count,
        );
        check(context.dispatch(&mut service, index).is_err(), &mut count);
    }
    check(context.counts() == (4, 4), &mut count);
    check(
        snapshot(&mut service).records == orphaned.records,
        &mut count,
    );
    drop(service);
    count
}

pub fn regressed_confirmation(path: &Path) -> usize {
    let (mut service, mut context) = Context::open(path);
    let mut count = 0;
    context.dispatch(&mut service, 0).unwrap();
    let tx = context.unsigned(0);
    context.source.include(&context.scope, &tx, id(500));
    let inclusion_head = context.source.head;
    context.source.advance();
    context.observe(&mut service, 0).unwrap();
    let confirmed_head = context.source.head;
    check(
        snapshot(&mut service).records[0].phase == Phase::Confirmed,
        &mut count,
    );
    service = context.reopen(service);

    // Retained inclusion remains canonical, but this lower observed head gives
    // only one confirmation. A historic Confirmed row cannot authorize role1.
    context.source.head = inclusion_head;
    check(context.observe(&mut service, 0).is_err(), &mut count);
    check(
        snapshot(&mut service).records[0].phase == Phase::Included,
        &mut count,
    );
    check(context.dispatch(&mut service, 1).is_err(), &mut count);
    check(
        context.counts() == (1, 1) && snapshot(&mut service).records.len() == 1,
        &mut count,
    );
    context.source.head = confirmed_head;
    context.observe(&mut service, 0).unwrap();
    service = context.reopen(service);
    context
        .source
        .receipts
        .get_mut(&tx.tx_id())
        .unwrap()
        .execution = ExecutionOutcome::Failed;
    let before = snapshot(&mut service);
    check(context.observe(&mut service, 0).is_err(), &mut count);
    check(context.dispatch(&mut service, 1).is_err(), &mut count);
    check(
        context.counts() == (1, 1) && snapshot(&mut service) == before,
        &mut count,
    );
    drop(service);
    count
}
