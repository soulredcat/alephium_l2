//! Real Store callback barriers using synthetic DATA; no production capability.
use super::*;
use crate::development;
use std::{cell::Cell, path::Path};

pub(crate) fn run_checks(root: &Path, planned: &Record, signature: &[u8]) -> usize {
    let identity = &planned.immutable;
    let spec = FundingPreparationSpec {
        purpose_id: identity.purpose_id,
        operator_source: identity.operator_source,
        caller_public_key: identity.caller_public_key.as_slice().try_into().unwrap(),
        network_genesis_id: identity.network_genesis_id,
        funding_source_id: identity.funding_source_id,
        gas_amount: identity.gas_amount,
        gas_price: identity.gas_price,
    };
    let genesis = development::genesis();
    let mut count = 0;
    let mut check = |ok: bool| {
        assert!(
            ok,
            "Preparation controller check failed; private data suppressed"
        );
        count += 1;
    };
    for scenario in 0..7 {
        let mut store = Store::open(&root.join(format!("dispatch-{scenario}")), &genesis).unwrap();
        let calls = Cell::new(0);
        if scenario == 6 {
            store.fail_next_commit_for_test();
        }
        let mut controller = FundingPreparationController::new(&mut store, spec.clone());
        if scenario == 6 {
            check(matches!(
                controller.plan_inner(planned.clone()),
                Err(Error::Durability(StoreError::Storage))
            ));
            check(controller.stopped());
            check(
                controller
                    .sign_inner(identity, |_, _| {
                        calls.set(calls.get() + 1);
                        Ok(signature.to_vec())
                    })
                    .err()
                    == Some(Error::Stopped),
            );
            check(calls.get() == 0);
            continue;
        }
        controller.plan_inner(planned.clone()).unwrap();
        if scenario == 5 {
            controller.store.fail_next_commit_for_test();
        }
        let signed = controller.sign_inner(identity, |attempt, store| {
            calls.set(calls.get() + 1);
            assert!(
                store.load_funding_preparation(identity.purpose_id).unwrap()
                    == Some(attempt.clone())
            );
            assert!(
                attempt.phase == Phase::SignAttempted
                    && attempt.sign_attempts == 1
                    && attempt.signature.is_none()
            );
            if scenario == 1 {
                Err(PreparationExternalError::Unavailable)
            } else if scenario == 2 {
                Ok(vec![0; 64])
            } else {
                Ok(signature.to_vec())
            }
        });
        if scenario == 5 {
            check(matches!(
                signed,
                Err(Error::Durability(StoreError::Storage))
            ));
            check(calls.get() == 0 && controller.stopped());
            continue;
        }
        check(calls.get() == 1);
        if scenario == 1 || scenario == 2 {
            check(matches!(signed, Err(Error::SignAmbiguous(_))));
            check(controller.stopped());
            drop(controller);
            check(
                store
                    .load_funding_preparation(identity.purpose_id)
                    .unwrap()
                    .is_some_and(|row| {
                        row.phase == Phase::SignAmbiguous && row.signature.is_none()
                    }),
            );
            let mut recovered = FundingPreparationController::new(&mut store, spec.clone());
            check(
                recovered
                    .sign_inner(identity, |_, _| {
                        calls.set(calls.get() + 1);
                        Ok(signature.to_vec())
                    })
                    .err()
                    == Some(Error::WrongPhase),
            );
            check(calls.get() == 1);
            continue;
        }
        check(signed.unwrap().phase == Phase::Signed);
        let submitted = controller.submit_inner(identity, |attempt, store| {
            calls.set(calls.get() + 1);
            assert!(
                store.load_funding_preparation(identity.purpose_id).unwrap()
                    == Some(attempt.clone())
            );
            assert!(
                attempt.phase == Phase::SubmitAttempted
                    && attempt.submit_attempts == 1
                    && attempt.signature.as_deref() == Some(signature)
            );
            if scenario == 3 {
                Err(PreparationExternalError::Unavailable)
            } else if scenario == 4 {
                Ok(B256::repeat_byte(99))
            } else {
                Ok(identity.transaction_id)
            }
        });
        check(calls.get() == 2 && controller.stopped());
        if scenario == 0 {
            check(submitted.unwrap().phase == Phase::Submitted);
        } else {
            check(matches!(submitted, Err(Error::SubmitAmbiguous(_))));
        }
        drop(controller);
        let retained = store
            .load_funding_preparation(identity.purpose_id)
            .unwrap()
            .unwrap();
        check(
            retained.inclusion.is_none()
                && retained.sign_attempts == 1
                && retained.submit_attempts == 1,
        );
        let mut recovered = FundingPreparationController::new(&mut store, spec.clone());
        check(
            recovered
                .submit_inner(identity, |_, _| {
                    calls.set(calls.get() + 1);
                    Ok(identity.transaction_id)
                })
                .err()
                == Some(Error::WrongPhase),
        );
        check(calls.get() == 2);
    }
    count
}
