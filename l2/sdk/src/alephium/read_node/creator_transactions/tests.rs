//! Pure cross-chain cases included by the existing single SDK aggregate.
use super::*;
use crate::alephium::read_node::{ConfirmationCounts, InclusionStatus, transport};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

fn parse<T: DeserializeOwned>(value: &Value) -> T {
    transport::decode_response(&serde_json::to_vec(value).unwrap()).unwrap()
}
fn raw_header(from: i32, to: i32) -> Value {
    let mut dependencies = vec![hex::encode([0; 32]); 7];
    dependencies[3] = hex::encode([6; 32]);
    json!({"hash":hex::encode([3;32]),"height":50,"timestamp":1000,
        "chainFrom":from,"chainTo":to,"deps":dependencies})
}
fn inclusion() -> InclusionStatus {
    InclusionStatus {
        block_hash: B256::repeat_byte(3),
        transaction_index: 0,
        confirmations: ConfirmationCounts {
            chain: 7,
            from_group: 11,
            to_group: 13,
        },
    }
}
fn transaction(success: bool) -> Value {
    json!({"unsigned":{"txId":hex::encode([4;32]),"version":0,"networkId":1},"scriptExecutionOk":success})
}
fn correlated(
    identity: &IdentityObservation,
    header: ChainHeader,
    success: bool,
) -> TransactionDetailsObservation {
    let details = transaction(success);
    let succeeded = transactions::exact_transaction(
        B256::repeat_byte(4),
        0,
        std::slice::from_ref(&details),
        &details,
        &[],
    )
    .unwrap();
    let outcome = if succeeded {
        TransactionOutcome::ScriptSucceeded {
            inclusion: inclusion(),
            header,
        }
    } else {
        TransactionOutcome::ScriptFailed {
            inclusion: inclusion(),
            header,
        }
    };
    TransactionDetailsObservation {
        observation: TransactionObservation {
            identity: identity.clone(),
            transaction_id: B256::repeat_byte(4),
            outcome,
        },
        retained_details: Some(details),
    }
}

pub(crate) fn run_checks(identity: &IdentityObservation) -> usize {
    let mut checks = 0;
    macro_rules! check {
        ($condition:expr) => {{
            assert!($condition);
            checks += 1;
        }};
    }
    let tx_id = B256::repeat_byte(4);
    let discovery = transactions::status_query(tx_id, None).unwrap();
    check!(discovery == [("txId", hex::encode(tx_id))]);
    let settlement = transactions::status_query(tx_id, Some(0)).unwrap();
    check!(
        settlement[0] == ("fromGroup", "0".to_owned())
            && settlement[1] == ("toGroup", "0".to_owned())
    );
    for from in 0..4 {
        let query = transactions::status_query(tx_id, Some(from)).unwrap();
        check!(
            query[0] == ("fromGroup", from.to_string())
                && query[1] == ("toGroup", "0".to_owned())
                && query[2] == discovery[0]
        );
        let raw: blocks::Header = parse(&raw_header(i32::from(from), 0));
        check!(blocks::owner0_chain(&raw).unwrap() == from);
        let checked = raw.checked_owner0(B256::repeat_byte(3), 50, from).unwrap();
        check!(checked.parent() == Some(B256::repeat_byte(6)));
        let creator = bind(from, checked.clone(), correlated(identity, checked, true)).unwrap();
        check!(creator.chain_from() == Some(from) && creator.chain_to() == Some(0));
        check!(creator.transaction().details().is_some());
        if from != 0 {
            let default: blocks::Header = parse(&raw_header(i32::from(from), 0));
            check!(default.checked(B256::repeat_byte(3), 50).is_err());
            let mismatched: blocks::Header = parse(&raw_header(i32::from(from), 0));
            check!(
                mismatched
                    .checked_owner0(B256::repeat_byte(3), 50, 0)
                    .is_err()
            );
        }
    }
    for (from, to) in [(-1, 0), (4, 0), (1, -1), (1, 1), (1, 4)] {
        let raw: blocks::Header = parse(&raw_header(from, to));
        check!(blocks::owner0_chain(&raw).is_err());
        let raw: blocks::Header = parse(&raw_header(from, to));
        check!(raw.checked_owner0(B256::repeat_byte(3), 50, 1).is_err());
    }
    check!(transactions::status_query(tx_id, Some(4)).is_err());
    check!(blocks::owner0_query(4).is_err());
    let raw: blocks::Header = parse(&raw_header(1, 0));
    check!(raw.checked_owner0(B256::repeat_byte(3), 51, 1).is_err());
    let mut missing_parent = raw_header(1, 0);
    missing_parent["deps"][3] = json!(hex::encode([0; 32]));
    let raw: blocks::Header = parse(&missing_parent);
    check!(raw.checked_owner0(B256::repeat_byte(3), 50, 1).is_err());

    for status in [
        TransactionStatus::TxNotFound,
        TransactionStatus::MemPooled,
        TransactionStatus::Conflicted(inclusion()),
    ] {
        let expected = status.clone();
        let creator = unconfirmed(identity.clone(), tx_id, status).unwrap();
        check!(
            creator.chain_from().is_none()
                && creator.chain_to().is_none()
                && creator.transaction().details().is_none()
        );
        check!(matches!(
            (expected, &creator.transaction().observation().outcome),
            (
                TransactionStatus::TxNotFound,
                TransactionOutcome::TxNotFound
            ) | (TransactionStatus::MemPooled, TransactionOutcome::MemPooled)
                | (
                    TransactionStatus::Conflicted(_),
                    TransactionOutcome::Conflicted(_)
                )
        ));
    }
    check!(
        unconfirmed(
            identity.clone(),
            tx_id,
            TransactionStatus::Confirmed(inclusion())
        )
        .is_err()
    );
    let header = parse::<blocks::Header>(&raw_header(1, 0))
        .checked_owner0(B256::repeat_byte(3), 50, 1)
        .unwrap();
    let failed = bind(
        1,
        header.clone(),
        correlated(identity, header.clone(), false),
    )
    .unwrap();
    check!(matches!(
        &failed.transaction().observation().outcome,
        TransactionOutcome::ScriptFailed { .. }
    ));
    let mut changed = header.clone();
    changed.height += 1;
    check!(bind(1, changed, correlated(identity, header.clone(), true)).is_err());
    check!(
        bind(
            4,
            header.clone(),
            correlated(identity, header.clone(), true)
        )
        .is_err()
    );
    let mut changed_status = inclusion();
    changed_status.block_hash = B256::repeat_byte(9);
    check!(
        transactions::same_inclusion(&inclusion(), TransactionStatus::Confirmed(changed_status))
            .is_err()
    );
    let mut changed_status = inclusion();
    changed_status.transaction_index += 1;
    check!(
        transactions::same_inclusion(&inclusion(), TransactionStatus::Confirmed(changed_status))
            .is_err()
    );
    let details = transaction(true);
    let changed = transaction(false);
    check!(
        transactions::exact_transaction(tx_id, 0, std::slice::from_ref(&details), &changed, &[])
            .is_err()
    );
    check!(
        transactions::exact_transaction(tx_id, 1, std::slice::from_ref(&details), &details, &[])
            .is_err()
    );
    check!(
        transactions::exact_transaction(
            tx_id,
            0,
            &[details.clone(), details.clone()],
            &details,
            &[]
        )
        .is_err()
    );
    checks
}
