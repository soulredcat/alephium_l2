//! Precise metadata-only refusals, inside the existing single aggregate.
use super::fixture;
use crate::alephium::{
    current_funding::{CurrentFundingError as Error, checks},
    read_node::{ConfirmationCounts, TransactionOutcome},
};

pub(super) fn run_checks() -> usize {
    let f = fixture::build(None);
    let inclusion = f.observation.provenance()[0].inclusion.clone();
    let mut header = f.observation.head_before().header.clone();
    header.hash = inclusion.block_hash;
    let mut count = 0;
    let mut check = |ok: bool| {
        assert!(
            ok,
            "Funding refusal diagnostic check failed; payload suppressed"
        );
        count += 1;
    };
    for (outcome, expected) in [
        (TransactionOutcome::TxNotFound, Error::CreatorTxNotFound),
        (TransactionOutcome::MemPooled, Error::CreatorMemPooled),
        (
            TransactionOutcome::Conflicted(inclusion.clone()),
            Error::CreatorConflicted,
        ),
        (
            TransactionOutcome::ScriptFailed {
                inclusion: inclusion.clone(),
                header: header.clone(),
            },
            Error::CreatorScriptFailed,
        ),
    ] {
        check(checks::creator_execution(&outcome).err() == Some(expected));
    }
    let success = TransactionOutcome::ScriptSucceeded { inclusion, header };
    check(checks::creator_execution(&success).is_ok());
    let required = ConfirmationCounts {
        chain: 2,
        from_group: 3,
        to_group: 4,
    };
    let above = ConfirmationCounts {
        chain: 11,
        from_group: 12,
        to_group: 13,
    };
    for component in 0..3 {
        let mut observed = above;
        match component {
            0 => observed.chain = required.chain - 1,
            1 => observed.from_group = required.from_group - 1,
            _ => observed.to_group = required.to_group - 1,
        }
        check(
            checks::confirmations(observed, required).err()
                == Some(Error::CreatorConfirmationsInsufficient {
                    observed_chain: observed.chain,
                    observed_from_group: observed.from_group,
                    observed_to_group: observed.to_group,
                    required_chain: 2,
                    required_from_group: 3,
                    required_to_group: 4,
                }),
        );
    }
    check(checks::confirmations(required, required).is_ok());
    check(checks::confirmations(above, required).is_ok());
    let observed = ConfirmationCounts {
        chain: 0,
        from_group: 1,
        to_group: 2,
    };
    let error = Error::CreatorConfirmationsInsufficient {
        observed_chain: 0,
        observed_from_group: 1,
        observed_to_group: 2,
        required_chain: 2,
        required_from_group: 3,
        required_to_group: 4,
    };
    check(checks::confirmations(observed, required).err() == Some(error));
    check(
        error.to_string()
            == "Current fixed-output funding refused: CreatorConfirmationsInsufficient { observed_chain: 0, observed_from_group: 1, observed_to_group: 2, required_chain: 2, required_from_group: 3, required_to_group: 4 }",
    );
    count
}
