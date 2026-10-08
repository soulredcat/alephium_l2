//! One creator discovery, followed only by reads on the discovered X -> 0 chain.
use super::{
    ChainHeader, IdentityObservation, Owner0CreatorDetails, ReadNodeError as Error,
    TransactionDetailsObservation, TransactionObservation, TransactionOutcome, TransactionStatus,
    blocks, transactions, transport::Transport, wire,
};
use alloy_primitives::B256;

#[cfg(test)]
pub(super) mod tests;

pub(super) fn read(
    transport: &Transport,
    tx_id: B256,
    identity: IdentityObservation,
) -> Result<Owner0CreatorDetails, Error> {
    let status = transactions::read_status(transport, tx_id, None)?;
    let first = match status {
        TransactionStatus::Confirmed(first) => first,
        other => return unconfirmed(identity, tx_id, other),
    };
    let raw: blocks::Header = transport.get(
        &format!("/blockflow/headers/{}", hex::encode(first.block_hash)),
        &[],
    )?;
    let chain_from = blocks::owner0_chain(&raw)?;
    let height = wire::nonnegative(i64::from(raw.height))?;
    let discovered = raw.checked_owner0(first.block_hash, height, chain_from)?;
    let transaction =
        transactions::confirmed_in_chain(transport, tx_id, identity, first, chain_from)?;
    bind(chain_from, discovered, transaction)
}

pub(super) fn unconfirmed(
    identity: IdentityObservation,
    tx_id: B256,
    status: TransactionStatus,
) -> Result<Owner0CreatorDetails, Error> {
    let outcome = match status {
        TransactionStatus::TxNotFound => TransactionOutcome::TxNotFound,
        TransactionStatus::MemPooled => TransactionOutcome::MemPooled,
        TransactionStatus::Conflicted(value) => TransactionOutcome::Conflicted(value),
        TransactionStatus::Confirmed(_) => return Err(Error::TransactionMismatch),
    };
    Ok(Owner0CreatorDetails {
        chain_from: None,
        transaction: TransactionDetailsObservation {
            observation: TransactionObservation {
                identity,
                transaction_id: tx_id,
                outcome,
            },
            retained_details: None,
        },
    })
}

pub(super) fn bind(
    chain_from: u8,
    discovered: ChainHeader,
    transaction: TransactionDetailsObservation,
) -> Result<Owner0CreatorDetails, Error> {
    if chain_from >= 4 || transaction.details().is_none() {
        return Err(Error::TransactionMismatch);
    }
    let (inclusion, header) = match &transaction.observation().outcome {
        TransactionOutcome::ScriptSucceeded { inclusion, header }
        | TransactionOutcome::ScriptFailed { inclusion, header } => (inclusion, header),
        _ => return Err(Error::TransactionMismatch),
    };
    if header != &discovered || inclusion.block_hash != discovered.hash {
        return Err(Error::ObservationChanged);
    }
    Ok(Owner0CreatorDetails {
        chain_from: Some(chain_from),
        transaction,
    })
}
