use super::{ConfirmationCounts, InclusionStatus, ReadNodeError as Error, TransactionStatus, wire};
use alloy_primitives::B256;
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub(super) enum Status {
    Confirmed {
        #[serde(rename = "blockHash")]
        block_hash: wire::Hash,
        #[serde(rename = "txIndex")]
        tx_index: i32,
        #[serde(rename = "chainConfirmations")]
        chain_confirmations: i32,
        #[serde(rename = "fromGroupConfirmations")]
        from_group_confirmations: i32,
        #[serde(rename = "toGroupConfirmations")]
        to_group_confirmations: i32,
    },
    Conflicted {
        #[serde(rename = "blockHash")]
        block_hash: wire::Hash,
        #[serde(rename = "txIndex")]
        tx_index: i32,
        #[serde(rename = "chainConfirmations")]
        chain_confirmations: i32,
        #[serde(rename = "fromGroupConfirmations")]
        from_group_confirmations: i32,
        #[serde(rename = "toGroupConfirmations")]
        to_group_confirmations: i32,
    },
    MemPooled,
    TxNotFound,
}

impl Status {
    pub(super) fn checked(self) -> Result<TransactionStatus, Error> {
        let inclusion = |block_hash: wire::Hash, tx_index: i32, chain: i32, from: i32, to: i32| {
            if block_hash.0 == B256::ZERO {
                return Err(Error::MalformedResponse);
            }
            Ok(InclusionStatus {
                block_hash: block_hash.0,
                transaction_index: usize::try_from(tx_index)
                    .map_err(|_| Error::MalformedResponse)?,
                confirmations: ConfirmationCounts {
                    chain: u32::try_from(chain).map_err(|_| Error::MalformedResponse)?,
                    from_group: u32::try_from(from).map_err(|_| Error::MalformedResponse)?,
                    to_group: u32::try_from(to).map_err(|_| Error::MalformedResponse)?,
                },
            })
        };
        Ok(match self {
            Self::Confirmed {
                block_hash,
                tx_index,
                chain_confirmations,
                from_group_confirmations,
                to_group_confirmations,
            } => TransactionStatus::Confirmed(inclusion(
                block_hash,
                tx_index,
                chain_confirmations,
                from_group_confirmations,
                to_group_confirmations,
            )?),
            Self::Conflicted {
                block_hash,
                tx_index,
                chain_confirmations,
                from_group_confirmations,
                to_group_confirmations,
            } => TransactionStatus::Conflicted(inclusion(
                block_hash,
                tx_index,
                chain_confirmations,
                from_group_confirmations,
                to_group_confirmations,
            )?),
            Self::MemPooled => TransactionStatus::MemPooled,
            Self::TxNotFound => TransactionStatus::TxNotFound,
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UnsignedIdentity {
    tx_id: wire::Hash,
    version: u8,
    network_id: u8,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TransactionIdentity {
    unsigned: UnsignedIdentity,
    script_execution_ok: bool,
}

/// Compare the entire returned transaction JSON, including signatures and all
/// outputs, without publishing or deriving Debug for that retained payload.
/// Parsing only the identity here never validates a transaction for signing.
pub(super) fn exact_transaction(
    requested: B256,
    index: usize,
    transactions: &[Value],
    details: &Value,
    conflicted: &[B256],
) -> Result<bool, Error> {
    let entry = transactions.get(index).ok_or(Error::TransactionMismatch)?;
    if entry != details || conflicted.contains(&requested) {
        return Err(Error::TransactionMismatch);
    }
    let mut matches = 0usize;
    let mut success = false;
    for transaction in transactions {
        let item =
            TransactionIdentity::deserialize(transaction).map_err(|_| Error::MalformedResponse)?;
        if item.unsigned.version != 0 || item.unsigned.network_id != 1 {
            return Err(Error::WrongNetwork);
        }
        if item.unsigned.tx_id.0 == requested {
            matches += 1;
            success = item.script_execution_ok;
        }
    }
    let selected = TransactionIdentity::deserialize(entry).map_err(|_| Error::MalformedResponse)?;
    if matches != 1 || selected.unsigned.tx_id.0 != requested {
        return Err(Error::TransactionMismatch);
    }
    Ok(success)
}

pub(super) fn same_inclusion(
    first: &InclusionStatus,
    latest: TransactionStatus,
) -> Result<InclusionStatus, Error> {
    match latest {
        TransactionStatus::Confirmed(value)
            if value.block_hash == first.block_hash
                && value.transaction_index == first.transaction_index =>
        {
            Ok(value)
        }
        _ => Err(Error::ObservationChanged),
    }
}
