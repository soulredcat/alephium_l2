use crate::protocol::{CHAIN_ID, MAX_TRANSACTION_BYTES, TransactionInfo, validate_chain_id};
use alloy_consensus::{Transaction, TxEnvelope, transaction::SignerRecoverable};
use alloy_eips::eip2718::{Decodable2718, Encodable2718};
use revm::context::TxEnv;

/// Default-chain fixture convenience; configured runtime callers use the explicit variant.
pub fn inspect(raw: &[u8]) -> Result<TransactionInfo, String> {
    inspect_for_chain(raw, CHAIN_ID)
}

pub fn inspect_for_chain(raw: &[u8], chain_id: u64) -> Result<TransactionInfo, String> {
    decode(raw, chain_id).map(|(_, info)| info)
}

/// Exact canonical envelope and EIP-2 checked signer recovery use Alloy, not a
/// custom codec. Only replay-protected legacy and EIP-1559 are activated.
pub(super) fn decode(raw: &[u8], chain_id: u64) -> Result<(TxEnv, TransactionInfo), String> {
    validate_chain_id(chain_id)?;
    if raw.is_empty() || raw.len() > MAX_TRANSACTION_BYTES {
        return Err("transaction envelope size is outside the supported limit".into());
    }
    let mut remaining = raw;
    let envelope = TxEnvelope::decode_2718(&mut remaining)
        .map_err(|_| "invalid transaction envelope".to_owned())?;
    if !remaining.is_empty() || envelope.encoded_2718() != raw {
        return Err("transaction envelope is not canonical or has trailing bytes".into());
    }
    let tx_type = match &envelope {
        TxEnvelope::Legacy(_) => 0,
        TxEnvelope::Eip1559(_) => 2,
        _ => return Err("only signed legacy and EIP-1559 transactions are supported".into()),
    };
    if envelope.chain_id() != Some(chain_id) {
        return Err("transaction belongs to an unsupported chain".into());
    }
    let sender = envelope
        .recover_signer()
        .map_err(|_| "invalid transaction signature".to_owned())?;
    let gas_price = envelope.max_fee_per_gas();
    let priority_fee = envelope.max_priority_fee_per_gas();
    if priority_fee.is_some_and(|priority| priority > gas_price) {
        return Err("priority fee exceeds maximum gas fee".into());
    }
    let tx = TxEnv::builder()
        .tx_type(Some(tx_type))
        .caller(sender)
        .chain_id(Some(chain_id))
        .nonce(envelope.nonce())
        .gas_limit(envelope.gas_limit())
        .gas_price(gas_price)
        .gas_priority_fee(priority_fee)
        .access_list(envelope.access_list().cloned().unwrap_or_default())
        .kind(envelope.kind())
        .value(envelope.value())
        .data(envelope.input().clone())
        .build()
        .map_err(|_| "invalid transaction environment".to_owned())?;
    let info = TransactionInfo {
        hash: *envelope.tx_hash(),
        sender,
        nonce: envelope.nonce(),
        gas_limit: envelope.gas_limit(),
    };
    Ok((tx, info))
}
