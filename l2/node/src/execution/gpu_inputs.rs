//! Canonical public recovery inputs; device results cannot construct prepared state.
use crate::protocol::{MAX_TRANSACTION_BYTES, validate_chain_id};
use alloy_consensus::{Transaction, TxEnvelope, crypto::SECP256K1N_HALF};
use alloy_eips::eip2718::{Decodable2718, Encodable2718};
use alloy_primitives::{B256, U256};

const CURVE_ORDER: U256 = U256::from_be_bytes([
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
]);

/// Contains public signed-transaction material, never a private signing key.
pub(crate) struct Input {
    pub(crate) msg_hash: [u8; 32],
    pub(crate) signature: [u8; 64],
    pub(crate) recovery_id: i32,
    pub(crate) raw_hash: B256,
}

pub(crate) fn recovery_input(raw: &[u8], chain_id: u64) -> Result<Input, String> {
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
    let signature = match &envelope {
        TxEnvelope::Legacy(tx) => tx.signature(),
        TxEnvelope::Eip1559(tx) => tx.signature(),
        _ => return Err("only signed legacy and EIP-1559 transactions are supported".into()),
    };
    if envelope.chain_id() != Some(chain_id) {
        return Err("transaction belongs to an unsupported chain".into());
    }
    if signature.r().is_zero()
        || signature.r() >= CURVE_ORDER
        || signature.s().is_zero()
        || signature.s() > SECP256K1N_HALF
    {
        return Err("invalid transaction signature".into());
    }
    if envelope
        .max_priority_fee_per_gas()
        .is_some_and(|priority| priority > envelope.max_fee_per_gas())
    {
        return Err("priority fee exceeds maximum gas fee".into());
    }
    let mut bytes = [0; 64];
    bytes[..32].copy_from_slice(&signature.r().to_be_bytes::<32>());
    bytes[32..].copy_from_slice(&signature.s().to_be_bytes::<32>());
    Ok(Input {
        msg_hash: envelope.signature_hash().0,
        signature: bytes,
        recovery_id: i32::from(signature.v()),
        raw_hash: *envelope.tx_hash(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{development, protocol::CHAIN_ID};
    use alloy_consensus::SignableTransaction;
    use alloy_eips::eip2930::AccessList;
    use alloy_primitives::{Address, Signature, keccak256};

    fn legacy() -> Vec<u8> {
        development::sign(
            0,
            Some(Address::repeat_byte(0x83)),
            U256::ONE,
            vec![],
            21_000,
        )
        .unwrap()
    }

    #[test]
    fn supported_envelopes_extract_exact_digest_signature_and_raw_identity() {
        let typed = development::sign_type2(
            0,
            Some(Address::repeat_byte(0x84)),
            U256::ONE,
            vec![],
            21_000,
            5,
            2,
            AccessList::default(),
        )
        .unwrap();
        for raw in [legacy(), typed] {
            let input = recovery_input(&raw, CHAIN_ID).unwrap();
            let envelope = TxEnvelope::decode_2718(&mut raw.as_slice()).unwrap();
            let sig = match &envelope {
                TxEnvelope::Legacy(tx) => tx.signature(),
                TxEnvelope::Eip1559(tx) => tx.signature(),
                _ => unreachable!(),
            };
            assert_eq!(input.raw_hash, keccak256(&raw));
            assert_eq!(input.msg_hash, envelope.signature_hash().0);
            assert!(input.signature[..32] == sig.r().to_be_bytes::<32>());
            assert!(input.signature[32..] == sig.s().to_be_bytes::<32>());
            assert_eq!(input.recovery_id, i32::from(sig.v()));
        }
    }

    #[test]
    fn malformed_trailing_and_wrong_chain_are_rejected_before_device_use() {
        assert!(recovery_input(&[], CHAIN_ID).is_err());
        assert!(recovery_input(&[0xff], CHAIN_ID).is_err());
        let mut raw = legacy();
        assert!(recovery_input(&raw, CHAIN_ID + 1).is_err());
        raw.push(0);
        assert!(recovery_input(&raw, CHAIN_ID).is_err());
    }

    #[test]
    fn scalar_bounds_reject_high_s_without_normalizing_it() {
        let raw = legacy();
        let TxEnvelope::Legacy(signed) = TxEnvelope::decode_2718(&mut raw.as_slice()).unwrap()
        else {
            unreachable!()
        };
        let (tx, _, _) = signed.into_parts();
        for (r, s, accepted) in [
            (U256::ONE, SECP256K1N_HALF, true),
            (U256::ONE, SECP256K1N_HALF + U256::ONE, false),
            (U256::ZERO, U256::ONE, false),
            (CURVE_ORDER, U256::ONE, false),
            (U256::ONE, U256::ZERO, false),
        ] {
            let candidate: TxEnvelope = tx.clone().into_signed(Signature::new(r, s, false)).into();
            // Extraction checks bounds; actual recovery is independently authoritative.
            assert_eq!(
                recovery_input(&candidate.encoded_2718(), CHAIN_ID).is_ok(),
                accepted
            );
        }
    }
}
