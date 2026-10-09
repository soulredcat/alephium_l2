//! Flat initial-field metadata commitment only; no state/source authority.
use super::{alephium_hash, compact, read_node::ContractValue};
use alloy_primitives::B256;

const MAX_FIELDS: usize = 255;
const MAX_ENCODED_FIELDS: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContractInitialStateHashError {
    FieldCount,
    EncodedSize,
    UnsupportedType,
    Encoding,
}
impl std::fmt::Display for ContractInitialStateHashError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(out, "Initial-state metadata hash refused: {self:?}")
    }
}
impl std::error::Error for ContractInitialStateHashError {}

/// Hash.doubleHash(codeHash ++ serialize(immFields ++ initialMutFields)).
/// The caller supplies that flat order; arrays and all other Val types refuse.
/// Native Val tags: U256=2, ByteVec=3; lengths use signed compact Int.
/// The16KiB bound covers the serialized field vector, excluding codeHash32.
/// https://github.com/alephium/alephium/blob/v4.7.1/protocol/src/main/scala/org/alephium/protocol/vm/Contract.scala#L214-L217
pub fn contract_initial_state_hash(
    code_hash: B256,
    fields: &[ContractValue],
) -> Result<B256, ContractInitialStateHashError> {
    use ContractInitialStateHashError as Error;
    if fields.len() > MAX_FIELDS {
        return Err(Error::FieldCount);
    }
    let mut preimage = Vec::with_capacity(32 + MAX_ENCODED_FIELDS);
    preimage.extend_from_slice(code_hash.as_slice());
    compact::put_int(&mut preimage, fields.len() as u32).map_err(|_| Error::Encoding)?;
    for field in fields {
        let mut encoded = Vec::with_capacity(34);
        match field {
            ContractValue::U256(value) => {
                encoded.push(2);
                compact::put_amount(&mut encoded, *value);
            }
            ContractValue::ByteVec(bytes) => {
                if bytes.len() > MAX_ENCODED_FIELDS {
                    return Err(Error::EncodedSize);
                }
                encoded.push(3);
                compact::put_int(&mut encoded, bytes.len() as u32).map_err(|_| Error::Encoding)?;
                if preimage.len() - 32 + encoded.len() + bytes.len() > MAX_ENCODED_FIELDS {
                    return Err(Error::EncodedSize);
                }
                preimage.extend_from_slice(&encoded);
                preimage.extend_from_slice(bytes);
                continue;
            }
            _ => return Err(Error::UnsupportedType),
        }
        if preimage.len() - 32 + encoded.len() > MAX_ENCODED_FIELDS {
            return Err(Error::EncodedSize);
        }
        preimage.extend_from_slice(&encoded);
    }
    Ok(alephium_hash(alephium_hash(&preimage).as_slice()))
}
