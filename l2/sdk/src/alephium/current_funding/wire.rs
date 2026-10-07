//! Bounded JSON scalars and canonical unsigned-byte assembly for creator reads.
use super::super::compact;
use super::CurrentFundingError as Error;
use alloy_primitives::{B256, U256};
use serde_json::{Map, Value};

pub(super) const MAX_ITEMS: usize = 256;
pub(super) const MAX_SCRIPT_BYTES: usize = 32_768;
const MAX_UNSIGNED_BYTES: usize = 131_072;

pub(super) fn object<'a>(
    value: &'a Value,
    required: &[&str],
    optional: &[&str],
) -> Result<&'a Map<String, Value>, Error> {
    let object = value.as_object().ok_or(Error::MalformedCreator)?;
    if required.iter().any(|key| !object.contains_key(*key))
        || object
            .keys()
            .any(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
    {
        return Err(Error::MalformedCreator);
    }
    Ok(object)
}

pub(super) fn field<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a Value, Error> {
    object.get(name).ok_or(Error::MalformedCreator)
}

pub(super) fn list(value: &Value) -> Result<&[Value], Error> {
    let values = value.as_array().ok_or(Error::MalformedCreator)?;
    if values.len() > MAX_ITEMS {
        return Err(Error::Bounds);
    }
    Ok(values)
}

pub(super) fn text(value: &Value) -> Result<&str, Error> {
    value.as_str().ok_or(Error::MalformedCreator)
}

pub(super) fn number(value: &Value, maximum: u64) -> Result<u64, Error> {
    let number = value.as_u64().ok_or(Error::MalformedCreator)?;
    if number > maximum {
        return Err(Error::Bounds);
    }
    Ok(number)
}

pub(super) fn hint(value: &Value) -> Result<u32, Error> {
    let value = value.as_i64().ok_or(Error::MalformedCreator)?;
    let value = i32::try_from(value).map_err(|_| Error::MalformedCreator)?;
    Ok(value as u32)
}

pub(super) fn hex_bytes(value: &Value, maximum: usize) -> Result<Vec<u8>, Error> {
    let encoded = text(value)?;
    if encoded.len() / 2 > maximum {
        return Err(Error::Bounds);
    }
    if encoded.len() % 2 != 0
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Error::MalformedCreator);
    }
    hex::decode(encoded).map_err(|_| Error::MalformedCreator)
}

pub(super) fn hash(value: &Value) -> Result<B256, Error> {
    let bytes = hex_bytes(value, 32)?;
    if bytes.len() != 32 {
        return Err(Error::MalformedCreator);
    }
    Ok(B256::from_slice(&bytes))
}

pub(super) fn amount(value: &Value) -> Result<U256, Error> {
    let value = text(value)?;
    if value.is_empty()
        || value.len() > 78
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || value.len() > 1 && value.starts_with('0')
    {
        return Err(Error::MalformedCreator);
    }
    U256::from_str_radix(value, 10).map_err(|_| Error::MalformedCreator)
}

pub(super) struct Writer(Vec<u8>);

impl Writer {
    pub(super) fn new() -> Self {
        Self(Vec::new())
    }

    pub(super) fn bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let length = self.0.len().checked_add(bytes.len()).ok_or(Error::Bounds)?;
        if length > MAX_UNSIGNED_BYTES {
            return Err(Error::Bounds);
        }
        self.0.extend_from_slice(bytes);
        Ok(())
    }

    pub(super) fn int(&mut self, value: u32) -> Result<(), Error> {
        let mut bytes = Vec::with_capacity(5);
        compact::put_int(&mut bytes, value).map_err(|_| Error::MalformedCreator)?;
        self.bytes(&bytes)
    }

    pub(super) fn amount(&mut self, value: U256) -> Result<(), Error> {
        let mut bytes = Vec::with_capacity(33);
        compact::put_amount(&mut bytes, value);
        self.bytes(&bytes)
    }

    pub(super) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
