//! Strict scalar and collection bounds for the selected public REST models.
use super::{ReadNodeError as Error, TokenAmount};
use alloy_primitives::{B256, U256};
use serde::{
    Deserialize, Deserializer,
    de::{Error as _, SeqAccess, Visitor},
};
use std::fmt;

pub(super) fn hash(value: &str) -> Result<B256, Error> {
    if value.len() != 64 {
        return Err(Error::MalformedResponse);
    }
    Ok(B256::from_slice(&hex_bytes(value, 32)?))
}

pub(super) fn hex_bytes(value: &str, maximum: usize) -> Result<Vec<u8>, Error> {
    if !value.len().is_multiple_of(2)
        || value.len() / 2 > maximum
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::MalformedResponse);
    }
    hex::decode(value).map_err(|_| Error::MalformedResponse)
}

pub(super) fn amount(value: &str) -> Result<U256, Error> {
    if value.is_empty()
        || value.len() > 78
        || !value.bytes().all(|b| b.is_ascii_digit())
        || value.len() > 1 && value.starts_with('0')
    {
        return Err(Error::MalformedResponse);
    }
    U256::from_str_radix(value, 10).map_err(|_| Error::MalformedResponse)
}

pub(super) fn nonnegative(value: i64) -> Result<u64, Error> {
    u64::try_from(value).map_err(|_| Error::MalformedResponse)
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Hash(pub B256);
impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        hash(&String::deserialize(d)?)
            .map(Self)
            .map_err(|_| D::Error::custom("Invalid hash field"))
    }
}

pub(super) struct Amount(pub U256);
impl<'de> Deserialize<'de> for Amount {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        amount(&String::deserialize(d)?)
            .map(Self)
            .map_err(|_| D::Error::custom("Invalid amount field"))
    }
}

pub(super) struct Bytes<const N: usize>(pub Vec<u8>);
impl<'de, const N: usize> Deserialize<'de> for Bytes<N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        hex_bytes(&String::deserialize(d)?, N)
            .map(Self)
            .map_err(|_| D::Error::custom("Invalid byte field"))
    }
}

pub(super) struct List<T, const N: usize>(pub Vec<T>);
impl<'de, T: Deserialize<'de>, const N: usize> Deserialize<'de> for List<T, N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Bounded<T, const N: usize>(std::marker::PhantomData<T>);
        impl<'de, T: Deserialize<'de>, const N: usize> Visitor<'de> for Bounded<T, N> {
            type Value = List<T, N>;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("bounded array")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut items = Vec::new();
                while let Some(item) = seq.next_element()? {
                    if items.len() == N {
                        return Err(A::Error::custom("Array exceeds supported bound"));
                    }
                    items.push(item);
                }
                Ok(List(items))
            }
        }
        d.deserialize_seq(Bounded::<T, N>(std::marker::PhantomData))
    }
}

#[derive(Deserialize)]
pub(super) struct Token {
    pub id: Hash,
    pub amount: Amount,
}

pub(super) fn tokens(values: Vec<Token>) -> Result<Vec<TokenAmount>, Error> {
    let mut seen = std::collections::BTreeSet::new();
    let mut tokens = Vec::with_capacity(values.len());
    for token in values {
        if token.amount.0.is_zero() || !seen.insert(token.id.0) {
            return Err(Error::MalformedResponse);
        }
        tokens.push(TokenAmount {
            id: token.id.0,
            amount: token.amount.0,
        });
    }
    Ok(tokens)
}
