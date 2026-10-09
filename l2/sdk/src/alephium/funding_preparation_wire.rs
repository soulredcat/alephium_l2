//! Closed v0 wire form, independent of the publisher's single-change codec.
use super::super::{
    OutputRef,
    compact::{self, Reader},
};
use super::{
    FUNDING_PREPARATION_MAX_BYTES, FundingPreparationError as Error, FundingPreparationSpec,
};
use alloy_primitives::{B256, U256};

pub(super) fn encode(
    spec: &FundingPreparationSpec,
    input: OutputRef,
    owner: B256,
    amounts: &[U256; 4],
) -> Result<Vec<u8>, Error> {
    let mut raw = Vec::with_capacity(FUNDING_PREPARATION_MAX_BYTES);
    raw.extend_from_slice(&[0, 1, 0]); // v0, network1, no StatefulScript.
    compact::put_int(&mut raw, spec.gas_amount)?;
    compact::put_amount(&mut raw, spec.gas_price);
    compact::put_int(&mut raw, 1)?;
    raw.extend_from_slice(&input.hint.to_be_bytes());
    raw.extend_from_slice(input.key.as_slice());
    raw.push(0); // Full P2PKH unlock; no SameAsPrevious or multisig.
    raw.extend_from_slice(&spec.caller_public_key);
    compact::put_int(&mut raw, 4)?;
    for amount in amounts {
        compact::put_amount(&mut raw, *amount);
        raw.push(0); // P2PKH lock.
        raw.extend_from_slice(owner.as_slice());
        raw.extend_from_slice(&0_u64.to_be_bytes());
        compact::put_int(&mut raw, 0)?; // No tokens.
        compact::put_int(&mut raw, 0)?; // No additional data.
    }
    Ok(raw)
}

pub(super) fn validate(
    raw: &[u8],
    spec: &FundingPreparationSpec,
    input: OutputRef,
    owner: B256,
    amounts: &[U256; 4],
) -> Result<(), Error> {
    if raw.is_empty() || raw.len() > FUNDING_PREPARATION_MAX_BYTES {
        return Err(Error::Bounds);
    }
    let mut reader = Reader::new(raw);
    if reader.fixed::<3>()? != [0, 1, 0]
        || reader.int()? != spec.gas_amount
        || reader.amount()? != spec.gas_price
        || reader.int()? != 1
        || u32::from_be_bytes(reader.fixed()?) != input.hint
        || B256::from(reader.fixed::<32>()?) != input.key
        || reader.byte()? != 0
        || reader.fixed::<33>()? != spec.caller_public_key
        || reader.int()? != 4
    {
        return Err(Error::UnsupportedShape);
    }
    for amount in amounts {
        if reader.amount()? != *amount
            || reader.byte()? != 0
            || B256::from(reader.fixed::<32>()?) != owner
            || u64::from_be_bytes(reader.fixed()?) != 0
            || reader.int()? != 0
            || reader.int()? != 0
        {
            return Err(Error::UnsupportedShape);
        }
    }
    reader.finish()?;
    if encode(spec, input, owner, amounts)?.as_slice() != raw {
        return Err(Error::NoncanonicalUnsigned);
    }
    Ok(())
}
