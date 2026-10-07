//! Pinned unsigned v0 encoding, restricted to full P2PKH unlocks and ALPH change.
use super::{
    compact::{self, Reader},
    types::*,
};
use alloy_primitives::{B256, U256};

pub(super) struct Input {
    pub reference: OutputRef,
    pub public_key: [u8; 33],
}
pub(super) struct Output {
    pub amount: U256,
    pub owner_hash: B256,
    pub lock_time_ms: u64,
}
pub(super) struct Unsigned {
    pub network_id: u8,
    pub gas_amount: u32,
    pub gas_price: U256,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
}

/// Pinned DjbHash/ScriptHint/Hint: wrap the hash and set the asset discriminator.
pub(super) fn owner_hint(owner_hash: B256) -> u32 {
    owner_hash.as_slice().iter().fold(5381u32, |hash, byte| {
        hash.wrapping_mul(33).wrapping_add(u32::from(*byte))
    }) | 1
}

pub(super) fn owner_group(owner_hash: B256, groups: u8) -> Result<u8, AlephiumValidationError> {
    if groups != 4 {
        return Err(AlephiumValidationError::UnsupportedProfile);
    }
    let hint = owner_hint(owner_hash);
    Ok(((hint ^ (hint >> 8) ^ (hint >> 16) ^ (hint >> 24)) as u8) % groups)
}

pub(super) fn is_owner_lock(bytes: &[u8], owner_hash: B256) -> bool {
    bytes.len() == 33 && bytes[0] == 0 && bytes[1..] == owner_hash.as_slice()[..]
}

pub(super) fn decode(
    raw: &[u8],
    approved: &ApprovedOperation,
) -> Result<Unsigned, AlephiumValidationError> {
    use AlephiumValidationError as Error;
    if raw.is_empty() || raw.len() > MAX_UNSIGNED_BYTES {
        return Err(Error::Bounds);
    }
    let mut input = Reader::new(raw);
    if input.byte()? != 0 {
        return Err(Error::UnsupportedProfile);
    }
    let network_id = input.byte()?;
    if network_id != approved.spec.funding.network_id {
        return Err(Error::FundingMismatch);
    }
    match (input.byte()?, approved.script.as_deref()) {
        (0, None) => {}
        (1, Some(script)) if input.take(script.len())? == script => {}
        _ => return Err(Error::ScriptMismatch),
    }
    let gas_amount = input.int()?;
    let gas_price = input.amount()?;
    let count = input.count(MAX_INPUTS, 4 + 32 + 1 + 33)?;
    let mut inputs = Vec::with_capacity(count);
    for _ in 0..count {
        let reference = OutputRef {
            hint: u32::from_be_bytes(input.fixed()?),
            key: B256::from(input.fixed::<32>()?),
        };
        // Reject SameAsPrevious, multisig, script and alternative key forms.
        if input.byte()? != 0 {
            return Err(Error::UnsupportedProfile);
        }
        let public_key = input.fixed::<33>()?;
        if public_key != approved.spec.caller_public_key
            || reference.hint != owner_hint(approved.owner_hash)
        {
            return Err(Error::OwnershipMismatch);
        }
        inputs.push(Input {
            reference,
            public_key,
        });
    }
    let count = input.count(1, 1 + 33 + 8 + 1 + 1)?;
    let mut outputs = Vec::with_capacity(count);
    for _ in 0..count {
        let amount = input.amount()?;
        if input.byte()? != 0 {
            return Err(Error::UnsupportedProfile);
        }
        let owner_hash = B256::from(input.fixed::<32>()?);
        let lock_time_ms = u64::from_be_bytes(input.fixed()?);
        if owner_hash != approved.owner_hash || lock_time_ms > i64::MAX as u64 {
            return Err(Error::OwnershipMismatch);
        }
        if input.int()? != 0 || input.int()? != 0 {
            return Err(Error::UnsupportedProfile);
        }
        outputs.push(Output {
            amount,
            owner_hash,
            lock_time_ms,
        });
    }
    input.finish()?;
    let tx = Unsigned {
        network_id,
        gas_amount,
        gas_price,
        inputs,
        outputs,
    };
    if encode(&tx, approved)?.as_slice() != raw {
        return Err(Error::NoncanonicalUnsigned);
    }
    Ok(tx)
}

fn encode(tx: &Unsigned, approved: &ApprovedOperation) -> Result<Vec<u8>, AlephiumValidationError> {
    let mut out = vec![0, tx.network_id];
    if let Some(script) = &approved.script {
        out.push(1);
        out.extend_from_slice(script);
    } else {
        out.push(0);
    }
    compact::put_int(&mut out, tx.gas_amount)?;
    compact::put_amount(&mut out, tx.gas_price);
    compact::put_int(&mut out, tx.inputs.len() as u32)?;
    for input in &tx.inputs {
        out.extend_from_slice(&input.reference.hint.to_be_bytes());
        out.extend_from_slice(input.reference.key.as_slice());
        out.push(0);
        out.extend_from_slice(&input.public_key);
    }
    compact::put_int(&mut out, tx.outputs.len() as u32)?;
    for output in &tx.outputs {
        compact::put_amount(&mut out, output.amount);
        out.push(0);
        out.extend_from_slice(output.owner_hash.as_slice());
        out.extend_from_slice(&output.lock_time_ms.to_be_bytes());
        out.push(0);
        out.push(0);
    }
    if out.len() > MAX_UNSIGNED_BYTES {
        return Err(AlephiumValidationError::Bounds);
    }
    Ok(out)
}
