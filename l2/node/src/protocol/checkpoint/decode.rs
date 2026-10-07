//! Shared canonical decoder for a slice or an exact-length streamed payload.
use super::{reader::Reader, *};

pub(super) fn from_slice(
    mut bytes: &[u8],
    expected: Option<Capacity>,
) -> Result<ExecutionCheckpoint, String> {
    let total_len = bytes.len();
    read(
        &mut |output| reader::read_slice(&mut bytes, output),
        total_len,
        expected,
    )
}

pub(super) fn capacity_from_prefix(mut bytes: &[u8]) -> Result<Capacity, String> {
    let total_len = bytes.len();
    let mut source = |output: &mut [u8]| reader::read_slice(&mut bytes, output);
    read_prefix(&mut Reader::new(&mut source, total_len)).map(|(_, _, capacity)| capacity)
}

fn read_prefix(
    input: &mut Reader<'_, impl FnMut(&mut [u8]) -> Result<(), String>>,
) -> Result<(u32, u64, Capacity), String> {
    if input.fixed::<{ DOMAIN.len() }>()?.as_slice() != DOMAIN {
        return Err("invalid checkpoint encoding domain".into());
    }
    let schema = input.u32()?;
    let chain_id = input.u64()?;
    validate_chain_id(chain_id)?;
    let capacity = match schema {
        1 => Capacity::default(),
        2 | 3 => Capacity {
            block_gas: input.u64()?,
            block_bytes: usize::try_from(input.u64()?)
                .map_err(|_| "Checkpoint byte capacity overflow")?,
            max_pending: usize::try_from(input.u64()?)
                .map_err(|_| "Checkpoint count capacity overflow")?,
        },
        _ => return Err("Unsupported checkpoint capacity schema".into()),
    };
    capacity.validate()?;
    if schema != capacity.checkpoint_schema() {
        return Err("Noncanonical checkpoint capacity schema".into());
    }
    Ok((schema, chain_id, capacity))
}

pub(super) fn read(
    source: &mut impl FnMut(&mut [u8]) -> Result<(), String>,
    total_len: usize,
    expected: Option<Capacity>,
) -> Result<ExecutionCheckpoint, String> {
    let mut input = Reader::new(source, total_len);
    let (schema, chain_id, capacity) = read_prefix(&mut input)?;
    if expected.is_some_and(|expected| expected != capacity) {
        return Err("checkpoint capacity differs from the authenticated transport header".into());
    }
    let limit = capacity.runtime_checkpoint_bytes()?;
    if total_len > limit {
        return Err("checkpoint exceeds its capacity-bound canonical byte limit".into());
    }
    let genesis_id = input.hash()?;
    let head = Head {
        height: input.u64()?,
        timestamp: input.u64()?,
        commit_id: input.hash()?,
        genesis_id: input.hash()?,
    };
    let count = input.count(105, limit / 105)?;
    let mut accounts = Vec::with_capacity(count);
    let mut total_slots = 0usize;
    for _ in 0..count {
        let address = Address::from(input.fixed::<20>()?);
        let deleted = match input.fixed::<1>()?[0] {
            0 => false,
            1 => true,
            _ => return Err("invalid checkpoint boolean".into()),
        };
        let balance = input.amount()?;
        let nonce = input.u64()?;
        let code_hash = input.hash()?;
        let storage_epoch = input.u64()?;
        let count = input.count(64, limit / 64)?;
        total_slots = total_slots
            .checked_add(count)
            .ok_or("checkpoint slot overflow")?;
        if total_slots > limit / 64 {
            return Err("checkpoint exceeds total slot bound".into());
        }
        let mut slots = Vec::with_capacity(count);
        for _ in 0..count {
            slots.push(CheckpointSlot {
                key: input.amount()?,
                value: input.amount()?,
            });
        }
        accounts.push(CheckpointAccount {
            address,
            balance,
            nonce,
            code_hash,
            storage_epoch,
            deleted,
            slots,
        });
    }
    let count = input.count(36, limit / 36)?;
    let mut codes = Vec::with_capacity(count);
    for _ in 0..count {
        let hash = input.hash()?;
        let length = input.count(1, MAX_CHECKPOINT_CODE_BYTES)?;
        let mut bytes = vec![0; length];
        input.read_into(&mut bytes)?;
        codes.push(CheckpointCode { hash, bytes });
    }
    let count = input.count(40, 256)?;
    let mut block_hashes = Vec::with_capacity(count);
    for _ in 0..count {
        block_hashes.push(CheckpointBlockHash {
            height: input.u64()?,
            hash: input.hash()?,
        });
    }
    if input.remaining != 0 {
        return Err("checkpoint contains trailing bytes".into());
    }
    let checkpoint = ExecutionCheckpoint {
        schema,
        chain_id,
        capacity,
        genesis_id,
        head,
        accounts,
        codes,
        block_hashes,
    };
    checkpoint.validate()?;
    Ok(checkpoint)
}
