//! Generic authenticated suffix boundary, including non-genesis batch two.
use super::{literal, types::Policy};
use crate::settlement::{
    bootstrap,
    journal::{Head, Journal},
};
use std::path::Path;

pub(super) struct DataBoundary {
    pub bytes: Vec<u8>,
    pub checkpoint_sha256: [u8; 32],
}

pub(super) fn read(
    path: &Path,
    journal: &Journal,
    policy: &Policy,
    first: bool,
) -> Result<DataBoundary, String> {
    let bytes = bootstrap::read_private(path)?;
    validate(bytes, journal, policy, first)
}

pub(super) fn validate(
    bytes: Vec<u8>,
    journal: &Journal,
    policy: &Policy,
    first: bool,
) -> Result<DataBoundary, String> {
    if bytes.is_empty() || bytes.len() > 3000 || literal::sha(&bytes) != journal.data_hash {
        return Err("Complete inline DA differs from the actual receipt commitment".into());
    }
    let mut reader = Reader::new(&bytes);
    if reader.field()? != b"alephium-l2/reconstruction/checkpoint-suffix/v4"
        || reader.take(65)? != &journal.bytes[161..226]
        || reader.take(32)? != policy.execution_profile
        || reader.take(32)? != policy.transport_limits
    {
        return Err("DA namespace/domain/profile/limits differ".into());
    }
    let cp = reader.field()?;
    let checkpoint_sha256 = literal::sha(cp);
    let (capacity, schema, head) = checkpoint_prefix(cp, policy.l2_chain_id, &policy.l2_genesis)?;
    if capacity != policy.capacity
        || head != journal.parent.bytes
        || bootstrap::profile(capacity, schema, &policy.transport_limits)
            != policy.execution_profile
        || first
            && (checkpoint_sha256 != policy.genesis_checkpoint_sha256
                || cp != policy.genesis_checkpoint
                || head != policy.genesis_head)
    {
        return Err("DA checkpoint is not the exact authenticated batch predecessor".into());
    }
    let mut root = b"alephium-l2/continuation-root/v2".to_vec();
    root.extend(policy.execution_profile);
    root.extend(&journal.bytes[161..226]);
    root.extend(policy.transport_limits);
    root.extend(cp);
    if literal::sha(&root) != journal.old_root {
        return Err("DA predecessor root differs".into());
    }
    let blocks = reader.u64()?;
    if blocks != journal.blocks {
        return Err("DA suffix block count differs".into());
    }
    let mut timestamp = journal.parent.timestamp;
    let mut count = 0_u64;
    for index in 0..blocks {
        let number = reader.u64()?;
        let time = reader.u64()?;
        let gas = reader.u64()?;
        let transactions = u64::from(reader.u32()?);
        if journal.batch_start.checked_add(index) != Some(number)
            || time < timestamp
            || gas != capacity[0]
            || transactions == 0
            || transactions > capacity[2]
        {
            return Err("DA ordered context/count differs from approved profile".into());
        }
        let mut logical = 148_u64;
        for _ in 0..transactions {
            let raw = reader.field()?;
            if raw.is_empty() || raw.len() > 131_072 {
                return Err("DA envelope length invalid".into());
            }
            logical = logical
                .checked_add(4 + raw.len() as u64)
                .ok_or("DA length overflow")?;
        }
        if logical > capacity[1] {
            return Err("DA exceeds approved block payload capacity".into());
        }
        timestamp = time;
        count = count
            .checked_add(transactions)
            .ok_or("DA transaction count overflow")?;
    }
    if !reader.finished() || timestamp != journal.head.timestamp || count != journal.transactions {
        return Err("DA suffix does not end at the exact proven boundary".into());
    }
    Ok(DataBoundary {
        bytes,
        checkpoint_sha256,
    })
}

pub(crate) fn checkpoint_prefix(
    bytes: &[u8],
    chain: u64,
    genesis: &[u8; 32],
) -> Result<([u64; 3], u32, [u8; 80]), String> {
    let mut reader = Reader::new(bytes);
    let namespace = b"alephium-l2/execution-checkpoint/v1";
    if reader.take(namespace.len())? != namespace {
        return Err("Checkpoint namespace/chain differs".into());
    }
    let schema = reader.u32()?;
    if reader.u64()? != chain {
        return Err("Checkpoint chain differs".into());
    }
    let capacity = match schema {
        1 => [30_000_000, 1_048_576, 256],
        2 | 3 => [reader.u64()?, reader.u64()?, reader.u64()?],
        _ => return Err("Unsupported checkpoint schema".into()),
    };
    let expected_schema = if capacity == [30_000_000, 1_048_576, 256] {
        1
    } else if capacity[2] as u128 * 512 + capacity[1] as u128 + 1_048_576 > 16_777_216
        || capacity[2] as u128 * 256 + 1_048_576 > 16_777_216
    {
        3
    } else {
        2
    };
    if schema != expected_schema {
        return Err("Checkpoint schema/capacity differs".into());
    }
    if reader.take(32)? != genesis {
        return Err("Checkpoint genesis differs".into());
    }
    let head = Head::decode(reader.take(80)?)?;
    if head.genesis != *genesis {
        return Err("Checkpoint head genesis differs".into());
    }
    bootstrap::capacity_limits(capacity)?;
    Ok((capacity, schema, head.bytes))
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn take(&mut self, count: usize) -> Result<&'a [u8], String> {
        let end = self.offset.checked_add(count).ok_or("DA offset overflow")?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or("Truncated canonical DA")?;
        self.offset = end;
        Ok(value)
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| "Invalid u32")?,
        ))
    }
    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| "Invalid u64")?,
        ))
    }
    fn field(&mut self) -> Result<&'a [u8], String> {
        let count = self.u32()? as usize;
        self.take(count)
    }
    fn finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}
