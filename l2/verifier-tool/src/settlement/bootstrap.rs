//! Independently pinned initial checkpoint and exact inline DA boundary.
use super::journal::{self, Head, Journal, array, framed, sha, u64_at};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
};

pub(super) const MAX_DATA: usize = 3000;
const CHECKPOINT_DOMAIN: &[u8] = b"alephium-l2/execution-checkpoint/v1";
const DEFAULT_CAPACITY: [u64; 3] = [30_000_000, 1_048_576, 256];

pub(super) struct Bootstrap {
    pub data: Vec<u8>,
    pub checkpoint: Vec<u8>,
    pub checkpoint_hash: [u8; 32],
    pub limits: [u8; 32],
    pub capacity: [u64; 3],
}

impl Bootstrap {
    pub fn read(path: &Path, checkpoint_pin: &str, journal: &Journal) -> Result<Self, String> {
        let checkpoint_pin: [u8; 32] = hex::decode(checkpoint_pin)
            .map_err(|_| "Invalid independently selected initial checkpoint pin")?
            .try_into()
            .map_err(|_| "Initial checkpoint pin must contain 32 bytes")?;
        let data = read_private(path)?;
        if data.is_empty() || sha(&data) != journal.data_hash {
            return Err("Complete inline DA differs from the proven canonical commitment".into());
        }
        let mut reader = Reader::new(&data);
        if reader.field()? != b"alephium-l2/reconstruction/checkpoint-suffix/v4"
            || reader.take(65)? != &journal.bytes[161..226]
            || reader.take(32)? != journal.profile.as_slice()
        {
            return Err("Inline DA domain/profile differs from the exact proven journal".into());
        }
        let limits: [u8; 32] = reader.take(32)?.try_into().map_err(|_| "Invalid limits")?;
        let checkpoint = reader.field()?.to_vec();
        if sha(&checkpoint) != checkpoint_pin {
            return Err(
                "Initial checkpoint differs from its independent original-input pin".into(),
            );
        }
        let (capacity, schema) = checkpoint_identity(&checkpoint, journal)?;
        if limits != capacity_limits(capacity)?
            || profile(capacity, schema, &limits) != journal.profile
        {
            return Err("Checkpoint capacity/limits differ from the canonical profile".into());
        }
        let mut root = Sha256::new();
        root.update(b"alephium-l2/continuation-root/v2");
        root.update(journal.profile);
        root.update(&journal.bytes[161..226]);
        root.update(limits);
        root.update(&checkpoint);
        if <[u8; 32]>::from(root.finalize()) != journal.old_root {
            return Err("Initial checkpoint does not derive the proven old execution root".into());
        }
        let blocks = reader.u64()?;
        if blocks != journal.blocks {
            return Err("Inline DA block count differs".into());
        }
        let mut timestamp = journal.parent.timestamp;
        let mut count = 0_u64;
        for index in 0..blocks {
            let number = reader.u64()?;
            let next_time = reader.u64()?;
            let gas = reader.u64()?;
            let transactions = reader.u32()? as u64;
            if journal.batch_start.checked_add(index) != Some(number)
                || next_time < timestamp
                || gas != capacity[0]
                || transactions == 0
                || transactions > capacity[2]
            {
                return Err("Inline DA context/count differs from the proven profile".into());
            }
            let mut logical = 148_u64;
            for _ in 0..transactions {
                let raw = reader.field()?;
                if raw.is_empty() || raw.len() > 131_072 {
                    return Err("Inline DA contains an invalid envelope field length".into());
                }
                logical = logical
                    .checked_add(4 + raw.len() as u64)
                    .ok_or("DA byte overflow")?;
            }
            if logical > capacity[1] {
                return Err("Inline DA exceeds block payload capacity".into());
            }
            count = count
                .checked_add(transactions)
                .ok_or("DA transaction count overflow")?;
            timestamp = next_time;
        }
        if reader.offset != data.len()
            || count != journal.transactions
            || timestamp != journal.head.timestamp
        {
            return Err("Inline DA suffix does not end at the exact proven boundary".into());
        }
        Ok(Self {
            data,
            checkpoint,
            checkpoint_hash: checkpoint_pin,
            limits,
            capacity,
        })
    }
}

fn checkpoint_identity(bytes: &[u8], journal: &Journal) -> Result<([u64; 3], u32), String> {
    let mut input = Reader::new(bytes);
    if input.take(CHECKPOINT_DOMAIN.len())? != CHECKPOINT_DOMAIN {
        return Err("Initial checkpoint encoding namespace differs".into());
    }
    let schema = input.u32()?;
    if input.u64()? != journal.chain_id {
        return Err("Initial checkpoint chain differs".into());
    }
    let capacity = match schema {
        1 => DEFAULT_CAPACITY,
        2 | 3 => [input.u64()?, input.u64()?, input.u64()?],
        _ => return Err("Unsupported initial checkpoint schema".into()),
    };
    if schema != capacity_schema(capacity)
        || input.take(32)? != journal.genesis.as_slice()
        || Head::decode(input.take(80)?)? != journal.parent
        || journal.parent.height != 0
        || journal.parent.timestamp != 0
    {
        return Err("Initial checkpoint does not match the approved genesis head".into());
    }
    let mut preimage = b"alephium-l2-development/genesis-commit/v1".to_vec();
    preimage.extend(journal.genesis);
    if sha(&preimage) != journal.parent.commit {
        return Err("Initial head is not the canonical genesis commit".into());
    }
    Ok((capacity, schema))
}

fn capacity_schema(capacity: [u64; 3]) -> u32 {
    if capacity == DEFAULT_CAPACITY {
        1
    } else if capacity[2] as u128 * 512 + capacity[1] as u128 + 1_048_576 > 16_777_216
        || capacity[2] as u128 * 256 + 1_048_576 > 16_777_216
    {
        3
    } else {
        2
    }
}

fn capacity_limits(capacity: [u64; 3]) -> Result<[u8; 32], String> {
    if capacity[0] < 21_000
        || !(4096..=u32::MAX as u64).contains(&capacity[1])
        || !(1..=u32::MAX as u64).contains(&capacity[2])
    {
        return Err("Invalid checkpoint capacity".into());
    }
    let checkpoint = (capacity[2] * 256 + 1_048_576).clamp(16_777_216, u32::MAX as u64);
    let transcript =
        (capacity[2] * 512 + capacity[1] + 1_048_576).clamp(16_777_216, u32::MAX as u64);
    let input = checkpoint + transcript + 1_048_576;
    if input > 128 * 1024 * 1024 {
        return Err("Checkpoint profile exceeds schema-four bounds".into());
    }
    let mut bytes = [0; 32];
    for (chunk, value) in bytes
        .chunks_exact_mut(8)
        .zip([checkpoint, transcript, input, 8_388_608])
    {
        chunk.copy_from_slice(&value.to_be_bytes());
    }
    Ok(bytes)
}

fn profile(capacity: [u64; 3], schema: u32, limits: &[u8; 32]) -> [u8; 32] {
    let mut inner = Vec::new();
    for text in [
        b"alephium-l2/execution-profile/v2".as_slice(),
        b"cancun-full-history-batch/v2",
        journal::RPC,
        journal::ENGINE,
        b"Cancun",
        b"legacy,type2",
    ] {
        framed(&mut inner, text);
    }
    inner.extend(2_u32.to_be_bytes());
    for value in [30_000_000_u64, 1_048_576, 200, 256, 131_072] {
        inner.extend(value.to_be_bytes());
    }
    framed(
        &mut inner,
        b"inbox/outbox-empty-only/v1;zero-basefee;zero-beneficiary",
    );
    framed(
        &mut inner,
        b"Cancun-precompiles-01..0a;guest-k256-arkworks;producer-secp256k1-arkworks",
    );
    if capacity != DEFAULT_CAPACITY {
        framed(&mut inner, b"alephium-l2/execution-capacity/v1");
        for value in capacity {
            inner.extend(value.to_be_bytes());
        }
    }
    let mut out = Vec::new();
    framed(&mut out, b"alephium-l2/checkpoint-execution-profile/v4");
    framed(&mut out, journal::SCOPE);
    out.extend(sha(&inner));
    out.extend(schema.to_be_bytes());
    out.extend(256_u64.to_be_bytes());
    out.extend(limits);
    sha(&out)
}

fn read_private(path: &Path) -> Result<Vec<u8>, String> {
    if !path.is_absolute() {
        return Err("Inline DA path must be absolute".into());
    }
    let mut ancestor = PathBuf::new();
    for part in path.components() {
        if matches!(part, Component::ParentDir) {
            return Err("Inline DA path cannot traverse parents".into());
        }
        ancestor.push(part.as_os_str());
        if matches!(part, Component::Prefix(_)) {
            continue;
        }
        let meta = fs::symlink_metadata(&ancestor).map_err(|_| "Cannot inspect inline DA path")?;
        if meta.file_type().is_symlink() {
            return Err("Inline DA path cannot redirect".into());
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if meta.file_attributes() & 0x400 != 0 {
                return Err("Inline DA path cannot redirect".into());
            }
        }
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000);
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(0x0002_0000);
    }
    let file = options.open(path).map_err(|_| "Cannot read inline DA")?;
    let before = file.metadata().map_err(|_| "Cannot inspect inline DA")?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if before.file_attributes() & 0x400 != 0 {
            return Err("Opened inline DA cannot be a reparse point".into());
        }
    }
    if !before.is_file() || before.len() > MAX_DATA as u64 {
        return Err("Inline DA exceeds 3000-byte scope".into());
    }
    let mut bytes = Vec::new();
    (&file)
        .take(MAX_DATA as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Cannot read inline DA")?;
    let after = file.metadata().map_err(|_| "Cannot recheck inline DA")?;
    if bytes.len() as u64 != before.len()
        || after.len() != before.len()
        || after.modified().ok() != before.modified().ok()
    {
        return Err("Inline DA changed during bounded read".into());
    }
    Ok(bytes)
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
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or("Truncated inline DA")?;
        self.offset = end;
        Ok(bytes)
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_be_bytes(array(self.take(4)?, 0)?))
    }
    fn u64(&mut self) -> Result<u64, String> {
        u64_at(self.take(8)?, 0)
    }
    fn field(&mut self) -> Result<&'a [u8], String> {
        let count = self.u32()? as usize;
        self.take(count)
    }
}
