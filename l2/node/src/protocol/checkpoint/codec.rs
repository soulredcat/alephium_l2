use super::*;

pub(super) fn encode(checkpoint: &ExecutionCheckpoint) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(DOMAIN);
    out.extend(checkpoint.schema.to_be_bytes());
    out.extend(checkpoint.chain_id.to_be_bytes());
    out.extend_from_slice(checkpoint.genesis_id.as_slice());
    out.extend(checkpoint.head.height.to_be_bytes());
    out.extend(checkpoint.head.timestamp.to_be_bytes());
    out.extend_from_slice(checkpoint.head.commit_id.as_slice());
    out.extend_from_slice(checkpoint.head.genesis_id.as_slice());
    out.extend((checkpoint.accounts.len() as u32).to_be_bytes());
    for account in &checkpoint.accounts {
        out.extend_from_slice(account.address.as_slice());
        out.push(u8::from(account.deleted));
        out.extend(account.balance.to_be_bytes::<32>());
        out.extend(account.nonce.to_be_bytes());
        out.extend_from_slice(account.code_hash.as_slice());
        out.extend(account.storage_epoch.to_be_bytes());
        out.extend((account.slots.len() as u32).to_be_bytes());
        for slot in &account.slots {
            out.extend(slot.key.to_be_bytes::<32>());
            out.extend(slot.value.to_be_bytes::<32>());
        }
    }
    out.extend((checkpoint.codes.len() as u32).to_be_bytes());
    for code in &checkpoint.codes {
        out.extend_from_slice(code.hash.as_slice());
        out.extend((code.bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&code.bytes);
    }
    out.extend((checkpoint.block_hashes.len() as u32).to_be_bytes());
    for block in &checkpoint.block_hashes {
        out.extend(block.height.to_be_bytes());
        out.extend_from_slice(block.hash.as_slice());
    }
    out
}

pub(super) fn decode(bytes: &[u8]) -> Result<ExecutionCheckpoint, String> {
    if bytes.len() > MAX_CHECKPOINT_BYTES {
        return Err("checkpoint exceeds canonical byte bound".into());
    }
    let mut input = Reader { bytes, offset: 0 };
    if input.take(DOMAIN.len())? != DOMAIN {
        return Err("invalid checkpoint encoding domain".into());
    }
    let schema = input.u32()?;
    let chain_id = input.u64()?;
    let genesis_id = input.hash()?;
    let head = Head {
        height: input.u64()?,
        timestamp: input.u64()?,
        commit_id: input.hash()?,
        genesis_id: input.hash()?,
    };
    let count = input.count(105, MAX_CHECKPOINT_ACCOUNTS)?;
    let mut accounts = Vec::with_capacity(count);
    let mut total_slots = 0usize;
    for _ in 0..count {
        let address = Address::from_slice(input.take(20)?);
        let deleted = match input.take(1)?[0] {
            0 => false,
            1 => true,
            _ => return Err("invalid checkpoint boolean".into()),
        };
        let balance = input.amount()?;
        let nonce = input.u64()?;
        let code_hash = input.hash()?;
        let storage_epoch = input.u64()?;
        let count = input.count(64, MAX_CHECKPOINT_SLOTS)?;
        total_slots = total_slots
            .checked_add(count)
            .ok_or("checkpoint slot overflow")?;
        if total_slots > MAX_CHECKPOINT_SLOTS {
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
    let count = input.count(36, MAX_CHECKPOINT_CODES)?;
    let mut codes = Vec::with_capacity(count);
    for _ in 0..count {
        let hash = input.hash()?;
        let length = input.count(1, MAX_CHECKPOINT_CODE_BYTES)?;
        codes.push(CheckpointCode {
            hash,
            bytes: input.take(length)?.to_vec(),
        });
    }
    let count = input.count(40, 256)?;
    let mut block_hashes = Vec::with_capacity(count);
    for _ in 0..count {
        block_hashes.push(CheckpointBlockHash {
            height: input.u64()?,
            hash: input.hash()?,
        });
    }
    if input.offset != bytes.len() {
        return Err("checkpoint contains trailing bytes".into());
    }
    let checkpoint = ExecutionCheckpoint {
        schema,
        chain_id,
        genesis_id,
        head,
        accounts,
        codes,
        block_hashes,
    };
    checkpoint.validate()?;
    Ok(checkpoint)
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, size: usize) -> Result<&'a [u8], String> {
        let end = self
            .offset
            .checked_add(size)
            .ok_or("checkpoint offset overflow")?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or("truncated checkpoint encoding")?;
        self.offset = end;
        Ok(bytes)
    }

    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| "invalid checkpoint u32")?,
        ))
    }

    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| "invalid checkpoint u64")?,
        ))
    }

    fn hash(&mut self) -> Result<B256, String> {
        Ok(B256::from_slice(self.take(32)?))
    }

    fn amount(&mut self) -> Result<U256, String> {
        Ok(U256::from_be_slice(self.take(32)?))
    }

    fn count(&mut self, minimum_bytes: usize, maximum: usize) -> Result<usize, String> {
        let count = self.u32()? as usize;
        if count > maximum || count > (self.bytes.len() - self.offset) / minimum_bytes {
            return Err("checkpoint count exceeds remaining input or resource bound".into());
        }
        Ok(count)
    }
}
