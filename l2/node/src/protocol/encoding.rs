use alloy_primitives::{Address, B256, U256};

pub(crate) const MAX_RECORD: usize = 16 * 1024 * 1024;

#[derive(Default)]
pub(crate) struct Encoder(pub Vec<u8>);

impl Encoder {
    pub fn byte(&mut self, value: u8) {
        self.0.push(value);
    }
    pub fn u32(&mut self, value: u32) {
        self.0.extend(value.to_be_bytes());
    }
    pub fn u64(&mut self, value: u64) {
        self.0.extend(value.to_be_bytes());
    }
    pub fn u128(&mut self, value: u128) {
        self.0.extend(value.to_be_bytes());
    }
    pub fn amount(&mut self, value: U256) {
        self.0.extend(value.to_be_bytes::<32>());
    }
    pub fn address(&mut self, value: Address) {
        self.0.extend(value.as_slice());
    }
    pub fn hash(&mut self, value: B256) {
        self.0.extend(value.as_slice());
    }
    pub fn bytes(&mut self, value: &[u8]) -> Result<(), String> {
        if value.len() > MAX_RECORD {
            return Err("record field exceeds storage limit".into());
        }
        self.u32(u32::try_from(value.len()).map_err(|_| "record field overflow")?);
        self.0.extend(value);
        Ok(())
    }
    pub fn optional_address(&mut self, value: Option<Address>) {
        self.byte(u8::from(value.is_some()));
        if let Some(value) = value {
            self.address(value);
        }
    }
    pub fn finish(self) -> Result<Vec<u8>, String> {
        if self.0.len() > MAX_RECORD {
            Err("record exceeds storage limit".into())
        } else {
            Ok(self.0)
        }
    }
}

pub(crate) struct Decoder<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self, String> {
        if data.len() > MAX_RECORD {
            return Err("record exceeds storage limit".into());
        }
        Ok(Self { data, offset: 0 })
    }
    pub fn take(&mut self, length: usize) -> Result<&'a [u8], String> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or("record length overflow")?;
        let slice = self
            .data
            .get(self.offset..end)
            .ok_or("truncated storage record")?;
        self.offset = end;
        Ok(slice)
    }
    pub fn byte(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    pub fn boolean(&mut self) -> Result<bool, String> {
        match self.byte()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err("invalid record flag".into()),
        }
    }
    pub fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub fn u128(&mut self) -> Result<u128, String> {
        Ok(u128::from_be_bytes(self.take(16)?.try_into().unwrap()))
    }
    pub fn amount(&mut self) -> Result<U256, String> {
        Ok(U256::from_be_slice(self.take(32)?))
    }
    pub fn address(&mut self) -> Result<Address, String> {
        Ok(Address::from_slice(self.take(20)?))
    }
    pub fn hash(&mut self) -> Result<B256, String> {
        Ok(B256::from_slice(self.take(32)?))
    }
    pub fn bytes(&mut self) -> Result<Vec<u8>, String> {
        let length = self.u32()? as usize;
        Ok(self.take(length)?.to_vec())
    }
    pub fn count(&mut self, minimum_size: usize) -> Result<usize, String> {
        let count = self.u32()? as usize;
        if count > self.remaining() / minimum_size {
            return Err("invalid record count".into());
        }
        Ok(count)
    }
    pub fn optional_address(&mut self) -> Result<Option<Address>, String> {
        if self.boolean()? {
            Ok(Some(self.address()?))
        } else {
            Ok(None)
        }
    }
    pub fn remaining(&self) -> usize {
        self.data.len() - self.offset
    }
    pub fn finish(self) -> Result<(), String> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err("trailing storage record bytes".into())
        }
    }
}

pub(crate) fn key(prefix: u8, suffix: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(suffix.len() + 1);
    key.push(prefix);
    key.extend(suffix);
    key
}

pub(crate) fn slot_key(address: Address, epoch: u64, slot: U256) -> Vec<u8> {
    let mut out = key(0x11, address.as_slice());
    out.extend(epoch.to_be_bytes());
    out.extend(slot.to_be_bytes::<32>());
    out
}
