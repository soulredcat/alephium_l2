//! Exact-length checkpoint reads, independent of surrounding frame metadata.
use alloy_primitives::{B256, U256};

pub(super) struct Reader<'a, F> {
    source: &'a mut F,
    pub(super) remaining: usize,
}

impl<'a, F: FnMut(&mut [u8]) -> Result<(), String>> Reader<'a, F> {
    pub(super) fn new(source: &'a mut F, total_len: usize) -> Self {
        Self {
            source,
            remaining: total_len,
        }
    }

    pub(super) fn read_into(&mut self, bytes: &mut [u8]) -> Result<(), String> {
        if bytes.len() > self.remaining {
            return Err("truncated checkpoint encoding".into());
        }
        (self.source)(bytes)?;
        self.remaining -= bytes.len();
        Ok(())
    }

    pub(super) fn fixed<const N: usize>(&mut self) -> Result<[u8; N], String> {
        let mut bytes = [0; N];
        self.read_into(&mut bytes)?;
        Ok(bytes)
    }

    pub(super) fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_be_bytes(self.fixed()?))
    }

    pub(super) fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }

    pub(super) fn hash(&mut self) -> Result<B256, String> {
        Ok(B256::from(self.fixed::<32>()?))
    }

    pub(super) fn amount(&mut self) -> Result<U256, String> {
        Ok(U256::from_be_bytes(self.fixed::<32>()?))
    }

    pub(super) fn count(&mut self, minimum_bytes: usize, maximum: usize) -> Result<usize, String> {
        let count = self.u32()? as usize;
        if count > maximum || count > self.remaining / minimum_bytes {
            return Err("checkpoint count exceeds remaining input or resource bound".into());
        }
        Ok(count)
    }
}

pub(super) fn read_slice(source: &mut &[u8], output: &mut [u8]) -> Result<(), String> {
    let (bytes, remaining) = source
        .split_at_checked(output.len())
        .ok_or("truncated checkpoint encoding")?;
    output.copy_from_slice(bytes);
    *source = remaining;
    Ok(())
}
