//! Alephium v4.7.0 CompactInteger.scala: positive signed Int and unsigned U256.
use super::types::AlephiumValidationError as Error;
use alloy_primitives::U256;

pub(super) struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub(super) fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        let end = self.offset.checked_add(count).ok_or(Error::Overflow)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(Error::MalformedUnsigned)?;
        self.offset = end;
        Ok(bytes)
    }

    pub(super) fn fixed<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?
            .try_into()
            .map_err(|_| Error::MalformedUnsigned)
    }

    pub(super) fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.fixed::<1>()?[0])
    }

    /// Negative signed compact integers are outside lengths and GasBox support.
    pub(super) fn int(&mut self) -> Result<u32, Error> {
        let first = self.byte()?;
        let mode = first >> 6;
        if mode < 3 && first & 0x20 != 0 {
            return Err(Error::MalformedUnsigned);
        }
        let value = match mode {
            0 => u32::from(first),
            1 => (u32::from(first & 0x3f) << 8) | u32::from(self.byte()?),
            2 => {
                let suffix = self.fixed::<3>()?;
                u32::from_be_bytes([first & 0x3f, suffix[0], suffix[1], suffix[2]])
            }
            _ if first == 0xc0 => u32::from_be_bytes(self.fixed()?),
            _ => return Err(Error::MalformedUnsigned),
        };
        if value > i32::MAX as u32 {
            return Err(Error::MalformedUnsigned);
        }
        Ok(value)
    }

    pub(super) fn amount(&mut self) -> Result<U256, Error> {
        let first = self.byte()?;
        Ok(match first >> 6 {
            0 => U256::from(first),
            1 => U256::from((u32::from(first & 0x3f) << 8) | u32::from(self.byte()?)),
            2 => {
                let suffix = self.fixed::<3>()?;
                U256::from(u32::from_be_bytes([
                    first & 0x3f,
                    suffix[0],
                    suffix[1],
                    suffix[2],
                ]))
            }
            _ => {
                let length = usize::from(first & 0x3f) + 4;
                if length > 32 {
                    return Err(Error::Bounds);
                }
                U256::from_be_slice(self.take(length)?)
            }
        })
    }

    pub(super) fn count(&mut self, maximum: usize, minimum_bytes: usize) -> Result<usize, Error> {
        let count = self.int()? as usize;
        if count > maximum || count > (self.bytes.len() - self.offset) / minimum_bytes {
            return Err(Error::Bounds);
        }
        Ok(count)
    }

    pub(super) fn finish(self) -> Result<(), Error> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::NoncanonicalUnsigned)
        }
    }
}

pub(super) fn put_int(out: &mut Vec<u8>, value: u32) -> Result<(), Error> {
    if value > i32::MAX as u32 {
        return Err(Error::Bounds);
    }
    let bytes = value.to_be_bytes();
    if value < (1 << 5) {
        out.push(value as u8);
    } else if value < (1 << 13) {
        out.extend_from_slice(&[bytes[2] | 0x40, bytes[3]]);
    } else if value < (1 << 29) {
        out.extend_from_slice(&[bytes[0] | 0x80, bytes[1], bytes[2], bytes[3]]);
    } else {
        out.push(0xc0);
        out.extend_from_slice(&bytes);
    }
    Ok(())
}

pub(super) fn put_amount(out: &mut Vec<u8>, value: U256) {
    let bytes = value.to_be_bytes::<32>();
    if value < U256::from(1u64 << 6) {
        out.push(bytes[31]);
    } else if value < U256::from(1u64 << 14) {
        out.extend_from_slice(&[bytes[30] | 0x40, bytes[31]]);
    } else if value < U256::from(1u64 << 30) {
        out.extend_from_slice(&[bytes[28] | 0x80, bytes[29], bytes[30], bytes[31]]);
    } else {
        let start = bytes.iter().position(|byte| *byte != 0).unwrap_or(31);
        let length = 32 - start;
        out.push(0xc0 + (length - 4) as u8);
        out.extend_from_slice(&bytes[start..]);
    }
}
