use super::{Encoder, ProofLimits, decode::Reader};
use crate::protocol::{Capacity, checkpoint::ExecutionCheckpoint};
use std::io::Read;

pub(super) fn frame_count(total: usize, limits: ProofLimits) -> Result<usize, String> {
    limits.validate()?;
    if total == 0 || total > limits.checkpoint_bytes {
        return Err("checkpoint frame total exceeds selected bound".into());
    }
    total
        .checked_add(limits.frame_bytes - 1)
        .map(|bytes| bytes / limits.frame_bytes)
        .ok_or_else(|| "checkpoint frame count overflow".into())
}

pub(super) fn encode(
    out: &mut Encoder,
    checkpoint: &ExecutionCheckpoint,
    total: usize,
    limits: ProofLimits,
) -> Result<(), String> {
    let count = frame_count(total, limits)?;
    out.u64(u64::try_from(total).map_err(|_| "checkpoint frame total overflow")?);
    out.u32(u32::try_from(count).map_err(|_| "checkpoint frame count overflow")?);
    let mut remaining = total;
    let mut frame_remaining = 0usize;
    let mut index = 0usize;
    checkpoint.write_encoded(&mut |mut bytes| {
        while !bytes.is_empty() {
            if frame_remaining == 0 {
                if remaining == 0 || index >= count {
                    return Err("checkpoint emitted excess frame data".into());
                }
                frame_remaining = remaining.min(limits.frame_bytes);
                out.u32(u32::try_from(index).map_err(|_| "frame index overflow")?);
                out.u32(u32::try_from(frame_remaining).map_err(|_| "frame length overflow")?);
                index += 1;
            }
            let written = bytes.len().min(frame_remaining);
            let end = out
                .0
                .len()
                .checked_add(written)
                .ok_or("frame byte size overflow")?;
            if end > limits.input_bytes {
                return Err("framed checkpoint exceeds selected input bound".into());
            }
            out.0.extend_from_slice(&bytes[..written]);
            frame_remaining -= written;
            remaining -= written;
            bytes = &bytes[written..];
        }
        Ok(())
    })?;
    if remaining != 0 || frame_remaining != 0 || index != count {
        return Err("checkpoint emitted incomplete canonical frames".into());
    }
    Ok(())
}

pub(super) fn decode<R: Read>(
    input: &mut Reader<'_, R>,
    capacity: Capacity,
    limits: ProofLimits,
) -> Result<ExecutionCheckpoint, String> {
    let total = usize::try_from(input.u64()?).map_err(|_| "checkpoint total overflow")?;
    let count = input.u32()? as usize;
    let expected_count = frame_count(total, limits)?;
    let complete = total
        .checked_add(count.checked_mul(8).ok_or("frame metadata overflow")?)
        .ok_or("checkpoint frame size overflow")?;
    if count != expected_count || complete > input.remaining {
        return Err("checkpoint frame count/total exceeds remaining input".into());
    }
    let mut frames = FrameReader {
        input,
        remaining: total,
        frame_remaining: 0,
        next_index: 0,
        count,
        frame_bytes: limits.frame_bytes,
    };
    // The shared decoder reads and authenticates the capacity prefix on the
    // stack before allocating collections. No flat checkpoint Vec is retained.
    let checkpoint = ExecutionCheckpoint::read_encoded_for_capacity(
        &mut |bytes| frames.read_into(bytes),
        total,
        capacity,
    )?;
    if frames.remaining != 0 || frames.frame_remaining != 0 || frames.next_index != count {
        return Err("checkpoint frames do not reconstruct exact total".into());
    }
    Ok(checkpoint)
}

/// Supplies only checkpoint payload bytes; each canonical frame header stays
/// outside the decoder's count/allocation budget, even across scalar reads.
struct FrameReader<'a, 'b, R> {
    input: &'a mut Reader<'b, R>,
    remaining: usize,
    frame_remaining: usize,
    next_index: usize,
    count: usize,
    frame_bytes: usize,
}

impl<R: Read> FrameReader<'_, '_, R> {
    fn read_into(&mut self, mut bytes: &mut [u8]) -> Result<(), String> {
        if bytes.len() > self.remaining {
            return Err("checkpoint field exceeds declared frame total".into());
        }
        while !bytes.is_empty() {
            if self.frame_remaining == 0 {
                self.next_frame()?;
            }
            let length = bytes.len().min(self.frame_remaining);
            self.input.read_into(&mut bytes[..length])?;
            self.frame_remaining -= length;
            self.remaining -= length;
            bytes = &mut bytes[length..];
        }
        Ok(())
    }

    fn next_frame(&mut self) -> Result<(), String> {
        if self.next_index >= self.count || self.input.u32()? as usize != self.next_index {
            return Err("checkpoint frame order is not canonical".into());
        }
        let length = self.input.u32()? as usize;
        if length == 0 || length != self.remaining.min(self.frame_bytes) {
            return Err("checkpoint frame length differs from exact canonical partition".into());
        }
        // Keep the original first-frame rule; the longest prefix is the
        // 35-byte domain followed by schema, chain and capacity integers.
        if self.next_index == 0 && length < 35 + 4 + 8 + 24 {
            return Err("invalid first checkpoint frame length".into());
        }
        self.frame_remaining = length;
        self.next_index += 1;
        Ok(())
    }
}
