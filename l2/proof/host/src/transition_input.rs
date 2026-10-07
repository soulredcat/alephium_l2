//! Probe profile bounds before allocating; stream one checked input handle.

use crate::{
    HostResult,
    input_stream::{InputCompletion, PayloadReader},
    inputs::{CheckedFile, MAX_INPUT_BYTES},
};
use alephium_l2_transition_core::{
    LARGE_CHECKPOINT_HEADER_BYTES, LARGE_CHECKPOINT_WIRE_MAGIC, ProofInput, decode_input_reader,
    large_checkpoint_transition_header,
};
use std::{
    fs::File,
    io::{BufReader, Chain, Cursor, Read, Seek},
    path::Path,
};

pub struct TransitionInput {
    source: CheckedFile,
    pub length: usize,
    pub schema: u32,
    pub byte_limit: usize,
    digest: Option<[u8; 32]>,
}

pub struct GuestInput {
    pub reader: Chain<Cursor<[u8; 4]>, PayloadReader<File>>,
    pub completion: InputCompletion,
    pub expected_digest: [u8; 32],
}

impl TransitionInput {
    pub fn open(path: &Path) -> HostResult<Self> {
        let mut source = CheckedFile::open(path)?;
        let length = usize::try_from(source.length)
            .map_err(|_| "Private input length cannot be represented on this host.")?;
        let mut header = [0; LARGE_CHECKPOINT_HEADER_BYTES];
        let prefix_bytes = length.min(header.len());
        source
            .file
            .read_exact(&mut header[..prefix_bytes])
            .map_err(|_| "Private transition header became truncated; payload suppressed.")?;
        let (schema, byte_limit) = probe_limits(&header[..prefix_bytes], length)?;
        source.check_unchanged()?;
        source
            .file
            .rewind()
            .map_err(|_| "Cannot rewind the checked private input.")?;
        Ok(Self {
            source,
            length,
            schema,
            byte_limit,
            digest: None,
        })
    }

    pub fn replay_input(&mut self) -> HostResult<ProofInput> {
        self.source.check_unchanged()?;
        self.source
            .file
            .rewind()
            .map_err(|_| "Cannot rewind private replay input.")?;
        let file = self
            .source
            .file
            .try_clone()
            .map_err(|_| "Cannot share the checked private input handle.")?;
        let (mut reader, completion) =
            PayloadReader::new(BufReader::with_capacity(64 * 1024, file), self.length);
        let bundle = decode_input_reader(&mut reader, self.length)
            .map_err(|_| "Invalid bounded private transition; payload suppressed.")?;
        self.digest = Some(completion.finish(None)?);
        self.source.check_unchanged()?;
        self.schema = match &bundle {
            ProofInput::Native(bundle) => bundle.schema,
            ProofInput::Batch(bundle) => bundle.schema,
            ProofInput::Checkpoint(bundle) => bundle.schema,
        };
        Ok(bundle)
    }

    pub fn guest_input(&mut self) -> HostResult<GuestInput> {
        let expected_digest = self.digest()?;
        self.source.check_unchanged()?;
        self.source
            .file
            .rewind()
            .map_err(|_| "Cannot rewind private guest input.")?;
        let file = self
            .source
            .file
            .try_clone()
            .map_err(|_| "Cannot share the checked guest input handle.")?;
        let length =
            u32::try_from(self.length).map_err(|_| "Private guest input framing overflow.")?;
        let (payload, completion) = PayloadReader::new(file, self.length);
        Ok(GuestInput {
            reader: Cursor::new(length.to_le_bytes()).chain(payload),
            completion,
            expected_digest,
        })
    }

    pub fn check_unchanged(&self) -> HostResult<()> {
        self.source.check_unchanged()
    }

    pub fn digest(&self) -> HostResult<[u8; 32]> {
        self.digest
            .ok_or("Private input has not passed complete independent replay.")
    }
}

fn probe_limits(prefix: &[u8], length: usize) -> HostResult<(u32, usize)> {
    if prefix.starts_with(LARGE_CHECKPOINT_WIRE_MAGIC) {
        if prefix.len() != LARGE_CHECKPOINT_HEADER_BYTES {
            return Err("Truncated schema-four profile header; payload suppressed.");
        }
        let (_, limits) = large_checkpoint_transition_header(prefix).map_err(
            |_| "Invalid schema-four profile or exact capacity bounds; payload suppressed.",
        )?;
        if length > limits.input_bytes {
            return Err("Schema-four private input exceeds its exact profile byte limit.");
        }
        Ok((4, limits.input_bytes))
    } else if length == 0 || length > MAX_INPUT_BYTES {
        Err("Legacy private input exceeds its unchanged sixteen MiB limit.")
    } else {
        Ok((0, MAX_INPUT_BYTES))
    }
}

#[cfg(test)]
mod tests {
    use super::{LARGE_CHECKPOINT_WIRE_MAGIC, MAX_INPUT_BYTES, TransitionInput, probe_limits};
    use alephium_l2_transition_core::protocol::{Capacity, proof_transport::ProofLimits};
    use sha2::{Digest, Sha256};
    use std::{fs, io::Read, time::SystemTime};

    #[test]
    fn probe_does_not_widen_legacy_or_accept_a_short_large_header() {
        assert!(probe_limits(b"legacy", MAX_INPUT_BYTES).is_ok());
        assert!(probe_limits(b"legacy", MAX_INPUT_BYTES + 1).is_err());
        assert!(
            probe_limits(
                LARGE_CHECKPOINT_WIRE_MAGIC,
                LARGE_CHECKPOINT_WIRE_MAGIC.len()
            )
            .is_err()
        );
        assert!(probe_limits(b"", 0).is_err());
    }

    #[test]
    fn large_probe_requires_exact_capacity_limits_before_a_large_read() {
        let capacity = Capacity {
            block_gas: 3_000_000_000,
            block_bytes: 32 * 1024 * 1024,
            max_pending: 100_000,
        };
        let limits = ProofLimits::for_capacity(capacity).unwrap();
        let mut header = LARGE_CHECKPOINT_WIRE_MAGIC.to_vec();
        header.extend_from_slice(&4_u32.to_be_bytes());
        for value in [
            capacity.block_gas,
            capacity.block_bytes as u64,
            capacity.max_pending as u64,
        ] {
            header.extend_from_slice(&value.to_be_bytes());
        }
        header.extend_from_slice(&limits.binding_bytes().unwrap());
        assert_eq!(
            probe_limits(&header, limits.input_bytes),
            Ok((4, limits.input_bytes))
        );
        assert!(probe_limits(&header, limits.input_bytes + 1).is_err());
        *header.last_mut().unwrap() ^= 1;
        assert!(probe_limits(&header, limits.input_bytes).is_err());
    }

    #[test]
    fn guest_feed_preserves_legacy_length_bytes_and_requires_native_digest() {
        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("l2-feed-check-{}-{nonce}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("input.bin");
        let payload = b"public synthetic framing fixture";
        fs::write(&path, payload).unwrap();
        let mut input = TransitionInput::open(&path).unwrap();
        assert!(input.guest_input().is_err());
        input.digest = Some(Sha256::digest(payload).into());
        let mut feed = input.guest_input().unwrap();
        let mut framed = Vec::new();
        feed.reader.read_to_end(&mut framed).unwrap();
        assert_eq!(&framed[..4], &(payload.len() as u32).to_le_bytes());
        assert_eq!(&framed[4..], payload);
        feed.completion.finish(Some(feed.expected_digest)).unwrap();
        input.check_unchanged().unwrap();
        drop(feed);
        drop(input);
        fs::remove_file(path).unwrap();
        fs::remove_dir(directory).unwrap();
    }
}
