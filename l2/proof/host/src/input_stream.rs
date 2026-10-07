//! Digest exactly the bounded payload consumed by native replay or guest stdin.

use crate::HostResult;
use sha2::{Digest, Sha256};
use std::{cell::RefCell, io::Read, rc::Rc};

struct ReadState {
    bytes: usize,
    digest: Sha256,
}

pub struct PayloadReader<R> {
    source: R,
    remaining: usize,
    state: Rc<RefCell<ReadState>>,
}

pub struct InputCompletion {
    expected_bytes: usize,
    state: Rc<RefCell<ReadState>>,
}

impl<R: Read> PayloadReader<R> {
    pub fn new(source: R, length: usize) -> (Self, InputCompletion) {
        let state = Rc::new(RefCell::new(ReadState {
            bytes: 0,
            digest: Sha256::new(),
        }));
        (
            Self {
                source,
                remaining: length,
                state: state.clone(),
            },
            InputCompletion {
                expected_bytes: length,
                state,
            },
        )
    }
}

impl<R: Read> Read for PayloadReader<R> {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if output.is_empty() || self.remaining == 0 {
            return Ok(0);
        }
        let maximum = output.len().min(self.remaining);
        let count = self.source.read(&mut output[..maximum])?;
        if count == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        self.remaining -= count;
        let mut state = self.state.borrow_mut();
        state.bytes += count;
        state.digest.update(&output[..count]);
        Ok(count)
    }
}

impl InputCompletion {
    /// Bytes supplied into the SDK's bounded stdin buffer, including read-ahead.
    /// This is not an assertion of successful guest execution or a valid proof.
    pub fn bytes_fed(&self) -> usize {
        self.state.borrow().bytes
    }

    pub fn finish(&self, expected_digest: Option<[u8; 32]>) -> HostResult<[u8; 32]> {
        let state = self.state.borrow();
        if state.bytes != self.expected_bytes {
            return Err("Private input stream was not consumed completely; payload suppressed.");
        }
        let digest: [u8; 32] = state.digest.clone().finalize().into();
        if expected_digest.is_some_and(|expected| digest != expected) {
            return Err(
                "Guest input stream differs from independently replayed bytes; payload suppressed.",
            );
        }
        Ok(digest)
    }
}

#[cfg(test)]
mod tests {
    use super::PayloadReader;
    use sha2::{Digest, Sha256};
    use std::io::{Cursor, Read};

    #[test]
    fn stream_digest_rejects_short_incomplete_and_changed_payloads() {
        let bytes = b"bounded payload";
        let expected: [u8; 32] = Sha256::digest(bytes).into();
        let (mut reader, completion) = PayloadReader::new(Cursor::new(bytes), bytes.len());
        let mut first = [0; 3];
        reader.read_exact(&mut first).unwrap();
        assert!(completion.finish(Some(expected)).is_err());
        let mut rest = Vec::new();
        reader.read_to_end(&mut rest).unwrap();
        assert_eq!(completion.finish(Some(expected)).unwrap(), expected);
        assert!(completion.finish(Some([0; 32])).is_err());
        let (mut short, completion) = PayloadReader::new(Cursor::new(bytes), bytes.len() + 1);
        assert!(short.read_to_end(&mut Vec::new()).is_err());
        assert!(completion.finish(None).is_err());
    }
}
