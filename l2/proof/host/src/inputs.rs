//! Bounded reads of private transition input and the packaged guest program.

use crate::HostResult;
use sha2::{Digest, Sha256};
use std::{fs::File, io::Read, path::Path};

pub const MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_PROGRAM_BYTES: usize = 32 * 1024 * 1024;

pub fn read_bounded(path: &Path, maximum: usize) -> HostResult<Vec<u8>> {
    let file = File::open(path).map_err(|_| "Cannot open input artifact.")?;
    let metadata = file
        .metadata()
        .map_err(|_| "Cannot inspect input artifact.")?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum as u64 {
        return Err("Input artifact is not a nonempty regular file within its byte limit.");
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Cannot read input artifact.")?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err("Input artifact exceeds its bounded read limit or became empty.");
    }
    Ok(bytes)
}

pub fn sha256_bounded(path: &Path, maximum: u64) -> HostResult<[u8; 32]> {
    let file = File::open(path).map_err(|_| "Cannot open pinned prover executable.")?;
    let metadata = file
        .metadata()
        .map_err(|_| "Cannot inspect pinned prover executable.")?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err("Pinned prover is not a nonempty regular file within its byte limit.");
    }
    let mut file = file.take(maximum + 1);
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut read = 0_u64;
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| "Cannot hash pinned prover executable.")?;
        if count == 0 {
            break;
        }
        read += count as u64;
        if read > maximum {
            return Err("Pinned prover executable changed beyond its byte limit.");
        }
        digest.update(&buffer[..count]);
    }
    if read != metadata.len() {
        return Err("Pinned prover executable changed while hashing.");
    }
    Ok(digest.finalize().into())
}
