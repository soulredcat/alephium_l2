//! Core DA assertions called by the single host filesystem/DA bulk harness.
use alephium_l2_transition_core::{
    BatchTransitionJournal, CheckpointTransitionBundle, ProofInput, ProvenTransition,
    checkpoint_batch_commitment,
    da::{ExpectedDa, read_checkpoint_da, reconstruct_checkpoint_da, write_checkpoint_da},
    decode_input,
    protocol::{Capacity, proof_transport::ProofLimits},
    prove_input,
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Cursor, Read},
    path::Path,
};

#[path = "da_reconstruction/layout.rs"]
mod layout;
use layout::layout;

/// Private retained/derived material; never add Debug or print its bytes.
pub struct DaFixture {
    pub bundle: CheckpointTransitionBundle,
    pub journal: BatchTransitionJournal,
    pub bytes: Vec<u8>,
    pub checkpoint_bytes: Vec<u8>,
    pub checks: usize,
}

fn checked<T, E>(value: Result<T, E>, label: &str) -> T {
    value.unwrap_or_else(|_| panic!("{label}"))
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn check(value: bool, checks: &mut usize, label: &str) {
    assert!(value, "{label}");
    *checks += 1;
}

fn reject(bytes: &[u8], journal: &BatchTransitionJournal, capacity: Capacity, repin: bool) {
    let mut candidate = journal.clone();
    if repin {
        // Test structural/execution guards even when an untrusted package's
        // digest is supplied. Such a candidate is never settlement authority.
        candidate.da_commitment = hash(bytes).into();
    }
    let expected = ExpectedDa {
        journal: &candidate,
        capacity,
    };
    if let Ok(decoded) = read_checkpoint_da(&mut Cursor::new(bytes), bytes.len(), &expected) {
        assert!(
            reconstruct_checkpoint_da(decoded, &expected).is_err(),
            "invalid DA or candidate statement was accepted"
        );
    }
}

struct ShortReads<'a>(Cursor<&'a [u8]>);
impl Read for ShortReads<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let length = out.len().min(7);
        self.0.read(&mut out[..length])
    }
}

struct NoRead(bool);
impl Read for NoRead {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        self.0 = true;
        Err(io::Error::other("unexpected read after invalid length"))
    }
}

/// All cases belong to the caller's one aggregate job, not separate test runs.
pub fn fixture_and_core_checks(input: &Path) -> DaFixture {
    let capacity = Capacity {
        block_gas: 3_000_000_000,
        block_bytes: 32 * 1024 * 1024,
        max_pending: 1_000,
    };
    let limits = checked(ProofLimits::for_capacity(capacity), "selected DA profile");
    let metadata = checked(fs::symlink_metadata(input), "retained DA input metadata");
    assert!(metadata.is_file() && !metadata.file_type().is_symlink());
    assert!(metadata.len() == 416_041 && metadata.len() <= limits.input_bytes as u64);
    let wire = checked(fs::read(input), "read retained DA fixture");
    let mut checks = 0;
    check(
        hex::encode(hash(&wire))
            == "477e8da9e1933231e1a6471279124b1940dff2d9432e49d0d5721cf825fb07d6",
        &mut checks,
        "retained fixture identity changed",
    );
    let decoded = checked(decode_input(&wire), "decode retained witness");
    let ProvenTransition::Checkpoint(native) =
        checked(prove_input(&decoded), "native reference replay")
    else {
        panic!("expected native checkpoint result")
    };
    let ProofInput::Checkpoint(bundle) = decoded else {
        panic!("expected checkpoint input")
    };
    check(
        bundle.schema == 4
            && bundle.checkpoint.capacity == capacity
            && native.journal.blocks == 8
            && native.journal.executed_transactions == 1_000,
        &mut checks,
        "fixture differs from the current bounded development scope",
    );
    let journal_bytes = checked(native.journal.encode(), "encode native reference journal");
    let checkpoint_bytes = checked(native.checkpoint.encode(), "encode native checkpoint");
    check(
        hex::encode(hash(&journal_bytes))
            == "49cf48125de4c4935c25407b1e92ad647cce6a308ba1da9934fcafc6e7a9b57a",
        &mut checks,
        "native journal differs from independently retained reference",
    );
    check(
        hex::encode(hash(&checkpoint_bytes))
            == "6f0568897687d678a895728a98acd98c8c1d87fc10dc3a4c923176146ff9e8f2",
        &mut checks,
        "native checkpoint differs from retained reference",
    );
    let journal = native.journal;
    let expected = ExpectedDa {
        journal: &journal,
        capacity,
    };
    let mut bytes = Vec::new();
    let evidence = checked(
        write_checkpoint_da(&bundle, &mut |part| {
            bytes.extend_from_slice(part);
            Ok(())
        }),
        "write canonical DA",
    );
    check(
        evidence.bytes == bytes.len()
            && evidence.commitment.as_slice() == hash(&bytes).as_slice()
            && evidence.commitment == journal.da_commitment
            && evidence.commitment
                == checked(checkpoint_batch_commitment(&bundle), "existing DA digest"),
        &mut checks,
        "DA writer differs from the existing canonical commitment",
    );
    let mut source = ShortReads(Cursor::new(bytes.as_slice()));
    let clean = checked(
        read_checkpoint_da(&mut source, bytes.len(), &expected),
        "short-read DA decode",
    );
    check(
        source.0.position() == bytes.len() as u64
            && clean.encoding().bytes == bytes.len()
            && clean.encoding().commitment == evidence.commitment,
        &mut checks,
        "DA decoder did not consume the exact pinned bytes",
    );
    let reconstructed = checked(
        reconstruct_checkpoint_da(clean, &expected),
        "clean DA reconstruction",
    );
    check(
        checked(
            reconstructed.journal.encode(),
            "encode reconstructed journal",
        ) == journal_bytes,
        &mut checks,
        "DA-derived journal differs from native execution",
    );
    check(
        checked(
            reconstructed.checkpoint.encode(),
            "encode reconstructed checkpoint",
        ) == checkpoint_bytes,
        &mut checks,
        "DA-derived checkpoint differs from native execution",
    );

    let mut false_oracles = bundle.clone();
    false_oracles.head.commit_id = [0_u8; 32].into();
    false_oracles.expected_state_digest = [0_u8; 32].into();
    for block in &mut false_oracles.blocks {
        block.parent.commit_id = [0_u8; 32].into();
        block.head.commit_id = [0_u8; 32].into();
        for input in &mut block.transactions {
            input.transaction_hash = [0_u8; 32].into();
            input.expected_receipt.success = !input.expected_receipt.success;
        }
    }
    let mut without_oracles = Vec::new();
    checked(
        write_checkpoint_da(&false_oracles, &mut |part| {
            without_oracles.extend_from_slice(part);
            Ok(())
        }),
        "oracle-independent DA export",
    );
    check(
        without_oracles == bytes,
        &mut checks,
        "output oracles leaked into DA authority",
    );
    check(
        write_checkpoint_da(&bundle, &mut |_| Err("injected DA sink failure".into())).is_err(),
        &mut checks,
        "failed DA sink was reported complete",
    );

    for kind in 0..5 {
        let mut wrong = journal.clone();
        match kind {
            0 => wrong.domain.l1_genesis_id = [0x91_u8; 32].into(),
            1 => wrong.execution_profile = [0_u8; 32].into(),
            2 => wrong.old_state_root = [0_u8; 32].into(),
            3 => wrong.new_state_root = [0_u8; 32].into(),
            _ => wrong.parent.commit_id = [0_u8; 32].into(),
        }
        reject(&bytes, &wrong, capacity, false);
        checks += 1;
    }
    let mut wrong_capacity = capacity;
    wrong_capacity.max_pending += 1;
    reject(&bytes, &journal, wrong_capacity, false);
    checks += 1;

    let positions = layout(&bytes, capacity);
    for position in [
        4,
        positions.domain,
        positions.domain + 1,
        positions.domain + 33,
        positions.profile,
    ] {
        let mut wrong = bytes.clone();
        wrong[position] ^= 1;
        reject(&wrong, &journal, capacity, true);
        checks += 1;
    }
    for field in 0..4 {
        let mut wrong = bytes.clone();
        let offset = positions.limits + field * 8;
        wrong[offset..offset + 8].copy_from_slice(&u64::MAX.to_be_bytes());
        reject(&wrong, &journal, capacity, true);
        checks += 1;
    }
    let first = &positions.blocks[0];
    for (offset, width) in [
        (0, 4),
        (positions.checkpoint_length, 4),
        (positions.accounts_count, 4),
        (positions.block_count, 8),
        (first.range.start + 24, 4),
        (first.records[0].start, 4),
    ] {
        let mut wrong = bytes.clone();
        wrong[offset..offset + width].fill(0xff);
        reject(&wrong, &journal, capacity, true);
        checks += 1;
    }
    for length in [
        0,
        positions.checkpoint_start,
        positions.block_count,
        bytes.len() - 1,
    ] {
        reject(&bytes[..length], &journal, capacity, true);
        checks += 1;
    }
    check(
        read_checkpoint_da(
            &mut Cursor::new(&bytes[..bytes.len() - 1]),
            bytes.len(),
            &expected,
        )
        .is_err(),
        &mut checks,
        "physically truncated DA satisfied its declared length",
    );
    let mut trailing = bytes.clone();
    trailing.push(0);
    check(
        read_checkpoint_da(&mut Cursor::new(&trailing), bytes.len(), &expected).is_err(),
        &mut checks,
        "physical trailing DA bytes were ignored",
    );
    reject(&trailing, &journal, capacity, true);
    checks += 1;
    for length in [0, limits.input_bytes + 1, usize::MAX] {
        let mut unread = NoRead(false);
        check(
            read_checkpoint_da(&mut unread, length, &expected).is_err() && !unread.0,
            &mut checks,
            "invalid DA length was not rejected before I/O/allocation",
        );
    }

    let mut wrong_order = bytes.clone();
    let second = &positions.blocks[1];
    let reordered = [&bytes[second.range.clone()], &bytes[first.range.clone()]].concat();
    drop(wrong_order.splice(first.range.start..second.range.end, reordered));
    reject(&wrong_order, &journal, capacity, true);
    checks += 1;
    let multi = positions
        .blocks
        .iter()
        .find(|block| block.records.len() >= 2)
        .expect("retained fixture must exercise ordered transaction data");
    let a = &multi.records[0];
    let b = &multi.records[1];
    let mut wrong_order = bytes.clone();
    drop(wrong_order.splice(
        a.start..b.end,
        [&bytes[b.clone()], &bytes[a.clone()]].concat(),
    ));
    reject(&wrong_order, &journal, capacity, true);
    checks += 1;
    let mut invalid_raw = bytes.clone();
    invalid_raw[first.records[0].start + 4] = 0xff;
    reject(&invalid_raw, &journal, capacity, true);
    checks += 1;
    let mut missing = bytes.clone();
    drop(missing.drain(a.clone()));
    missing[multi.range.start + 24..multi.range.start + 28]
        .copy_from_slice(&((multi.records.len() - 1) as u32).to_be_bytes());
    reject(&missing, &journal, capacity, true);
    checks += 1;
    let account_bytes = 105 + 64 * bundle.checkpoint.accounts[0].slots.len();
    let mut missing_account = bytes.clone();
    let start = positions.accounts_count + 4;
    drop(missing_account.drain(start..start + account_bytes));
    missing_account[positions.accounts_count..positions.accounts_count + 4]
        .copy_from_slice(&((bundle.checkpoint.accounts.len() - 1) as u32).to_be_bytes());
    let checkpoint_length = positions.block_count - positions.checkpoint_start - account_bytes;
    missing_account[positions.checkpoint_length..positions.checkpoint_length + 4]
        .copy_from_slice(&(checkpoint_length as u32).to_be_bytes());
    reject(&missing_account, &journal, capacity, true);
    checks += 1;
    DaFixture {
        bundle,
        journal,
        bytes,
        checkpoint_bytes,
        checks,
    }
}
