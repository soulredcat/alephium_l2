//! Manually enabled native replay of the retained GPU development suffix.
//! This produces no guest receipt, settlement or throughput qualification.
use alephium_l2_transition_core::{
    LARGE_CHECKPOINT_SCOPE, ProofInput, checkpoint_profile_v4_with_capacity, decode_input_reader,
    protocol::{Capacity, proof_transport::ProofLimits},
    prove_checkpoint_transition,
};
use alloy_primitives::B256;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

struct HashedInput {
    file: File,
    hash: Sha256,
    bytes: usize,
}

impl Read for HashedInput {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let count = self.file.read(out)?;
        self.bytes = self
            .bytes
            .checked_add(count)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "input size overflow"))?;
        self.hash.update(&out[..count]);
        Ok(count)
    }
}

fn input_path(name: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("set {name} explicitly")))
}

fn create_private_file(path: &Path) -> File {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).expect("create new local evidence file")
}

fn create_private_directory(path: &Path) {
    let mut options = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        options.mode(0o700);
    }
    options
        .create(path)
        .expect("output must be a new directory under an existing local parent");
}

fn observed_mode(path: &Path) -> Option<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        Some(
            fs::metadata(path)
                .expect("evidence metadata")
                .permissions()
                .mode()
                & 0o777,
        )
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

fn persist_bytes(path: &Path, bytes: &[u8]) -> B256 {
    let mut file = create_private_file(path);
    file.write_all(bytes).expect("write local evidence");
    file.sync_all().expect("sync local evidence");
    B256::from_slice(&Sha256::digest(bytes))
}

#[test]
#[ignore = "requires the retained 100,000-transfer GPU runtime suffix and a new local output directory"]
fn retained_gpu_development_suffix_matches_portable_native_execution() {
    let path = input_path("L2_LARGE_TRANSITION_INPUT");
    let output = input_path("L2_LARGE_TRANSITION_OUTPUT");
    assert!(
        !output.exists(),
        "preserve earlier evidence; choose a fresh output directory"
    );
    let metadata = fs::symlink_metadata(&path).expect("private retained input metadata");
    assert!(metadata.is_file() && !metadata.file_type().is_symlink());
    let bytes = usize::try_from(metadata.len()).expect("representable input length");
    let capacity = Capacity {
        block_gas: 3_000_000_000,
        block_bytes: 32 * 1024 * 1024,
        max_pending: 100_000,
    };
    let limits = ProofLimits::for_capacity(capacity).unwrap();
    assert!(bytes > 16 * 1024 * 1024 && bytes <= limits.input_bytes);
    let mut input = HashedInput {
        file: File::open(&path).expect("open retained input"),
        hash: Sha256::new(),
        bytes: 0,
    };
    let ProofInput::Checkpoint(bundle) =
        decode_input_reader(&mut input, bytes).expect("decode bounded schema-four private input")
    else {
        panic!("retained large input must be a checkpoint suffix");
    };
    assert_eq!(
        input.bytes, bytes,
        "decoder must consume the complete declared body"
    );
    let after = input
        .file
        .metadata()
        .expect("retained input metadata after read");
    assert_eq!(after.len(), metadata.len());
    assert_eq!(
        after.modified().ok(),
        metadata.modified().ok(),
        "input changed during decode"
    );
    let input_hash = B256::from_slice(&input.hash.finalize());
    assert_eq!(bundle.schema, 4);
    assert_eq!(bundle.checkpoint.capacity, capacity);
    assert_eq!(bundle.blocks.len(), 6);
    assert_eq!(
        (bundle.checkpoint.head.height, bundle.head.height),
        (201, 207)
    );
    assert_eq!(
        bundle
            .blocks
            .iter()
            .map(|block| block.transactions.len())
            .sum::<usize>(),
        100_000
    );
    let mut parent = &bundle.checkpoint.head;
    for block in &bundle.blocks {
        assert_eq!(&block.parent, parent);
        assert_eq!(block.context.number, parent.height + 1);
        assert_eq!(block.head.height, block.context.number);
        assert_eq!(block.context.gas_limit, capacity.block_gas);
        assert!(
            block
                .transactions
                .iter()
                .all(|input| input.expected_receipt.success)
        );
        parent = &block.head;
    }
    let result = prove_checkpoint_transition(&bundle)
        .expect("portable execution must match every retained head, receipt and final state");
    let journal = &result.journal;
    assert_eq!(journal.schema, 4);
    assert_eq!(journal.proof_scope, LARGE_CHECKPOINT_SCOPE);
    assert_eq!(
        journal.execution_profile,
        checkpoint_profile_v4_with_capacity(capacity).unwrap()
    );
    assert_eq!(journal.executed_transactions, 100_000);
    assert_eq!(journal.blocks, 6);
    assert_eq!(journal.witness_blocks, 6);
    assert_eq!(journal.parent, bundle.checkpoint.head);
    assert_eq!(journal.head, bundle.head);
    assert_eq!(result.checkpoint.head, bundle.head);
    assert_eq!(journal.after_state_digest, bundle.expected_state_digest);
    assert_eq!(
        journal.before_total_balance, journal.after_total_balance,
        "native transfers and fee beneficiary accounting must conserve exact assets"
    );
    assert!(journal.after_account_count >= 200_000);
    assert!(result.checkpoint.accounts.len() >= 200_000);
    assert_eq!(result.checkpoint.capacity, capacity);
    assert_eq!((journal.inbox_count, journal.outbox_count), (0, 0));
    let checkpoint_bytes = result.checkpoint.encoded_len().unwrap();
    assert!(checkpoint_bytes > 16 * 1024 * 1024 && checkpoint_bytes <= limits.checkpoint_bytes);

    create_private_directory(&output);
    let checkpoint_path = output.join("checkpoint.bin");
    let mut checkpoint_file = create_private_file(&checkpoint_path);
    let mut checkpoint_hash = Sha256::new();
    let mut written = 0usize;
    result
        .checkpoint
        .write_encoded(&mut |part| {
            checkpoint_file
                .write_all(part)
                .map_err(|_| "checkpoint evidence write failed")?;
            checkpoint_hash.update(part);
            written = written
                .checked_add(part.len())
                .ok_or("checkpoint evidence byte overflow")?;
            Ok(())
        })
        .expect("stream complete final checkpoint evidence");
    checkpoint_file
        .sync_all()
        .expect("sync final checkpoint evidence");
    assert_eq!(written, checkpoint_bytes);
    assert_eq!(
        checkpoint_file.metadata().unwrap().len(),
        checkpoint_bytes as u64
    );
    let checkpoint_hash = B256::from_slice(&checkpoint_hash.finalize());
    let journal_bytes = journal.encode().expect("canonical schema-four journal");
    let journal_path = output.join("journal.bin");
    let journal_hash = persist_bytes(&journal_path, &journal_bytes);
    let report_path = output.join("report.json");
    let mut report_file = create_private_file(&report_path);
    let report = serde_json::json!({
        "status": "passed", "scope": "native-portable-core/retained-gpu-runtime-schema-four",
        "input_sha256": input_hash, "input_bytes": bytes,
        "witness_schema": 4, "execution_storage_schema": 2,
        "capacity": capacity,
        "proof_limits": { "checkpoint_bytes": limits.checkpoint_bytes,
            "transcript_bytes": limits.transcript_bytes, "input_bytes": limits.input_bytes,
            "frame_bytes": limits.frame_bytes },
        "transactions": journal.executed_transactions, "blocks": journal.blocks,
        "parent_height": journal.parent.height, "head_height": journal.head.height,
        "all_retained_heads_receipts_and_final_state_match": true,
        "exact_total_balance_conserved": true,
        "before_account_count": journal.before_account_count,
        "after_account_count": journal.after_account_count,
        "journal_sha256": journal_hash, "journal_bytes": journal_bytes.len(),
        "checkpoint_sha256": checkpoint_hash, "checkpoint_bytes": checkpoint_bytes,
        "journal": journal,
        "guest_receipt_generated": false, "settlement_verified": false,
        "mainnet_qualified": false, "cuda_executed_by_this_check": false,
        "filesystem": { "platform": std::env::consts::OS,
            "requested_unix_directory_mode": "0700", "requested_unix_file_mode": "0600",
            "directory_observed_mode": observed_mode(&output),
            "checkpoint_observed_mode": observed_mode(&checkpoint_path),
            "journal_observed_mode": observed_mode(&journal_path),
            "report_observed_mode": observed_mode(&report_path),
            "private_access_guaranteed_by_this_check": false }
    });
    report_file
        .write_all(&serde_json::to_vec_pretty(&report).unwrap())
        .unwrap();
    report_file.sync_all().expect("sync safe report");
    println!(
        "{}",
        serde_json::json!({ "status": "passed", "scope": "native-portable-core",
        "transactions": journal.executed_transactions, "blocks": journal.blocks,
        "parent_height": journal.parent.height, "head_height": journal.head.height,
        "input_bytes": bytes, "input_sha256": input_hash,
        "checkpoint_bytes": checkpoint_bytes, "checkpoint_sha256": checkpoint_hash,
        "journal_sha256": journal_hash, "semantic_agreement": true,
        "guest_receipt_generated": false, "settlement_verified": false })
    );
}
