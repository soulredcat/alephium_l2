//! Bounded inline preparation against independently selected statement and parent.
use super::types::{
    INLINE_DATA_VERSION, InlineDataMetadata, MAX_INLINE_DATA_BYTES, OriginalParentCheckpoint,
    ParentCheckpointMetadata, PreparedInlineData,
};
use crate::{HostResult, inputs};
use alephium_l2_transition_core::{
    EXECUTION_ENGINE, LARGE_CHECKPOINT_SCOPE, ProofInput, RPC_PROFILE,
    da::{ExpectedDa, read_checkpoint_da},
    decode_input,
    settlement::{SettlementAnchor, SettlementPolicy, decode_journal_v4},
};
use sha2::{Digest, Sha256};
use std::{io::Cursor, path::Path};

/// This authenticates a native candidate's bytes and policy only. The caller's
/// independently pinned policy/parent is not a receipt or canonical L1 observation.
pub fn prepare_inline_data(
    bytes: &[u8],
    expected: &ExpectedDa<'_>,
    expected_journal_sha256: [u8; 32],
    expected_parent_checkpoint_sha256: Option<[u8; 32]>,
    policy: &SettlementPolicy,
    parent: &SettlementAnchor,
    l1_timestamp_ms: u64,
) -> HostResult<PreparedInlineData> {
    if bytes.is_empty() || bytes.len() > MAX_INLINE_DATA_BYTES {
        return Err("Inline DA data must contain 1 to 3000 canonical bytes.");
    }
    let journal = expected.journal;
    // Reject unbounded alternate string fields before canonical allocation.
    if journal.schema != 4
        || journal.proof_scope != LARGE_CHECKPOINT_SCOPE
        || journal.rpc_profile != RPC_PROFILE
        || journal.execution_engine != EXECUTION_ENGINE
    {
        return Err("Inline DA requires the exact current journal profile.");
    }
    let journal_bytes = journal
        .encode()
        .map_err(|_| "Cannot encode the independently pinned inline DA journal.")?;
    let journal_sha256: [u8; 32] = Sha256::digest(&journal_bytes).into();
    if journal_sha256 != expected_journal_sha256 {
        return Err("Inline DA journal differs from its independent SHA-256 pin.");
    }
    let journal = decode_journal_v4(&journal_bytes)
        .map_err(|_| "Inline DA journal is not the supported canonical statement.")?;
    policy
        .validate(parent, &journal, l1_timestamp_ms)
        .map_err(|_| "Inline DA statement does not match the pinned policy/parent/time.")?;
    let checked = ExpectedDa {
        journal: &journal,
        capacity: expected.capacity,
    };
    let decoded = read_checkpoint_da(&mut Cursor::new(bytes), bytes.len(), &checked)
        .map_err(|_| "Inline DA bytes differ from canonical statement data; payload suppressed.")?;
    let data_sha256: [u8; 32] = Sha256::digest(bytes).into();
    if data_sha256.as_slice() != journal.da_commitment.as_slice()
        || decoded.encoding().bytes != bytes.len()
        || decoded.encoding().commitment != journal.da_commitment
    {
        return Err("Inline DA full-data hash or exact length differs from the journal.");
    }
    let parent_checkpoint = decoded
        .parent_checkpoint()
        .encode()
        .map_err(|_| "Cannot encode the original inline DA parent checkpoint.")?;
    let parent_checkpoint_sha256: [u8; 32] = Sha256::digest(&parent_checkpoint).into();
    if expected_parent_checkpoint_sha256.is_some_and(|pin| pin != parent_checkpoint_sha256) {
        return Err("Original parent checkpoint differs from its independent SHA-256 pin.");
    }
    Ok(PreparedInlineData {
        metadata: InlineDataMetadata {
            version: INLINE_DATA_VERSION,
            bytes: bytes.len() as u32,
            data_sha256,
            journal_sha256,
            parent_checkpoint_sha256,
            domain: journal.domain,
            chain_id: journal.chain_id,
            genesis_id: journal.genesis_id.into(),
            execution_profile: journal.execution_profile.into(),
            capacity: expected.capacity,
            parent: journal.parent,
            head: journal.head,
            old_state_root: journal.old_state_root.into(),
            new_state_root: journal.new_state_root.into(),
            blocks: journal.blocks,
            executed_transactions: journal.executed_transactions,
        },
        data: bytes.to_vec(),
        parent_checkpoint,
    })
}

/// Reuse the original checked regular-file/identity/length helpers; no daemon,
/// RPC, signer, database or prover starts while reading a bounded local input.
pub fn prepare_inline_data_file(
    path: &Path,
    expected: &ExpectedDa<'_>,
    expected_journal_sha256: [u8; 32],
    expected_parent_checkpoint_sha256: Option<[u8; 32]>,
    policy: &SettlementPolicy,
    parent: &SettlementAnchor,
    l1_timestamp_ms: u64,
) -> HostResult<PreparedInlineData> {
    let bytes = inputs::read_bounded(path, MAX_INLINE_DATA_BYTES)?;
    prepare_inline_data(
        &bytes,
        expected,
        expected_journal_sha256,
        expected_parent_checkpoint_sha256,
        policy,
        parent,
        l1_timestamp_ms,
    )
}

/// Extract the ORIGINAL parent from a separately pinned retained input. The
/// decoder and checkpoint encoder are pure; this calls no EVM/replay/prover.
pub fn extract_original_parent_checkpoint(
    input: &[u8],
    expected_input_sha256: [u8; 32],
) -> HostResult<OriginalParentCheckpoint> {
    use alephium_l2_transition_core::protocol::proof_transport::ABSOLUTE_MAX_V4_INPUT;
    if input.is_empty() || input.len() > ABSOLUTE_MAX_V4_INPUT {
        return Err("Original-parent extraction input exceeds the current wire bound.");
    }
    let actual: [u8; 32] = Sha256::digest(input).into();
    if actual != expected_input_sha256 {
        return Err("Original-parent extraction input differs from its independent pin.");
    }
    let ProofInput::Checkpoint(bundle) = decode_input(input)
        .map_err(|_| "Original-parent extraction input is not canonical; payload suppressed.")?
    else {
        return Err("Original-parent extraction requires a checkpoint transition.");
    };
    if bundle.schema != 4 {
        return Err("Original-parent extraction requires the current schema-four input.");
    }
    let bytes = bundle
        .checkpoint
        .encode()
        .map_err(|_| "Cannot encode the original retained parent checkpoint.")?;
    let sha256: [u8; 32] = Sha256::digest(&bytes).into();
    Ok(OriginalParentCheckpoint {
        metadata: ParentCheckpointMetadata {
            bytes: u32::try_from(bytes.len()).map_err(|_| "Original checkpoint exceeds u32.")?,
            sha256,
            schema: bundle.checkpoint.schema,
            chain_id: bundle.checkpoint.chain_id,
            genesis_id: bundle.checkpoint.genesis_id.into(),
            capacity: bundle.checkpoint.capacity,
            head: bundle.checkpoint.head,
        },
        bytes,
    })
}

#[cfg(test)]
pub(crate) mod test_data {
    use super::*;
    use alephium_l2_transition_core::{
        BatchTransitionJournal, CheckpointTransitionBundle, EXECUTION_ENGINE,
        LARGE_CHECKPOINT_SCOPE, RPC_PROFILE, RawEnvelope, SettlementDomain, TransitionBlock,
        TransitionContext, TransitionInput, checkpoint_profile_v4_with_capacity,
        da::{ExpectedDa, write_checkpoint_da},
        protocol::{
            Capacity, Head, Receipt,
            checkpoint::{CheckpointBlockHash, ExecutionCheckpoint},
            proof_transport::ProofLimits,
        },
        settlement::{SettlementAnchor, SettlementPolicy},
    };
    use sha2::{Digest, Sha256};

    pub(crate) fn sha(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    // Public synthetic codec input only: deliberately not a signed transaction
    // or valid receipt. Native preparation must never claim cryptographic validity.
    pub(crate) fn fixture() -> (
        CheckpointTransitionBundle,
        BatchTransitionJournal,
        SettlementPolicy,
        SettlementAnchor,
    ) {
        let capacity = Capacity {
            block_gas: 3_000_000_000,
            block_bytes: 32 * 1024 * 1024,
            max_pending: 1_000,
        };
        let genesis = [2; 32].into();
        let mut genesis_hash = Sha256::new();
        genesis_hash.update(b"alephium-l2-development/genesis-commit/v1");
        genesis_hash.update([2; 32]);
        let parent = Head {
            height: 0,
            timestamp: 0,
            commit_id: <[u8; 32]>::from(genesis_hash.finalize()).into(),
            genesis_id: genesis,
        };
        let head = Head {
            height: 1,
            timestamp: 1,
            commit_id: [3; 32].into(),
            genesis_id: genesis,
        };
        let checkpoint = ExecutionCheckpoint {
            schema: capacity.checkpoint_schema(),
            chain_id: 424_243,
            capacity,
            genesis_id: genesis,
            head: parent.clone(),
            accounts: vec![],
            codes: vec![],
            block_hashes: vec![CheckpointBlockHash {
                height: 0,
                hash: parent.commit_id,
            }],
        };
        let mut factory_id = [12; 32];
        factory_id[31] = 0;
        let domain = SettlementDomain {
            l1_network: 1,
            l1_genesis_id: [11; 32].into(),
            settlement_contract_id: factory_id.into(),
        };
        let profile = checkpoint_profile_v4_with_capacity(capacity).unwrap();
        let old_root = checkpoint
            .root_for_transport(
                profile,
                domain.l1_network,
                domain.l1_genesis_id,
                domain.settlement_contract_id,
                ProofLimits::for_capacity(capacity).unwrap(),
            )
            .unwrap();
        let receipt = Receipt {
            hash: [4; 32].into(),
            from: [5; 20].into(),
            to: Some([6; 20].into()),
            contract: None,
            success: true,
            gas_used: 21_000,
            gas_price: 1,
            logs: vec![],
            block_height: 1,
            block_hash: head.commit_id,
            transaction_index: 0,
            cumulative_gas: 21_000,
            first_log_index: 0,
        };
        let bundle = CheckpointTransitionBundle {
            schema: 4,
            rpc_profile: RPC_PROFILE.into(),
            execution_engine: EXECUTION_ENGINE.into(),
            domain: domain.clone(),
            checkpoint,
            blocks: vec![TransitionBlock {
                parent: parent.clone(),
                head: head.clone(),
                context: TransitionContext {
                    number: 1,
                    timestamp: 1,
                    gas_limit: capacity.block_gas,
                },
                transactions: vec![TransitionInput {
                    transaction_hash: receipt.hash,
                    raw_envelope_hex: RawEnvelope::from_bytes(vec![1]).unwrap(),
                    expected_receipt: receipt,
                }],
            }],
            head: head.clone(),
            expected_state_digest: [7; 32].into(),
        };
        let messages = |kind: &[u8]| {
            let mut hash = Sha256::new();
            hash.update(b"alephium-l2/authenticated-messages/v1");
            hash.update(kind);
            hash.update([domain.l1_network]);
            hash.update(domain.l1_genesis_id);
            hash.update(domain.settlement_contract_id);
            hash.update(genesis);
            hash.update(0_u64.to_be_bytes());
            <[u8; 32]>::from(hash.finalize()).into()
        };
        let journal = BatchTransitionJournal {
            schema: 4,
            proof_scope: LARGE_CHECKPOINT_SCOPE.into(),
            rpc_profile: RPC_PROFILE.into(),
            execution_engine: EXECUTION_ENGINE.into(),
            domain: domain.clone(),
            chain_id: bundle.checkpoint.chain_id,
            genesis_id: genesis,
            execution_profile: profile,
            batch_start: 1,
            parent: parent.clone(),
            head,
            blocks: 1,
            executed_transactions: 1,
            witness_blocks: 1,
            old_state_root: old_root,
            new_state_root: [8; 32].into(),
            before_state_digest: [9; 32].into(),
            after_state_digest: [7; 32].into(),
            before_account_count: 0,
            after_account_count: 0,
            before_total_balance: Default::default(),
            after_total_balance: Default::default(),
            transactions_commitment: [10; 32].into(),
            context_commitment: [13; 32].into(),
            receipts_commitment: [14; 32].into(),
            inbox_commitment: messages(b"inbox"),
            outbox_commitment: messages(b"outbox"),
            inbox_count: 0,
            outbox_count: 0,
            da_commitment: [15; 32].into(),
        };
        let policy = SettlementPolicy {
            domain,
            chain_id: journal.chain_id,
            genesis_id: genesis,
            execution_profile: profile,
            max_future_seconds: 0,
        };
        let anchor = SettlementAnchor {
            head: parent,
            state_root: old_root,
        };
        (bundle, journal, policy, anchor)
    }

    pub(crate) fn encode_da(
        bundle: &CheckpointTransitionBundle,
        journal: &mut BatchTransitionJournal,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        let result = write_checkpoint_da(bundle, &mut |part| {
            bytes.extend_from_slice(part);
            Ok(())
        })
        .unwrap();
        journal.da_commitment = result.commitment;
        bytes
    }

    pub(crate) fn prepared(
        bytes: &[u8],
        journal: &BatchTransitionJournal,
        capacity: Capacity,
        policy: &SettlementPolicy,
        anchor: &SettlementAnchor,
    ) -> PreparedInlineData {
        prepare_inline_data(
            bytes,
            &ExpectedDa { journal, capacity },
            sha(&journal.encode().unwrap()),
            None,
            policy,
            anchor,
            1_000,
        )
        .unwrap_or_else(|_| panic!("synthetic native inline preparation failed"))
    }
}
