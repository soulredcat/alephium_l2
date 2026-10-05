//! Deterministic proof core reusing the pinned runtime engine and encodings.
//! Schema 1 preserves the native-transfer fixture. Schema 2 reexecutes bounded
//! complete history including supported contracts and commits a selected batch.
//! Program presence or local replay alone is not approved proof/settlement.

#[path = "../../../node/src/operator/transition_types.rs"]
mod input;
use input as transition_types;
// An inline module sets the directory, so `protocol.rs` loads as an ordinary
// file and its own submodules resolve under `node/src/protocol/`.
#[path = "../../../node/src"]
mod node_source {
    pub mod protocol;
}
pub use node_source::protocol;
#[path = "../../../node/src/operator/transition_wire.rs"]
mod transition_wire;

// Reuse the production canonical formats and lifecycle normalization without
// linking its database, networking, asynchronous worker or node crate.
#[allow(dead_code)]
#[path = "../../../node/src/storage/block.rs"]
mod block;
#[path = "../../../node/src/execution/changes.rs"]
mod changes;
use protocol::encoding;
#[allow(dead_code, unused_imports)]
#[path = "../../../node/src/storage/records.rs"]
mod records;
#[allow(dead_code)]
#[path = "../../../node/src/execution/transaction.rs"]
mod transaction;

mod batch;
mod batch_execution;
mod batch_journal;
mod batch_replay;
mod batch_state;
mod canonical;
mod checkpoint_batch;
mod execution;
mod journal;
mod proof_input;
mod state;

pub use batch::prove_batch_transition;
pub use batch_journal::{BatchTransitionJournal, batch_data};
pub use checkpoint_batch::{
    CheckpointTransitionOutput, checkpoint_batch_data, checkpoint_profile,
    checkpoint_profile_with_capacity, prove_checkpoint_transition,
};
pub use input::{
    BatchTransitionBundle, BatchTransitionReport, MAX_TRANSITION_BLOCKS, SettlementDomain,
    TransitionBlock, TransitionInput,
};
pub use input::{CheckpointTransitionBundle, CheckpointTransitionReport};
pub use input::{TransitionBundle, TransitionContext, TransitionReport};
pub use journal::{TransferAccounting, TransitionJournal};
pub use proof_input::{ProofInput, ProvenTransition, decode_input, prove_input};
pub use transition_wire::{
    MAX_CHECKPOINT_WIRE_BYTES, MAX_CONTINUATION_CHECKPOINT_BYTES, decode_checkpoint_transition,
    encode_checkpoint_transition, is_checkpoint_wire,
};

use protocol::{BLOCK_GAS, BlockCommit, Capacity};

pub const RPC_PROFILE: &str = "development/c5-v1";
pub const EXECUTION_ENGINE: &str = "REVM 43.0.3/Cancun (same library as producer)";
pub const PROOF_SCOPE: &str = "genesis-first-native-eoa-transfer/v1";

/// Reconstruct full genesis, recover the actual signer and execute REVM before
/// comparing any supplied output oracle. Bundle verification flags are ignored.
pub fn prove_transition(bundle: &TransitionBundle) -> Result<TransitionJournal, String> {
    // Schema one has no capacity-bearing journal. Custom chains must use the
    // existing full-history or checkpoint batch statement, which binds it.
    if bundle.genesis.capacity != Capacity::default() {
        return Err("legacy single-transfer proof requires the default capacity".into());
    }
    if bundle.schema != 1
        || bundle.rpc_profile != RPC_PROFILE
        || bundle.execution_engine != EXECUTION_ENGINE
        || bundle.chain_id != bundle.genesis.chain_id
    {
        return Err("unsupported transition bundle identity or execution profile".into());
    }
    let parent = records::genesis_head(&records::genesis_bytes(&bundle.genesis)?);
    if bundle.parent != parent || bundle.genesis_id != parent.genesis_id {
        return Err("transition must start from its complete canonical genesis".into());
    }
    let context = protocol::BlockContext {
        number: bundle.context.number,
        timestamp: bundle.context.timestamp,
        gas_limit: bundle.context.gas_limit,
    };
    if context.number != 1 || context.gas_limit != BLOCK_GAS {
        return Err("transition must contain the first block under the pinned gas profile".into());
    }
    let raw = execution::private_envelope(&bundle.raw_envelope_hex)?;
    let before = state::NativeState::genesis(&bundle.genesis)?;
    let before_state_digest = before.digest()?;
    let before_total = before.total_balance()?;
    let execution = execution::execute(&before, &raw, bundle.chain_id, context)?;
    let mut after = before.clone();
    let stored = after.apply(&execution.changes)?;
    let commit = BlockCommit {
        parent: parent.clone(),
        context,
        transactions: vec![execution.receipt.hash],
        changes: execution.changes,
        receipts: vec![execution.receipt.clone()],
        rejected: Vec::new(),
    };
    block::validate(&commit)?;
    block::logical_bytes(&commit, std::iter::once(raw.as_slice()))?;
    let (head, _) = block::encode(&commit, &stored)?;
    let mut receipt = execution.receipt;
    receipt.block_hash = head.commit_id;
    let after_state_digest = after.digest()?;
    let accounting = state::check_accounting(
        &before,
        &after,
        &receipt,
        execution.value,
        execution.beneficiary,
    )?;
    let journal = TransitionJournal {
        schema: 1,
        proof_scope: PROOF_SCOPE.into(),
        rpc_profile: RPC_PROFILE.into(),
        execution_engine: EXECUTION_ENGINE.into(),
        chain_id: bundle.chain_id,
        genesis_id: parent.genesis_id,
        parent,
        head,
        context: context.into(),
        transaction_hash: receipt.hash,
        before_state_digest,
        after_state_digest,
        before_account_count: before.account_count(),
        after_account_count: after.account_count(),
        before_total_balance: before_total,
        after_total_balance: after.total_balance()?,
        receipt,
        accounting,
    };
    // These are host export oracles, never the source of the proven outputs.
    // No boolean supplied by the host can replace execution or identity checks.
    if journal.head != bundle.head
        || journal.transaction_hash != bundle.transaction_hash
        || journal.receipt != bundle.expected_receipt
        || journal.after_state_digest != bundle.expected_state_digest
    {
        return Err("executed transition differs from the retained output oracle".into());
    }
    Ok(journal)
}
