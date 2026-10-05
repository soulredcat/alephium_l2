//! Canonical full-history statement and reconstruction data commitments.
use crate::{
    BatchTransitionBundle, EXECUTION_ENGINE, RPC_PROFILE, SettlementDomain, encoding::Encoder,
    execution::private_envelope, protocol::*, records,
};
use alloy_primitives::{B256, U256};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const BATCH_SCOPE: &str = "cancun-full-history-batch/v2";

/// Roots commit full guest-reexecuted state and its canonical head. The witness
/// is bounded complete history, not a sparse witness or a mainnet scalability claim.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchTransitionJournal {
    pub schema: u32,
    pub proof_scope: String,
    pub rpc_profile: String,
    pub execution_engine: String,
    pub domain: SettlementDomain,
    pub chain_id: u64,
    pub genesis_id: B256,
    pub execution_profile: B256,
    pub batch_start: u64,
    pub parent: Head,
    pub head: Head,
    pub blocks: u64,
    pub executed_transactions: u64,
    pub witness_blocks: u64,
    pub old_state_root: B256,
    pub new_state_root: B256,
    pub before_state_digest: B256,
    pub after_state_digest: B256,
    pub before_account_count: u32,
    pub after_account_count: u32,
    pub before_total_balance: U256,
    pub after_total_balance: U256,
    pub transactions_commitment: B256,
    pub context_commitment: B256,
    pub receipts_commitment: B256,
    pub inbox_commitment: B256,
    pub outbox_commitment: B256,
    pub inbox_count: u64,
    pub outbox_count: u64,
    pub da_commitment: B256,
}

impl BatchTransitionJournal {
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let mut out = Encoder::default();
        out.bytes(match self.schema {
            2 => b"alephium-l2-transition-proof/journal/v2",
            3 => b"alephium-l2-transition-proof/journal/v3",
            _ => return Err("unsupported batch journal version".into()),
        })?;
        out.u32(self.schema);
        out.bytes(self.proof_scope.as_bytes())?;
        out.bytes(self.rpc_profile.as_bytes())?;
        out.bytes(self.execution_engine.as_bytes())?;
        encode_domain(&mut out, &self.domain);
        out.u64(self.chain_id);
        out.hash(self.genesis_id);
        out.hash(self.execution_profile);
        out.u64(self.batch_start);
        out.0.extend(records::encode_head(&self.parent));
        out.0.extend(records::encode_head(&self.head));
        out.u64(self.blocks);
        out.u64(self.executed_transactions);
        out.u64(self.witness_blocks);
        out.hash(self.old_state_root);
        out.hash(self.new_state_root);
        out.hash(self.before_state_digest);
        out.hash(self.after_state_digest);
        out.u32(self.before_account_count);
        out.u32(self.after_account_count);
        out.amount(self.before_total_balance);
        out.amount(self.after_total_balance);
        out.hash(self.transactions_commitment);
        out.hash(self.context_commitment);
        out.hash(self.receipts_commitment);
        out.hash(self.inbox_commitment);
        out.u64(self.inbox_count);
        out.hash(self.outbox_commitment);
        out.u64(self.outbox_count);
        out.hash(self.da_commitment);
        out.finish()
    }
}

pub(crate) fn encode_domain(out: &mut Encoder, domain: &SettlementDomain) {
    out.byte(domain.l1_network);
    out.hash(domain.l1_genesis_id);
    out.hash(domain.settlement_contract_id);
}

pub(crate) fn profile_commitment() -> Result<B256, String> {
    let mut out = Encoder::default();
    out.bytes(b"alephium-l2/execution-profile/v2")?;
    for text in [
        BATCH_SCOPE,
        RPC_PROFILE,
        EXECUTION_ENGINE,
        "Cancun",
        "legacy,type2",
    ] {
        out.bytes(text.as_bytes())?;
    }
    out.u32(SCHEMA);
    out.u64(BLOCK_GAS);
    out.u64(BLOCK_BYTES as u64);
    out.u64(BLOCK_INTERVAL_MS);
    out.u64(MAX_PENDING as u64);
    out.u64(MAX_TRANSACTION_BYTES as u64);
    // No deposit/withdrawal input is accepted by schema 2. P6 must implement and
    // repin a new program/profile before accepting nonempty authenticated queues.
    out.bytes(b"inbox/outbox-empty-only/v1;zero-basefee;zero-beneficiary")?;
    out.bytes(b"Cancun-precompiles-01..0a;guest-k256-arkworks;producer-secp256k1-arkworks")?;
    Ok(hash(&out.finish()?))
}

pub(crate) fn state_root(head: &Head, logical: B256, profile: B256) -> B256 {
    let mut digest = Sha256::new();
    digest.update(b"alephium-l2/authenticated-execution-state/v2");
    digest.update(profile);
    digest.update(records::encode_head(head));
    digest.update(logical);
    B256::from_slice(&digest.finalize())
}

pub(crate) fn empty_messages(domain: &SettlementDomain, genesis: B256, kind: &[u8]) -> B256 {
    let mut out = Encoder::default();
    out.0
        .extend_from_slice(b"alephium-l2/authenticated-messages/v1");
    out.0.extend_from_slice(kind);
    encode_domain(&mut out, domain);
    out.hash(genesis);
    out.u64(0);
    hash(&out.0)
}

pub(crate) fn hash(bytes: &[u8]) -> B256 {
    B256::from_slice(&Sha256::digest(bytes))
}

/// Private canonical DA payload: complete genesis plus ordered contexts and
/// signed inputs. Never log this buffer. Output oracles/pass flags are excluded.
pub fn batch_data(bundle: &BatchTransitionBundle) -> Result<Vec<u8>, String> {
    bundle.domain.validate()?;
    if bundle.blocks.is_empty() || bundle.blocks.len() as u64 > crate::MAX_TRANSITION_BLOCKS {
        return Err("batch reconstruction witness exceeds block bound".into());
    }
    let mut out = Encoder::default();
    out.bytes(b"alephium-l2/reconstruction/full-history/v2")?;
    encode_domain(&mut out, &bundle.domain);
    out.u64(bundle.chain_id);
    out.hash(bundle.genesis_id);
    out.hash(profile_commitment()?);
    out.bytes(&records::genesis_bytes(&bundle.genesis)?)?;
    out.u64(bundle.batch_start);
    out.u64(bundle.blocks.len() as u64);
    for block in &bundle.blocks {
        out.u64(block.context.number);
        out.u64(block.context.timestamp);
        out.u64(block.context.gas_limit);
        if block.transactions.is_empty() || block.transactions.len() > MAX_PENDING {
            return Err("batch reconstruction transaction count exceeds bound".into());
        }
        out.u32(block.transactions.len() as u32);
        for input in &block.transactions {
            out.bytes(&private_envelope(&input.raw_envelope_hex)?)?;
            if out.0.len() > crate::encoding::MAX_RECORD {
                return Err("batch reconstruction data exceeds byte bound".into());
            }
        }
    }
    out.finish()
}
