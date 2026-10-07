//! Configured consensus-source observations, never caller-supplied verified flags.
use super::types::*;
use alloy_primitives::B256;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ChainHead {
    pub network: u8,
    pub genesis: B256,
    pub hash: B256,
    pub parent: B256,
    pub height: u64,
    pub timestamp_ms: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ExecutionOutcome {
    Succeeded,
    Failed,
}

#[derive(Clone, Copy)]
pub struct ObservedReceipt {
    pub tx_id: B256,
    pub block: B256,
    pub height: u64,
    pub factory: B256,
    pub script_hash: B256,
    pub effect_digest: B256,
    pub execution: ExecutionOutcome,
}

/// Explicit trust boundary for an independently configured consensus-validating
/// node. All methods must use the exact supplied head snapshot and refuse a
/// changed/unavailable view. Receipts include actual script/effect extraction;
/// this trait is not a cryptographic light-client proof or a wallet receipt.
pub trait CanonicalSource {
    fn source_id(&self) -> B256;
    fn head(&mut self, scope: &Scope) -> Result<ChainHead, PublisherError>;
    fn canonical_hash(
        &mut self,
        scope: &Scope,
        head: &ChainHead,
        height: u64,
    ) -> Result<Option<B256>, PublisherError>;
    fn receipt(
        &mut self,
        scope: &Scope,
        head: &ChainHead,
        tx_id: B256,
    ) -> Result<Option<ObservedReceipt>, PublisherError>;
}

pub(super) fn checked_head(
    source: &mut impl CanonicalSource,
    scope: &Scope,
) -> Result<ChainHead, PublisherError> {
    if source.source_id() != scope.canonical_source {
        return Err(PublisherError::InvalidObservation);
    }
    let head = source.head(scope)?;
    if head.network != scope.l1_network
        || head.genesis != scope.l1_genesis
        || head.hash == B256::ZERO
        || source.canonical_hash(scope, &head, head.height)? != Some(head.hash)
        || head.height > 0
            && source.canonical_hash(scope, &head, head.height - 1)? != Some(head.parent)
    {
        return Err(PublisherError::InvalidObservation);
    }
    Ok(head)
}

pub(super) fn checked_receipt(
    source: &mut impl CanonicalSource,
    scope: &Scope,
    head: &ChainHead,
    row: &Publication,
) -> Result<Option<ObservedReceipt>, PublisherError> {
    let Some(receipt) = source.receipt(scope, head, row.intent.tx_id)? else {
        return Ok(None);
    };
    if receipt.tx_id != row.intent.tx_id
        || receipt.factory != scope.factory
        || receipt.script_hash != row.intent.script_hash
        || receipt.effect_digest != row.intent.expected_effect
        || receipt.execution != ExecutionOutcome::Succeeded
        || receipt.block == B256::ZERO
        || receipt.height > head.height
        || source.canonical_hash(scope, head, receipt.height)? != Some(receipt.block)
    {
        return Err(PublisherError::InvalidObservation);
    }
    Ok(Some(receipt))
}
