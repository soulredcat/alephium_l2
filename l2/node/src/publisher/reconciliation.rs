//! Canonical reconciliation never signs, broadcasts, or trusts an acknowledgement.
use super::{
    observation::{self, CanonicalSource, ChainHead},
    service::{Publisher, row, row_mut},
    types::*,
};
use alloy_primitives::B256;
use std::collections::BTreeSet;

impl<R: Repository> Publisher<R> {
    /// Refresh the declared head and atomically invalidate orphaned publications
    /// plus every local descendant. Source failures leave the durable state alone.
    pub fn refresh_head(
        &mut self,
        expected: Token,
        source: &mut impl CanonicalSource,
    ) -> Result<Token, PublisherError> {
        let mut next = self.state(expected, true)?;
        let head = observation::checked_head(source, &self.scope)?;
        let orphaned = invalidated(&next, &head, source)?;
        if !orphaned.is_empty() {
            for record in &mut next.records {
                if orphaned.contains(&record.intent.id) && record.phase != Phase::Abandoned {
                    record.phase = Phase::Orphaned;
                }
            }
            next.canonical_head = head.hash;
            return self.persist(expected, next, AuditKind::Reorg, None, head.timestamp_ms);
        }
        if next.canonical_head == head.hash {
            return Ok(expected);
        }
        next.canonical_head = head.hash;
        self.persist(
            expected,
            next,
            AuditKind::CanonicalHead,
            None,
            head.timestamp_ms,
        )
    }

    /// One explicit observation for an already submitted attempt. An observed
    /// reorg is persisted first; a later call can reconcile its surviving branch.
    pub fn reconcile(
        &mut self,
        expected: Token,
        id: B256,
        source: &mut impl CanonicalSource,
    ) -> Result<Token, PublisherError> {
        self.reconcile_observed(expected, id, source)
            .map(|(token, _)| token)
    }

    /// Distinguish a newly checked receipt from a retained historical phase.
    /// `false` means no positive current receipt was accepted by this call;
    /// callers must not treat an unchanged Confirmed record as fresh acceptance.
    pub fn reconcile_observed(
        &mut self,
        expected: Token,
        id: B256,
        source: &mut impl CanonicalSource,
    ) -> Result<(Token, bool), PublisherError> {
        let refreshed = self.refresh_head(expected, source)?;
        if refreshed != expected {
            return Ok((refreshed, false));
        }
        let mut next = self.state(expected, true)?;
        let head = observation::checked_head(source, &self.scope)?;
        if head.hash != expected.canonical_head {
            return Err(PublisherError::Conflict);
        }
        let record = row(&next, id)?;
        if !matches!(
            record.phase,
            Phase::SubmitAttempted
                | Phase::SubmitAmbiguous
                | Phase::Submitted
                | Phase::Included
                | Phase::Confirmed
                | Phase::Orphaned
                | Phase::Abandoned
        ) || record.submit_attempts != 1
            || record.sign_attempts != 1
            || record.signature.is_none()
            || !record.reservations_retained
        {
            return Err(PublisherError::InvalidTransition);
        }
        let Some(receipt) = observation::checked_receipt(source, &self.scope, &head, record)?
        else {
            return Ok((expected, false));
        };
        if let Some(parent) = record.intent.parent {
            let parent = row(&next, parent)?;
            let inclusion = parent
                .inclusion
                .as_ref()
                .ok_or(PublisherError::InvalidObservation)?;
            if parent.phase != Phase::Confirmed
                || inclusion.height > receipt.height
                || source.canonical_hash(&self.scope, &head, inclusion.height)?
                    != Some(inclusion.block)
            {
                return Err(PublisherError::InvalidObservation);
            }
        }
        let confirmations = head
            .height
            .checked_sub(receipt.height)
            .and_then(|distance| distance.checked_add(1))
            .ok_or(PublisherError::InvalidObservation)?;
        let inclusion = Inclusion {
            block: receipt.block,
            height: receipt.height,
            canonical_head: head.hash,
        };
        let phase = if confirmations >= record.intent.confirmations {
            Phase::Confirmed
        } else {
            Phase::Included
        };
        if record.phase == phase && record.inclusion.as_ref() == Some(&inclusion) {
            return Ok((expected, true));
        }
        let record = row_mut(&mut next, id)?;
        record.phase = phase;
        record.inclusion = Some(inclusion);
        self.persist(
            expected,
            next,
            AuditKind::CanonicalObservation,
            Some(id),
            head.timestamp_ms,
        )
        .map(|token| (token, true))
    }

    /// Explicit reviewed abandonment after its approved review time. Absence is
    /// not proof that a signed transaction cannot land: such inputs stay reserved.
    pub fn abandon(
        &mut self,
        expected: Token,
        id: B256,
        source: &mut impl CanonicalSource,
    ) -> Result<Token, PublisherError> {
        let mut next = self.state(expected, true)?;
        let head = observation::checked_head(source, &self.scope)?;
        if head.hash != expected.canonical_head {
            return Err(PublisherError::Conflict);
        }
        let record = row(&next, id)?;
        if matches!(record.phase, Phase::Confirmed | Phase::Abandoned)
            || head.timestamp_ms < record.intent.review_after_ms
            || source
                .receipt(&self.scope, &head, record.intent.tx_id)?
                .is_some()
        {
            return Err(PublisherError::InvalidTransition);
        }
        // A signed ambiguous ancestor cannot be repurposed, and descendants are
        // not released by dropping the parent's local work queue entry.
        let record = row_mut(&mut next, id)?;
        record.phase = Phase::Abandoned;
        record.reservations_retained = record.sign_attempts != 0;
        self.persist(
            expected,
            next,
            AuditKind::Abandon,
            Some(id),
            head.timestamp_ms,
        )
    }
}

fn invalidated(
    snapshot: &PublisherSnapshot,
    head: &ChainHead,
    source: &mut impl CanonicalSource,
) -> Result<BTreeSet<B256>, PublisherError> {
    let mut invalid = BTreeSet::new();
    for record in &snapshot.records {
        if matches!(record.phase, Phase::Included | Phase::Confirmed) {
            let inclusion = record
                .inclusion
                .as_ref()
                .ok_or(PublisherError::CorruptState)?;
            if inclusion.height > head.height
                || source.canonical_hash(&snapshot.scope, head, inclusion.height)?
                    != Some(inclusion.block)
            {
                invalid.insert(record.intent.id);
            }
        }
    }
    // Append-order parents make one pass sufficient for transitive descendants.
    for record in &snapshot.records {
        if record
            .intent
            .parent
            .is_some_and(|parent| invalid.contains(&parent))
        {
            invalid.insert(record.intent.id);
        }
    }
    Ok(invalid)
}
