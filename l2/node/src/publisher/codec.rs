//! Durable shape/transition validation; only Services authorize external effects.
use super::types::*;
use alloy_primitives::B256;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

impl Scope {
    /// Local approval-domain identity; no signer/network authority is implied.
    pub fn identity(&self) -> Result<B256, PublisherError> {
        scope_id(self)
    }
}

pub(crate) fn scope_id(scope: &Scope) -> Result<B256, PublisherError> {
    if scope.l1_network > 2
        || scope.l2_chain_id == 0
        || scope.publisher_key.len() != 33
        || !matches!(scope.publisher_key[0], 2 | 3)
        || [
            scope.l1_genesis,
            scope.l2_genesis,
            scope.factory,
            scope.execution_profile,
            scope.canonical_source,
        ]
        .contains(&B256::ZERO)
    {
        return Err(PublisherError::InvalidInput);
    }
    let mut hash = Sha256::new();
    hash.update(b"ALPH/L2/publisher-scope/v1");
    hash.update([scope.l1_network]);
    hash.update(scope.l1_genesis);
    hash.update(scope.l2_chain_id.to_be_bytes());
    hash.update(scope.l2_genesis);
    hash.update(scope.factory);
    hash.update(scope.execution_profile);
    hash.update(&scope.publisher_key);
    hash.update(scope.canonical_source);
    Ok(B256::from_slice(&hash.finalize()))
}

pub(crate) fn validate_snapshot(snapshot: &PublisherSnapshot) -> Result<(), PublisherError> {
    scope_id(&snapshot.scope)?;
    if snapshot.schema != 1
        || snapshot.records.len() > MAX_PUBLICATIONS
        || snapshot.history.len() > MAX_HISTORY
        || snapshot.history.len() as u64 != snapshot.revision
    {
        return Err(PublisherError::CorruptState);
    }
    if snapshot.revision == 0 {
        return if snapshot.fencing_epoch == 0
            && snapshot.records.is_empty()
            && snapshot.canonical_head == B256::ZERO
        {
            Ok(())
        } else {
            Err(PublisherError::CorruptState)
        };
    }
    let mut epoch = 0_u64;
    let mut canonical_head = B256::ZERO;
    for (index, entry) in snapshot.history.iter().enumerate() {
        if entry.revision != index as u64 + 1 {
            return Err(PublisherError::CorruptState);
        }
        if entry.kind == AuditKind::Fence {
            epoch = epoch.checked_add(1).ok_or(PublisherError::CorruptState)?;
        }
        if entry.fencing_epoch != epoch || epoch == 0 {
            return Err(PublisherError::CorruptState);
        }
        if canonical_head != entry.canonical_head
            && !matches!(
                entry.kind,
                AuditKind::CanonicalHead | AuditKind::CanonicalObservation | AuditKind::Reorg
            )
        {
            return Err(PublisherError::CorruptState);
        }
        canonical_head = entry.canonical_head;
        if (entry.kind == AuditKind::CanonicalObservation) != entry.inclusion.is_some()
            || entry.inclusion.as_ref().is_some_and(|value| {
                value.canonical_head != canonical_head
                    || value.block == B256::ZERO
                    || canonical_head == B256::ZERO
            })
        {
            return Err(PublisherError::CorruptState);
        }
    }
    if epoch != snapshot.fencing_epoch || canonical_head != snapshot.canonical_head {
        return Err(PublisherError::CorruptState);
    }
    let mut ids = BTreeSet::new();
    let mut operations = BTreeSet::new();
    let mut transactions = BTreeSet::new();
    let mut reserved = BTreeSet::new();
    for row in &snapshot.records {
        let intent = &row.intent;
        if [
            intent.id,
            intent.operation_id,
            intent.tx_id,
            intent.artifact_hash,
            intent.script_hash,
            intent.expected_effect,
        ]
        .contains(&B256::ZERO)
            || intent.unsigned.is_empty()
            || intent.unsigned.len() > MAX_UNSIGNED_BYTES
            || intent.inputs.is_empty()
            || intent.inputs.len() > MAX_INPUTS
            || intent.authority_key != snapshot.scope.publisher_key
            || intent.network != snapshot.scope.l1_network
            || intent.l1_genesis != snapshot.scope.l1_genesis
            || intent.canonical_source != snapshot.scope.canonical_source
            || intent.review_after_ms < intent.created_at_ms
            || intent.confirmations == 0
            || row.sign_attempts > 1
            || row.submit_attempts > row.sign_attempts
            || !ids.insert(intent.id)
            || !operations.insert(intent.operation_id)
            || !transactions.insert(intent.tx_id)
        {
            return Err(PublisherError::CorruptState);
        }
        // Parents must already exist in append order, ruling out cycles.
        if intent
            .parent
            .is_some_and(|parent| parent == intent.id || !ids.contains(&parent))
        {
            return Err(PublisherError::CorruptState);
        }
        let mut inputs = BTreeSet::new();
        for input in &intent.inputs {
            if input.key == B256::ZERO
                || !inputs.insert(input.key)
                || row.reservations_retained && !reserved.insert(input.key)
            {
                return Err(PublisherError::CorruptState);
            }
        }
        if row
            .signature
            .as_ref()
            .is_some_and(|signature| signature.len() != 64 || row.sign_attempts != 1)
            || (row.submit_attempts == 1 && row.signature.is_none())
            || (row.phase == Phase::Intent && (row.sign_attempts != 0 || row.signature.is_some()))
            || (matches!(row.phase, Phase::SignAttempted | Phase::SignAmbiguous)
                && (row.sign_attempts != 1 || row.signature.is_some()))
            || (matches!(
                row.phase,
                Phase::Signed | Phase::SubmitAttempted | Phase::SubmitAmbiguous | Phase::Submitted
            ) && row.signature.is_none())
            || (matches!(
                row.phase,
                Phase::SubmitAttempted | Phase::SubmitAmbiguous | Phase::Submitted
            ) && row.submit_attempts != 1)
            || (matches!(row.phase, Phase::Included | Phase::Confirmed)
                && (row.inclusion.is_none() || row.signature.is_none() || row.submit_attempts != 1))
            || (row.inclusion.is_some()
                && (!matches!(
                    row.phase,
                    Phase::Included | Phase::Confirmed | Phase::Orphaned | Phase::Abandoned
                ) || row.signature.is_none()
                    || row.submit_attempts != 1))
            || (row.phase != Phase::Abandoned && !row.reservations_retained)
            || (row.sign_attempts != 0 && !row.reservations_retained)
        {
            return Err(PublisherError::CorruptState);
        }
        if row.inclusion.as_ref().is_some_and(|inclusion| {
            inclusion.block == B256::ZERO || inclusion.canonical_head == B256::ZERO
        }) {
            return Err(PublisherError::CorruptState);
        }
    }
    for event in &snapshot.history {
        if event.intent_id.is_some_and(|id| !ids.contains(&id)) {
            return Err(PublisherError::CorruptState);
        }
    }
    super::history::validate(snapshot)
}

pub(crate) fn validate_transition(
    previous: Option<&PublisherSnapshot>,
    next: &PublisherSnapshot,
) -> Result<(), PublisherError> {
    validate_snapshot(next)?;
    let Some(previous) = previous else {
        return if next.revision == 1
            && next.fencing_epoch == 1
            && next.records.is_empty()
            && next.canonical_head == B256::ZERO
            && next.history[0].kind == AuditKind::Fence
            && next.history[0].intent_id.is_none()
        {
            Ok(())
        } else {
            Err(PublisherError::InvalidTransition)
        };
    };
    validate_snapshot(previous)?;
    if previous.scope != next.scope
        || previous.revision.checked_add(1) != Some(next.revision)
        || next.history.len() != previous.history.len() + 1
        || next.history[..previous.history.len()] != previous.history
        || next.records.len() < previous.records.len()
        || next.records.len() > previous.records.len() + 1
    {
        return Err(PublisherError::InvalidTransition);
    }
    let event = next
        .history
        .last()
        .ok_or(PublisherError::InvalidTransition)?;
    let fencing = if event.kind == AuditKind::Fence {
        previous.fencing_epoch.checked_add(1)
    } else {
        Some(previous.fencing_epoch)
    };
    if fencing != Some(next.fencing_epoch) {
        return Err(PublisherError::InvalidTransition);
    }
    if event.kind == AuditKind::Fence
        && (previous.records != next.records
            || previous.canonical_head != next.canonical_head
            || event.intent_id.is_some())
    {
        return Err(PublisherError::InvalidTransition);
    }
    if event.kind == AuditKind::CanonicalHead
        && (previous.records != next.records
            || previous.canonical_head == next.canonical_head
            || next.canonical_head == B256::ZERO
            || event.intent_id.is_some())
    {
        return Err(PublisherError::InvalidTransition);
    }
    let mut changed = Vec::new();
    for (before, after) in previous.records.iter().zip(&next.records) {
        if before.intent != after.intent
            || after.sign_attempts < before.sign_attempts
            || after.submit_attempts < before.submit_attempts
            || before
                .signature
                .as_ref()
                .is_some_and(|value| after.signature.as_ref() != Some(value))
        {
            return Err(PublisherError::InvalidTransition);
        }
        if before != after {
            if !legal_phase(before.phase, after.phase, event.kind)
                || !attempt_change(before, after, event.kind)
            {
                return Err(PublisherError::InvalidTransition);
            }
            changed.push(before.intent.id);
        }
    }
    if next.records.len() > previous.records.len() {
        let added = next
            .records
            .last()
            .ok_or(PublisherError::InvalidTransition)?;
        if event.kind != AuditKind::Intent
            || event.intent_id != Some(added.intent.id)
            || added.phase != Phase::Intent
            || added.sign_attempts != 0
            || added.submit_attempts != 0
            || added.signature.is_some()
            || added.inclusion.is_some()
            || !changed.is_empty()
        {
            return Err(PublisherError::InvalidTransition);
        }
    } else if !matches!(
        event.kind,
        AuditKind::Fence
            | AuditKind::CanonicalHead
            | AuditKind::CanonicalObservation
            | AuditKind::Reorg
    ) && (changed.len() != 1 || event.intent_id != changed.first().copied())
    {
        return Err(PublisherError::InvalidTransition);
    }
    if previous.canonical_head != next.canonical_head
        && !matches!(
            event.kind,
            AuditKind::CanonicalHead | AuditKind::CanonicalObservation | AuditKind::Reorg
        )
    {
        return Err(PublisherError::InvalidTransition);
    }
    Ok(())
}

fn attempt_change(before: &Publication, after: &Publication, kind: AuditKind) -> bool {
    let sign = if kind == AuditKind::SignAttempt {
        before.sign_attempts.checked_add(1)
    } else {
        Some(before.sign_attempts)
    };
    let submit = if kind == AuditKind::SubmitAttempt {
        before.submit_attempts.checked_add(1)
    } else {
        Some(before.submit_attempts)
    };
    sign == Some(after.sign_attempts) && submit == Some(after.submit_attempts)
}

fn legal_phase(before: Phase, after: Phase, kind: AuditKind) -> bool {
    match kind {
        AuditKind::SignAttempt => before == Phase::Intent && after == Phase::SignAttempted,
        AuditKind::SignAmbiguous => before == Phase::SignAttempted && after == Phase::SignAmbiguous,
        AuditKind::Signed => {
            matches!(before, Phase::SignAttempted | Phase::SignAmbiguous) && after == Phase::Signed
        }
        AuditKind::SubmitAttempt => before == Phase::Signed && after == Phase::SubmitAttempted,
        AuditKind::SubmitAmbiguous => {
            before == Phase::SubmitAttempted && after == Phase::SubmitAmbiguous
        }
        AuditKind::Submitted => before == Phase::SubmitAttempted && after == Phase::Submitted,
        AuditKind::CanonicalObservation => {
            matches!(after, Phase::Included | Phase::Confirmed)
                && matches!(
                    before,
                    Phase::SubmitAttempted
                        | Phase::SubmitAmbiguous
                        | Phase::Submitted
                        | Phase::Included
                        | Phase::Confirmed
                        | Phase::Orphaned
                        | Phase::Abandoned
                )
        }
        AuditKind::Reorg => after == Phase::Orphaned,
        AuditKind::Abandon => {
            before != Phase::Confirmed && before != Phase::Abandoned && after == Phase::Abandoned
        }
        AuditKind::Fence | AuditKind::CanonicalHead | AuditKind::Intent => false,
    }
}
