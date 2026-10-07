//! Causal audit checks survive restart; no receipt authenticity is inferred here.
use super::types::*;
use alloy_primitives::B256;
use std::collections::BTreeMap;

#[derive(Default)]
struct Trace {
    created: Option<u64>,
    sign: Option<u64>,
    signed: Option<u64>,
    submit: Option<u64>,
    last: Option<AuditKind>,
    last_revision: u64,
    inclusion: Option<Inclusion>,
}

pub(super) fn validate(snapshot: &PublisherSnapshot) -> Result<(), PublisherError> {
    let mut traces = BTreeMap::<B256, Trace>::new();
    let mut global_reorg = 0_u64;
    for event in &snapshot.history {
        if matches!(event.kind, AuditKind::Fence | AuditKind::CanonicalHead) {
            if event.intent_id.is_some() {
                return Err(PublisherError::CorruptState);
            }
            continue;
        }
        if event.kind == AuditKind::Reorg && event.intent_id.is_none() {
            global_reorg = event.revision;
            continue;
        }
        let id = event.intent_id.ok_or(PublisherError::CorruptState)?;
        let trace = traces.entry(id).or_default();
        let valid = match event.kind {
            AuditKind::Intent => {
                let fresh = trace.created.is_none();
                trace.created = Some(event.revision);
                fresh
            }
            AuditKind::SignAttempt => {
                let valid = trace.created.is_some()
                    && trace.sign.is_none()
                    && trace.last == Some(AuditKind::Intent);
                trace.sign = Some(event.revision);
                valid
            }
            AuditKind::Signed => {
                let valid = trace.sign.is_some()
                    && trace.signed.is_none()
                    && matches!(
                        trace.last,
                        Some(AuditKind::SignAttempt | AuditKind::SignAmbiguous)
                    );
                trace.signed = Some(event.revision);
                valid
            }
            AuditKind::SignAmbiguous => trace.last == Some(AuditKind::SignAttempt),
            AuditKind::SubmitAttempt => {
                let valid = trace.signed.is_some()
                    && trace.submit.is_none()
                    && trace.last == Some(AuditKind::Signed);
                trace.submit = Some(event.revision);
                valid
            }
            AuditKind::SubmitAmbiguous | AuditKind::Submitted => {
                trace.last == Some(AuditKind::SubmitAttempt)
            }
            AuditKind::CanonicalObservation => {
                // Abandonment stops dispatch; it cannot erase a previously
                // submitted signed transaction that later lands canonically.
                let valid = trace.submit.is_some() && trace.signed.is_some();
                trace.inclusion = event.inclusion.clone();
                valid
            }
            AuditKind::Abandon => trace.created.is_some() && trace.last != Some(AuditKind::Abandon),
            AuditKind::Reorg => false,
            AuditKind::Fence | AuditKind::CanonicalHead => false,
        };
        if !valid {
            return Err(PublisherError::CorruptState);
        }
        trace.last = Some(event.kind);
        trace.last_revision = event.revision;
    }
    for record in &snapshot.records {
        let trace = traces
            .get(&record.intent.id)
            .ok_or(PublisherError::CorruptState)?;
        if trace.created.is_none()
            || u8::from(trace.sign.is_some()) != record.sign_attempts
            || u8::from(trace.submit.is_some()) != record.submit_attempts
            || trace.signed.is_some() != record.signature.is_some()
            || trace.inclusion != record.inclusion
        {
            return Err(PublisherError::CorruptState);
        }
        let valid = match record.phase {
            Phase::Intent => trace.last == Some(AuditKind::Intent),
            Phase::SignAttempted => trace.last == Some(AuditKind::SignAttempt),
            Phase::SignAmbiguous => trace.last == Some(AuditKind::SignAmbiguous),
            Phase::Signed => trace.last == Some(AuditKind::Signed),
            Phase::SubmitAttempted => trace.last == Some(AuditKind::SubmitAttempt),
            Phase::SubmitAmbiguous => trace.last == Some(AuditKind::SubmitAmbiguous),
            Phase::Submitted => trace.last == Some(AuditKind::Submitted),
            Phase::Included | Phase::Confirmed => {
                trace.last == Some(AuditKind::CanonicalObservation)
            }
            Phase::Orphaned => global_reorg > trace.last_revision,
            Phase::Abandoned => trace.last == Some(AuditKind::Abandon),
        };
        if !valid {
            return Err(PublisherError::CorruptState);
        }
    }
    if traces.len() != snapshot.records.len() {
        return Err(PublisherError::CorruptState);
    }
    Ok(())
}
