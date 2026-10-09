//! Frozen four-role bootstrap policy, fresh dependencies and one-shot effects.
use super::{
    CanonicalSource, ExternalSigner, ExternalSubmitter, Phase, Plan, Publication, Publisher,
    PublisherError as Error, PublisherSnapshot, Repository, ReservedInput, Token,
};
use alephium_l2_sdk::alephium::{
    ApprovedOperation, ValidatedUnsignedAlephium, alephium_hash, unsigned_input_refs,
};
use alloy_primitives::B256;
use std::collections::BTreeSet;

#[derive(Clone, PartialEq, Eq)]
pub struct SerialOperation {
    id: B256,
    operation: B256,
    policy: B256,
    scope: B256,
    artifact: B256,
    script: B256,
    tx: B256,
    raw: Vec<u8>,
    network: u8,
    genesis: B256,
    source: B256,
    caller: Vec<u8>,
    inputs: Vec<ReservedInput>,
    effect: B256,
    confirmations: u64,
}
impl SerialOperation {
    /// Static data only. A current opaque validated transaction is still required to dispatch.
    pub fn from_approved(
        op: &ApprovedOperation,
        raw: &[u8],
        effect: B256,
        confirmations: u64,
    ) -> Result<Self, Error> {
        let s = op.spec();
        if effect == B256::ZERO || confirmations == 0 {
            return Err(Error::InvalidInput);
        }
        let inputs = unsigned_input_refs(op, raw).map_err(|_| Error::InvalidInput)?;
        Ok(Self {
            id: s.intent_id,
            operation: s.operation_id,
            policy: super::handoff::operation_policy_hash(op),
            scope: s.publication_scope,
            artifact: s.source_artifact_sha256,
            script: s
                .script_blake2b256
                .filter(|h| *h != B256::ZERO)
                .ok_or(Error::InvalidInput)?,
            tx: alephium_hash(raw),
            raw: raw.to_vec(),
            network: s.funding.network_id,
            genesis: s.funding.network_genesis_id,
            source: s.funding.source_id,
            caller: s.caller_public_key.to_vec(),
            inputs: inputs
                .into_iter()
                .map(|r| ReservedInput {
                    hint: r.hint,
                    key: r.key,
                })
                .collect(),
            effect,
            confirmations,
        })
    }
    fn matches(&self, row: &Publication, parent: Option<B256>) -> bool {
        let i = &row.intent;
        i.id == self.id
            && i.operation_id == self.operation
            && i.operation_policy_sha256 == self.policy
            && i.artifact_hash == self.artifact
            && i.script_hash == self.script
            && i.tx_id == self.tx
            && i.unsigned == self.raw
            && i.network == self.network
            && i.l1_genesis == self.genesis
            && i.canonical_source == self.source
            && i.authority_key == self.caller
            && i.inputs == self.inputs
            && i.expected_effect == self.effect
            && i.parent == parent
            && i.confirmations == self.confirmations
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResumeDecision {
    Fresh,
    RecheckConfirmed,
    ReconcileOnly,
}

pub struct SerialBootstrapPlan {
    steps: [SerialOperation; 4],
}
impl SerialBootstrapPlan {
    /// The frozen packet uses a serial chain: both templates are ancestors of factory.
    pub fn new(steps: [SerialOperation; 4]) -> Result<Self, Error> {
        let mut ids = BTreeSet::new();
        let mut operations = BTreeSet::new();
        let mut txs = BTreeSet::new();
        let mut inputs = BTreeSet::new();
        for step in &steps {
            if step.scope != steps[0].scope
                || step.caller != steps[0].caller
                || step.network != steps[0].network
                || step.genesis != steps[0].genesis
                || step.source != steps[0].source
                || !ids.insert(step.id)
                || !operations.insert(step.operation)
                || !txs.insert(step.tx)
                || step.inputs.iter().any(|r| !inputs.insert(r.key))
            {
                return Err(Error::InvalidInput);
            }
        }
        Ok(Self { steps })
    }
    fn step(&self, index: usize) -> Result<&SerialOperation, Error> {
        self.steps.get(index).ok_or(Error::InvalidInput)
    }
    fn parent(&self, index: usize) -> Option<B256> {
        index.checked_sub(1).map(|i| self.steps[i].id)
    }
    pub fn check_existing(&self, snapshot: &PublisherSnapshot) -> Result<(), Error> {
        if snapshot.scope.identity()? != self.steps[0].scope {
            return Err(Error::InvalidInput);
        }
        for (index, step) in self.steps.iter().enumerate() {
            if snapshot
                .records
                .iter()
                .filter(|r| r.intent.id == step.id)
                .any(|r| !step.matches(r, self.parent(index)))
            {
                return Err(Error::InvalidInput);
            }
        }
        Ok(())
    }
    pub fn decision(
        &self,
        snapshot: &PublisherSnapshot,
        index: usize,
    ) -> Result<ResumeDecision, Error> {
        self.check_existing(snapshot)?;
        let step = self.step(index)?;
        Ok(
            match snapshot.records.iter().find(|r| r.intent.id == step.id) {
                None => ResumeDecision::Fresh,
                Some(row) if row.phase == Phase::Confirmed => ResumeDecision::RecheckConfirmed,
                Some(_) => ResumeDecision::ReconcileOnly,
            },
        )
    }
    /// One explicit positive observation for every required ancestor, at this source view.
    /// Missing/insufficient evidence stops progress even if an old row says Confirmed.
    pub fn observe_confirmed<R: Repository>(
        &self,
        publisher: &mut Publisher<R>,
        mut token: Token,
        index: usize,
        source: &mut impl CanonicalSource,
    ) -> Result<Token, Error> {
        self.step(index)?;
        token = publisher.refresh_head(token, source)?;
        self.check_existing(&publisher.snapshot(token)?)?;
        for step in &self.steps[..=index] {
            let (next, positive) = publisher.reconcile_observed(token, step.id, source)?;
            token = next;
            if !positive {
                return Err(Error::InvalidObservation);
            }
            let snapshot = publisher.snapshot(token)?;
            self.check_existing(&snapshot)?;
            if !snapshot.records.iter().any(|r| {
                r.intent.id == step.id
                    && r.phase == Phase::Confirmed
                    && r.inclusion
                        .as_ref()
                        .is_some_and(|i| i.canonical_head == token.canonical_head)
            }) {
                return Err(Error::InvalidObservation);
            }
        }
        Ok(token)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn dispatch<R: Repository>(
        &self,
        publisher: &mut Publisher<R>,
        mut token: Token,
        index: usize,
        unsigned: ValidatedUnsignedAlephium,
        source: &mut impl CanonicalSource,
        signer: &mut impl ExternalSigner,
        submitter: &mut impl ExternalSubmitter,
        now_ms: u64,
    ) -> Result<Token, Error> {
        let step = self.step(index)?;
        if SerialOperation::from_approved(
            unsigned.operation(),
            unsigned.unsigned_bytes(),
            step.effect,
            step.confirmations,
        )? != *step
        {
            return Err(Error::InvalidInput);
        }
        token = publisher.refresh_head(token, source)?;
        if self.decision(&publisher.snapshot(token)?, index)? != ResumeDecision::Fresh {
            return Err(Error::InvalidTransition);
        }
        if index > 0 {
            token = self.observe_confirmed(publisher, token, index - 1, source)?;
        }
        if token.canonical_head != unsigned.operation().spec().funding.head_hash {
            return Err(Error::Conflict);
        }
        token = publisher.register(
            token,
            &unsigned,
            Plan {
                parent: self.parent(index),
                expected_effect: step.effect,
                confirmations: step.confirmations,
                review_after_ms: now_ms.checked_add(86_400_000).ok_or(Error::InvalidInput)?,
            },
            now_ms,
        )?;
        let (token, signed) = publisher.sign(token, unsigned, signer, now_ms)?;
        publisher.submit(token, &signed, submitter, now_ms)
    }
}
