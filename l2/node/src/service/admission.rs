//! Immutable preparation can run independently; current-state validation and
//! durable admission stay ordered over one pinned committed view.
use super::{Core, preparation, production::BlockBudget};
use crate::{execution, protocol::*, storage::ReadView};
use alloy_primitives::{B256, keccak256};
use std::{
    collections::{HashMap, HashSet},
    time::Instant,
};

enum Outcome {
    Existing(TransactionStatus),
    Staged(usize),
    Rejected(String),
}

enum Candidate {
    Existing(TransactionStatus),
    New(B256, usize),
    Rejected(String),
}

fn answers(
    outcomes: Vec<Outcome>,
    statuses: &[TransactionStatus],
    failure: Option<&str>,
) -> Vec<Result<TransactionStatus, String>> {
    outcomes
        .into_iter()
        .map(|outcome| match outcome {
            Outcome::Rejected(error) => Err(error),
            Outcome::Existing(status) => match failure {
                Some(error) => Err(error.into()),
                None => Ok(status),
            },
            Outcome::Staged(index) => match failure {
                Some(error) => Err(error.into()),
                None => Ok(statuses[index].clone()),
            },
        })
        .collect()
}

impl Core {
    #[cfg(test)]
    pub(super) fn submit(&mut self, raw: Vec<u8>) -> Result<TransactionStatus, String> {
        self.admit_queued(vec![raw]).pop().unwrap()
    }

    #[cfg(test)]
    pub(super) fn admit_group(
        &mut self,
        inputs: Vec<(Vec<u8>, Head)>,
    ) -> Vec<Result<TransactionStatus, String>> {
        self.admit_queued(inputs.into_iter().map(|(raw, _head)| raw).collect())
    }

    fn candidates(
        &self,
        inputs: &[Vec<u8>],
        view: &ReadView,
    ) -> Result<(Vec<Candidate>, Vec<usize>), String> {
        let mut candidates = Vec::with_capacity(inputs.len());
        let mut leaders = Vec::new();
        let mut hashes = HashMap::<B256, usize>::new();
        for (position, raw) in inputs.iter().enumerate() {
            if raw.is_empty() || raw.len() > MAX_TRANSACTION_BYTES {
                candidates.push(Candidate::Rejected(
                    "Transaction encoding exceeds admission bounds".into(),
                ));
                continue;
            }
            let hash = keccak256(raw);
            if let Some(status) = view.status(hash)? {
                if view.raw_transaction(hash)?.as_deref() != Some(raw.as_slice()) {
                    return Err("Stored transaction identity conflicts; recovery required".into());
                }
                if status.status == "durably_accepted" {
                    let prepared = self
                        .prepared
                        .get(&hash)
                        .ok_or("Prepared pending cache missing; recovery required")?;
                    if !prepared.matches(raw, view.chain_id()) || prepared.info().hash != hash {
                        return Err(
                            "Prepared pending cache binding mismatch; recovery required".into()
                        );
                    }
                }
                candidates.push(Candidate::Existing(status));
            } else if let Some(&index) = hashes.get(&hash) {
                if inputs[leaders[index]] != *raw {
                    candidates.push(Candidate::Rejected(
                        "Conflicting canonical transaction identity".into(),
                    ));
                } else {
                    candidates.push(Candidate::New(hash, index));
                }
            } else {
                let index = leaders.len();
                leaders.push(position);
                hashes.insert(hash, index);
                candidates.push(Candidate::New(hash, index));
            }
        }
        Ok((candidates, leaders))
    }

    pub(super) fn admit_queued(
        &mut self,
        inputs: Vec<Vec<u8>>,
    ) -> Vec<Result<TransactionStatus, String>> {
        if self.handle.failure().is_some() {
            return inputs
                .into_iter()
                .map(|_| Err("Recovery required".into()))
                .collect();
        }
        let validation_started = Instant::now();
        let prepared = (|| {
            let view = self.handle.view()?;
            let context = self.context()?;
            let (candidates, leaders) = self.candidates(&inputs, &view)?;
            let raw_inputs: Vec<_> = leaders
                .iter()
                .map(|&index| inputs[index].as_slice())
                .collect();
            let verified = preparation::prepare_parallel(
                &raw_inputs,
                view.chain_id(),
                self.handle.verification_workers,
            )?;
            Ok::<_, String>((view, context, candidates, verified))
        })();
        let (view, context, candidates, verified) = match prepared {
            Ok(prepared) => prepared,
            Err(_) => {
                self.handle
                    .metrics
                    .validation
                    .record(validation_started.elapsed());
                self.fail();
                return inputs
                    .into_iter()
                    .map(|_| Err("Preparation unavailable; recovery required".into()))
                    .collect();
            }
        };
        let mut staged: Vec<Pending> = Vec::new();
        let mut staged_prepared = Vec::new();
        let mut hashes = HashMap::<B256, usize>::new();
        let mut senders: HashSet<_> = self.pending.iter().map(|entry| entry.sender).collect();
        let mut outcomes = Vec::with_capacity(inputs.len());
        let capacity = view.capacity();
        for (raw, candidate) in inputs.into_iter().zip(candidates) {
            let outcome = (|| -> Result<Outcome, String> {
                if self.handle.failure().is_some() {
                    return Err("Recovery required".into());
                }
                let (hash, index) = match candidate {
                    Candidate::Existing(status) => return Ok(Outcome::Existing(status)),
                    Candidate::Rejected(error) => return Err(error),
                    Candidate::New(hash, index) => (hash, index),
                };
                if let Some(&index) = hashes.get(&hash) {
                    return Ok(Outcome::Staged(index));
                }
                if self.pending.len() + staged.len() >= capacity.max_pending {
                    return Err("Pending queue full".into());
                }
                let prepared = verified[index].as_ref().map_err(Clone::clone)?;
                if !prepared.matches(&raw, view.chain_id()) || prepared.info().hash != hash {
                    self.fail();
                    return Err("Prepared input binding mismatch; recovery required".into());
                }
                let info = execution::validate_prepared((*view).clone(), prepared, context)
                    .inspect_err(|error| {
                        if execution::is_infrastructure_error(error) {
                            self.fail();
                        }
                    })?;
                if info.gas_price < self.handle.min_gas_price {
                    return Err("Gas price is below the node minimum".into());
                }
                if info.gas_limit == 0 || info.gas_limit > capacity.block_gas {
                    return Err("Transaction cannot fit block gas budget".into());
                }
                if senders.contains(&info.sender) {
                    return Err("One pending transaction per sender is supported".into());
                }
                if !BlockBudget::new(capacity).can_reserve(info.gas_limit, raw.len()) {
                    return Err("Transaction cannot fit block byte budget".into());
                }
                senders.insert(info.sender);
                let index = staged.len();
                hashes.insert(hash, index);
                staged.push(Pending {
                    hash,
                    sender: info.sender,
                    raw,
                });
                staged_prepared.push(prepared.clone());
                Ok(Outcome::Staged(index))
            })();
            outcomes.push(outcome.unwrap_or_else(Outcome::Rejected));
        }
        self.handle
            .metrics
            .validation
            .record(validation_started.elapsed());
        if self.handle.failure().is_some() {
            return answers(outcomes, &[], Some("Outcome ambiguous; recovery required"));
        }
        if staged.is_empty() {
            return answers(outcomes, &[], None);
        }
        let admission_started = Instant::now();
        let admitted = self.store.admit_batch(&staged);
        self.handle
            .metrics
            .durable_admission
            .record(admission_started.elapsed());
        let statuses = match admitted {
            Ok(statuses) => statuses,
            Err(_) => {
                self.fail();
                return answers(
                    outcomes,
                    &[],
                    Some("Durable admission failed; reconcile after recovery"),
                );
            }
        };
        if statuses.len() != staged.len()
            || statuses.iter().zip(&staged).any(|(status, entry)| {
                status.hash != entry.hash
                    || status.status != "durably_accepted"
                    || status.block_height.is_some()
                    || status.error.is_some()
            })
        {
            self.fail();
            return answers(outcomes, &[], Some("Outcome ambiguous; recovery required"));
        }
        // Only the successful durable barrier authorizes cache insertion.
        for (pending, prepared) in staged.iter().zip(staged_prepared) {
            self.prepared.insert(pending.hash, prepared);
        }
        self.handle.metrics.admitted(staged.len());
        self.pending.extend(staged);
        if self
            .store
            .view()
            .and_then(|view| self.publish(view))
            .is_err()
        {
            self.fail();
            return answers(outcomes, &[], Some("Outcome ambiguous; recovery required"));
        }
        answers(outcomes, &statuses, None)
    }
}
