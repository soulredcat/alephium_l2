//! Native settlement candidate checks over the unchanged schema-four journal.
//! Decoding and policy eligibility confer no proof, DA or settlement authority.
mod journal;
mod policy;

pub use journal::decode_journal_v4;
pub use policy::{SettlementAnchor, SettlementPolicy};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BatchTransitionJournal, EXECUTION_ENGINE, LARGE_CHECKPOINT_SCOPE, RPC_PROFILE,
        SettlementDomain, batch_journal,
        protocol::{Head, checkpoint::genesis_commit},
    };
    use alloy_primitives::{B256, U256};

    fn fixture() -> (SettlementPolicy, SettlementAnchor, BatchTransitionJournal) {
        let genesis_id = B256::repeat_byte(2);
        let domain = SettlementDomain {
            l1_network: 1,
            l1_genesis_id: B256::repeat_byte(11),
            settlement_contract_id: B256::repeat_byte(12),
        };
        let parent = Head {
            height: 9,
            timestamp: 1_000,
            commit_id: B256::repeat_byte(4),
            genesis_id,
        };
        let policy = SettlementPolicy {
            domain: domain.clone(),
            chain_id: 424_243,
            genesis_id,
            execution_profile: B256::repeat_byte(3),
            max_future_seconds: 2,
        };
        let anchor = SettlementAnchor {
            head: parent.clone(),
            state_root: B256::repeat_byte(21),
        };
        let journal = BatchTransitionJournal {
            schema: 4,
            proof_scope: LARGE_CHECKPOINT_SCOPE.into(),
            rpc_profile: RPC_PROFILE.into(),
            execution_engine: EXECUTION_ENGINE.into(),
            domain: domain.clone(),
            chain_id: policy.chain_id,
            genesis_id,
            execution_profile: policy.execution_profile,
            batch_start: 10,
            parent,
            head: Head {
                height: 11,
                timestamp: 1_002,
                commit_id: B256::repeat_byte(5),
                genesis_id,
            },
            blocks: 2,
            executed_transactions: 3,
            witness_blocks: 2,
            old_state_root: anchor.state_root,
            new_state_root: B256::repeat_byte(22),
            before_state_digest: B256::repeat_byte(23),
            after_state_digest: B256::repeat_byte(24),
            before_account_count: 4,
            after_account_count: 3,
            before_total_balance: U256::from(100),
            after_total_balance: U256::from(99),
            transactions_commitment: B256::repeat_byte(25),
            context_commitment: B256::repeat_byte(26),
            receipts_commitment: B256::repeat_byte(27),
            inbox_commitment: batch_journal::empty_messages(&domain, genesis_id, b"inbox"),
            outbox_commitment: batch_journal::empty_messages(&domain, genesis_id, b"outbox"),
            inbox_count: 0,
            outbox_count: 0,
            da_commitment: B256::repeat_byte(28),
        };
        (policy, anchor, journal)
    }

    #[test]
    fn canonical_journal_and_settlement_policy_bulk_cases() -> Result<(), String> {
        let (policy, anchor, journal) = fixture();
        let bytes = journal.encode()?;
        let decoded = decode_journal_v4(&bytes)?;
        assert!(decoded.encode()? == bytes);
        policy.validate(&anchor, &decoded, 1_000_000)?; // Exact inclusive bound.
        policy.validate(&anchor, &decoded, 1_000_999)?; // L1 subsecond precision.
        assert!(policy.validate(&anchor, &decoded, 999_999).is_err());
        let mut no_drift = policy.clone();
        no_drift.max_future_seconds = 0;
        no_drift.validate(&anchor, &decoded, 1_002_000)?;
        assert!(no_drift.validate(&anchor, &decoded, 1_001_999).is_err());
        let mut same_time = journal.clone();
        same_time.head.timestamp = same_time.parent.timestamp;
        policy.validate(&anchor, &same_time, 1_000_000)?;

        // Each possible truncation is an in-process assertion, not another job.
        for end in 0..bytes.len() {
            assert!(decode_journal_v4(&bytes[..end]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode_journal_v4(&trailing).is_err());
        assert!(decode_journal_v4(&[0; 4097]).is_err());
        let mut bad_length = bytes.clone();
        bad_length[..4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode_journal_v4(&bad_length).is_err());
        let mut bad_domain = bytes.clone();
        bad_domain[4] ^= 1;
        assert!(decode_journal_v4(&bad_domain).is_err());

        let invalid: &[fn(&mut BatchTransitionJournal)] = &[
            |j| j.proof_scope.push('x'),
            |j| j.rpc_profile.clear(),
            |j| j.execution_engine.push('x'),
            |j| j.domain.l1_genesis_id = B256::ZERO,
            |j| j.domain.settlement_contract_id = B256::ZERO,
            |j| j.chain_id = 0,
            |j| j.genesis_id = B256::ZERO,
            |j| j.execution_profile = B256::ZERO,
            |j| j.parent.genesis_id = B256::ZERO,
            |j| j.head.genesis_id = B256::ZERO,
            |j| j.parent.commit_id = B256::ZERO,
            |j| j.head.commit_id = B256::ZERO,
            |j| j.blocks = 0,
            |j| j.blocks = 257,
            |j| j.witness_blocks += 1,
            |j| j.executed_transactions = 1,
            |j| j.executed_transactions = u64::MAX,
            |j| j.batch_start += 1,
            |j| j.head.height += 1,
            |j| j.parent.height = u64::MAX,
            |j| {
                j.parent.height = u64::MAX - 1;
                j.batch_start = u64::MAX;
            },
            |j| j.head.timestamp = j.parent.timestamp - 1,
            |j| j.inbox_count = 1,
            |j| j.outbox_count = 1,
            |j| j.inbox_commitment = j.outbox_commitment,
            |j| j.outbox_commitment = B256::ZERO,
            |j| j.old_state_root = B256::ZERO,
            |j| j.new_state_root = B256::ZERO,
            |j| j.before_state_digest = B256::ZERO,
            |j| j.after_state_digest = B256::ZERO,
            |j| j.transactions_commitment = B256::ZERO,
            |j| j.context_commitment = B256::ZERO,
            |j| j.receipts_commitment = B256::ZERO,
            |j| j.da_commitment = B256::ZERO,
        ];
        for mutate in invalid {
            let mut changed = journal.clone();
            mutate(&mut changed);
            assert!(decode_journal_v4(&changed.encode()?).is_err());
            assert!(policy.validate(&anchor, &changed, 1_000_000).is_err());
        }
        let mut older = journal.clone();
        older.schema = 3;
        assert!(decode_journal_v4(&older.encode()?).is_err());
        assert!(policy.validate(&anchor, &older, 1_000_000).is_err());

        let wrong_pins: &[fn(&mut SettlementPolicy)] = &[
            |p| p.domain.l1_network ^= 1,
            |p| p.domain.l1_genesis_id = B256::repeat_byte(90),
            |p| p.domain.settlement_contract_id = B256::repeat_byte(91),
            |p| p.chain_id += 1,
            |p| p.chain_id = 0,
            |p| p.genesis_id = B256::repeat_byte(92),
            |p| p.genesis_id = B256::ZERO,
            |p| p.execution_profile = B256::repeat_byte(93),
            |p| p.execution_profile = B256::ZERO,
            |p| p.max_future_seconds = u64::MAX,
        ];
        for mutate in wrong_pins {
            let mut changed = policy.clone();
            mutate(&mut changed);
            assert!(changed.validate(&anchor, &journal, 1_000_000).is_err());
        }
        let wrong_anchor: &[fn(&mut SettlementAnchor)] = &[
            |a| a.head.height -= 1,
            |a| a.head.timestamp -= 1,
            |a| a.head.commit_id = B256::repeat_byte(94),
            |a| a.head.genesis_id = B256::repeat_byte(95),
            |a| a.state_root = B256::repeat_byte(96),
        ];
        for mutate in wrong_anchor {
            let mut changed = anchor.clone();
            mutate(&mut changed);
            assert!(policy.validate(&changed, &journal, 1_000_000).is_err());
        }
        assert!(policy.validate(&anchor, &journal, u64::MAX).is_err());
        let mut overflow = journal.clone();
        overflow.head.timestamp = u64::MAX / 1000 + 1;
        assert!(policy.validate(&anchor, &overflow, 1_000_000).is_err());

        let next_anchor = SettlementAnchor {
            head: journal.head.clone(),
            state_root: journal.new_state_root,
        };
        assert!(policy.validate(&next_anchor, &journal, 1_002_000).is_err());
        let mut next = journal.clone();
        next.parent = next_anchor.head.clone();
        next.old_state_root = next_anchor.state_root;
        next.batch_start = next.parent.height + 1;
        next.head.height = next.parent.height + next.blocks;
        next.head.timestamp += 2;
        next.head.commit_id = B256::repeat_byte(98);
        next.new_state_root = B256::repeat_byte(99);
        policy.validate(
            &next_anchor,
            &decode_journal_v4(&next.encode()?)?,
            1_002_000,
        )?;

        let mut genesis = journal;
        genesis.parent.height = 0;
        genesis.parent.timestamp = 0;
        genesis.parent.commit_id = genesis_commit(genesis.genesis_id);
        genesis.batch_start = 1;
        genesis.head.height = genesis.blocks;
        let genesis_anchor = SettlementAnchor {
            head: genesis.parent.clone(),
            state_root: genesis.old_state_root,
        };
        decode_journal_v4(&genesis.encode()?)?;
        policy.validate(&genesis_anchor, &genesis, 1_000_000)?;
        genesis.parent.timestamp = 1;
        assert!(decode_journal_v4(&genesis.encode()?).is_err());
        genesis.parent.timestamp = 0;
        genesis.parent.commit_id = B256::repeat_byte(97);
        assert!(decode_journal_v4(&genesis.encode()?).is_err());
        Ok(())
    }
}
