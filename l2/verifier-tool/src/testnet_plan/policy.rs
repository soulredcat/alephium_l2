//! Genesis approval and selected public-testnet profile, without live defaults.
use super::{
    literal,
    types::{Actor, Policy},
};
use crate::settlement::{bootstrap, journal};
use num_bigint::BigUint;

impl Policy {
    pub fn validate(&self, actor: &Actor) -> Result<(), String> {
        literal::caller(actor)?;
        // This planner revision uses the retained qualified program, not a
        // caller-selected toy image. A program migration requires review/repin.
        if hex::encode(self.approved_image)
            != "7c0928057347cbc0d752845b053de0628896f7a56bdaa6230b8ac1b7bf76f53f"
            || hex::encode(self.program_sha256)
                != "efea889c2a44e41be156824cf9d56b9e5a3bc1b3332cba0b917924156ff77d98"
        {
            return Err(
                "Offline planner requires the retained independently pinned program".into(),
            );
        }
        if self.l2_chain_id == 0
            || self.confirmations == 0
            || self.max_future_seconds.checked_mul(1000).is_none()
            || self.minimum_contract_deposit == BigUint::from(0_u8)
            || self.minimum_contract_deposit.bits() > 256
            || [
                self.l1_genesis,
                self.l2_genesis,
                self.execution_profile,
                self.approved_image,
                self.program_sha256,
                self.genesis_checkpoint_sha256,
            ]
            .contains(&[0; 32])
            || self.genesis_checkpoint.is_empty()
            || self.genesis_checkpoint.len() > 3000
            || literal::sha(&self.genesis_checkpoint) != self.genesis_checkpoint_sha256
            || bootstrap::capacity_limits(self.capacity)? != self.transport_limits
        {
            return Err(
                "Independent genesis/program/profile and explicit policy pins required".into(),
            );
        }
        let head = journal::Head::decode(&self.genesis_head)?;
        let mut genesis_commit = b"alephium-l2-development/genesis-commit/v1".to_vec();
        genesis_commit.extend(self.l2_genesis);
        if head.height != 0
            || head.timestamp != 0
            || head.genesis != self.l2_genesis
            || head.commit != literal::sha(&genesis_commit)
        {
            return Err("Approved initialization head is not canonical genesis".into());
        }
        let (capacity, schema, cp_head) = super::da::checkpoint_prefix(
            &self.genesis_checkpoint,
            self.l2_chain_id,
            &self.l2_genesis,
        )?;
        if capacity != self.capacity
            || cp_head != self.genesis_head
            || bootstrap::profile(capacity, schema, &self.transport_limits)
                != self.execution_profile
        {
            return Err("Approved checkpoint/profile differs from initialization policy".into());
        }
        Ok(())
    }

    pub fn genesis_root(&self, factory: &[u8; 32]) -> [u8; 32] {
        let mut input = b"alephium-l2/continuation-root/v2".to_vec();
        input.extend(self.execution_profile);
        input.push(1);
        input.extend(self.l1_genesis);
        input.extend(factory);
        input.extend(self.transport_limits);
        input.extend(&self.genesis_checkpoint);
        literal::sha(&input)
    }
}
