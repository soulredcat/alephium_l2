//! Cache only immutable verified decoding for durably pending envelopes.
//! Account state is never cached here; execution rechecks the current state.
use super::Core;
use crate::{execution::PreparedTransaction, protocol::Pending};

impl Core {
    pub(super) fn prepared_pending(
        &self,
        pending: &Pending,
        chain_id: u64,
    ) -> Result<&PreparedTransaction, String> {
        let Some(prepared) = self.prepared.get(&pending.hash) else {
            self.fail();
            return Err("Prepared pending cache missing; recovery required".into());
        };
        if !prepared.matches(&pending.raw, chain_id)
            || prepared.info().hash != pending.hash
            || prepared.info().sender != pending.sender
        {
            self.fail();
            return Err("Prepared pending cache binding mismatch; recovery required".into());
        }
        Ok(prepared)
    }

    pub(super) fn retain_pending_preparations(&mut self) -> Result<(), String> {
        let hashes: std::collections::HashSet<_> =
            self.pending.iter().map(|pending| pending.hash).collect();
        self.prepared.retain(|hash, _| hashes.contains(hash));
        if self.prepared.len() != self.pending.len() {
            self.fail();
            return Err(
                "Prepared pending cache differs from durable queue; recovery required".into(),
            );
        }
        Ok(())
    }
}
