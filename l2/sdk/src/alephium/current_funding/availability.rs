//! Match a bounded latest node projection to independently checked fixed outputs.
use super::{
    CurrentFundingError as Error, CurrentFundingPolicy, FixedOutputProvenance, FundingPin,
    IdentityObservation, LockTimeProjection, P2pkhAddress, PreviousOutput, ReadNode, checks,
};
use crate::alephium::read_node::FundingView;

pub(super) fn latest(
    node: &ReadNode,
    pin: &FundingPin,
    identity: &IdentityObservation,
    owner: &P2pkhAddress,
    outputs: &[PreviousOutput],
    provenance: &[FixedOutputProvenance],
    policy: &CurrentFundingPolicy,
) -> Result<Vec<LockTimeProjection>, Error> {
    if outputs.len() != provenance.len() {
        return Err(Error::CreatorMismatch);
    }
    let current = node.unanchored_utxos(owner)?;
    checks::identity(pin, &current.identity, policy)?;
    if &current.identity != identity
        || &current.owner != owner
        || current.view != FundingView::LatestIncludingMempoolUnanchored
    {
        return Err(Error::IdentityMismatch);
    }
    outputs
        .iter()
        .zip(provenance)
        .map(|(fixed, fact)| {
            let observed = current
                .outputs
                .iter()
                .find(|out| out.reference == fixed.reference)
                .ok_or(Error::AvailabilityMismatch)?;
            checks::latest(fixed, observed, fact, owner.hash(), pin.timestamp_ms)
        })
        .collect()
}
