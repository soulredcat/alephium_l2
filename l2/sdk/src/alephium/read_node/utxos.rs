use super::{
    FundingView, IdentityObservation, P2pkhAddress, ReadNodeError as Error, UnanchoredUtxo,
    UnanchoredUtxos, wire,
};
use crate::alephium::OutputRef;
use serde::Deserialize;

#[derive(Deserialize)]
struct Reference {
    hint: i32,
    key: wire::Hash,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Utxo {
    #[serde(rename = "ref")]
    reference: Reference,
    amount: wire::Amount,
    tokens: Option<wire::List<wire::Token, 64>>,
    lock_time: Option<i64>,
    additional_data: Option<wire::Bytes<4096>>,
}

#[derive(Deserialize)]
pub(super) struct Utxos {
    utxos: wire::List<Utxo, 4096>,
}

impl Utxos {
    pub(super) fn checked(
        self,
        owner: &P2pkhAddress,
        identity: IdentityObservation,
    ) -> Result<UnanchoredUtxos, Error> {
        if owner.group() != 0 {
            return Err(Error::UnsupportedAddress);
        }
        let expected_hint = crate::alephium::codec::owner_hint(owner.hash());
        let mut seen = std::collections::BTreeSet::new();
        let mut out = Vec::with_capacity(self.utxos.0.len());
        for value in self.utxos.0 {
            // Scala's API hint is signed Int, but serialization preserves all
            // four bytes. A negative JSON hint is not itself invalid.
            let reference = OutputRef {
                hint: value.reference.hint as u32,
                key: value.reference.key.0,
            };
            if reference.hint != expected_hint
                || !seen.insert(reference)
                || value.amount.0.is_zero()
            {
                return Err(Error::MalformedResponse);
            }
            out.push(UnanchoredUtxo {
                reference,
                amount: value.amount.0,
                tokens: wire::tokens(value.tokens.map_or_else(Vec::new, |tokens| tokens.0))?,
                lock_time_ms: value.lock_time.map(wire::nonnegative).transpose()?,
                additional_data: value.additional_data.map(|bytes| bytes.0),
            });
        }
        Ok(UnanchoredUtxos {
            identity,
            owner: owner.clone(),
            view: FundingView::LatestIncludingMempoolUnanchored,
            outputs: out,
        })
    }
}
