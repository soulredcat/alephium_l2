//! Settlement artifacts reuse the unchanged staged receipt source closure.
use crate::{source_inventory::Source, staged_sources::STAGED_RECEIPT};

pub(crate) fn sources() -> Vec<Source> {
    let mut sources = STAGED_RECEIPT.to_vec();
    sources.extend([
        Source {
            filename: "batch_journal.ral",
            origin: "l2/contracts/alephium/settlement/batch_journal.ral",
            contract: "Risc0BatchJournal",
            bytes: include_bytes!("../../contracts/alephium/settlement/batch_journal.ral"),
        },
        Source {
            filename: "batch_data.ral",
            origin: "l2/contracts/alephium/settlement/batch_data.ral",
            contract: "Risc0BatchData",
            bytes: include_bytes!("../../contracts/alephium/settlement/batch_data.ral"),
        },
        Source {
            filename: "settlement_factory.ral",
            origin: "l2/contracts/alephium/settlement/settlement_factory.ral",
            contract: "Risc0BatchSettlementFactory",
            bytes: include_bytes!("../../contracts/alephium/settlement/settlement_factory.ral"),
        },
    ]);
    sources
}
