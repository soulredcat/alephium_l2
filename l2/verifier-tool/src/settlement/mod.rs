//! P5 native journal/DA policy and one aggregate synthetic settlement trajectory.
pub(crate) mod bootstrap;
mod cases;
mod flow;
pub(crate) mod journal;
mod layout;
mod policy_cases;
mod service;
mod state;

use crate::{actual_receipt, staged_cases::Fixture};
use bootstrap::Bootstrap;
use journal::{Journal, sha};
use serde_json::Value;
use std::path::Path;

pub(crate) use service::execute;
pub(crate) const MAX_REQUESTS: usize = state::MAX_REQUESTS + 12;

pub(crate) struct Prepared {
    journal: Journal,
    bootstrap: Bootstrap,
    fixture: Fixture,
    ids: state::Ids,
    image: [u8; 32],
    seal_hash: [u8; 32],
    auxiliary_hash: [u8; 32],
    actual_evidence: Value,
}

/// The checkpoint pin must come from the original reviewed proof input, not a
/// package manifest. Actual receipt loading verifies external image/journal pins
/// and independent pairing exactly once before its child-bound fixture is rebased.
pub(crate) fn prepare(
    actual: &actual_receipt::Input,
    data: &Path,
    original_checkpoint_sha256: &str,
) -> Result<Prepared, String> {
    let actual = actual_receipt::prepare_for_child(actual, &[0; 32])?;
    let journal = Journal::decode(actual.journal)?;
    let bootstrap = Bootstrap::read(data, original_checkpoint_sha256, &journal)?;
    let arg = |index: usize| -> Result<Vec<u8>, String> {
        let argument = &actual.fixture.begin_args[index];
        if argument["type"] != "ByteVec" {
            return Err("Invalid verified receipt argument type".into());
        }
        hex::decode(
            argument["value"]
                .as_str()
                .ok_or("Missing verified receipt argument")?,
        )
        .map_err(|_| "Malformed verified receipt argument".into())
    };
    let image: [u8; 32] = arg(1)?
        .try_into()
        .map_err(|_| "Invalid verified image width")?;
    if arg(2)? != journal.digest {
        return Err("Raw settlement journal differs from verified receipt claim".into());
    }
    let seal_hash = sha(&arg(0)?);
    let auxiliary_hash = sha(&arg(3)?);
    let ids = state::ids(
        &journal.factory,
        &image,
        &journal.digest,
        &seal_hash,
        &auxiliary_hash,
    );
    let fixture = Fixture::from_args(&ids.proof, &actual.fixture.begin_args)?;
    let mut actual_evidence = actual.evidence;
    actual_evidence["canonicalChildId"] = serde_json::json!(hex::encode(ids.proof));
    actual_evidence["statementSha256"] = serde_json::json!(fixture.statement_id);
    actual_evidence["maximumRequests"] = serde_json::json!(MAX_REQUESTS);
    actual_evidence["canonicalTargetAccepted"] = serde_json::json!(false);
    Ok(Prepared {
        journal,
        bootstrap,
        fixture,
        ids,
        image,
        seal_hash,
        auxiliary_hash,
        actual_evidence,
    })
}
