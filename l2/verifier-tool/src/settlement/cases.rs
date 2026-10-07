//! One aggregate inventory: byte-boundary checks precede any target request.
use super::{
    bootstrap::{Bootstrap, MAX_DATA},
    journal::{self, Journal, sha},
};
use serde_json::{Value, json};

pub(super) const NATIVE_CASES: usize = 18;

pub(super) fn native(journal: &Journal, bootstrap: &Bootstrap) -> Result<Vec<Value>, String> {
    let mut records = Vec::with_capacity(NATIVE_CASES);
    check(
        &mut records,
        "exact-v4-journal-and-header",
        journal.bytes.len() == journal::JOURNAL_BYTES
            && journal::header().len() == journal::HEADER_BYTES,
    )?;
    check(
        &mut records,
        "exact-complete-inline-data-hash",
        !bootstrap.data.is_empty()
            && bootstrap.data.len() <= MAX_DATA
            && sha(&bootstrap.data) == journal.data_hash,
    )?;
    check(
        &mut records,
        "independent-original-checkpoint-pin",
        sha(&bootstrap.checkpoint) == bootstrap.checkpoint_hash,
    )?;
    let historical_factory =
        crate::factory_state::fixture_id(b"ALPH/L2/stagedfactory/development-fixture/v1");
    check(
        &mut records,
        "independent-blake2b256-group0-child-golden-vector",
        super::state::child_id(&historical_factory, b"v1")
            == crate::factory_service::canonical_child_id()?,
    )?;
    for (name, changed) in [
        (
            "journal-truncation",
            journal.bytes[..journal.bytes.len() - 1].to_vec(),
        ),
        ("journal-extension", {
            let mut bytes = journal.bytes.clone();
            bytes.push(0);
            bytes
        }),
        ("journal-header", changed_byte(&journal.bytes, 4)),
        ("journal-parent-genesis", changed_byte(&journal.bytes, 354)),
        ("journal-head-genesis", changed_byte(&journal.bytes, 434)),
        (
            "journal-empty-inbox-binding",
            changed_byte(&journal.bytes, 786),
        ),
        (
            "journal-empty-outbox-binding",
            changed_byte(&journal.bytes, 826),
        ),
    ] {
        check(&mut records, name, Journal::decode(changed).is_err())?;
    }
    for (name, offset, value) in [
        ("journal-zero-chain", 226, 0),
        ("journal-zero-blocks", 466, 0),
        ("journal-witness-count", 482, journal.blocks + 1),
        ("journal-nonempty-inbox", 818, 1),
        ("journal-nonempty-outbox", 858, 1),
    ] {
        let mut changed = journal.bytes.clone();
        changed[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        check(&mut records, name, Journal::decode(changed).is_err())?;
    }
    check(
        &mut records,
        "missing-data-cannot-match-commitment",
        sha(&[]) != journal.data_hash,
    )?;
    check(
        &mut records,
        "partial-data-cannot-match-commitment",
        sha(&bootstrap.data[..bootstrap.data.len() - 1]) != journal.data_hash,
    )?;
    if records.len() != NATIVE_CASES {
        return Err("Settlement native case inventory differs".into());
    }
    Ok(records)
}

pub(super) fn changed_byte(bytes: &[u8], offset: usize) -> Vec<u8> {
    let mut changed = bytes.to_vec();
    changed[offset] ^= 1;
    changed
}

fn check(records: &mut Vec<Value>, name: &str, passed: bool) -> Result<(), String> {
    records.push(json!({"name": name, "passed": passed, "scope": "native-boundary"}));
    if !passed {
        return Err(format!(
            "Settlement native case {name} failed; values suppressed"
        ));
    }
    Ok(())
}
