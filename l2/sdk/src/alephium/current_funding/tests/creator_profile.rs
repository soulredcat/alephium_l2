//! Source-derived creator forms and source-v4 binding; simulated facts only.
use super::fixture;
use crate::alephium::{
    FundingModel, alephium_hash,
    current_funding::{CurrentFundingError as Error, checks, creator, policy},
    read_node::OFFICIAL_TESTNET_ORIGIN,
};
use serde_json::json;

pub(super) fn run_checks() -> usize {
    let mut count = 0;
    let mut check = |ok: bool| {
        assert!(ok, "Creator profile check failed; payload suppressed");
        count += 1;
    };
    for tags in [&[0, 3][..], &[0, 3, 3][..]] {
        let f = fixture::build_with_unlocks(None, tags);
        check(creator::fixed_outputs(&f.details, f.creator_id, None).is_ok());
    }
    let first_previous = fixture::build_with_unlocks(None, &[3, 0]);
    check(matches!(
        creator::fixed_outputs(&first_previous.details, first_previous.creator_id, None),
        Err(Error::UnsupportedCreator)
    ));
    let f = fixture::build_with_unlocks(None, &[0, 3, 3]);
    for mutation in 0..4 {
        let mut altered = f.details.clone();
        match mutation {
            0 => {
                altered["unsigned"]["inputs"][1]["outputRef"]["hint"] =
                    json!((f.fixed[0].reference.hint ^ 2) as i32)
            }
            1 => altered["unsigned"]["inputs"][1]["unlockScript"] = json!("0300"),
            2 => altered["unsigned"]["inputs"][2]["unlockScript"] = json!("04"),
            _ => {
                altered["unsigned"]["inputs"][2]["outputRef"]["key"] =
                    f.details["unsigned"]["inputs"][0]["outputRef"]["key"].clone()
            }
        }
        check(creator::fixed_outputs(&altered, f.creator_id, None).is_err());
    }
    // An equivalent full-key unlock changes the committed bytes and txId.
    let mut expanded = f.details.clone();
    expanded["unsigned"]["inputs"][1]["unlockScript"] =
        f.details["unsigned"]["inputs"][0]["unlockScript"].clone();
    check(creator::fixed_outputs(&expanded, f.creator_id, None).is_err());
    check(policy::CREATOR_CHAIN_POLICY == [4, 0, 0, 1, 0, 2, 0, 3, 0]);
    check(policy::CREATOR_UNLOCK_POLICY == [2, 0, 3]);
    for from in 0..4 {
        check(policy::allows_creator_chain(from, 0));
    }
    for (from, to) in [(4, 0), (0, 1), (1, 2), (3, 3)] {
        check(!policy::allows_creator_chain(from, to));
    }
    let inclusion = &f.observation.provenance()[0].inclusion;
    let mut creator_header = f.observation.head_before().header.clone();
    creator_header.hash = inclusion.block_hash;
    creator_header.height = f.observation.pin().head_height + 10_000;
    check(checks::creator_inclusion(1, 0, inclusion, &creator_header).is_ok());
    check(checks::creator_inclusion(1, 2, inclusion, &creator_header).is_err());
    creator_header.hash = f.observation.pin().head_hash;
    check(checks::creator_inclusion(1, 0, inclusion, &creator_header).is_err());
    let policy = f.observation.policy();
    let identity = &f.observation.head_before().identity;
    let current = policy
        .source_id(OFFICIAL_TESTNET_ORIGIN, identity.chain_0_0_genesis)
        .unwrap();
    // Exact former source-v1 framing, retained as a compatibility boundary.
    let mut legacy = b"alephium-l2/current-fixed-funding-source/v1".to_vec();
    legacy.extend_from_slice(&(OFFICIAL_TESTNET_ORIGIN.len() as u32).to_be_bytes());
    legacy.extend_from_slice(OFFICIAL_TESTNET_ORIGIN.as_bytes());
    legacy.extend_from_slice(identity.chain_0_0_genesis.hash.as_slice());
    legacy.extend_from_slice(&[FundingModel::CanonicalFixedCurrentV1 as u8, 1, 0, 4]);
    legacy.extend_from_slice(&[2, 4, 7, 0, 4, 7, 1]);
    let minimum = policy.minimum_confirmations;
    for value in [minimum.chain, minimum.from_group, minimum.to_group] {
        legacy.extend_from_slice(&value.to_be_bytes());
    }
    // Golden v2 profile bytes inserted after the unchanged version policy.
    let domain_len = b"alephium-l2/current-fixed-funding-source/v1".len();
    let profile_offset = domain_len + 4 + OFFICIAL_TESTNET_ORIGIN.len() + 32 + 4 + 7;
    let mut expected_v2 = legacy.clone();
    expected_v2[domain_len - 1] = b'2';
    drop(expected_v2.splice(
        profile_offset..profile_offset,
        [4, 0, 0, 1, 0, 2, 0, 3, 0, 2, 0, 3],
    ));
    check(current != alephium_hash(&expected_v2));
    let mut expected_v3 = expected_v2.clone();
    expected_v3[domain_len - 1] = b'3';
    let head_policy_offset = profile_offset + 12;
    drop(expected_v3.splice(head_policy_offset..head_policy_offset, [1, 0, 0, 0, 32]));
    check(current != alephium_hash(&expected_v3));
    let mut expected_v4 = expected_v3.clone();
    expected_v4[domain_len - 1] = b'4';
    let lock_policy_offset = head_policy_offset + 5;
    drop(expected_v4.splice(lock_policy_offset..lock_policy_offset, [1, 2, 0, 1, 1]));
    check(policy::LOCK_TIME_POLICY == [1, 2, 0, 1, 1]);
    check(current == alephium_hash(&expected_v4));
    let legacy_id = alephium_hash(&legacy);
    check(legacy_id != current);
    let mut old_pin = f.observation.pin().clone();
    old_pin.source_id = legacy_id;
    let mut old_identity = identity.clone();
    old_identity.source_id = legacy_id;
    check(checks::identity(&old_pin, &old_identity, policy).is_err());
    old_pin.source_id = alephium_hash(&expected_v2);
    old_identity.source_id = old_pin.source_id;
    check(checks::identity(&old_pin, &old_identity, policy).is_err());
    old_pin.source_id = alephium_hash(&expected_v3);
    old_identity.source_id = old_pin.source_id;
    check(checks::identity(&old_pin, &old_identity, policy).is_err());
    count
}
