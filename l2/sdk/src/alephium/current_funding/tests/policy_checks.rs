//! Pure static-profile binding regressions; no network or signing operation.
use super::fixture;
use crate::alephium::{
    current_funding::{checks, validate_current_unsigned},
    read_node::{GenesisPin, GenesisProvenance, NodeVersion, OFFICIAL_TESTNET_ORIGIN},
};
use alloy_primitives::B256;

pub(super) fn run_checks() -> usize {
    let f = fixture::build(None);
    let policy = f.observation.policy();
    let identity = &f.observation.head_before().identity;
    let genesis = identity.chain_0_0_genesis;
    let source = policy.source_id(OFFICIAL_TESTNET_ORIGIN, genesis).unwrap();
    let mut count = 0;
    let mut check = |ok: bool| {
        assert!(
            ok,
            "Current-funding source policy check failed; payload suppressed"
        );
        count += 1;
    };
    check(source != B256::ZERO && source == f.observation.pin().source_id);
    check(checks::identity(f.observation.pin(), identity, policy).is_ok());
    check(
        policy
            .source_id(&format!("{OFFICIAL_TESTNET_ORIGIN}/"), genesis)
            .unwrap()
            == source,
    );
    // Allowed policy is stable across both reviewed server version reports.
    let mut version = identity.clone();
    version.version = NodeVersion::V4_7_0;
    check(checks::identity(f.observation.pin(), &version, policy).is_ok());
    version.version = NodeVersion::V4_7_1;
    check(checks::identity(f.observation.pin(), &version, policy).is_ok());
    for component in 0..3 {
        let mut changed = policy.clone();
        match component {
            0 => changed.minimum_confirmations.chain -= 1,
            1 => changed.minimum_confirmations.from_group -= 1,
            _ => changed.minimum_confirmations.to_group -= 1,
        }
        check(changed.source_id(OFFICIAL_TESTNET_ORIGIN, genesis).unwrap() != source);
        check(checks::identity(f.observation.pin(), identity, &changed).is_err());
        let mut sealed = fixture::build(None);
        sealed.observation.policy = changed;
        check(
            validate_current_unsigned(&sealed.operation, &sealed.observation, &sealed.spend)
                .is_err(),
        );
    }
    let mut missing_pin = f.observation.pin().clone();
    missing_pin.source_id = B256::ZERO;
    check(checks::identity(&missing_pin, identity, policy).is_err());
    let mut missing_identity = identity.clone();
    missing_identity.source_id = B256::ZERO;
    check(checks::identity(f.observation.pin(), &missing_identity, policy).is_err());
    let mut arbitrary = identity.clone();
    arbitrary.source_id = B256::repeat_byte(88);
    let mut same_arbitrary_pin = f.observation.pin().clone();
    same_arbitrary_pin.source_id = arbitrary.source_id;
    check(checks::identity(&same_arbitrary_pin, &arbitrary, policy).is_err());
    let alternate = "https://alternate.example.org";
    check(policy.source_id(alternate, genesis).unwrap() != source);
    let mut alternate_identity = identity.clone();
    alternate_identity.origin = alternate.into();
    check(checks::identity(f.observation.pin(), &alternate_identity, policy).is_err());
    let different_genesis = GenesisPin {
        hash: B256::repeat_byte(87),
        ..genesis
    };
    check(
        policy
            .source_id(OFFICIAL_TESTNET_ORIGIN, different_genesis)
            .unwrap()
            != source,
    );
    for invalid_genesis in [
        GenesisPin {
            hash: B256::ZERO,
            ..genesis
        },
        GenesisPin {
            provenance: GenesisProvenance::DiagnosticObserved,
            ..genesis
        },
    ] {
        check(
            policy
                .source_id(OFFICIAL_TESTNET_ORIGIN, invalid_genesis)
                .is_err(),
        );
    }
    for invalid_origin in [
        "http://node.testnet.alephium.org",
        "https://node.testnet.alephium.org:443",
        "https://NODE.TESTNET.ALEPHIUM.ORG",
        "https://user@node.testnet.alephium.org",
        "https://node.testnet.alephium.org/path",
        "https://node.testnet.alephium.org?query=1",
        "https://node.testnet.alephium.org#fragment",
        "https://node.testnet.alephium.org\\path",
        " https://node.testnet.alephium.org",
        "https://127.0.0.1",
    ] {
        check(policy.source_id(invalid_origin, genesis).is_err());
    }
    count
}
