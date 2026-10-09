use super::*;

pub(super) fn run() -> usize {
    let expected = B256::repeat_byte(7);
    let valid = json!({"txId":hex::encode(expected),"fromGroup":0,"toGroup":0});
    let mut count = 0;
    let mut check = |ok: bool| {
        assert!(
            ok,
            "Submission boundary aggregate failed; values suppressed"
        );
        count += 1;
    };
    check(parse_ack(&serde_json::to_vec(&valid).unwrap(), expected) == Ok(expected));
    for changed in [
        json!({"txId":hex::encode(B256::repeat_byte(8)),"fromGroup":0,"toGroup":0}),
        json!({"txId":hex::encode(expected),"fromGroup":1,"toGroup":0}),
        json!({"txId":hex::encode(expected),"fromGroup":0,"toGroup":1}),
        json!({"txId":hex::encode(expected),"fromGroup":0,"toGroup":0,"unexpected":true}),
        json!({"txId":"00","fromGroup":0,"toGroup":0}),
        json!({"fromGroup":0,"toGroup":0}),
    ] {
        check(parse_ack(&serde_json::to_vec(&changed).unwrap(), expected).is_err());
    }
    check(checked_origin(OFFICIAL_TESTNET_ORIGIN, 1).is_ok());
    for (origin, network) in [
        (OFFICIAL_TESTNET_ORIGIN, 0),
        ("http://node.testnet.alephium.org", 1),
        ("https://user@node.testnet.alephium.org", 1),
        ("https://node.testnet.alephium.org/other", 1),
        ("https://node.testnet.alephium.org?override=1", 1),
        ("https://node.mainnet.alephium.org", 1),
    ] {
        check(checked_origin(origin, network).is_err());
    }
    count
}
