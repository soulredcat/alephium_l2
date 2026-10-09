//! Pure transport boundary checks; no client, endpoint or POST is started.
use super::*;

pub(crate) fn run_checks() -> usize {
    let expected = B256::repeat_byte(8);
    let valid = format!(
        "{{\"txId\":\"{}\",\"fromGroup\":0,\"toGroup\":0}}",
        hex::encode(expected)
    );
    let mut count = 0;
    let mut check = |ok: bool| {
        assert!(ok, "Preparation HTTP boundary failed; payload suppressed");
        count += 1;
    };
    check(checked_origin(OFFICIAL_TESTNET_ORIGIN).is_ok());
    check(checked_origin(&format!("{OFFICIAL_TESTNET_ORIGIN}/")).is_ok());
    for origin in [
        "http://node.testnet.alephium.org",
        "https://node.testnet.alephium.org:443",
        "https://node.testnet.alephium.org/path",
        "https://node.testnet.alephium.org?x=1",
        "https://user@node.testnet.alephium.org",
        "https://node.testnet.alephium.org#x",
        "https://node.mainnet.alephium.org",
    ] {
        check(checked_origin(origin).is_err());
    }
    check(parse_ack(valid.as_bytes(), expected) == Ok(expected));
    check(parse_ack(valid.as_bytes(), B256::repeat_byte(9)).is_err());
    check(parse_ack(&[], expected).is_err());
    check(parse_ack(&vec![b' '; 4097], expected).is_err());
    for malformed in [
        valid.replace("\"fromGroup\":0", "\"fromGroup\":1"),
        valid.replace("\"toGroup\":0", "\"toGroup\":1"),
        valid.replace(",\"toGroup\":0", ""),
        valid.replace("\"toGroup\":0", "\"toGroup\":0,\"extra\":0"),
        valid.replace("\"toGroup\":0", "\"toGroup\":0,\"toGroup\":0"),
        valid.replace("0808", "0X08"),
    ] {
        check(parse_ack(malformed.as_bytes(), expected).is_err());
    }
    count
}
