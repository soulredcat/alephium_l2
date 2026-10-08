//! One pure response-boundary bundle. No client construction, network or signing.
use super::*;
use alloy_primitives::{B256, U256};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::io::Cursor;

fn hash(byte: u8) -> String {
    hex::encode([byte; 32])
}
fn parse<T: DeserializeOwned>(value: &Value) -> Result<T, ReadNodeError> {
    transport::decode_response(&serde_json::to_vec(value).unwrap())
}
fn config(provenance: GenesisProvenance) -> ReadNodeConfig {
    ReadNodeConfig::official_testnet(
        B256::repeat_byte(1),
        GenesisPin {
            hash: B256::repeat_byte(2),
            provenance,
        },
    )
}
fn identity_fixture(config: &ReadNodeConfig) -> IdentityObservation {
    identity::validate(
        config,
        OFFICIAL_TESTNET_ORIGIN,
        parse(&json!({"version":"v4.7.1"})).unwrap(),
        parse(&json!({"networkId":1,"groups":4,"groupNumPerBroker":4,"numZerosAtLeastInHash":18}))
            .unwrap(),
        parse(&json!({"selfReady":true,"synced":true})).unwrap(),
    )
    .unwrap()
}
fn header(hash_byte: u8, height: i32) -> Value {
    let mut deps = vec![hash(0); 7];
    if height != 0 {
        deps[3] = hash(2);
    }
    json!({"hash":hash(hash_byte),"height":height,"timestamp":1000,"chainFrom":0,"chainTo":0,"deps":deps})
}
fn status(kind: &str) -> Value {
    json!({"type":kind,"blockHash":hash(3),"txIndex":0,
        "chainConfirmations":7,"fromGroupConfirmations":11,"toGroupConfirmations":13})
}
fn transaction(success: bool) -> Value {
    // Synthetic REST identity fields; no transaction validity/execution claim.
    json!({"unsigned":{"txId":hash(4),"version":0,"networkId":1},
        "scriptExecutionOk":success,"generatedOutputs":[],"inputSignatures":[],"scriptSignatures":[]})
}
fn contract_state(address: &ContractAddress, code: &[u8]) -> Value {
    json!({"address":address.as_str(),"bytecode":hex::encode(code),
        "codeHash":hex::encode(crate::alephium::alephium_hash(code)),
        "immFields":[{"type":"ByteVec","value":"000102"}],
        "mutFields":[{"type":"U256","value":"7"},{"type":"Bool","value":true}],
        "asset":{"attoAlphAmount":"1000","tokens":[]}})
}

pub(crate) fn run_checks() -> usize {
    let mut checks = 0;
    macro_rules! check {
        ($condition:expr $(,)?) => {{
            assert!($condition);
            checks += 1;
        }};
    }
    check!(transport::parse_origin(OFFICIAL_TESTNET_ORIGIN).is_ok());
    let expected = OFFICIAL_TESTNET_ORIGIN;
    check!(canonical_origin(expected).unwrap() == expected);
    check!(canonical_origin(&format!("{expected}/")).unwrap() == expected);
    for bad in [
        "http://node.testnet.alephium.org",
        "https://127.0.0.1",
        "https://localhost",
        "https://localhost.",
        "https://node.local.",
        "https://a:b@node.testnet.alephium.org",
        "https://node.testnet.alephium.org:12973",
        "https://node.testnet.alephium.org/path",
        "https://node.testnet.alephium.org?q=1",
        "https://node.testnet.alephium.org#fragment",
        " https://node.testnet.alephium.org",
        "https://node.testnet.alephium.org\\evil",
    ] {
        check!(transport::parse_origin(bad).is_err());
        check!(canonical_origin(bad).is_err());
    }
    check!(transport::check_status(200).is_ok());
    for status in [201, 204, 301, 302, 307, 400, 403, 404, 500] {
        check!(transport::check_status(status).is_err());
    }
    let valid = br#"{"version":"v4.7.1"}"#;
    for length in 0..valid.len() {
        check!(transport::decode_response::<identity::Version>(&valid[..length]).is_err());
    }
    check!(transport::decode_response::<identity::Version>(br#"{"version":"v4.7.1"} {}"#).is_err());
    let oversized = vec![b' '; MAX_RESPONSE_BYTES + 1];
    check!(transport::decode_response::<Value>(&oversized).is_err());
    check!(transport::read_bounded(&mut Cursor::new(&oversized)).is_err());
    check!(
        transport::read_bounded(&mut Cursor::new(&oversized[..MAX_RESPONSE_BYTES]))
            .unwrap()
            .len()
            == MAX_RESPONSE_BYTES
    );

    let independent = identity_fixture(&config(GenesisProvenance::Independent));
    let diagnostic = identity_fixture(&config(GenesisProvenance::DiagnosticObserved));
    checks += creator_transactions::tests::run_checks(&diagnostic);
    check!(independent.chain_0_0_genesis.provenance == GenesisProvenance::Independent);
    check!(diagnostic.chain_0_0_genesis.provenance == GenesisProvenance::DiagnosticObserved);
    for version in ["v4.7.0", "v4.7.1", "4.7.1", "v4.7.10", "v4.7.1-unsafe"] {
        let result = identity::validate(
            &config(GenesisProvenance::Independent),
            OFFICIAL_TESTNET_ORIGIN,
            parse(&json!({"version":version})).unwrap(),
            parse(
                &json!({"networkId":1,"groups":4,"groupNumPerBroker":4,"numZerosAtLeastInHash":18}),
            )
            .unwrap(),
            parse(&json!({"selfReady":true,"synced":true})).unwrap(),
        );
        check!(result.is_ok() == matches!(version, "v4.7.0" | "v4.7.1"));
    }
    for (network, groups, ready, synced) in [
        (0, 4, true, true),
        (1, 3, true, true),
        (1, 4, false, true),
        (1, 4, true, false),
    ] {
        check!(identity::validate(&config(GenesisProvenance::Independent), OFFICIAL_TESTNET_ORIGIN,
            parse(&json!({"version":"v4.7.1"})).unwrap(),
            parse(&json!({"networkId":network,"groups":groups,"groupNumPerBroker":4,"numZerosAtLeastInHash":18})).unwrap(),
            parse(&json!({"selfReady":ready,"synced":synced})).unwrap()).is_err());
    }
    let genesis = parse::<blocks::Header>(&header(2, 0))
        .unwrap()
        .checked(B256::repeat_byte(2), 0)
        .unwrap();
    check!(genesis.parent().is_none());
    check!(client::check_genesis(&independent, &genesis).is_ok());
    let wrong_genesis = parse::<blocks::Header>(&header(9, 0))
        .unwrap()
        .checked(B256::repeat_byte(9), 0)
        .unwrap();
    check!(client::check_genesis(&independent, &wrong_genesis).is_err());
    let candidates =
        blocks::candidates(parse(&json!({"headers":[hash(8),hash(3),hash(9)]})).unwrap()).unwrap();
    check!(
        blocks::select_unique(&candidates, &[false, true, false]).unwrap() == B256::repeat_byte(3)
    );
    for membership in [
        &[true, true, false][..],
        &[false, false, false][..],
        &[false, true][..],
    ] {
        check!(blocks::select_unique(&candidates, membership).is_err());
    }
    check!(blocks::candidates(parse(&json!({"headers":[hash(3),hash(3)]})).unwrap()).is_err());
    check!(
        parse::<blocks::Hashes>(&json!({"headers":vec![hash(3);MAX_CANONICAL_CANDIDATES+1]}))
            .is_err()
    );
    let child = parse::<blocks::Header>(&header(3, 1))
        .unwrap()
        .checked(B256::repeat_byte(3), 1)
        .unwrap();
    check!(child.parent() == Some(B256::repeat_byte(2)));
    for (key, value) in [
        ("chainFrom", json!(1)),
        ("chainTo", json!(1)),
        ("height", json!(2)),
        ("hash", json!(hash(9))),
        ("timestamp", json!(-1)),
        ("deps", json!(vec![hash(2); 6])),
    ] {
        let mut changed = header(3, 1);
        changed[key] = value;
        check!(
            parse::<blocks::Header>(&changed)
                .and_then(|h| h.checked(B256::repeat_byte(3), 1))
                .is_err()
        );
    }
    let mut bad_parent = header(3, 1);
    bad_parent["deps"][3] = json!(hash(0));
    check!(
        parse::<blocks::Header>(&bad_parent)
            .unwrap()
            .checked(B256::repeat_byte(3), 1)
            .is_err()
    );

    let confirmed = match parse::<transactions::Status>(&status("Confirmed"))
        .unwrap()
        .checked()
        .unwrap()
    {
        TransactionStatus::Confirmed(value) => value,
        _ => panic!("Expected confirmed fixture"),
    };
    check!(
        confirmed.confirmations.chain == 7
            && confirmed.confirmations.from_group == 11
            && confirmed.confirmations.to_group == 13
    );
    let conflicted = parse::<transactions::Status>(&status("Conflicted"))
        .unwrap()
        .checked()
        .unwrap();
    check!(matches!(conflicted, TransactionStatus::Conflicted(_)));
    check!(transactions::same_inclusion(&confirmed, conflicted).is_err());
    for kind in ["MemPooled", "TxNotFound"] {
        check!(
            parse::<transactions::Status>(&json!({"type":kind}))
                .unwrap()
                .checked()
                .is_ok()
        );
    }
    for bad in [
        json!({"type":"Accepted"}),
        json!({"type":"Confirmed"}),
        json!({"type":"Confirmed","blockHash":hash(3),"txIndex":0,"chainConfirmations":-1,"fromGroupConfirmations":1,"toGroupConfirmations":1}),
    ] {
        check!(
            parse::<transactions::Status>(&bad)
                .and_then(|s| s.checked())
                .is_err()
        );
    }
    let tx = transaction(true);
    check!(
        transactions::exact_transaction(
            B256::repeat_byte(4),
            0,
            std::slice::from_ref(&tx),
            &tx,
            &[]
        )
        .unwrap()
    );
    let failed = transaction(false);
    check!(
        !transactions::exact_transaction(
            B256::repeat_byte(4),
            0,
            std::slice::from_ref(&failed),
            &failed,
            &[]
        )
        .unwrap()
    );
    check!(
        transactions::exact_transaction(
            B256::repeat_byte(4),
            1,
            std::slice::from_ref(&tx),
            &tx,
            &[]
        )
        .is_err()
    );
    check!(
        transactions::exact_transaction(
            B256::repeat_byte(4),
            0,
            std::slice::from_ref(&tx),
            &failed,
            &[]
        )
        .is_err()
    );
    check!(
        transactions::exact_transaction(
            B256::repeat_byte(4),
            0,
            &[tx.clone(), tx.clone()],
            &tx,
            &[]
        )
        .is_err()
    );
    check!(
        transactions::exact_transaction(
            B256::repeat_byte(4),
            0,
            std::slice::from_ref(&tx),
            &tx,
            &[B256::repeat_byte(4)]
        )
        .is_err()
    );
    let mut missing = tx.clone();
    missing.as_object_mut().unwrap().remove("scriptExecutionOk");
    check!(
        transactions::exact_transaction(
            B256::repeat_byte(4),
            0,
            std::slice::from_ref(&missing),
            &missing,
            &[]
        )
        .is_err()
    );

    for amount in ["", "01", "+1", "-1", "0x1", " 1", "1.0", &"9".repeat(79)] {
        check!(wire::amount(amount).is_err());
    }
    check!(wire::amount("0").unwrap() == U256::ZERO);
    for hex in ["0x00", "Ff", "0", "gg"] {
        check!(wire::hex_bytes(hex, 32).is_err());
    }
    let owner = (0..=255)
        .map(|b| P2pkhAddress::from_hash(B256::repeat_byte(b)))
        .find(|a| a.group() == 0 && (crate::alephium::codec::owner_hint(a.hash()) as i32) < 0)
        .unwrap();
    check!(P2pkhAddress::parse(owner.as_str()).unwrap() == owner);
    check!(P2pkhAddress::parse(&format!("1{}", owner.as_str())).is_err());
    check!(P2pkhAddress::parse("0invalid").is_err());
    let mut contract_id = [7; 32];
    contract_id[31] = 0;
    let address = ContractAddress::from_id(B256::from(contract_id)).unwrap();
    check!(ContractAddress::parse(address.as_str()).unwrap() == address);
    check!(P2pkhAddress::parse(address.as_str()).is_err());
    let hint = crate::alephium::codec::owner_hint(owner.hash());
    let response = json!({"utxos":[{"ref":{"hint":hint as i32,"key":hash(8)},"amount":"1000"}]});
    let unanchored = parse::<utxos::Utxos>(&response)
        .unwrap()
        .checked(&owner, diagnostic.clone())
        .unwrap();
    let query = client::creator_query(unanchored.outputs[0].reference).unwrap();
    check!(query[0].1 == (hint as i32).to_string() && query[1].1 == hash(8));
    check!(parse::<wire::Hash>(&json!(hash(8))).unwrap().0 == B256::repeat_byte(8));
    check!(parse::<wire::Hash>(&json!({"txId":hash(8)})).is_err());
    check!(
        unanchored.outputs[0].reference.hint == hint
            && (unanchored.outputs[0].reference.hint as i32) < 0
    );
    check!(unanchored.view == FundingView::LatestIncludingMempoolUnanchored);
    check!(
        unanchored.outputs[0].lock_time_ms.is_none()
            && unanchored.outputs[0].additional_data.is_none()
    );
    check!(
        unanchored.identity.chain_0_0_genesis.provenance == GenesisProvenance::DiagnosticObserved
    );
    let mut bad = response.clone();
    bad["utxos"][0]["amount"] = json!("01");
    check!(parse::<utxos::Utxos>(&bad).is_err());

    let code = vec![1, 2, 3]; // Synthetic bytes: no VM/compiler validity claim.
    let code_hash = crate::alephium::alephium_hash(&code);
    let state = contract_state(&address, &code);
    let observed = parse::<contract::State>(&state)
        .unwrap()
        .checked(diagnostic.clone(), &address, code_hash, code.clone(), 36)
        .unwrap();
    check!(observed.view == ContractView::CurrentUnanchored && observed.field_data_bytes == 36);
    check!(observed.identity.chain_0_0_genesis.provenance == GenesisProvenance::DiagnosticObserved);
    check!(
        parse::<contract::State>(&state)
            .unwrap()
            .checked(diagnostic.clone(), &address, code_hash, code.clone(), 35)
            .is_err()
    );
    check!(
        parse::<contract::State>(&state)
            .unwrap()
            .checked(
                diagnostic.clone(),
                &address,
                B256::repeat_byte(99),
                code.clone(),
                36
            )
            .is_err()
    );
    check!(
        parse::<contract::State>(&state)
            .unwrap()
            .checked(diagnostic.clone(), &address, code_hash, vec![3, 2, 1], 36)
            .is_err()
    );
    for field in [
        json!({"type":"Unknown","value":true}),
        json!({"type":"I256","value":"-0"}),
        json!({"type":"U256","value":"01"}),
        json!({"type":"ByteVec","value":"Ff"}),
    ] {
        let mut changed = state.clone();
        changed["mutFields"][0] = field;
        check!(
            parse::<contract::State>(&changed)
                .and_then(|s| s.checked(diagnostic.clone(), &address, code_hash, code.clone(), 100))
                .is_err()
        );
    }
    checks
}
