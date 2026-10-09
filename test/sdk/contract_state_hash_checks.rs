//! One boundary aggregate. Literal native framing is separate from the helper.
use alephium_l2_sdk::alephium::{
    alephium_hash, contract_initial_state_hash,
    read_node::{ContractAddress, ContractValue as Val, P2pkhAddress},
};
use alloy_primitives::{B256, I256, U256};

fn expected(code: B256, serialized: &[u8]) -> B256 {
    let mut bytes = code.as_slice().to_vec();
    bytes.extend_from_slice(serialized);
    alephium_hash(alephium_hash(&bytes).as_slice())
}

#[test]
fn contract_initial_state_hash_bulk() {
    let code = B256::repeat_byte(7);
    let mut count = 0;
    let mut check = |ok: bool| {
        assert!(ok, "Initial-state hash aggregate failed; values suppressed");
        count += 1;
    };
    for (fields, wire) in [
        (vec![], vec![0]),
        (vec![Val::U256(U256::ZERO)], vec![1, 2, 0]),
        (vec![Val::ByteVec(vec![])], vec![1, 3, 0]),
        (
            vec![Val::U256(U256::from(1)), Val::ByteVec(vec![0, 255])],
            vec![2, 2, 1, 3, 2, 0, 255],
        ),
    ] {
        check(contract_initial_state_hash(code, &fields).unwrap() == expected(code, &wire));
    }
    for (value, hex) in [
        (63u64, "3f"),
        (64, "4040"),
        (16383, "7fff"),
        (16384, "80004000"),
        (1073741823, "bfffffff"),
        (1073741824, "c040000000"),
    ] {
        let mut wire = vec![1, 2];
        wire.extend(hex::decode(hex).unwrap());
        check(
            contract_initial_state_hash(code, &[Val::U256(U256::from(value))]).unwrap()
                == expected(code, &wire),
        );
    }
    let mut maximum = vec![1, 2, 0xdc];
    maximum.extend([255; 32]);
    check(
        contract_initial_state_hash(code, &[Val::U256(U256::MAX)]).unwrap()
            == expected(code, &maximum),
    );
    for (length, prefix) in [
        (31usize, vec![31]),
        (32, vec![0x40, 32]),
        (8191, vec![0x5f, 0xff]),
        (8192, vec![0x80, 0, 0x20, 0]),
    ] {
        let data = vec![0x55; length];
        let mut wire = vec![1, 3];
        wire.extend(prefix);
        wire.extend(&data);
        check(
            contract_initial_state_hash(code, &[Val::ByteVec(data)]).unwrap()
                == expected(code, &wire),
        );
    }
    for (length, prefix) in [
        (31usize, vec![31]),
        (32, vec![0x40, 32]),
        (255, vec![0x40, 255]),
    ] {
        let mut wire = prefix;
        for _ in 0..length {
            wire.extend([2, 0]);
        }
        check(
            contract_initial_state_hash(code, &vec![Val::U256(U256::ZERO); length]).unwrap()
                == expected(code, &wire),
        );
    }
    check(contract_initial_state_hash(code, &vec![Val::U256(U256::ZERO); 256]).is_err());
    check(contract_initial_state_hash(code, &[Val::ByteVec(vec![0; 16378])]).is_ok());
    check(contract_initial_state_hash(code, &[Val::ByteVec(vec![0; 16379])]).is_err());
    check(contract_initial_state_hash(code, &[Val::ByteVec(vec![0; 16384])]).is_err());
    check(
        contract_initial_state_hash(
            code,
            &[Val::ByteVec(vec![0; 8190]), Val::ByteVec(vec![0; 8190])],
        )
        .is_err(),
    );
    let mut id = [1; 32];
    id[31] = 0;
    for unsupported in [
        Val::Bool(false),
        Val::I256(I256::ZERO),
        Val::Array(vec![]),
        Val::P2pkhAddress(P2pkhAddress::from_hash(code)),
        Val::ContractAddress(ContractAddress::from_id(id.into()).unwrap()),
    ] {
        check(contract_initial_state_hash(code, &[unsupported]).is_err());
    }
    let fields = [Val::U256(U256::from(1)), Val::ByteVec(vec![2])];
    let hash = contract_initial_state_hash(code, &fields).unwrap();
    check(hash != contract_initial_state_hash(B256::repeat_byte(8), &fields).unwrap());
    check(
        hash != contract_initial_state_hash(code, &[fields[1].clone(), fields[0].clone()]).unwrap(),
    );
    check(
        hash != contract_initial_state_hash(code, &[Val::U256(U256::from(2)), fields[1].clone()])
            .unwrap(),
    );
    check(contract_initial_state_hash(B256::ZERO, &[]).unwrap() == expected(B256::ZERO, &[0]));
    println!("Initial-state hash aggregate: PASS checks={count}; synthetic metadata only");
}
