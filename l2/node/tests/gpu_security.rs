//! Bounded hardware parity checks, explicitly run by the local build coordinator.
#![cfg(feature = "cuda")]

use alephium_l2_gpu::{GpuBackend, RecoveredKey, RecoveryInput};
use alephium_l2_node::{
    config::{Config, VerificationBackend},
    development,
    protocol::CHAIN_ID,
    service,
};
use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope, TxLegacy};
use alloy_eips::{
    eip2718::{Decodable2718, Encodable2718},
    eip2930::{AccessList, AccessListItem},
};
use alloy_primitives::{Address, B256, Bytes, Signature, TxKind, U256, keccak256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;

const ORDER: &str = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";

fn input(envelope: &TxEnvelope) -> RecoveryInput {
    let signature = match envelope {
        TxEnvelope::Legacy(tx) => tx.signature(),
        TxEnvelope::Eip1559(tx) => tx.signature(),
        _ => panic!("fixture type is unsupported"),
    };
    let mut bytes = [0; 64];
    bytes[..32].copy_from_slice(&signature.r().to_be_bytes::<32>());
    bytes[32..].copy_from_slice(&signature.s().to_be_bytes::<32>());
    RecoveryInput {
        msg_hash: envelope.signature_hash().0,
        signature: bytes,
        recovery_id: i32::from(signature.v()),
    }
}

fn copied(input: &RecoveryInput) -> RecoveryInput {
    RecoveryInput {
        msg_hash: input.msg_hash,
        signature: input.signature,
        recovery_id: input.recovery_id,
    }
}

fn golden(input: &RecoveryInput) -> Option<RecoveredKey> {
    let signature = Signature::new(
        U256::from_be_slice(&input.signature[..32]),
        U256::from_be_slice(&input.signature[32..]),
        input.recovery_id == 1,
    );
    let key = signature
        .recover_from_prehash_secp256k1(&B256::from(input.msg_hash))
        .ok()?;
    let public_key = key.serialize_uncompressed();
    let hash = keccak256(&public_key[1..]);
    Some(RecoveredKey {
        public_key,
        address: hash[12..].try_into().unwrap(),
    })
}

fn fixtures() -> Vec<RecoveryInput> {
    let mut inputs = Vec::new();
    for scalar in 1..=8u64 {
        // Small published scalar values are deliberately development-only.
        let signer =
            PrivateKeySigner::from_bytes(&B256::from(U256::from(scalar).to_be_bytes::<32>()))
                .unwrap();
        for nonce in 0..4 {
            let envelope: TxEnvelope = if nonce % 2 == 0 {
                let tx = TxLegacy {
                    chain_id: Some(CHAIN_ID),
                    nonce,
                    gas_price: 2,
                    gas_limit: 21_000,
                    to: TxKind::Call(Address::repeat_byte(0x91)),
                    value: U256::from(scalar),
                    input: Bytes::new(),
                };
                let signature = signer.sign_hash_sync(&tx.signature_hash()).unwrap();
                tx.into_signed(signature).into()
            } else {
                let tx = TxEip1559 {
                    chain_id: CHAIN_ID,
                    nonce,
                    max_fee_per_gas: 5,
                    max_priority_fee_per_gas: 2,
                    gas_limit: 40_000,
                    to: TxKind::Call(Address::repeat_byte(0x92)),
                    value: U256::from(scalar),
                    input: Bytes::from(vec![0, 1, 2]),
                    access_list: AccessList(vec![AccessListItem {
                        address: Address::repeat_byte(0x93),
                        storage_keys: vec![B256::repeat_byte(0x42)],
                    }]),
                };
                let signature = signer.sign_hash_sync(&tx.signature_hash()).unwrap();
                tx.into_signed(signature).into()
            };
            let raw = envelope.encoded_2718();
            let decoded = TxEnvelope::decode_2718(&mut raw.as_slice()).unwrap();
            inputs.push(input(&decoded));
        }
    }
    assert!(inputs.iter().any(|entry| entry.recovery_id == 0));
    assert!(inputs.iter().any(|entry| entry.recovery_id == 1));
    inputs
}

fn assert_parity(gpu: &mut GpuBackend, inputs: &[RecoveryInput]) {
    let result = gpu.recover(inputs).expect("hardware recovery must succeed");
    assert!(result.len() == inputs.len(), "device output length changed");
    for (entry, recovered) in inputs.iter().zip(result) {
        let expected = golden(entry).expect("valid fixture must recover on CPU");
        let actual = recovered.expect("valid fixture must recover on GPU");
        assert!(
            actual.public_key == expected.public_key,
            "GPU key disagrees with CPU"
        );
        assert!(
            actual.address == expected.address,
            "GPU address disagrees with CPU"
        );
    }
}

fn scalar_input(r: U256, s: U256) -> RecoveryInput {
    let mut signature = [0; 64];
    signature[..32].copy_from_slice(&r.to_be_bytes::<32>());
    signature[32..].copy_from_slice(&s.to_be_bytes::<32>());
    RecoveryInput {
        msg_hash: [0; 32],
        signature,
        recovery_id: 0,
    }
}

#[test]
#[ignore = "requires explicitly authorized local NVIDIA CUDA hardware"]
fn recovery_matches_cpu_and_preserves_order_across_buffer_growth_and_reuse() {
    let mut gpu = GpuBackend::new(0).expect("owned CUDA device must initialize");
    let fixtures = fixtures();
    for count in [0, 1, 127, 128, 129, 1, 0, 128] {
        let inputs: Vec<_> = (0..count)
            .map(|index| copied(&fixtures[index % fixtures.len()]))
            .collect();
        assert_parity(&mut gpu, &inputs);
    }
    let oversized: Vec<_> = (0..=gpu.suggested_chunk())
        .map(|_| copied(&fixtures[0]))
        .collect();
    assert!(
        gpu.recover(&oversized).is_err(),
        "chunk overflow must reject before launch"
    );
    let mut invalid_id = copied(&fixtures[0]);
    invalid_id.recovery_id = 2;
    assert!(
        gpu.recover(&[invalid_id]).is_err(),
        "Ethereum parity cannot be recovery ID two"
    );
    // Host-side rejection must not corrupt the previously allocated buffers.
    assert_parity(&mut gpu, &fixtures);
}

#[test]
#[ignore = "requires explicitly authorized local NVIDIA CUDA hardware"]
fn invalid_scalars_and_non_curve_lift_are_none_amid_valid_inputs() {
    let order = U256::from_be_slice(&hex::decode(ORDER).unwrap());
    let half = alloy_consensus::crypto::SECP256K1N_HALF;
    let mut invalid = vec![
        scalar_input(U256::ZERO, U256::ONE),
        scalar_input(order, U256::ONE),
        scalar_input(U256::ONE, U256::ZERO),
        scalar_input(U256::ONE, order),
        scalar_input(U256::ONE, half + U256::ONE),
    ];
    // Find a low, in-range x coordinate that fails CPU curve lift/recovery.
    let non_curve = (1..=255u64)
        .map(|r| scalar_input(U256::from(r), U256::ONE))
        .find(|candidate| golden(candidate).is_none())
        .expect("small coordinate corpus must include a non-curve point");
    invalid.push(non_curve);
    let valid = fixtures();
    let mut mixed = Vec::new();
    for (index, rejected) in invalid.into_iter().enumerate() {
        mixed.push(copied(&valid[index]));
        mixed.push(rejected);
    }
    let mut gpu = GpuBackend::new(0).expect("owned CUDA device must initialize");
    let result = gpu
        .recover(&mixed)
        .expect("invalid individual signatures are not CUDA errors");
    assert!(result.len() == mixed.len());
    for (index, recovered) in result.iter().enumerate() {
        if index % 2 == 1 {
            assert!(
                recovered.is_none(),
                "invalid signature unexpectedly recovered"
            );
        } else {
            let actual = recovered.as_ref().expect("valid neighbor must recover");
            let expected = golden(&mixed[index]).unwrap();
            assert!(
                actual.public_key == expected.public_key,
                "mixed input order/key changed"
            );
            assert!(
                actual.address == expected.address,
                "mixed input address changed"
            );
        }
    }
}

#[test]
#[ignore = "explicit local CUDA startup failure check; creates only owned project-drive temp"]
fn invalid_device_fails_before_store_creation() {
    let directory = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let data = directory.path().join("data");
    let config = Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        data_dir: data.clone(),
        genesis: development::genesis(),
        min_gas_price: 0,
        max_checkpoint_bytes: alephium_l2_node::operator::MAX_CONTINUATION_CHECKPOINT_BYTES,
        rpc: Default::default(),
        verification_workers_per_cpu: 1,
        verification_backend: VerificationBackend::Cuda,
        gpu_device: usize::MAX,
    };
    match service::start(&config) {
        Err(_) => {}
        Ok((handle, worker)) => {
            tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap()
                .block_on(handle.stop());
            worker.join().unwrap();
            panic!("invalid CUDA ordinal unexpectedly started a node");
        }
    }
    assert!(!data.exists(), "failed CUDA initialization created a store");
}
