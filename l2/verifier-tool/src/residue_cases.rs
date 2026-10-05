//! Same historical receipt plus a versioned, untrusted algebraic witness.
use crate::{
    cases::{Case, Expected, FP_MODULUS},
    ordinary_miller, receipt_cases, residue_witness,
};
use ark_bn254::{Fq, Fq6, Fq12};
use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
use num_bigint::BigUint;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const MAX_CASES: usize = receipt_cases::MAX_CASES + 7;

fn witness() -> Result<[u8; 577], String> {
    let pairs = receipt_cases::official_pair_inputs()?;
    let product = ordinary_miller::miller_product(&pairs)?;
    ordinary_miller::certify_normalized_product(&pairs, product)?;
    residue_witness::generate(product)
}

pub fn evidence() -> Result<Value, String> {
    let encoded = witness()?;
    Ok(
        json!({"version": 1, "encoding": "01 || 18 canonical BE32 Fp words",
        "auxiliaryBytes": encoded.len(), "auxiliarySha256": hex::encode(Sha256::digest(encoded)),
        "rootInverseFp12Words": 12, "correctionFp6Words": 6,
        "canonicalReceiptInputBytes": 901, "completeTransactionBytesMeasured": false,
        "rawMillerProducer": "pinned ordinary homogeneous Gnark Crypto; no normalization",
        "normalizedProductComparedWithArkworks": true,
        "encodedWitnessEquationVerifiedWithGeneralPower": true,
        "targetMustRecomputeMillerAndVerifyWitness": true,
        "hostMembershipBooleanPassedToVm": false}),
    )
}

pub fn corpus() -> Result<Vec<Case>, String> {
    let auxiliary = witness()?;
    let mut cases = receipt_cases::corpus()?;
    for case in &mut cases {
        case.args.push(hex::encode(auxiliary));
    }
    let original = cases.first().ok_or("Empty receipt corpus")?.args.clone();
    let mut add = |name, bytes: &[u8], assertion| {
        let mut args = original.clone();
        args[3] = hex::encode(bytes);
        cases.push(Case {
            name,
            op: 0,
            args,
            expected: Expected::Assertion(assertion),
        });
    };
    add("residue-short-auxiliary", &auxiliary[..576], 1430);
    let mut wrong_version = auxiliary;
    wrong_version[0] = 2;
    add("residue-wrong-encoding-version", &wrong_version, 1431);
    let mut zero_root = auxiliary;
    zero_root[1..385].fill(0);
    add("residue-zero-root-inverse", &zero_root, 1432);
    let mut all_zero = [0; 577];
    all_zero[0] = 1;
    add("residue-all-zero-witness-forgery", &all_zero, 1432);
    let p = Fq::MODULUS.to_bytes_be();
    let mut invalid_root = auxiliary;
    invalid_root[1 + 11 * 32..1 + 12 * 32].copy_from_slice(&p);
    add(
        "residue-noncanonical-highest-root-coefficient",
        &invalid_root,
        1000,
    );
    let mut invalid_correction = auxiliary;
    invalid_correction[1 + 17 * 32..1 + 18 * 32].copy_from_slice(&p);
    add(
        "residue-noncanonical-highest-correction-coefficient",
        &invalid_correction,
        1000,
    );
    let mut changed = auxiliary;
    // Change a canonical correction coefficient and prove the supplied equation
    // no longer holds for the independently generated nonzero Miller product.
    let value = Fq::from_be_bytes_mod_order(&changed[385..417]) + Fq::ONE;
    changed[385..417].copy_from_slice(&value.into_bigint().to_bytes_be());
    let pairs = receipt_cases::official_pair_inputs()?;
    let product = ordinary_miller::miller_product(&pairs)?;
    if equation(product, &changed)? {
        return Err("Changed auxiliary unexpectedly satisfies the residue equation".into());
    }
    add("residue-altered-correction-equation", &changed, 1404);
    if cases.len() != MAX_CASES || cases.iter().any(|case| case.args.len() != 4) {
        return Err("Residue receipt corpus differs from its fixed bounds".into());
    }
    Ok(cases)
}

fn equation(f: Fq12, encoded: &[u8; 577]) -> Result<bool, String> {
    let words: Vec<_> = encoded[1..]
        .chunks_exact(32)
        .map(Fq::from_be_bytes_mod_order)
        .collect();
    let fp6 = |offset| {
        Fq6::new(
            ark_bn254::Fq2::new(words[offset], words[offset + 1]),
            ark_bn254::Fq2::new(words[offset + 2], words[offset + 3]),
            ark_bn254::Fq2::new(words[offset + 4], words[offset + 5]),
        )
    };
    let root = Fq12::new(fp6(0), fp6(6));
    let p = BigUint::parse_bytes(FP_MODULUS.as_bytes(), 10).ok_or("Invalid fixed base modulus")?;
    let lambda = BigUint::from(29_793_968_203_157_093_288_u128) + p.pow(3) - p.pow(2) + &p;
    Ok(f * Fq12::new(fp6(12), Fq6::ZERO) * root.pow(lambda.to_u64_digits()) == Fq12::ONE)
}
