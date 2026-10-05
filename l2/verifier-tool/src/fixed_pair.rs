// SPDX-License-Identifier: GPL-3.0-or-later
// Public key derivative retains verification_key.ral GPL provenance.
// Ordinary Miller arithmetic is imported with its separate Apache-2.0 notice.
//! Source-bound certificate for the original fixed (alpha, beta) raw factor.
//! No proof, caller-supplied Miller value, VM admission flag or network access.
use ark_bn254::{Fq, Fq2, Fq12, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup, scalar_mul::double_and_add_affine};
use ark_ff::{AdditiveGroup, BigInteger, PrimeField};
use num_bigint::BigUint;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const SOLIDITY: &[u8] = include_bytes!(
    "../../node/fixtures/risc0-groth16/vendor/contracts/src/groth16/Groth16Verifier.sol"
);
const KEY: &[u8] = include_bytes!("../../contracts/alephium/verifier/verification_key.ral");
const RALPH: &[u8] = include_bytes!("../../contracts/alephium/verifier/fixed_pair.ral");
const PRODUCER: &[u8] = include_bytes!("ordinary_miller.rs");
const SOLIDITY_SHA256: &str = "14bdf78c8b6168b12a5235395d42b8daabb48ee29d49913bb06d20071f156fd6";
const KEY_SHA256: &str = "e35616b85888a5fc133d6c5f7bdc82eaeea59dd16b600fb9db0ba74019c052af";
const RALPH_SHA256: &str = "b1679b322f52e96da6da28f49610f41d0cc6486ce80b4c0036db682761e8a818";
const PRODUCER_SHA256: &str = "281ef5a4b7b51704cb7650e2c964ae65a88631c2e6931a60cb9b16e75198b7f0";
const FACTOR_SHA256: &str = "b12010a5875da4f9a705c17c13bf6472949d53a2ff32cd25d868b06fc95af915";
const FACTOR_NAMES: [&str; 12] = [
    "FIXED_PAIR_FACTOR_C0_B0_A0",
    "FIXED_PAIR_FACTOR_C0_B0_A1",
    "FIXED_PAIR_FACTOR_C0_B1_A0",
    "FIXED_PAIR_FACTOR_C0_B1_A1",
    "FIXED_PAIR_FACTOR_C0_B2_A0",
    "FIXED_PAIR_FACTOR_C0_B2_A1",
    "FIXED_PAIR_FACTOR_C1_B0_A0",
    "FIXED_PAIR_FACTOR_C1_B0_A1",
    "FIXED_PAIR_FACTOR_C1_B1_A0",
    "FIXED_PAIR_FACTOR_C1_B1_A1",
    "FIXED_PAIR_FACTOR_C1_B2_A0",
    "FIXED_PAIR_FACTOR_C1_B2_A1",
];

pub fn certify() -> Result<Value, String> {
    // This is mandatory even if the owning service already certified the key.
    crate::verification_key::certify()?;
    let sources = [
        ("Groth16Verifier.sol", SOLIDITY, SOLIDITY_SHA256),
        ("verification_key.ral", KEY, KEY_SHA256),
        ("fixed_pair.ral", RALPH, RALPH_SHA256),
        ("ordinary_miller.rs", PRODUCER, PRODUCER_SHA256),
    ];
    for (_, bytes, expected) in sources {
        if sha256(bytes) != expected {
            return Err("Fixed-pair source differs from its exact SHA-256 pin".into());
        }
    }
    let sol = source(SOLIDITY)?;
    let target = source(RALPH)?;
    let p = decimal(declaration(sol, "uint256 constant ", "q", true)?)?;
    let r = decimal(declaration(sol, "uint256 constant ", "r", true)?)?;
    if p.to_string() != Fq::MODULUS.to_string() || r.to_string() != Fr::MODULUS.to_string() {
        return Err("Fixed-pair moduli differ from independent Arkworks fields".into());
    }
    let cell = |name| -> Result<Fq, String> {
        let integer = decimal(declaration(sol, "uint256 constant ", name, true)?)?;
        if integer >= p {
            return Err("Fixed-pair coordinate is noncanonical before field conversion".into());
        }
        Ok(Fq::from_be_bytes_mod_order(&integer.to_bytes_be()))
    };
    // Independently parse Solidity, including its imaginary-first Fp2 order.
    let alpha = G1Affine::new_unchecked(cell("alphax")?, cell("alphay")?);
    let beta = G2Affine::new_unchecked(
        Fq2::new(cell("betax2")?, cell("betax1")?),
        Fq2::new(cell("betay2")?, cell("betay1")?),
    );
    if alpha.is_zero() || beta.is_zero() || !alpha.is_on_curve() || !beta.is_on_curve() {
        return Err("Fixed-pair source point is not finite and on curve".into());
    }
    if double_and_add_affine(&alpha, r.to_u64_digits()) != G1Projective::ZERO
        || double_and_add_affine(&beta, r.to_u64_digits()) != G2Projective::ZERO
        || !beta.is_in_correct_subgroup_assuming_on_curve()
    {
        return Err("Fixed-pair source fails its full unreduced order certificate".into());
    }
    let infinity = (
        G1Projective::ZERO.into_affine(),
        G2Projective::ZERO.into_affine(),
    );
    let mut fixed = [infinity; 4];
    fixed[1] = (alpha, beta);
    let factor = crate::ordinary_miller::miller_product(&fixed)?;
    // Independent full-integer normalized power, not Arkworks' raw Miller loop.
    crate::ordinary_miller::certify_normalized_product(&fixed, factor)?;
    let cells = flatten(factor);
    if sha256(&word_bytes(cells)) != FACTOR_SHA256 {
        return Err("Fixed-pair ordinary raw factor differs from its word hash".into());
    }
    if target
        .lines()
        .filter(|line| line.trim().starts_with("const "))
        .count()
        != 13
    {
        return Err("Fixed-pair target declaration count differs from its bound".into());
    }
    for (name, value) in FACTOR_NAMES.into_iter().zip(cells) {
        let integer = decimal(declaration(target, "const ", name, false)?)?;
        if integer >= p || integer.to_string() != value.into_bigint().to_string() {
            return Err("Fixed-pair target word differs from the ordinary raw result".into());
        }
    }
    if declaration(target, "const ", "FIXED_PAIR_MISMATCH", false)? != "1440" {
        return Err("Fixed-pair mismatch guard differs from its exact error".into());
    }
    certify_helpers(target)?;
    certify_factorization(alpha, beta, infinity, factor)?;
    // Only source/word hashes and bounded counts leave this certificate.
    Ok(json!({
        "schema": 1,
        "sources": sources.iter().map(|(name, bytes, hash)| json!({
            "name": name, "sha256": hash, "bytes": bytes.len()
        })).collect::<Vec<_>>(),
        "factorWordsSha256": FACTOR_SHA256,
        "logicalPairCount": 4, "runtimeQAccumulatorCount": 3,
        "fixedSlot": 1, "guardedOriginalWordCount": 6, "factorWordCount": 12,
        "canonicalFiniteCurveChecks": 2, "fullUnreducedOrderChecks": 2,
        "normalizedPairingOracleChecks": 1, "exactRawFactorizationChecks": 1,
        "mandatoryVerificationKeyCertificate": true,
        "ordinaryRawProduct": true, "finalExponentAppliedToFactor": false,
        "hostMillerValuePassedToVm": false, "callerAdmissionFlag": false,
        "compiledArtifactBindingRequired": true
    }))
}

fn certify_factorization(
    alpha: G1Affine,
    beta: G2Affine,
    infinity: (G1Affine, G2Affine),
    factor: Fq12,
) -> Result<(), String> {
    let p = G1Projective::generator().into_affine();
    let q = G2Projective::generator().into_affine();
    let p_mul = |n| double_and_add_affine(&p, [n]).into_affine();
    let q_mul = |n| double_and_add_affine(&q, [n]).into_affine();
    let all = [
        (p_mul(2_u64), q_mul(3_u64)),
        (alpha, beta),
        (p_mul(5), q_mul(7)),
        (p_mul(11), q_mul(13)),
    ];
    let mut variable = all;
    variable[1] = infinity;
    if crate::ordinary_miller::miller_product(&all)?
        != crate::ordinary_miller::miller_product(&variable)? * factor
    {
        return Err("Shared raw Miller loop differs from three pairs times fixed factor".into());
    }
    Ok(())
}

fn certify_helpers(text: &str) -> Result<(), String> {
    let compact: String = text
        .lines()
        .map(|line| line.split("//").next().unwrap_or(""))
        .flat_map(str::chars)
        .filter(|c| !c.is_whitespace())
        .collect();
    let contract = concat!(
        "AbstractContractRisc0FixedPair(fpModulus:U256)extends",
        "Risc0VerificationKey(fpModulus),Bn254Fp12(fpModulus){"
    );
    let guard = concat!(
        "fnfixedPairGuard(pairs:[U256;24])->(){letalpha=vkAlpha()letbeta=vkBeta()",
        "assert!(pairs[6]==alpha[0]&&pairs[7]==alpha[1]&&pairs[8]==beta[0]",
        "&&pairs[9]==beta[1]&&pairs[10]==beta[2]&&pairs[11]==beta[3],",
        "FIXED_PAIR_MISMATCH)}"
    );
    let factor = format!(
        "fnfixedPairFactor()->[U256;12]{{return[{}]}}",
        FACTOR_NAMES.join(",")
    );
    if !compact.contains(contract)
        || !compact.contains(guard)
        || !compact.contains(&factor)
        || compact.matches("fnfixedPairGuard(").count() != 1
        || compact.matches("fnfixedPairFactor(").count() != 1
    {
        return Err("Fixed-pair contract, original slot guard or factor layout differs".into());
    }
    Ok(())
}

fn source(bytes: &[u8]) -> Result<&str, String> {
    std::str::from_utf8(bytes).map_err(|_| "Fixed-pair source is not UTF-8".into())
}

fn declaration<'a>(
    text: &'a str,
    prefix: &str,
    name: &str,
    semicolon: bool,
) -> Result<&'a str, String> {
    let pattern = format!("{prefix}{name} = ");
    let mut values = text
        .lines()
        .filter_map(|line| line.trim().strip_prefix(&pattern));
    let value = values.next().ok_or("Missing fixed-pair named constant")?;
    if values.next().is_some() {
        return Err("Duplicate fixed-pair named constant".into());
    }
    if semicolon {
        value
            .strip_suffix(';')
            .ok_or_else(|| "Malformed fixed-pair constant".into())
    } else {
        Ok(value)
    }
}

fn decimal(value: &str) -> Result<BigUint, String> {
    if value.is_empty()
        || !value.bytes().all(|b| b.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err("Noncanonical fixed-pair decimal integer".into());
    }
    BigUint::parse_bytes(value.as_bytes(), 10).ok_or_else(|| "Invalid fixed-pair integer".into())
}

fn flatten(value: Fq12) -> [Fq; 12] {
    [
        value.c0.c0.c0,
        value.c0.c0.c1,
        value.c0.c1.c0,
        value.c0.c1.c1,
        value.c0.c2.c0,
        value.c0.c2.c1,
        value.c1.c0.c0,
        value.c1.c0.c1,
        value.c1.c1.c0,
        value.c1.c1.c1,
        value.c1.c2.c0,
        value.c1.c2.c1,
    ]
}

fn word_bytes(cells: [Fq; 12]) -> [u8; 384] {
    let mut words = [0; 384];
    for (index, value) in cells.into_iter().enumerate() {
        let bytes = value.into_bigint().to_bytes_be();
        let end = (index + 1) * 32;
        words[end - bytes.len()..end].copy_from_slice(&bytes);
    }
    words
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
