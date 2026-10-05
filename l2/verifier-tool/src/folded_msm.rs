//! Exact-source certificate for the receipt's three immutable MSM terms.
//! No proof input, compilation, network access, or target admission flag.
use ark_bn254::{Fq, Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup, scalar_mul::double_and_add_affine};
use ark_ff::{AdditiveGroup, BigInteger, PrimeField};
use num_bigint::BigUint;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const SOLIDITY: &[u8] = include_bytes!(
    "../../node/fixtures/risc0-groth16/vendor/contracts/src/groth16/Groth16Verifier.sol"
);
const CONTROL: &[u8] =
    include_bytes!("../../node/fixtures/risc0-groth16/vendor/contracts/src/groth16/ControlID.sol");
const KEY: &[u8] = include_bytes!("../../contracts/alephium/verifier/verification_key.ral");
const CLAIMS: &[u8] = include_bytes!("../../contracts/alephium/verifier/receipt_claims.ral");
const SOLIDITY_SHA256: &str = "14bdf78c8b6168b12a5235395d42b8daabb48ee29d49913bb06d20071f156fd6";
const CONTROL_SHA256: &str = "753535e844a84a28b275fe21bd4c30022266b27bcdaa9b189220dece220accfa";
const KEY_SHA256: &str = "e35616b85888a5fc133d6c5f7bdc82eaeea59dd16b600fb9db0ba74019c052af";
const CLAIMS_SHA256: &str = "6fcfdbe9ba98db0a93eb0f4f9a0d1e9a72bae728f907733b55e17cc838354511";
const BASE_SHA256: &str = "7024f543aa1d90e857c7ba045265d7589c1278aff1263483821526c83b55544f";
const FIXED_SCALARS: [&str; 3] = [
    "87308967599310181518572122949978443173",
    "114477420512449248120330787787984922587",
    "1930158958971974673407180959543112854198801264531668442085542093806106933952",
];

pub fn certify() -> Result<Value, String> {
    let sources = [
        ("Groth16Verifier.sol", SOLIDITY, SOLIDITY_SHA256),
        ("ControlID.sol", CONTROL, CONTROL_SHA256),
        ("verification_key.ral", KEY, KEY_SHA256),
        ("receipt_claims.ral", CLAIMS, CLAIMS_SHA256),
    ];
    for (_, bytes, expected) in sources {
        if sha256(bytes) != expected {
            return Err("Receipt MSM source differs from its exact SHA-256 pin".into());
        }
    }
    let sol = source(SOLIDITY)?;
    let control = source(CONTROL)?;
    let claims = source(CLAIMS)?;
    let p = decimal(declaration(sol, "uint256 constant ", "q", true)?)?;
    let r = decimal(declaration(sol, "uint256 constant ", "r", true)?)?;
    if p.to_string() != Fq::MODULUS.to_string() || r.to_string() != Fr::MODULUS.to_string() {
        return Err("Receipt MSM moduli differ from independent Arkworks fields".into());
    }
    let root = solidity_bytes32(control, "CONTROL_ROOT")?;
    let control_id = solidity_bytes32(control, "BN254_CONTROL_ID")?;
    let target_root = declaration(claims, "const ", "RECEIPT_CONTROL_ROOT", false)?;
    if target_root != format!("#{}", hex::encode(root)) {
        return Err("Receipt MSM control root differs from the pinned source".into());
    }
    let scalars = [
        BigUint::from_bytes_le(&root[..16]),
        BigUint::from_bytes_le(&root[16..]),
        BigUint::from_bytes_be(&control_id),
    ];
    for (scalar, expected) in scalars.iter().zip(FIXED_SCALARS) {
        if scalar >= &r || scalar != &decimal(expected)? {
            return Err("Receipt MSM fixed scalar or endian mapping differs".into());
        }
    }
    if decimal(declaration(
        claims,
        "const ",
        "RECEIPT_BN254_CONTROL_ID",
        false,
    )?)? != scalars[2]
    {
        return Err("Receipt MSM control ID differs from its pinned BE integer".into());
    }
    let mut points = Vec::with_capacity(6);
    for index in 0..6 {
        let x = decimal(declaration(
            sol,
            "uint256 constant ",
            &format!("IC{index}x"),
            true,
        )?)?;
        let y = decimal(declaration(
            sol,
            "uint256 constant ",
            &format!("IC{index}y"),
            true,
        )?)?;
        points.push(admit_point(&x, &y, &p, &r)?);
    }
    let mut base = points[0].into_group();
    for (index, scalar) in [1, 2, 5].into_iter().zip(&scalars) {
        // Full nonnegative integer multiplication: never construct Fr scalars.
        base += double_and_add_affine(&points[index], scalar.to_u64_digits());
    }
    let derived = base.into_affine();
    let x = decimal(declaration(claims, "const ", "RECEIPT_MSM_BASE_X", false)?)?;
    let y = decimal(declaration(claims, "const ", "RECEIPT_MSM_BASE_Y", false)?)?;
    let target = admit_point(&x, &y, &p, &r)?;
    if derived != target || sha256(&point_words(target)) != BASE_SHA256 {
        return Err(
            "Receipt MSM fixed base differs from independent full-integer derivation".into(),
        );
    }
    certify_mapping(claims)?;
    // Only source/base hashes and bounded counts leave this certificate.
    Ok(json!({
        "schema": 1,
        "sources": sources.iter().map(|(name, bytes, hash)| json!({
            "name": name, "sha256": hash, "bytes": bytes.len()
        })).collect::<Vec<_>>(),
        "baseWordsSha256": BASE_SHA256,
        "publicSignalCount": 5, "originalIcPointCount": 6,
        "fixedScalarCount": 3, "variableScalarCount": 2,
        "canonicalFiniteCurveChecks": 7, "fullUnreducedOrderChecks": 7,
        "targetNormalizationCount": 1, "exactHelperAndCallMappings": 2
    }))
}

fn source(bytes: &[u8]) -> Result<&str, String> {
    std::str::from_utf8(bytes).map_err(|_| "Receipt MSM source is not UTF-8".into())
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
    let value = values.next().ok_or("Missing receipt MSM named constant")?;
    if values.next().is_some() {
        return Err("Duplicate receipt MSM named constant".into());
    }
    if semicolon {
        value
            .strip_suffix(';')
            .ok_or_else(|| "Malformed receipt MSM constant".into())
    } else {
        Ok(value)
    }
}

fn decimal(value: &str) -> Result<BigUint, String> {
    if value.is_empty()
        || !value.bytes().all(|b| b.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err("Noncanonical receipt MSM decimal integer".into());
    }
    BigUint::parse_bytes(value.as_bytes(), 10).ok_or_else(|| "Invalid receipt MSM integer".into())
}

fn solidity_bytes32(text: &str, name: &str) -> Result<[u8; 32], String> {
    let literal = declaration(text, "bytes32 public constant ", name, true)?;
    let digits = literal
        .strip_prefix("hex\"")
        .and_then(|value| value.strip_suffix('"'))
        .ok_or("Malformed receipt MSM control bytes")?;
    hex::decode(digits)
        .map_err(|_| "Invalid receipt MSM control hex")?
        .try_into()
        .map_err(|_| "Invalid receipt MSM control length".into())
}

fn admit_point(x: &BigUint, y: &BigUint, p: &BigUint, r: &BigUint) -> Result<G1Affine, String> {
    if x >= p || y >= p || (x == &BigUint::from(0_u8) && y == &BigUint::from(0_u8)) {
        return Err("Receipt MSM point is not finite and canonical before conversion".into());
    }
    let point = G1Affine::new_unchecked(
        Fq::from_be_bytes_mod_order(&x.to_bytes_be()),
        Fq::from_be_bytes_mod_order(&y.to_bytes_be()),
    );
    if point.is_zero()
        || !point.is_on_curve()
        || double_and_add_affine(&point, r.to_u64_digits()) != G1Projective::ZERO
    {
        return Err("Receipt MSM point fails its curve/full-integer order certificate".into());
    }
    Ok(point)
}

fn point_words(point: G1Affine) -> [u8; 64] {
    let mut words = [0; 64];
    for (index, coordinate) in [point.x, point.y].into_iter().enumerate() {
        let bytes = coordinate.into_bigint().to_bytes_be();
        let end = (index + 1) * 32;
        words[end - bytes.len()..end].copy_from_slice(&bytes);
    }
    words
}

fn certify_mapping(text: &str) -> Result<(), String> {
    let compact: String = text
        .lines()
        .map(|line| line.split("//").next().unwrap_or(""))
        .flat_map(str::chars)
        .filter(|c| !c.is_whitespace())
        .collect();
    let helper = concat!(
        "fnreceiptClaimMsm(claim0:U256,claim1:U256)->[U256;2]{",
        "letmutresult=g1FromAffine([RECEIPT_MSM_BASE_X,RECEIPT_MSM_BASE_Y])",
        "result=g1JacAdd(result,g1Mul([VK_IC3_X,VK_IC3_Y],claim0))",
        "result=g1JacAdd(result,g1Mul([VK_IC4_X,VK_IC4_Y],claim1))",
        "returng1ToAffine(result)}"
    );
    let signals = concat!(
        "letsignals=[receiptDigestHalfLE(RECEIPT_CONTROL_ROOT,0),",
        "receiptDigestHalfLE(RECEIPT_CONTROL_ROOT,16),receiptDigestHalfLE(claimDigest,0),",
        "receiptDigestHalfLE(claimDigest,16),RECEIPT_BN254_CONTROL_ID]",
        "for(letmuti=0;i<5;i=i+1){g1ScalarValidate(signals[i])}",
        "letvkX=receiptClaimMsm(signals[2],signals[3])"
    );
    if !compact.contains(helper)
        || !compact.contains(signals)
        || compact.matches("receiptClaimMsm(").count() != 2
    {
        return Err("Receipt MSM helper, five guards or claim-signal call mapping differs".into());
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
