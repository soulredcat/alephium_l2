//! Bounded certification of exact embedded public RISC Zero verification-key points.
//! No proof payload, VM admission flag, compilation, network access or signing.
use ark_bn254::{Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup, scalar_mul::double_and_add_affine};
use ark_ff::{AdditiveGroup, Field, PrimeField};
use num_bigint::BigUint;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const SOLIDITY: &[u8] = include_bytes!(
    "../../node/fixtures/risc0-groth16/vendor/contracts/src/groth16/Groth16Verifier.sol"
);
const RALPH: &[u8] = include_bytes!("../../contracts/alephium/verifier/verification_key.ral");
const SUBGROUP: &[u8] = include_bytes!("../../contracts/alephium/verifier/g2_subgroup.ral");
const SOLIDITY_SHA256: &str = "14bdf78c8b6168b12a5235395d42b8daabb48ee29d49913bb06d20071f156fd6";
const RALPH_SHA256: &str = "e35616b85888a5fc133d6c5f7bdc82eaeea59dd16b600fb9db0ba74019c052af";
const BN254_X: u64 = 4_965_661_367_192_848_881;
type Constants = BTreeMap<String, BigUint>;

pub fn certify() -> Result<Value, String> {
    if sha256(SOLIDITY) != SOLIDITY_SHA256 || sha256(RALPH) != RALPH_SHA256 {
        return Err("Fixed verification-key source differs from its exact SHA-256 pin".into());
    }
    let sol = decimal_constants(SOLIDITY, "uint256 constant ", true)?;
    let ral = decimal_constants(RALPH, "const ", false)?;
    let subgroup = decimal_constants(SUBGROUP, "const ", false)?;
    if sol.len() != 28 || ral.len() != 26 {
        return Err("Fixed verification-key declaration count differs from its exact bound".into());
    }
    let p = integer(&sol, "q")?;
    let r = integer(&sol, "r")?;
    if p.to_string() != Fq::MODULUS.to_string() || r.to_string() != Fr::MODULUS.to_string() {
        return Err("Pinned verification-key base/scalar parameters differ from Arkworks".into());
    }
    certify_helpers(RALPH)?;
    let mut g1_names = Vec::with_capacity(7);
    for (sol_prefix, ral_prefix) in [
        ("alpha", "ALPHA"),
        ("IC0", "IC0"),
        ("IC1", "IC1"),
        ("IC2", "IC2"),
        ("IC3", "IC3"),
        ("IC4", "IC4"),
        ("IC5", "IC5"),
    ] {
        let x = mapped(
            &sol,
            &ral,
            &format!("{sol_prefix}x"),
            &format!("VK_{ral_prefix}_X"),
            p,
        )?;
        let y = mapped(
            &sol,
            &ral,
            &format!("{sol_prefix}y"),
            &format!("VK_{ral_prefix}_Y"),
            p,
        )?;
        let point = G1Affine::new_unchecked(x, y);
        if (x == Fq::ZERO && y == Fq::ZERO)
            || !point.is_on_curve()
            || point.is_zero()
            || double_and_add_affine(&point, r.to_u64_digits()) != G1Projective::ZERO
        {
            return Err(format!("Fixed G1 point {sol_prefix} is zero or off curve"));
        }
        g1_names.push(sol_prefix);
    }
    let xi = Fq2::new(Fq::from(9_u64), Fq::ONE);
    let p_minus_one = p - BigUint::from(1_u8);
    // Derive psi independently from the untwist-Frobenius-twist definition.
    let psi_x = xi.pow((&p_minus_one / BigUint::from(3_u8)).to_u64_digits());
    let psi_y = xi.pow((&p_minus_one / BigUint::from(2_u8)).to_u64_digits());
    for (name, value) in [
        ("G2_PSI_X_REAL", psi_x.c0),
        ("G2_PSI_X_IMAGINARY", psi_x.c1),
        ("G2_PSI_Y_REAL", psi_y.c0),
        ("G2_PSI_Y_IMAGINARY", psi_y.c1),
    ] {
        if coordinate(&subgroup, name, p)? != value {
            return Err(format!(
                "Target psi coefficient {name} differs from independent derivation"
            ));
        }
    }
    if integer(&subgroup, "G2_SEED")? != &BigUint::from(BN254_X) {
        return Err("Target subgroup seed differs from the selected BN254 relation".into());
    }
    for name in ["beta", "gamma", "delta"] {
        let upper = name.to_ascii_uppercase();
        let mut cells = [Fq::ZERO; 4];
        for (index, (sol_suffix, ral_suffix)) in [
            ("x2", "X_REAL"),
            ("x1", "X_U"),
            ("y2", "Y_REAL"),
            ("y1", "Y_U"),
        ]
        .into_iter()
        .enumerate()
        {
            cells[index] = mapped(
                &sol,
                &ral,
                &format!("{name}{sol_suffix}"),
                &format!("VK_{upper}_{ral_suffix}"),
                p,
            )?;
        }
        let point =
            G2Affine::new_unchecked(Fq2::new(cells[0], cells[1]), Fq2::new(cells[2], cells[3]));
        if cells == [Fq::ZERO; 4] || point.is_zero() || !point.is_on_curve() {
            return Err(format!("Fixed G2 point {name} is zero or off curve"));
        }
        // Unreduced raw integer double-and-add, never Fr::from(r) or GLV.
        if double_and_add_affine(&point, r.to_u64_digits()) != G2Projective::ZERO
            || !point.is_in_correct_subgroup_assuming_on_curve()
            || !selected_psi_relation(point, psi_x, psi_y)
        {
            return Err(format!(
                "Fixed G2 point {name} failed its independent subgroup certificate"
            ));
        }
    }
    Ok(json!({
        "schema": 1, "scope": "exact embedded public RISC Zero Groth16 verification key",
        "upstreamRevision": "365e7b2db4f620fa256580c27558d2623362b9ae",
        "sources": [
            {"path": "l2/node/fixtures/risc0-groth16/vendor/contracts/src/groth16/Groth16Verifier.sol",
                "sha256": SOLIDITY_SHA256, "bytes": SOLIDITY.len(), "license": "GPL-3.0-or-later"},
            {"path": "l2/contracts/alephium/verifier/verification_key.ral",
                "sha256": RALPH_SHA256, "bytes": RALPH.len(), "license": "GPL-3.0-or-later"},
            {"path": "l2/contracts/alephium/verifier/g2_subgroup.ral",
                "sha256": sha256(SUBGROUP), "bytes": SUBGROUP.len(), "license": "Apache-2.0"}
        ],
        "oracle": {"library": "ark-bn254", "version": "0.6.0", "independentFromRalph": true},
        "parameters": {"fpModulus": p.to_string(), "scalarModulus": r.to_string()},
        "pointCounts": {"g1": 7, "g2": 3, "ic": 6, "signals": 5},
        "pointNames": {"g1": g1_names, "g2": ["beta", "gamma", "delta"]},
        "canonicalCoordinatesBeforeConversion": true, "nonzeroAndCurveChecksPassed": true,
        "exactNamedConstantsMatched": true, "exactHelperMappingMatched": true,
        "solidityFp2ToCanonicalOrder": "x2,x1,y2,y1 = x.real,x.u,y.real,y.u",
        "g2FullUnreducedOrderCheckPassed": true,
        "g1FullUnreducedOrderCheckPassed": true,
        "g2IndependentArkworksSubgroupCheckPassed": true,
        "g2SelectedPsiRelationPassed": true, "targetPsiFactorsIndependentlyDerived": true,
        "psiRelation": "[x0+1]Q + psi([x0]Q) + psi^2([x0]Q) = psi^3([2*x0]Q)",
        "compiledArtifactBindingRequired": true, "exactImmutableParameterBindingRequired": true,
        "hostMembershipBooleanPassedToVm": false, "completeVerifierAccepted": false
    }))
}

fn decimal_constants(bytes: &[u8], prefix: &str, semicolon: bool) -> Result<Constants, String> {
    let source = std::str::from_utf8(bytes).map_err(|_| "Verification-key source is not UTF-8")?;
    let mut constants = BTreeMap::new();
    for line in source.lines() {
        let Some(declaration) = line.trim().strip_prefix(prefix) else {
            continue;
        };
        let declaration = if semicolon {
            declaration
                .strip_suffix(';')
                .ok_or("Malformed Solidity decimal declaration")?
        } else {
            declaration
        };
        let (name, decimal) = declaration
            .split_once('=')
            .ok_or("Malformed named decimal declaration")?;
        let (name, decimal) = (name.trim(), decimal.trim());
        if name.is_empty()
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            || decimal.is_empty()
            || !decimal.bytes().all(|b| b.is_ascii_digit())
            || (decimal.len() > 1 && decimal.starts_with('0'))
        {
            return Err("Noncanonical named verification-key decimal declaration".into());
        }
        let value =
            BigUint::parse_bytes(decimal.as_bytes(), 10).ok_or("Invalid decimal integer")?;
        if constants.insert(name.into(), value).is_some() {
            return Err(format!("Duplicate verification-key constant {name}"));
        }
    }
    Ok(constants)
}

fn integer<'a>(constants: &'a Constants, name: &str) -> Result<&'a BigUint, String> {
    constants
        .get(name)
        .ok_or_else(|| format!("Missing verification-key constant {name}"))
}

fn coordinate(constants: &Constants, name: &str, p: &BigUint) -> Result<Fq, String> {
    let value = integer(constants, name)?;
    if value >= p {
        return Err(format!("Noncanonical verification-key coordinate {name}"));
    }
    // Reduction is harmless only after the integer canonicality check.
    Ok(Fq::from_be_bytes_mod_order(&value.to_bytes_be()))
}

fn mapped(
    sol: &Constants,
    ral: &Constants,
    sol_name: &str,
    ral_name: &str,
    p: &BigUint,
) -> Result<Fq, String> {
    if integer(sol, sol_name)? != integer(ral, ral_name)? {
        return Err(format!(
            "Ralph verification-key constant {ral_name} differs from {sol_name}"
        ));
    }
    coordinate(sol, sol_name, p)
}

fn psi(point: G2Affine, factor_x: Fq2, factor_y: Fq2) -> G2Affine {
    if point.is_zero() {
        return point;
    }
    G2Affine::new_unchecked(
        point.x.frobenius_map(1) * factor_x,
        point.y.frobenius_map(1) * factor_y,
    )
}

fn selected_psi_relation(point: G2Affine, factor_x: Fq2, factor_y: Fq2) -> bool {
    let seed_q = double_and_add_affine(&point, [BN254_X]).into_affine();
    let psi_q = psi(seed_q, factor_x, factor_y);
    let psi2_q = psi(psi_q, factor_x, factor_y);
    let psi3_q = psi(psi2_q, factor_x, factor_y);
    let lhs = seed_q.into_group() + point + psi_q + psi2_q;
    let rhs = psi3_q.into_group().double();
    lhs == rhs
}

fn certify_helpers(bytes: &[u8]) -> Result<(), String> {
    let source =
        std::str::from_utf8(bytes).map_err(|_| "Ralph verification-key source is not UTF-8")?;
    let compact: String = source
        .lines()
        .map(|line| line.split("//").next().unwrap_or(""))
        .flat_map(str::chars)
        .filter(|c| !c.is_whitespace())
        .collect();
    let header = "AbstractContractRisc0VerificationKey(fpModulus:U256)extendsBn254G1(fpModulus),Bn254G2Subgroup(fpModulus){";
    if !compact.starts_with(header) {
        return Err("Ralph verification-key inheritance differs from the reviewed closure".into());
    }
    for (function, words) in [
        ("Alpha", "VK_ALPHA_X,VK_ALPHA_Y"),
        (
            "Beta",
            "VK_BETA_X_REAL,VK_BETA_X_U,VK_BETA_Y_REAL,VK_BETA_Y_U",
        ),
        (
            "Gamma",
            "VK_GAMMA_X_REAL,VK_GAMMA_X_U,VK_GAMMA_Y_REAL,VK_GAMMA_Y_U",
        ),
        (
            "Delta",
            "VK_DELTA_X_REAL,VK_DELTA_X_U,VK_DELTA_Y_REAL,VK_DELTA_Y_U",
        ),
    ] {
        let length = if function == "Alpha" { 2 } else { 4 };
        let expected = format!("fnvk{function}()->[U256;{length}]{{return[{words}]}}");
        if !compact.contains(&expected) {
            return Err(format!(
                "Ralph vk{function} helper has a different point mapping"
            ));
        }
    }
    let points = (0..6)
        .flat_map(|i| [format!("VK_IC{i}_X"), format!("VK_IC{i}_Y")])
        .collect::<Vec<_>>()
        .join(",");
    let expected =
        format!("fnvkMsm(signals:[U256;5])->[U256;2]{{returng1Msm([{points}],signals)}}");
    if !compact.contains(&expected) {
        return Err("Ralph vkMsm differs from exact five-signal upstream IC order".into());
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
