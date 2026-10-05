// SPDX-License-Identifier: Apache-2.0
//! Three bounded stage diagnostics; none of the results accepts a receipt.
//! All four byte-vector inputs retain the official receipt/witness transport.
use crate::{
    cases::{Case, Expected},
    ordinary_miller, receipt_cases, residue_witness,
};
use ark_bn254::{Fq, Fq2, Fq6, Fq12};
use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
use num_bigint::BigUint;
use serde_json::{Value, json};

pub const MAX_CASES: usize = 3;
const BN254_U: u64 = 4_965_661_367_192_848_881;

pub fn corpus() -> Result<Vec<Case>, String> {
    let mut args = receipt_cases::corpus()?
        .into_iter()
        .next()
        .ok_or("Empty official receipt corpus")?
        .args;
    if args.len() != 3 {
        return Err("Official receipt diagnostic input count differs".into());
    }
    let pairs = receipt_cases::official_pair_inputs()?;
    let product = ordinary_miller::miller_product(&pairs)?;
    ordinary_miller::certify_normalized_product(&pairs, product)?;
    let auxiliary = residue_witness::generate(product)?;
    let root_inverse = decode_root_inverse(&auxiliary)?;
    let inverse = root_inverse
        .inverse()
        .ok_or("Diagnostic root inverse is zero")?;
    // Independent general power of the complete unreduced seed exponent.
    // No integrated Miller loop or signed-digit schedule is reimplemented.
    let root_exponent = BigUint::from(6_u8) * BigUint::from(BN254_U) + BigUint::from(2_u8);
    let seeded_product = product * root_inverse.pow(root_exponent.to_u64_digits());
    args.push(hex::encode(auxiliary));

    // official_pair_inputs already applies -A and derives the full claim MSM.
    // Target/Arkworks use real-first G2 cells, unlike the seal's ABI encoding.
    let pair_words = pairs
        .into_iter()
        .flat_map(|(p, q)| [p.x, p.y, q.x.c0, q.x.c1, q.y.c0, q.y.c1])
        .map(decimal)
        .collect::<Vec<_>>();
    // General extension-field inverse: no conjugation or subgroup shortcut.
    let inverse_words = padded_fp12(inverse);
    let seeded_words = padded_fp12(seeded_product);
    let cases = vec![
        Case {
            name: "residue-diagnostic-receipt-admission",
            op: 0,
            args: args.clone(),
            expected: Expected::Returns(pair_words),
        },
        Case {
            name: "residue-diagnostic-root-inverse",
            op: 1,
            args: args.clone(),
            expected: Expected::Returns(inverse_words),
        },
        Case {
            name: "residue-diagnostic-integrated-miller",
            op: 2,
            args,
            expected: Expected::Returns(seeded_words),
        },
    ];
    if cases.len() != MAX_CASES
        || cases.iter().any(|case| {
            case.args.len() != 4
                || !matches!(&case.expected, Expected::Returns(words) if words.len() == 24)
        })
    {
        return Err("Residue diagnostic corpus differs from its fixed bounds".into());
    }
    Ok(cases)
}

/// Names and scope only; never expose proof, pair or root coefficients.
pub fn evidence() -> Value {
    json!({
        "developmentDiagnosticOnly": true,
        "receiptAcceptance": false,
        "caseCount": MAX_CASES,
        "byteVectorArguments": 4,
        "stageArgument": "one U256 appended after the four ByteVec arguments",
        "resultWords": 24,
        "auxiliaryBytes": 577,
        "auxiliaryVersion": 1,
        "stages": [
            {"stage": 0, "name": "residue-diagnostic-receipt-admission",
             "scope": "parameter/envelope checks and complete receipt admission; four pairs",
             "targetIntegratedMillerLoopExecuted": false},
            {"stage": 1, "name": "residue-diagnostic-root-inverse",
             "scope": "stage 0 admission plus canonical/nonzero general Fp12 inversion; twelve zero pads",
             "targetIntegratedMillerLoopExecuted": false},
            {"stage": 2, "name": "residue-diagnostic-integrated-miller",
             "scope": "stage 1 admission/inversion plus the unchanged four-pair integrated Miller loop; twelve zero pads",
             "targetIntegratedMillerLoopExecuted": true}
        ],
        "targetIntegratedMillerLoopExecuted": true,
        "targetIntegratedMillerLoopStage": 2,
        "partialRootExponent": "6*u+2 = 29793968203157093288",
        "targetWitnessFrobeniusFactorsApplied": false,
        "targetCorrectionApplied": false,
        "targetFinalIdentityChecked": false,
        "targetResidueEquationVerified": false,
        "hostMembershipBooleanPassedToVm": false,
        "oracle": "pinned official pairs, ordinary raw Miller product, general Arkworks Fp12 inverse and unreduced integer power"
    })
}

fn decode_root_inverse(auxiliary: &[u8; 577]) -> Result<Fq12, String> {
    if auxiliary[0] != 1 {
        return Err("Diagnostic auxiliary encoding version differs".into());
    }
    let modulus = BigUint::from_bytes_be(&Fq::MODULUS.to_bytes_be());
    let mut words = [Fq::ZERO; 12];
    for (word, encoded) in words.iter_mut().zip(auxiliary[1..385].chunks_exact(32)) {
        if BigUint::from_bytes_be(encoded) >= modulus {
            return Err("Diagnostic root-inverse coefficient is noncanonical".into());
        }
        *word = Fq::from_be_bytes_mod_order(encoded);
    }
    let half = |offset: usize| {
        Fq6::new(
            Fq2::new(words[offset], words[offset + 1]),
            Fq2::new(words[offset + 2], words[offset + 3]),
            Fq2::new(words[offset + 4], words[offset + 5]),
        )
    };
    Ok(Fq12::new(half(0), half(6)))
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

fn padded_fp12(value: Fq12) -> Vec<String> {
    let mut words = flatten(value).into_iter().map(decimal).collect::<Vec<_>>();
    words.extend(std::iter::repeat_n("0".into(), 12));
    words
}

fn decimal(value: Fq) -> String {
    value.into_bigint().to_string()
}
