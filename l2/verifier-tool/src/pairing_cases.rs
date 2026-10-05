//! Bounded C10 sparse products and fixed exponent chains, checked with Arkworks.
//! The oracle uses general field multiplication/powers, not the Ralph chains.
use crate::cases::{Case, Expected};
use ark_bn254::{Fq, Fq2, Fq6, Fq12, Fr};
use ark_ff::{AdditiveGroup, Field, PrimeField};
use num_bigint::BigUint;

pub const MAX_CASES: usize = 8;
const BN254_X: u64 = 4_965_661_367_192_848_881;

pub fn corpus() -> Result<Vec<Case>, String> {
    // Distinct dense coefficients, including canonical values close to p.
    // Fp2 slots are C0.B0/B1/B2 followed by C1.B0/B1/B2, real then imaginary.
    let a = Fq12::new(
        Fq6::new(pair(7, 11), pair(13, 17), Fq2::new(-fq(19), fq(23))),
        Fq6::new(pair(53, 59), Fq2::new(fq(61), -fq(67)), pair(71, 73)),
    );
    let b = Fq12::new(
        Fq6::new(Fq2::new(fq(29), -fq(31)), pair(37, 41), pair(43, 47)),
        Fq6::new(pair(79, 83), Fq2::new(-fq(89), fq(97)), pair(101, 103)),
    );
    // The input b packs two independent 034 lines into its six Fp2 slots.
    // Build those as general Fq12 values; basis slots are exactly 0, 3, 4.
    let line_c = line034(b.c0.c0, b.c0.c1, b.c0.c2);
    let line_d = line034(b.c1.c0, b.c1.c1, b.c1.c2);
    let line_product = line_c * line_d;
    if line_product.c1.c2 != Fq2::ZERO {
        return Err("Fixed sparse product unexpectedly has a nonzero slot 5".into());
    }
    let operand = (a - b).square() * -(a + b);
    let inverse = a.inverse().ok_or("Fixed pairing vector has no inverse")?;
    let unitary = a.frobenius_map(6) * inverse;
    let cyclotomic = unitary.frobenius_map(2) * unitary;
    if cyclotomic == Fq12::ZERO || cyclotomic == Fq12::ONE {
        return Err("Fixed pairing easy-part vector must be nonzero and nonidentity".into());
    }
    let (canonical_exponent, normalized_exponent) = final_exponents()?;
    let canonical = a.pow(canonical_exponent.to_u64_digits());
    let normalized = a.pow(normalized_exponent.to_u64_digits());
    // Gnark preserves the identity predicate through the coprime factor s;
    // its serialized result intentionally differs from the bare canonical power.
    if normalized == canonical || normalized == Fq12::ONE {
        return Err("Fixed final-exponent vector does not distinguish Gnark normalization".into());
    }
    let scalar_modulus = modulus::<Fr>()?;
    if normalized.pow(scalar_modulus.to_u64_digits()) != Fq12::ONE {
        return Err("Independent final-exponent result is outside the target subgroup".into());
    }
    let mut cases = vec![
        positive(
            "fp12-add-sub-square-neg-mul-sparse034-flow",
            0,
            a,
            b,
            operand * line_c,
        ),
        positive("fp12-mul034-by034-prefix", 1, a, b, line_product),
        positive(
            "fp12-mul01234-from-two-034-lines",
            2,
            a,
            b,
            a * line_product,
        ),
        positive(
            "fp12-expt-after-conjugate-inverse-frobenius-easy-part",
            3,
            a,
            Fq12::ZERO,
            cyclotomic.pow([BN254_X]),
        ),
        positive(
            "fp12-final-exponentiation-gnark-normalized",
            4,
            a,
            Fq12::ZERO,
            normalized,
        ),
        positive(
            "fp12-final-exponentiation-easy-result-one-shortcut",
            5,
            Fq12::ONE,
            Fq12::ZERO,
            Fq12::ONE,
        ),
        rejected("fp12-zero-final-exponentiation", 4, zero_args(), 1041),
    ];
    let mut noncanonical_sparse = zero_args();
    // Op 2 consumes all twelve b scalars while forming its 01234 prefix.
    noncanonical_sparse[23] = Fq::MODULUS.to_string();
    cases.push(rejected(
        "fp12-sparse-noncanonical-highest-line-coefficient",
        2,
        noncanonical_sparse,
        1000,
    ));
    if cases.len() != MAX_CASES {
        return Err("Pairing arithmetic corpus differs from its fixed case bound".into());
    }
    Ok(cases)
}

// E=(p^12-1)/r is the canonical final exponent; Gnark uses s*E with
// s=2*x*(6*x^2+3*x+1). Keep all arithmetic full-width and check exact division
// and coprimality instead of reducing or silently changing this normalization.
fn final_exponents() -> Result<(BigUint, BigUint), String> {
    let (p, r) = (modulus::<Fq>()?, modulus::<Fr>()?);
    let numerator = p.pow(12) - BigUint::from(1_u8);
    if &numerator % &r != BigUint::from(0_u8) {
        return Err("BN254 canonical final exponent is not an exact integer".into());
    }
    let x = BigUint::from(BN254_X);
    let factor = BigUint::from(2_u8)
        * &x
        * (BigUint::from(6_u8) * &x * &x + BigUint::from(3_u8) * &x + BigUint::from(1_u8));
    let (mut left, mut right) = (factor.clone(), r.clone());
    while right != BigUint::from(0_u8) {
        let remainder = &left % &right;
        left = right;
        right = remainder;
    }
    if left != BigUint::from(1_u8) {
        return Err("Gnark final-exponent normalization is not coprime to r".into());
    }
    let canonical = numerator / r;
    let normalized = &canonical * factor;
    Ok((canonical, normalized))
}

fn modulus<F: PrimeField>() -> Result<BigUint, String> {
    BigUint::parse_bytes(F::MODULUS.to_string().as_bytes(), 10)
        .ok_or_else(|| "Pinned BN254 modulus is not an unsigned decimal integer".into())
}

fn fq(value: u64) -> Fq {
    Fq::from(value)
}

fn pair(real: u64, imaginary: u64) -> Fq2 {
    Fq2::new(fq(real), fq(imaginary))
}

fn line034(c0: Fq2, c3: Fq2, c4: Fq2) -> Fq12 {
    Fq12::new(
        Fq6::new(c0, Fq2::ZERO, Fq2::ZERO),
        Fq6::new(c3, c4, Fq2::ZERO),
    )
}

fn positive(name: &'static str, op: u64, a: Fq12, b: Fq12, result: Fq12) -> Case {
    let (a, b) = (flatten(a), flatten(b));
    Case {
        name,
        op,
        args: a.iter().chain(b.iter()).map(decimal).collect(),
        expected: Expected::Returns(flatten(result).iter().map(decimal).collect()),
    }
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

fn decimal(value: &Fq) -> String {
    value.into_bigint().to_string()
}

fn rejected(name: &'static str, op: u64, args: Vec<String>, code: u64) -> Case {
    Case {
        name,
        op,
        args,
        expected: Expected::Assertion(code),
    }
}

fn zero_args() -> Vec<String> {
    vec!["0".into(); 24]
}
