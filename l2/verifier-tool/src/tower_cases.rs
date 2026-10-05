//! Bounded C9 tower vectors, independently evaluated with pinned Arkworks 0.6.
//! Scalar wire order is C0.B0(real,imag), B1, B2, then the same for C1.
use crate::cases::{Case, Expected};
use ark_bn254::{Fq, Fq2, Fq6, Fq12};
use ark_ff::{AdditiveGroup, Field, PrimeField};

pub const MAX_CASES: usize = 18;

pub fn corpus() -> Result<Vec<Case>, String> {
    // Include distinct nonzero coefficients and canonical values close to p.
    let a6 = Fq6::new(pair(7, 11), pair(13, 17), Fq2::new(-fq(19), fq(23)));
    let b6 = Fq6::new(Fq2::new(fq(29), -fq(31)), pair(37, 41), pair(43, 47));
    let a12 = Fq12::new(
        a6,
        Fq6::new(pair(53, 59), Fq2::new(fq(61), -fq(67)), pair(71, 73)),
    );
    let b12 = Fq12::new(
        b6,
        Fq6::new(pair(79, 83), Fq2::new(-fq(89), fq(97)), pair(101, 103)),
    );
    let v = Fq6::new(Fq2::ZERO, Fq2::ONE, Fq2::ZERO);
    let scalar = Fq6::new(b6.c0, Fq2::ZERO, Fq2::ZERO);
    let sparse = Fq6::new(b6.c0, b6.c1, Fq2::ZERO);
    let inverse6 = a6.inverse().ok_or("Fixed Fp6 vector has no inverse")?;
    let inverse12 = a12.inverse().ok_or("Fixed Fp12 vector has no inverse")?;

    // The target wrapper establishes the cyclotomic precondition itself.
    // Independent Arkworks easy part: a^(p^6-1), then exponent p^2+1.
    let unitary = a12.frobenius_map(6) * inverse12;
    let cyclotomic = unitary.frobenius_map(2) * unitary;
    if cyclotomic == Fq12::ZERO || cyclotomic == Fq12::ONE {
        return Err("Fixed cyclotomic vector must be nonzero and nonidentity".into());
    }
    let mut cases = vec![
        fp6("fp6-mul", 0, a6, b6, a6 * b6),
        fp6("fp6-square", 1, a6, Fq6::ZERO, a6.square()),
        fp6("fp6-inverse", 2, a6, Fq6::ZERO, inverse6),
        fp6("fp6-mul-nonresidue", 3, a6, Fq6::ZERO, a6 * v),
        fp6("fp6-mul-fp2", 4, a6, b6, a6 * scalar),
        fp6("fp6-mul-01", 5, a6, b6, a6 * sparse),
        // The probe reaches Fp12 add/sub/neg before general multiplication.
        fp12(
            "fp12-add-sub-neg-mul-flow",
            6,
            a12,
            b12,
            (a12 - b12) * -(a12 + b12),
        ),
        fp12("fp12-square", 7, a12, Fq12::ZERO, a12.square()),
        fp12("fp12-inverse", 8, a12, Fq12::ZERO, inverse12),
        fp12("fp12-conjugate", 9, a12, Fq12::ZERO, a12.frobenius_map(6)),
        fp12(
            "fp12-frobenius-1",
            10,
            a12,
            Fq12::ZERO,
            a12.frobenius_map(1),
        ),
        fp12(
            "fp12-frobenius-2",
            11,
            a12,
            Fq12::ZERO,
            a12.frobenius_map(2),
        ),
        fp12(
            "fp12-frobenius-3",
            12,
            a12,
            Fq12::ZERO,
            a12.frobenius_map(3),
        ),
        fp12(
            "fp12-cyclotomic-square-after-easy-part",
            13,
            a12,
            Fq12::ZERO,
            cyclotomic.square(),
        ),
        rejected("fp6-zero-inverse", 2, zero_args(), 1021),
        rejected("fp12-zero-inverse", 8, zero_args(), 1031),
    ];
    let mut noncanonical6 = zero_args();
    noncanonical6[5] = Fq::MODULUS.to_string();
    let mut noncanonical12 = zero_args();
    noncanonical12[11] = Fq::MODULUS.to_string();
    cases.extend([
        rejected(
            "fp6-noncanonical-highest-coefficient",
            0,
            noncanonical6,
            1000,
        ),
        rejected(
            "fp12-noncanonical-highest-coefficient",
            6,
            noncanonical12,
            1000,
        ),
    ]);
    if cases.len() != MAX_CASES {
        return Err("Tower corpus differs from its fixed case bound".into());
    }
    Ok(cases)
}

fn fq(value: u64) -> Fq {
    Fq::from(value)
}

fn pair(real: u64, imaginary: u64) -> Fq2 {
    Fq2::new(fq(real), fq(imaginary))
}

fn fp6(name: &'static str, op: u64, a: Fq6, b: Fq6, result: Fq6) -> Case {
    fp12(
        name,
        op,
        Fq12::new(a, Fq6::ZERO),
        Fq12::new(b, Fq6::ZERO),
        Fq12::new(result, Fq6::ZERO),
    )
}

fn fp12(name: &'static str, op: u64, a: Fq12, b: Fq12, result: Fq12) -> Case {
    let (a, b) = (flatten(a), flatten(b));
    let args = a.iter().chain(b.iter()).map(decimal).collect();
    Case {
        name,
        op,
        args,
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
