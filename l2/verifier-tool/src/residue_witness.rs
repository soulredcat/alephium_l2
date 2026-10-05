//! Bounded ordinary-Fp12 residue witnesses; never a substitute for target checks.
//! Algorithm reference: Consensys gnark (Apache-2.0), revision
//! cfc7b2f907cc4212ec152077e022c6d0b4805759, sw_bn254/hints.go, finalExpWitness.
//! See https://eprint.iacr.org/2024/640, Section 4.3.2.
//! Wire: version 01, inverse root in C0.B0(real,imag), B1, B2, then C1;
//! six correction coefficients follow in the same C0 order. All words are BE32.
use ark_bn254::{Fq, Fq2, Fq6, Fq12, Fr};
use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
use num_bigint::{BigInt, BigUint};

const BN254_U: u64 = 4_965_661_367_192_848_881;
const ROOT27_REAL: &str =
    "9483667112135124394372960210728142145589475128897916459350428495526310884707";
const ROOT27_IMAG: &str =
    "4534159768373982659291990808346042891252278737770656686799127720849666919525";

struct Parameters {
    identity_exponent: BigUint,
    lambda: BigUint,
    cubic_test_exponent: BigUint,
    r_inverse: BigUint,
    m_inverse: BigUint,
    cube_exponent: BigUint,
    root27: Fq12,
}

/// Generates auxiliary bytes only. The target must independently verify the
/// original Miller product, nonzero inverse root, Fp6 correction and equation.
pub fn generate(f: Fq12) -> Result<[u8; 577], String> {
    if f == Fq12::ZERO {
        return Err("Residue witness input is zero".into());
    }
    let parameters = Parameters::derive()?;
    if power(f, &parameters.identity_exponent) != Fq12::ONE {
        return Err("Residue witness input fails the pairing identity predicate".into());
    }
    // Exactly three cubic classes occur inside the r-residue subgroup.
    let mut correction = Fq12::ONE;
    for _ in 0..3 {
        let scaled = f * correction;
        if power(scaled, &parameters.cubic_test_exponent) == Fq12::ONE {
            let r_root = power(scaled, &parameters.r_inverse);
            let rm_root = power(r_root, &parameters.m_inverse);
            let root = cube_root(rm_root, &parameters)?;
            let inverse_root = root.inverse().ok_or("Residue root is zero")?;
            if correction == Fq12::ZERO || correction.c1 != Fq6::ZERO {
                return Err("Residue correction is not a nonzero Fp6 element".into());
            }
            let bytes = encode(inverse_root, correction)?;
            // Reconstruct the exported coefficients, then check the complete
            // ordinary power independently of every root-extraction shortcut.
            verify_export(&bytes, f, &parameters.lambda)?;
            return Ok(bytes);
        }
        correction *= parameters.root27;
    }
    Err("No permitted cubic correction for residue input".into())
}

impl Parameters {
    fn derive() -> Result<Self, String> {
        let one = BigUint::from(1_u8);
        let three = BigUint::from(3_u8);
        let p = BigUint::from_bytes_be(&Fq::MODULUS.to_bytes_be());
        let r = BigUint::from_bytes_be(&Fr::MODULUS.to_bytes_be());
        let u = BigUint::from(BN254_U);
        // Establish the exact field parameters independently from the seed.
        let common = BigUint::from(36_u8) * u.pow(4)
            + BigUint::from(36_u8) * u.pow(3)
            + BigUint::from(6_u8) * &u
            + &one;
        if p != &common + BigUint::from(24_u8) * u.pow(2)
            || r != &common + BigUint::from(18_u8) * u.pow(2)
        {
            return Err("Pinned fields differ from BN254 seed parameters".into());
        }
        let order = p.pow(12) - &one;
        let identity_exponent = exact_division(&order, &r)?;
        let lambda = p.pow(3) - p.pow(2) + &p + BigUint::from(6_u8) * &u + BigUint::from(2_u8);
        let three_r = &three * &r;
        let m = exact_division(&lambda, &three_r)?;
        if gcd(&lambda, &order)? != three_r
            || gcd(&r, &identity_exponent)? != one
            || gcd(&m, &order)? != one
            || gcd(&r, &(p.pow(6) - &one))? != one
        {
            return Err("BN254 residue exponent coprimality differs".into());
        }
        let prime_to_three = exact_division(&order, &BigUint::from(27_u8))?;
        if &prime_to_three % &three == BigUint::from(0_u8) {
            return Err("BN254 extension order has unexpected 3-adicity".into());
        }
        let cube_exponent = exact_division(&(&prime_to_three + &one), &three)?;
        if &cube_exponent % &three == BigUint::from(0_u8) {
            return Err("BN254 cubic root correction step is not primitive".into());
        }
        let cubic_test_exponent = exact_division(&order, &three)?;
        // Gnark's fixed cubic nonresidue is in the shared Fp6 tower basis.
        let root27 = Fq12::new(
            Fq6::new(
                Fq2::ZERO,
                Fq2::new(coordinate(ROOT27_REAL, &p)?, coordinate(ROOT27_IMAG, &p)?),
                Fq2::ZERO,
            ),
            Fq6::ZERO,
        );
        if root27 == Fq12::ZERO
            || root27.pow([27_u64]) != Fq12::ONE
            || root27.pow([9_u64]) == Fq12::ONE
            || power(root27, &identity_exponent) != Fq12::ONE
            || power(root27, &cubic_test_exponent) == Fq12::ONE
        {
            return Err("Pinned cubic nonresidue fails its exact order checks".into());
        }
        Ok(Self {
            identity_exponent: identity_exponent.clone(),
            lambda,
            cubic_test_exponent,
            r_inverse: modular_inverse(&r, &identity_exponent)?,
            m_inverse: modular_inverse(&m, &order)?,
            cube_exponent,
            root27,
        })
    }
}

fn cube_root(value: Fq12, parameters: &Parameters) -> Result<Fq12, String> {
    if value == Fq12::ZERO || power(value, &parameters.cubic_test_exponent) != Fq12::ONE {
        return Err("Cubic root input is not a nonzero cubic residue".into());
    }
    let mut root = power(value, &parameters.cube_exponent);
    let value_inverse = value.inverse().ok_or("Cubic residue has no inverse")?;
    let defect = root.square() * root * value_inverse;
    if defect.pow([9_u64]) != Fq12::ONE {
        return Err("Cubic root defect is outside the order-nine subgroup".into());
    }
    let step = power(parameters.root27, &parameters.cube_exponent);
    // Gnark repeatedly multiplies by this same step. Its cube generates the
    // order-nine defect group, so nine candidates exhaust it without a loop
    // controlled by an unchecked witness or an unbounded root search.
    for _ in 0..9 {
        if root.square() * root == value {
            return Ok(root);
        }
        root *= step;
    }
    Err("Cubic root correction exceeded its fixed bound".into())
}

fn power(value: Fq12, exponent: &BigUint) -> Fq12 {
    value.pow(exponent.to_u64_digits())
}

fn exact_division(value: &BigUint, divisor: &BigUint) -> Result<BigUint, String> {
    if divisor == &BigUint::from(0_u8) || value % divisor != BigUint::from(0_u8) {
        return Err("Residue parameter division is not exact".into());
    }
    Ok(value / divisor)
}

fn gcd(left: &BigUint, right: &BigUint) -> Result<BigUint, String> {
    let (mut left, mut right) = (left.clone(), right.clone());
    // Euclid takes fewer than twice the input bit length divisions.
    for _ in 0..2 * left.bits().max(right.bits()) + 1 {
        if right == BigUint::from(0_u8) {
            return Ok(left);
        }
        let remainder = &left % &right;
        left = right;
        right = remainder;
    }
    Err("Residue parameter gcd exceeded its fixed bit-length bound".into())
}

fn modular_inverse(value: &BigUint, modulus: &BigUint) -> Result<BigUint, String> {
    let modulus_signed = BigInt::from(modulus.clone());
    let (mut r0, mut r1) = (modulus_signed.clone(), BigInt::from(value % modulus));
    let (mut t0, mut t1) = (BigInt::from(0_u8), BigInt::from(1_u8));
    for _ in 0..2 * modulus.bits() + 1 {
        if r1 == BigInt::from(0_u8) {
            if r0 != BigInt::from(1_u8) {
                return Err("Residue parameter has no modular inverse".into());
            }
            let inverse = ((t0 % &modulus_signed + &modulus_signed) % &modulus_signed)
                .to_biguint()
                .ok_or("Residue parameter inverse is negative")?;
            if value * &inverse % modulus != BigUint::from(1_u8) {
                return Err("Residue parameter inverse identity differs".into());
            }
            return Ok(inverse);
        }
        let quotient = &r0 / &r1;
        let next_r = &r0 - &quotient * &r1;
        let next_t = &t0 - &quotient * &t1;
        (r0, r1, t0, t1) = (r1, next_r, t1, next_t);
    }
    Err("Residue parameter inverse exceeded its fixed bit-length bound".into())
}

fn coordinate(decimal: &str, p: &BigUint) -> Result<Fq, String> {
    let integer = BigUint::parse_bytes(decimal.as_bytes(), 10)
        .ok_or("Pinned cubic nonresidue is not a decimal integer")?;
    if &integer >= p {
        return Err("Pinned cubic nonresidue coefficient is noncanonical".into());
    }
    Ok(Fq::from_be_bytes_mod_order(&integer.to_bytes_be()))
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

fn encode(inverse_root: Fq12, correction: Fq12) -> Result<[u8; 577], String> {
    let (root_words, correction_words) = (flatten(inverse_root), flatten(correction));
    let mut bytes = [0_u8; 577];
    bytes[0] = 1;
    for (index, coordinate) in root_words
        .into_iter()
        .chain(correction_words[..6].iter().copied())
        .enumerate()
    {
        let word = coordinate.into_bigint().to_bytes_be();
        if word.len() > 32 {
            return Err("Residue coefficient exceeds its canonical wire width".into());
        }
        let end = 1 + 32 * (index + 1);
        bytes[end - word.len()..end].copy_from_slice(&word);
    }
    Ok(bytes)
}

fn verify_export(bytes: &[u8; 577], f: Fq12, lambda: &BigUint) -> Result<(), String> {
    if bytes[0] != 1 {
        return Err("Residue witness wire version differs".into());
    }
    let p = BigUint::from_bytes_be(&Fq::MODULUS.to_bytes_be());
    let mut words = [Fq::ZERO; 18];
    for (word, encoded) in words.iter_mut().zip(bytes[1..].chunks_exact(32)) {
        if BigUint::from_bytes_be(encoded) >= p {
            return Err("Exported residue coefficient is noncanonical".into());
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
    let inverse_root = Fq12::new(half(0), half(6));
    let correction = Fq12::new(half(12), Fq6::ZERO);
    // No Frobenius shortcut, optimized addition chain, reduced exponent or
    // cyclotomic assumption is used for this final full-equation check.
    if inverse_root == Fq12::ZERO
        || correction == Fq12::ZERO
        || f * correction * power(inverse_root, lambda) != Fq12::ONE
    {
        return Err("Exported residue witness fails its full equation".into());
    }
    Ok(())
}
