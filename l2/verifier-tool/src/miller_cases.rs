//! Bounded C12 complete four-pair vectors, independently evaluated by Arkworks.
//! Input pairs are G1(x,y), G2(x.real,x.imag,y.real,y.imag); infinity is zero.
//! Expected values are the complete normalized Fq12 result, never a host flag
//! or an unreduced Miller value whose conventions can differ across libraries.
use crate::cases::{Case, Expected};
use ark_bn254::{Bn254, Fq, Fq2, Fq12, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{
    AffineRepr, CurveGroup, PrimeGroup, pairing::Pairing, scalar_mul::double_and_add_affine,
};
use ark_ff::{AdditiveGroup, Field, PrimeField};
use num_bigint::BigUint;

pub const MAX_CASES: usize = 9;
const BN254_X: u64 = 4_965_661_367_192_848_881;
type FourPairs = [(G1Affine, G2Affine); 4];

pub fn corpus() -> Result<Vec<Case>, String> {
    let g1 = G1Projective::generator();
    let g2 = G2Projective::generator();
    let p = |scalar| (g1 * Fr::from(scalar)).into_affine();
    let q = |scalar| (g2 * Fr::from(scalar)).into_affine();
    let (p2, p5, p11, p17) = (p(2_u64), p(5), p(11), p(17));
    let (q3, q7, q13, q19) = (q(3_u64), q(7), q(13), q(19));
    let (g1_zero, g2_zero) = (
        G1Projective::ZERO.into_affine(),
        G2Projective::ZERO.into_affine(),
    );
    // All four cancellation pairs are finite: the target must execute its
    // complete loop before its actual final-exponent identity shortcut.
    let cancellation = [(p2, q3), (-p2, q3), (p11, q13), (-p11, q13)];
    let distinct = [(p2, q3), (p5, q7), (p11, q13), (p17, q19)];
    let signed = [(-p2, q3), (p5, -q7), (-p11, -q13), (p17, q19)];
    let mixed = [(g1_zero, q3), (p5, g2_zero), (p11, q13), (p17, q19)];
    let empty = [(g1_zero, g2_zero); 4];
    let (canonical_exponent, normalized_exponent) = final_exponents()?;
    let cancellation_result =
        normalized_pairing(cancellation, &canonical_exponent, &normalized_exponent)?;
    let distinct_result = normalized_pairing(distinct, &canonical_exponent, &normalized_exponent)?;
    let signed_result = normalized_pairing(signed, &canonical_exponent, &normalized_exponent)?;
    let mixed_result = normalized_pairing(mixed, &canonical_exponent, &normalized_exponent)?;
    let empty_result = normalized_pairing(empty, &canonical_exponent, &normalized_exponent)?;
    if cancellation_result != Fq12::ONE {
        return Err("Four finite cancellation pairs do not yield the independent identity".into());
    }
    if [distinct_result, signed_result, mixed_result].contains(&Fq12::ONE)
        || distinct_result == signed_result
        || distinct_result == mixed_result
    {
        return Err("Four-pair nonidentity vectors do not distinguish all selected inputs".into());
    }
    let mut cases = vec![
        positive(
            "pairing4-four-finite-pair-cancellation",
            cancellation,
            cancellation_result,
        ),
        positive(
            "pairing4-four-distinct-nontrivial-pairs",
            distinct,
            distinct_result,
        ),
        positive(
            "pairing4-four-nontrivial-pairs-with-both-group-negations",
            signed,
            signed_result,
        ),
        positive(
            "pairing4-infinity-in-each-group-with-two-finite-pairs",
            mixed,
            mixed_result,
        ),
        positive(
            "pairing4-all-infinity-zero-active-boundary",
            empty,
            empty_result,
        ),
    ];
    // Infinity must not bypass validation of its supplied opposite point.
    // This raw on-curve Q was neither multiplied by a cofactor nor created
    // using target endomorphism constants; full unreduced [r]Q rejects it.
    let mut invalid_subgroup = distinct;
    invalid_subgroup[3] = (g1_zero, non_subgroup_point()?);
    cases.push(rejected(
        "pairing4-g1-infinity-does-not-hide-nonsubgroup-g2",
        pair_args(invalid_subgroup),
        1201,
    ));
    let mut noncanonical = pair_args(distinct);
    noncanonical[23] = Fq::MODULUS.to_string();
    cases.push(rejected(
        "pairing4-last-coordinate-equals-modulus",
        noncanonical,
        1000,
    ));
    let bad_g1 = G1Affine::new_unchecked(Fq::ONE, Fq::ONE);
    let bad_g2 = G2Affine::new_unchecked(Fq2::ONE, Fq2::ONE);
    if bad_g1.is_on_curve() || bad_g2.is_on_curve() {
        return Err("Selected invalid affine inputs are unexpectedly on curve".into());
    }
    let mut invalid_g1 = distinct;
    invalid_g1[3] = (bad_g1, g2_zero);
    let mut invalid_g2 = distinct;
    invalid_g2[3] = (g1_zero, bad_g2);
    cases.extend([
        rejected(
            "pairing4-g2-infinity-does-not-hide-offcurve-g1",
            pair_args(invalid_g1),
            1100,
        ),
        rejected(
            "pairing4-g1-infinity-does-not-hide-offcurve-g2",
            pair_args(invalid_g2),
            1200,
        ),
    ]);
    if cases.len() != MAX_CASES
        || cases
            .iter()
            .any(|case| case.args.len() != 24 || case.op != 0)
    {
        return Err("Miller corpus differs from its fixed four-pair case/input bound".into());
    }
    Ok(cases)
}

// Arkworks 0.6's BN hard chain already uses s*E, just like the selected target
// Gnark chain. Compute the expected result with general field pow and an
// independently derived integer exponent; do not apply s to multi_pairing.
// Compare only complete projected results, never raw Miller representatives.
fn normalized_pairing(
    pairs: FourPairs,
    canonical_exponent: &BigUint,
    normalized_exponent: &BigUint,
) -> Result<Fq12, String> {
    for (p, q) in pairs {
        if !p.is_on_curve()
            || !q.is_on_curve()
            || !q.is_in_correct_subgroup_assuming_on_curve()
            || !full_order_multiple_is_zero(q)
        {
            return Err(
                "Four-pair positive input failed its independent affine/subgroup checks".into(),
            );
        }
    }
    let (p, q) = (pairs.map(|pair| pair.0), pairs.map(|pair| pair.1));
    let raw = Bn254::multi_miller_loop(p, q).0;
    let canonical = raw.pow(canonical_exponent.to_u64_digits());
    let normalized = raw.pow(normalized_exponent.to_u64_digits());
    if normalized != Bn254::multi_pairing(p, q).0 {
        return Err(
            "General normalized pairing exponent differs from pinned Arkworks' complete result"
                .into(),
        );
    }
    if normalized == Fq12::ZERO || (canonical != Fq12::ONE && normalized == canonical) {
        return Err("Independent pairing does not distinguish the selected normalization".into());
    }
    Ok(normalized)
}

// s=2*x*(6*x^2+3*x+1), exactly the C10 normalization. Full-width arithmetic
// and gcd(s,r)=1 preserve the identity predicate without changing convention.
fn final_exponents() -> Result<(BigUint, BigUint), String> {
    let x = BigUint::from(BN254_X);
    let factor = BigUint::from(2_u8)
        * &x
        * (BigUint::from(6_u8) * &x * &x + BigUint::from(3_u8) * &x + BigUint::from(1_u8));
    let (p, r) = (modulus::<Fq>()?, modulus::<Fr>()?);
    let numerator = p.pow(12) - BigUint::from(1_u8);
    if &numerator % &r != BigUint::from(0_u8) {
        return Err("BN254 canonical final exponent is not an exact integer".into());
    }
    let (mut left, mut right) = (factor.clone(), r.clone());
    while right != BigUint::from(0_u8) {
        let remainder = &left % &right;
        left = right;
        right = remainder;
    }
    if left != BigUint::from(1_u8) {
        return Err("Gnark pairing normalization is not coprime to r".into());
    }
    let canonical = numerator / r;
    let normalized = &canonical * factor;
    Ok((canonical, normalized))
}

fn modulus<F: PrimeField>() -> Result<BigUint, String> {
    BigUint::parse_bytes(F::MODULUS.to_string().as_bytes(), 10)
        .ok_or_else(|| "Pinned BN254 modulus is not an unsigned decimal integer".into())
}

// Bounded raw curve construction repeats C11's independent membership oracle.
// Never convert r to Fr: reducing the group order to zero proves nothing.
fn non_subgroup_point() -> Result<G2Affine, String> {
    for real in 0..64_u64 {
        let x = Fq2::new(Fq::from(real), Fq::from(1_u64));
        let Some(point) = G2Affine::get_point_from_x_unchecked(x, false) else {
            continue;
        };
        if !point.is_on_curve() {
            return Err("Raw G2 square-root candidate is unexpectedly off curve".into());
        }
        if !point.is_in_correct_subgroup_assuming_on_curve() && !full_order_multiple_is_zero(point)
        {
            return Ok(point);
        }
    }
    Err("Bounded raw G2 construction found no independently rejected subgroup point".into())
}

fn full_order_multiple_is_zero(point: G2Affine) -> bool {
    double_and_add_affine(&point, Fr::MODULUS) == G2Projective::ZERO
}

fn pair_args(pairs: FourPairs) -> Vec<String> {
    let mut args = Vec::with_capacity(24);
    for (p, q) in pairs {
        match p.xy() {
            Some((x, y)) => args.extend([decimal(x), decimal(y)]),
            None => args.extend(["0".into(), "0".into()]),
        }
        match q.xy() {
            Some((x, y)) => {
                args.extend([decimal(x.c0), decimal(x.c1), decimal(y.c0), decimal(y.c1)])
            }
            None => args.extend(std::array::from_fn::<_, 4, _>(|_| "0".into())),
        }
    }
    args
}

fn positive(name: &'static str, pairs: FourPairs, result: Fq12) -> Case {
    Case {
        name,
        op: 0,
        args: pair_args(pairs),
        expected: Expected::Returns(flatten(result).into_iter().map(decimal).collect()),
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

fn decimal(value: Fq) -> String {
    value.into_bigint().to_string()
}

fn rejected(name: &'static str, args: Vec<String>, code: u64) -> Case {
    Case {
        name,
        op: 0,
        args,
        expected: Expected::Assertion(code),
    }
}
