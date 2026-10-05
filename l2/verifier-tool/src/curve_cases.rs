//! Bounded C11 curve vectors; pinned Arkworks supplies independent group results.
//! Public affine cells are canonical x/y, with Fq2 real before imaginary.
use crate::cases::{Case, Expected};
use ark_bn254::{Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup, scalar_mul::double_and_add_affine};
use ark_ff::{AdditiveGroup, Field, PrimeField};

pub const MAX_CASES: usize = 19;
const BN254_X: u64 = 4_965_661_367_192_848_881;

pub fn corpus() -> Result<Vec<Case>, String> {
    let g1_generator = G1Projective::generator();
    let g2_generator = G2Projective::generator();
    let g1_point = |scalar| (g1_generator * Fr::from(scalar)).into_affine();
    let g2_point = |scalar| (g2_generator * Fr::from(scalar)).into_affine();
    let (p2, p3, p5, p7, p11, p13) = (
        g1_point(2_u64),
        g1_point(3),
        g1_point(5),
        g1_point(7),
        g1_point(11),
        g1_point(13),
    );
    let (q2, q3, q7, q11) = (g2_point(2_u64), g2_point(3), g2_point(7), g2_point(11));
    let g1_zero = G1Projective::ZERO.into_affine();
    let g2_zero = G2Projective::ZERO.into_affine();
    // Never convert r into Fr for subgroup membership: that would reduce to zero.
    for point in [g2_generator.into_affine(), q2, q3, q7, q11, g2_zero] {
        if !point.is_on_curve()
            || !point.is_in_correct_subgroup_assuming_on_curve()
            || !full_order_multiple_is_zero(point)
        {
            return Err("Independent G2 positive vector failed its full-order oracle".into());
        }
    }
    let mut cases = vec![
        g1("g1-add-distinct-multiples", 0, p2, p5, Fr::ZERO, p2 + p5),
        g1(
            "g1-double-nontrivial-multiple",
            1,
            p3,
            g1_zero,
            Fr::ZERO,
            p3 + p3,
        ),
        g1(
            "g1-add-opposite-before-normalization",
            0,
            p7,
            -p7,
            Fr::ZERO,
            G1Projective::ZERO,
        ),
        g1(
            "g1-scalar-zero-infinity",
            2,
            p11,
            g1_zero,
            Fr::ZERO,
            G1Projective::ZERO,
        ),
        g1(
            "g1-scalar-r-minus-one",
            2,
            p13,
            g1_zero,
            -Fr::ONE,
            p13 * -Fr::ONE,
        ),
        msm(g1_generator)?,
        g1(
            "g1-neg-original-valid-point",
            8,
            p11,
            g1_zero,
            Fr::ZERO,
            (-p11).into_group(),
        ),
        g2("g2-add-distinct-subgroup-multiples", 4, q2, q3, q2 + q3),
        g2("g2-double-subgroup-multiple", 5, q3, g2_zero, q3 + q3),
        g2(
            "g2-fixed-seed-subgroup-multiple",
            6,
            q7,
            g2_zero,
            q7 * Fr::from(BN254_X),
        ),
        g2(
            "g2-add-opposite-before-normalization",
            4,
            q11,
            -q11,
            G2Projective::ZERO,
        ),
        g2(
            "g2-infinity-subgroup-and-normalization",
            5,
            g2_zero,
            g2_zero,
            G2Projective::ZERO,
        ),
        subgroup(
            "g2-generator-target-subgroup-check",
            g2_generator.into_affine(),
            None,
        ),
    ];
    let mut noncanonical_g1 = point_args(&flatten_g1(g1_generator.into_affine()), &[]);
    noncanonical_g1[0] = Fq::MODULUS.to_string();
    cases.push(rejected(
        "g1-noncanonical-original-x",
        0,
        noncanonical_g1,
        1000,
    ));
    let mut noncanonical_scalar = point_args(&flatten_g1(p13), &[]);
    noncanonical_scalar[14] = Fr::MODULUS.to_string();
    cases.push(rejected(
        "g1-scalar-modulus-rejected",
        2,
        noncanonical_scalar,
        1101,
    ));
    let mut off_curve_g1 = zero_args();
    off_curve_g1[0] = "1".into();
    off_curve_g1[1] = "3".into();
    cases.push(rejected("g1-off-curve-original-y", 1, off_curve_g1, 1100));
    let mut noncanonical_g2 = point_args(&flatten_g2(q2), &flatten_g2(q3));
    noncanonical_g2[1] = Fq::MODULUS.to_string();
    cases.push(rejected(
        "g2-noncanonical-imaginary-x",
        4,
        noncanonical_g2,
        1000,
    ));
    let mut off_curve_g2 = zero_args();
    off_curve_g2[0] = "1".into();
    cases.push(rejected(
        "g2-off-curve-subgroup-boundary",
        7,
        off_curve_g2,
        1200,
    ));
    cases.push(subgroup(
        "g2-on-curve-nonsubgroup-rejected",
        non_subgroup_point()?,
        Some(1201),
    ));
    if cases.len() != MAX_CASES || cases.iter().any(|case| case.args.len() != 24) {
        return Err("Curve corpus differs from its fixed case/input bound".into());
    }
    Ok(cases)
}

// General Arkworks multiplication/accumulation is independent of the target's
// two-bit window and sequential six-IC/five-signal implementation.
fn msm(generator: G1Projective) -> Result<Case, String> {
    let points = [1_u64, 2, 3, 5, 7, 11].map(|n| (generator * Fr::from(n)).into_affine());
    let signals = [
        Fr::ZERO,
        Fr::from(2_u64),
        Fr::from(5_u64),
        Fr::from(17_u64),
        -Fr::ONE,
    ];
    let mut args = zero_args();
    for (index, point) in points.iter().enumerate() {
        args[2 * index..2 * index + 2].clone_from_slice(&flatten_g1(*point));
    }
    let mut result = points[0].into_group();
    for (index, scalar) in signals.iter().enumerate() {
        args[12 + index] = scalar.into_bigint().to_string();
        result += points[index + 1] * scalar;
    }
    if result == G1Projective::ZERO || result == generator {
        return Err("Fixed five-signal MSM must be nonzero and nontrivial".into());
    }
    Ok(Case {
        name: "g1-six-ic-five-signal-msm",
        op: 3,
        args,
        expected: output(&flatten_g1(result.into_affine())),
    })
}

// Deterministic raw curve construction: no cofactor clearing and no dependence
// on the Ralph subgroup predicate or its endomorphism constants. The 64-x bound
// is fixed; the pinned Arkworks curve square-root helper chooses smaller y.
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
    // Explicit unreduced integer double-and-add bypasses Fr reduction and GLV.
    double_and_add_affine(&point, Fr::MODULUS) == G2Projective::ZERO
}

fn g1(
    name: &'static str,
    op: u64,
    a: G1Affine,
    b: G1Affine,
    scalar: Fr,
    result: G1Projective,
) -> Case {
    let mut args = point_args(&flatten_g1(a), &flatten_g1(b));
    args[14] = scalar.into_bigint().to_string();
    Case {
        name,
        op,
        args,
        expected: output(&flatten_g1(result.into_affine())),
    }
}

fn g2(name: &'static str, op: u64, a: G2Affine, b: G2Affine, result: G2Projective) -> Case {
    Case {
        name,
        op,
        args: point_args(&flatten_g2(a), &flatten_g2(b)),
        expected: output(&flatten_g2(result.into_affine())),
    }
}

fn subgroup(name: &'static str, point: G2Affine, rejected_code: Option<u64>) -> Case {
    Case {
        name,
        op: 7,
        args: point_args(&flatten_g2(point), &[]),
        // One is produced by the target only after its exact subgroup check.
        expected: rejected_code.map_or_else(|| output(&["1".into()]), Expected::Assertion),
    }
}

fn flatten_g1(point: G1Affine) -> [String; 2] {
    match point.xy() {
        Some((x, y)) => [decimal(x), decimal(y)],
        None => std::array::from_fn(|_| "0".into()),
    }
}

fn flatten_g2(point: G2Affine) -> [String; 4] {
    match point.xy() {
        Some((x, y)) => [decimal(x.c0), decimal(x.c1), decimal(y.c0), decimal(y.c1)],
        None => std::array::from_fn(|_| "0".into()),
    }
}

fn decimal(value: Fq) -> String {
    value.into_bigint().to_string()
}

fn point_args(a: &[String], b: &[String]) -> Vec<String> {
    let mut args = zero_args();
    args[..a.len()].clone_from_slice(a);
    args[12..12 + b.len()].clone_from_slice(b);
    args
}

fn output(cells: &[String]) -> Expected {
    let mut result = vec!["0".into(); 12];
    result[..cells.len()].clone_from_slice(cells);
    Expected::Returns(result)
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
