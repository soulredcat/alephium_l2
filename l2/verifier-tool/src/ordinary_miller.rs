// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 ConsenSys AG (Gnark Crypto reference).
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     https://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Ordinary MillerLoop and g2Proj line formulas translated from Gnark Crypto
// 703a260c2f991d01e245adf53d20f76af4210c5f, ecc/bn254/pairing.go and bn254.go.
// https://github.com/Consensys/gnark-crypto/blob/703a260c2f991d01e245adf53d20f76af4210c5f/ecc/bn254/pairing.go
//! Exact raw representative for Ralph's ordinary four-pair Miller product.
//! Homogeneous x=X/Z, y=Y/Z; no projective/line normalization or final exponent.
//! Arkworks supplies general tower arithmetic, not its different raw Miller loop.

use ark_bn254::{Bn254, Fq, Fq2, Fq6, Fq12, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, pairing::Pairing, scalar_mul::double_and_add_affine};
use ark_ff::{AdditiveGroup, Field, MontFp, PrimeField};
use num_bigint::BigUint;

const BN254_X: u64 = 4_965_661_367_192_848_881;
// Exactly 66 signed NAF digits, including 65=+1, 64=0, 63=-1.
const POSITIVE_DIGITS: u128 = 39_199_894_390_062_465_064;
const NEGATIVE_DIGITS: u128 = 9_405_926_186_905_371_776;
const HALF: Fq =
    MontFp!("10944121435919637611123202872628637544348155578648911831344518947322613104292");
const TWIST_B: Fq2 = Fq2::new(
    MontFp!("19485874751759354771024239261021720505790618469301721065564631296452457478373"),
    MontFp!("266929791119991161246907387137283842545076965332900288569378510910307636690"),
);
const PSI_X: Fq2 = Fq2::new(
    MontFp!("21575463638280843010398324269430826099269044274347216827212613867836435027261"),
    MontFp!("10307601595873709700152284273816112264069230130616436755625194854815875713954"),
);
const PSI_Y: Fq2 = Fq2::new(
    MontFp!("2821565182194536844548159561693502659359617185244120367078079554186484126554"),
    MontFp!("3505843767911556378687030309984248845540243509899259641013678093033130930403"),
);
const FROBENIUS2_X: Fq =
    MontFp!("21888242871839275220042445260109153167277707414472061641714758635765020556616");

/// Check all supplied points before filtering either member's infinity.
/// Fr::MODULUS stays an unreduced integer; using Fr::from(r) would be tautological.
pub fn miller_product(pairs: &[(G1Affine, G2Affine); 4]) -> Result<Fq12, String> {
    validate_pairs(pairs)?;
    if POSITIVE_DIGITS & NEGATIVE_DIGITS != 0
        || POSITIVE_DIGITS - NEGATIVE_DIGITS != 6 * u128::from(BN254_X) + 2
        || POSITIVE_DIGITS >> 65 != 1
        || NEGATIVE_DIGITS >> 63 != 1
        || ((POSITIVE_DIGITS | NEGATIVE_DIGITS) >> 64) & 1 != 0
    {
        return Err("Ordinary Miller signed schedule differs from its pinned 66 digits".into());
    }
    let mut active: Vec<_> = pairs
        .iter()
        .filter(|(p, q)| !p.is_zero() && !q.is_zero())
        .map(|&(p, q)| LoopPair {
            p,
            q,
            negative_q: -q,
            point: Homogeneous {
                x: q.x,
                y: q.y,
                z: Fq2::ONE,
            },
        })
        .collect();
    let mut product = Fq12::ONE;
    if active.is_empty() {
        return Ok(product);
    }
    // Index 64: assign the first line, then source-order line products.
    for (ordinal, pair) in active.iter_mut().enumerate() {
        let line = pair.point.double_step().evaluate(pair.p);
        product = if ordinal == 0 { line } else { line * product };
    }
    // Index 63: the exact source replacement starts at 2Q and ends at 3Q.
    product.square_in_place();
    for pair in &mut active {
        let second = pair.point.line_compute(pair.negative_q).evaluate(pair.p);
        let first = pair.point.add_mixed_step(pair.q).evaluate(pair.p);
        product *= first * second;
    }
    // One shared square per remaining signed digit, 62 through zero inclusive.
    for index in (0..63).rev() {
        product.square_in_place();
        for pair in &mut active {
            let first = pair.point.double_step().evaluate(pair.p);
            let signed_q = if (POSITIVE_DIGITS >> index) & 1 != 0 {
                Some(pair.q)
            } else if (NEGATIVE_DIGITS >> index) & 1 != 0 {
                Some(pair.negative_q)
            } else {
                None
            };
            if let Some(q) = signed_q {
                let second = pair.point.add_mixed_step(q).evaluate(pair.p);
                product *= first * second;
            } else {
                product *= first;
            }
        }
    }
    for pair in &mut active {
        let q1 = G2Affine::new_unchecked(conjugate(pair.q.x) * PSI_X, conjugate(pair.q.y) * PSI_Y);
        // Q2=-pi^2(Q): its y multiplier is -(-1)=+1, not a subgroup shortcut.
        let q2 = G2Affine::new_unchecked(scale(pair.q.x, FROBENIUS2_X), pair.q.y);
        let second = pair.point.add_mixed_step(q1).evaluate(pair.p);
        let first = pair.point.line_compute(q2).evaluate(pair.p);
        product *= first * second;
    }
    if product == Fq12::ZERO {
        return Err("Validated ordinary Miller product unexpectedly equals zero".into());
    }
    Ok(product)
}

/// Independent complete-pairing oracle for a raw producer result.
/// Call once for each admitted fixture/corpus product before witness generation.
/// General pow uses a full BigUint s*(p^12-1)/r, with no cyclotomic assumptions.
pub fn certify_normalized_product(
    pairs: &[(G1Affine, G2Affine); 4],
    product: Fq12,
) -> Result<(), String> {
    validate_pairs(pairs)?;
    if product == Fq12::ZERO {
        return Err("Zero cannot represent an admitted ordinary Miller product".into());
    }
    let p = modulus::<Fq>()?;
    let r = modulus::<Fr>()?;
    let numerator = p.pow(12) - BigUint::from(1_u8);
    if &numerator % &r != BigUint::from(0_u8) {
        return Err("BN254 canonical final exponent is not an exact integer".into());
    }
    let x = BigUint::from(BN254_X);
    let s = BigUint::from(2_u8)
        * &x
        * (BigUint::from(6_u8) * &x * &x + BigUint::from(3_u8) * &x + BigUint::from(1_u8));
    let exponent = numerator / r * s;
    let normalized = product.pow(exponent.to_u64_digits());
    let p = pairs.map(|pair| pair.0);
    let q = pairs.map(|pair| pair.1);
    if normalized != Bn254::multi_pairing(p, q).0 {
        return Err(
            "Ordinary Miller general normalized power differs from Arkworks pairing".into(),
        );
    }
    Ok(())
}

fn validate_pairs(pairs: &[(G1Affine, G2Affine); 4]) -> Result<(), String> {
    for (index, (p, q)) in pairs.iter().enumerate() {
        if !p.is_on_curve() || !q.is_on_curve() {
            return Err(format!(
                "Ordinary Miller pair {index} contains an off-curve point"
            ));
        }
        if double_and_add_affine(p, Fr::MODULUS) != G1Projective::ZERO
            || double_and_add_affine(q, Fr::MODULUS) != G2Projective::ZERO
        {
            return Err(format!(
                "Ordinary Miller pair {index} fails unreduced integer-order membership"
            ));
        }
    }
    Ok(())
}

fn modulus<F: PrimeField>() -> Result<BigUint, String> {
    BigUint::parse_bytes(F::MODULUS.to_string().as_bytes(), 10)
        .ok_or_else(|| "Pinned BN254 modulus is not an unsigned decimal integer".into())
}

struct LoopPair {
    p: G1Affine,
    q: G2Affine,
    negative_q: G2Affine,
    point: Homogeneous,
}

/// These coordinates never enter Arkworks' Jacobian curve operations.
#[derive(Clone, Copy)]
struct Homogeneous {
    x: Fq2,
    y: Fq2,
    z: Fq2,
}

impl Homogeneous {
    fn double_step(&mut self) -> Line {
        let a = scale(self.x * self.y, HALF);
        let b = self.y.square();
        let c = self.z.square();
        let d = c.double() + c;
        let e = d * TWIST_B;
        let f = e.double() + e;
        let g = scale(b + f, HALF);
        let h = (self.y + self.z).square() - (b + c);
        let i = e - b;
        let j = self.x.square();
        let ee = e.square();
        let k = ee.double() + ee;
        self.x = (b - f) * a;
        self.y = g.square() - k;
        self.z = b * h;
        Line {
            r0: -h,
            r1: j.double() + j,
            r2: i,
        }
    }

    fn add_mixed_step(&mut self, affine: G2Affine) -> Line {
        let (o, l, j) = self.mixed_terms(affine);
        let c = o.square();
        let d = l.square();
        let e = l * d;
        let f = self.z * c;
        let g = self.x * d;
        let h = e + f - g.double();
        let t1 = self.y * e;
        self.x = l * h;
        self.y = (g - h) * o - t1;
        self.z = e * self.z;
        Line {
            r0: l,
            r1: -o,
            r2: j,
        }
    }

    fn line_compute(self, affine: G2Affine) -> Line {
        let (o, l, j) = self.mixed_terms(affine);
        Line {
            r0: l,
            r1: -o,
            r2: j,
        }
    }

    fn mixed_terms(self, affine: G2Affine) -> (Fq2, Fq2, Fq2) {
        let o = self.y - affine.y * self.z;
        let l = self.x - affine.x * self.z;
        let j = affine.x * o - l * affine.y;
        (o, l, j)
    }
}

struct Line {
    r0: Fq2,
    r1: Fq2,
    r2: Fq2,
}

impl Line {
    fn evaluate(self, p: G1Affine) -> Fq12 {
        // Exact sparse 034 slots: C0.B0, C1.B0, C1.B1.
        Fq12::new(
            Fq6::new(scale(self.r0, p.y), Fq2::ZERO, Fq2::ZERO),
            Fq6::new(scale(self.r1, p.x), self.r2, Fq2::ZERO),
        )
    }
}

fn scale(value: Fq2, scalar: Fq) -> Fq2 {
    Fq2::new(value.c0 * scalar, value.c1 * scalar)
}

fn conjugate(value: Fq2) -> Fq2 {
    Fq2::new(value.c0, -value.c1)
}
