//! Bounded actual-receipt inputs; the target receives only seal/image/journal bytes.
//! Arkworks checks the complete pinned equation independently of the Ralph port.
use crate::cases::{Case, Expected};
use crate::receipt_fixture::{self, Fixture, KeyWords, bytes32, tagged};
use ark_bn254::{Bn254, Fq, Fq2, Fq12, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup, pairing::Pairing, scalar_mul::double_and_add_affine};
use ark_ff::{AdditiveGroup, BigInteger, Field, PrimeField};
use num_bigint::BigUint;
use serde_json::Value;

pub const MAX_CASES: usize = 14;
struct VerificationKey {
    alpha: G1Affine,
    beta: G2Affine,
    gamma: G2Affine,
    delta: G2Affine,
    ic: Vec<G1Affine>,
}

pub(crate) fn official_pair_inputs() -> Result<[(G1Affine, G2Affine); 4], String> {
    let (fixture, words) = receipt_fixture::load()?;
    pair_inputs_for(&fixture, &words, fixture.image, fixture.journal)
}

/// Externally supplied claims still use only the independently pinned key.
pub(crate) fn pair_inputs_for(
    fixture: &Fixture,
    words: &KeyWords,
    image: [u8; 32],
    journal: [u8; 32],
) -> Result<[(G1Affine, G2Affine); 4], String> {
    let key = verification_key(words)?;
    let proof = decode_proof(&fixture.seal)?;
    pairing_inputs(&key, proof, fixture, image, journal)
}

pub fn corpus() -> Result<Vec<Case>, String> {
    let (fixture, words) = receipt_fixture::load()?;
    let key = verification_key(&words)?;
    let proof = decode_proof(&fixture.seal)?;
    if pairing(&key, proof, &fixture, fixture.image, fixture.journal)? != Fq12::ONE {
        return Err(
            "Pinned official receipt fails the independent complete pairing equation".into(),
        );
    }
    let seal = &fixture.seal;
    let mut output = vec!["0".into(); 12];
    output[0] = "1".into();
    let mut cases = vec![Case {
        name: "receipt-official-complete-valid",
        op: 0,
        args: encoded(seal, &fixture.image, &fixture.journal),
        expected: Expected::Returns(output),
    }];
    let rejected = |name, bytes: &[u8], image: &[u8], journal: &[u8], code| Case {
        name,
        op: 0,
        args: encoded(bytes, image, journal),
        expected: Expected::Assertion(code),
    };
    let negative =
        |name, bytes: &[u8], code| rejected(name, bytes, &fixture.image, &fixture.journal, code);
    let mut wrong_selector = seal.clone();
    wrong_selector[0] ^= 1;
    let mut trailing = seal.clone();
    trailing.push(0);
    let mut oversized = seal.clone();
    oversized.resize(520, 0);
    let mut long_journal = fixture.journal.to_vec();
    long_journal.push(0);
    cases.extend([
        negative("receipt-wrong-parameter-selector", &wrong_selector, 1401),
        negative("receipt-short-seal", &seal[..259], 1400),
        negative("receipt-trailing-seal-byte", &trailing, 1400),
        negative("receipt-oversized-seal", &oversized, 1400),
        rejected(
            "receipt-short-image-id",
            seal,
            &fixture.image[..31],
            &fixture.journal,
            1400,
        ),
        rejected(
            "receipt-long-journal-digest",
            seal,
            &fixture.image,
            &long_journal,
            1400,
        ),
    ]);
    let mut noncanonical = seal.clone();
    write_word(&mut noncanonical, 1, &Fq::MODULUS.to_bytes_be());
    let mut off_curve_a = seal.clone();
    write_word(&mut off_curve_a, 0, &[1]);
    write_word(&mut off_curve_a, 1, &[1]);
    let mut off_curve_b = seal.clone();
    write_g2(
        &mut off_curve_b,
        G2Affine::new_unchecked(Fq2::ONE, Fq2::ONE),
    );
    if G1Affine::new_unchecked(Fq::ONE, Fq::ONE).is_on_curve()
        || G2Affine::new_unchecked(Fq2::ONE, Fq2::ONE).is_on_curve()
    {
        return Err("Selected invalid receipt proof points are unexpectedly on curve".into());
    }
    let mut non_subgroup_b = seal.clone();
    write_g2(&mut non_subgroup_b, non_subgroup_point()?);
    let mut infinity_a = non_subgroup_b.clone();
    write_word(&mut infinity_a, 0, &[]);
    write_word(&mut infinity_a, 1, &[]);
    cases.extend([
        negative("receipt-original-a-y-equals-p", &noncanonical, 1000),
        negative("receipt-off-curve-a", &off_curve_a, 1100),
        negative("receipt-off-curve-b", &off_curve_b, 1200),
        negative("receipt-on-curve-nonsubgroup-b", &non_subgroup_b, 1201),
        negative(
            "receipt-a-infinity-does-not-hide-nonsubgroup-b",
            &infinity_a,
            1201,
        ),
    ]);
    let mut wrong_image = fixture.image;
    wrong_image[0] ^= 1;
    let mut wrong_journal = fixture.journal;
    wrong_journal[0] ^= 1;
    for (name, image, journal) in [
        ("receipt-wrong-image-pairing", wrong_image, fixture.journal),
        (
            "receipt-wrong-journal-pairing",
            fixture.image,
            wrong_journal,
        ),
    ] {
        if pairing(&key, proof, &fixture, image, journal)? == Fq12::ONE {
            return Err("Altered receipt claim unexpectedly satisfies independent pairing".into());
        }
        cases.push(rejected(name, seal, &image, &journal, 1404));
    }
    if cases.len() != MAX_CASES || cases.iter().any(|case| case.args.len() != 3) {
        return Err("Receipt corpus differs from its fixed case/input bound".into());
    }
    Ok(cases)
}

/// Safe hashes and lengths only; no proof cells, seals or VM arguments.
pub fn fixture_evidence() -> Result<Value, String> {
    receipt_fixture::evidence(MAX_CASES)
}

fn verification_key(words: &KeyWords) -> Result<VerificationKey, String> {
    Ok(VerificationKey {
        alpha: g1(&words.alpha)?,
        beta: g2(&words.beta)?,
        gamma: g2(&words.gamma)?,
        delta: g2(&words.delta)?,
        ic: words
            .ic
            .iter()
            .map(|point| g1(point))
            .collect::<Result<_, _>>()?,
    })
}
fn pairing(
    key: &VerificationKey,
    (a, b, c): (G1Affine, G2Affine, G1Affine),
    fixture: &Fixture,
    image: [u8; 32],
    journal: [u8; 32],
) -> Result<Fq12, String> {
    let pairs = pairing_inputs(key, (a, b, c), fixture, image, journal)?;
    Ok(Bn254::multi_pairing(pairs.map(|pair| pair.0), pairs.map(|pair| pair.1)).0)
}

fn pairing_inputs(
    key: &VerificationKey,
    (a, b, c): (G1Affine, G2Affine, G1Affine),
    fixture: &Fixture,
    image: [u8; 32],
    journal: [u8; 32],
) -> Result<[(G1Affine, G2Affine); 4], String> {
    let output = tagged("risc0.Output", &[journal, [0; 32]], &[]);
    let zero_state = tagged("risc0.SystemState", &[[0; 32]], &[0; 4]);
    let claim = tagged(
        "risc0.ReceiptClaim",
        &[[0; 32], image, zero_state, output],
        &[0; 8],
    );
    let signal_bytes = [
        &fixture.control[..16],
        &fixture.control[16..],
        &claim[..16],
        &claim[16..],
        &fixture.control_id[..],
    ];
    let mut vk_x = key.ic[0].into_group();
    for (index, bytes) in signal_bytes.iter().enumerate() {
        let value = if index == 4 {
            BigUint::from_bytes_be(bytes)
        } else {
            BigUint::from_bytes_le(bytes)
        };
        if value >= BigUint::from_bytes_be(&Fr::MODULUS.to_bytes_be()) {
            return Err("Independent receipt public signal is not canonical in Fr".into());
        }
        vk_x += key.ic[index + 1] * Fr::from_be_bytes_mod_order(&value.to_bytes_be());
    }
    Ok([
        (-a, b),
        (key.alpha, key.beta),
        (vk_x.into_affine(), key.gamma),
        (c, key.delta),
    ])
}

fn decode_proof(seal: &[u8]) -> Result<(G1Affine, G2Affine, G1Affine), String> {
    if seal.len() != 260 || seal[..4] != [0x73, 0xc4, 0x57, 0xba] {
        return Err("Independent receipt seal length or certified selector differs".into());
    }
    let words = seal[4..]
        .chunks_exact(32)
        .map(bytes32)
        .collect::<Result<Vec<_>, _>>()?;
    Ok((g1(&words[..2])?, g2(&words[2..6])?, g1(&words[6..])?))
}

fn g1(words: &[[u8; 32]]) -> Result<G1Affine, String> {
    let (x, y) = (fq(&words[0])?, fq(&words[1])?);
    let point = if x == Fq::ZERO && y == Fq::ZERO {
        G1Projective::ZERO.into_affine()
    } else {
        G1Affine::new_unchecked(x, y)
    };
    if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err("Independent receipt/key G1 validation failed".into());
    }
    Ok(point)
}

fn g2(words: &[[u8; 32]]) -> Result<G2Affine, String> {
    // Solidity/EIP-197 encode imaginary first; Arkworks stores real first.
    let x = Fq2::new(fq(&words[1])?, fq(&words[0])?);
    let y = Fq2::new(fq(&words[3])?, fq(&words[2])?);
    let point = if x == Fq2::ZERO && y == Fq2::ZERO {
        G2Projective::ZERO.into_affine()
    } else {
        G2Affine::new_unchecked(x, y)
    };
    if !point.is_on_curve()
        || !point.is_in_correct_subgroup_assuming_on_curve()
        || double_and_add_affine(&point, Fr::MODULUS) != G2Projective::ZERO
    {
        return Err("Independent receipt/key G2 curve/full-order validation failed".into());
    }
    Ok(point)
}

fn non_subgroup_point() -> Result<G2Affine, String> {
    for real in 0..64_u64 {
        let x = Fq2::new(Fq::from(real), Fq::ONE);
        let Some(point) = G2Affine::get_point_from_x_unchecked(x, false) else {
            continue;
        };
        if !point.is_on_curve() {
            return Err("Raw G2 candidate is unexpectedly off curve".into());
        }
        if !point.is_in_correct_subgroup_assuming_on_curve()
            && double_and_add_affine(&point, Fr::MODULUS) != G2Projective::ZERO
        {
            return Ok(point);
        }
    }
    Err("Bounded raw G2 construction found no independently rejected subgroup point".into())
}

fn fq(bytes: &[u8; 32]) -> Result<Fq, String> {
    if BigUint::from_bytes_be(bytes) >= BigUint::from_bytes_be(&Fq::MODULUS.to_bytes_be()) {
        return Err("Independent receipt/key coordinate is not canonical in Fq".into());
    }
    Ok(Fq::from_be_bytes_mod_order(bytes))
}

fn write_word(seal: &mut [u8], index: usize, bytes: &[u8]) {
    let start = 4 + index * 32;
    seal[start..start + 32].fill(0);
    seal[start + 32 - bytes.len()..start + 32].copy_from_slice(bytes);
}

fn write_g2(seal: &mut [u8], point: G2Affine) {
    for (index, coordinate) in [point.x.c1, point.x.c0, point.y.c1, point.y.c0]
        .iter()
        .enumerate()
    {
        write_word(seal, index + 2, &coordinate.into_bigint().to_bytes_be());
    }
}

fn encoded(seal: &[u8], image: &[u8], journal: &[u8]) -> Vec<String> {
    [seal, image, journal]
        .into_iter()
        .map(hex::encode)
        .collect()
}
