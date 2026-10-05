//! Fixed public field vectors; expected arithmetic comes from pinned Arkworks.
use ark_bn254::{Fq, Fq2};
use ark_ff::{AdditiveGroup, Field, PrimeField};
use serde_json::{Value, json};

pub const MAX_CASES: usize = 20;
pub const FP_MODULUS: &str =
    "21888242871839275222246405745257275088696311157297823662689037894645226208583";

pub enum Expected {
    Returns(Vec<String>),
    Assertion(u64),
}

pub struct Case {
    pub name: &'static str,
    pub op: u64,
    pub args: Vec<String>,
    pub expected: Expected,
}

impl Case {
    // Receipt corpora supply their versioned hex byte vectors; arithmetic
    // corpora keep their existing decimal words and explicit operation code.
    pub fn receipt_request(&self, bytecode: &str, method_index: usize, modulus: &str) -> Value {
        json!({
            "group": 0, "bytecode": bytecode,
            "initialImmFields": [word(modulus)], "initialMutFields": [],
            "initialAsset": {"attoAlphAmount": "100000000000000000", "tokens": []},
            "methodIndex": method_index,
            "args": self.args.iter().map(|value| json!({"type": "ByteVec", "value": value})).collect::<Vec<_>>()
        })
    }

    pub fn request_with_modulus(
        &self,
        bytecode: &str,
        method_index: usize,
        modulus: &str,
    ) -> Value {
        let mut args = vec![word(&self.op.to_string())];
        args.extend(self.args.iter().map(|value| word(value)));
        json!({
            "group": 0, "bytecode": bytecode,
            "initialImmFields": [word(modulus)], "initialMutFields": [],
            "initialAsset": {"attoAlphAmount": "100000000000000000", "tokens": []},
            "methodIndex": method_index, "args": args
        })
    }
}

pub fn corpus() -> Result<Vec<Case>, String> {
    let (a, b) = (Fq::from(7_u64), Fq::from(13_u64));
    let (a2, b2) = (Fq2::new(a, Fq::from(11_u64)), Fq2::new(b, Fq::from(17_u64)));
    let mut cases = vec![
        fp("fp-add", 0, a, b, a + b),
        fp("fp-sub", 1, a, b, a - b),
        fp("fp-neg-zero", 2, Fq::ZERO, Fq::ZERO, -Fq::ZERO),
        fp("fp-mul", 3, a, b, a * b),
        fp("fp-square", 4, a, Fq::ZERO, a.square()),
        fp(
            "fp-inverse",
            5,
            a,
            Fq::ZERO,
            a.inverse()
                .ok_or("Fixed Fp vector unexpectedly has no inverse")?,
        ),
        fp2("fp2-add", 6, a2, b2, a2 + b2),
        fp2("fp2-sub", 7, a2, b2, a2 - b2),
        fp2("fp2-neg", 8, a2, Fq2::ZERO, -a2),
        fp2("fp2-mul", 9, a2, b2, a2 * b2),
        fp2("fp2-square", 10, a2, Fq2::ZERO, a2.square()),
        fp2(
            "fp2-inverse",
            11,
            a2,
            Fq2::ZERO,
            a2.inverse()
                .ok_or("Fixed Fp2 vector unexpectedly has no inverse")?,
        ),
        fp2(
            "fp2-mul-nonresidue",
            12,
            a2,
            Fq2::ZERO,
            a2 * Fq2::new(Fq::from(9_u64), Fq::ONE),
        ),
    ];
    let near_p = -Fq::ONE;
    let pure_imaginary = Fq2::new(Fq::ZERO, near_p);
    cases.extend([
        fp("fp-add-near-modulus", 0, near_p, near_p, near_p + near_p),
        fp("fp-sub-underflow", 1, Fq::ZERO, near_p, -near_p),
        fp2(
            "fp2-square-pure-imaginary",
            10,
            pure_imaginary,
            Fq2::ZERO,
            pure_imaginary.square(),
        ),
    ]);
    let modulus = Fq::MODULUS.to_string();
    cases.extend([
        rejected(
            "fp-noncanonical-modulus",
            3,
            [modulus.clone(), "0".into(), "1".into(), "0".into()],
            1000,
        ),
        rejected(
            "fp2-noncanonical-imaginary",
            9,
            ["1".into(), modulus, "1".into(), "0".into()],
            1000,
        ),
        rejected("fp-zero-inverse", 5, zero_args(), 1001),
        rejected("fp2-zero-inverse", 11, zero_args(), 1011),
    ]);
    if cases.len() != MAX_CASES {
        return Err("Field corpus exceeds or differs from its fixed case bound".into());
    }
    Ok(cases)
}

fn fp(name: &'static str, op: u64, a: Fq, b: Fq, result: Fq) -> Case {
    Case {
        name,
        op,
        args: vec![decimal(a), "0".into(), decimal(b), "0".into()],
        expected: Expected::Returns(vec![decimal(result), "0".into()]),
    }
}

fn fp2(name: &'static str, op: u64, a: Fq2, b: Fq2, result: Fq2) -> Case {
    Case {
        name,
        op,
        args: vec![decimal(a.c0), decimal(a.c1), decimal(b.c0), decimal(b.c1)],
        expected: Expected::Returns(vec![decimal(result.c0), decimal(result.c1)]),
    }
}

fn rejected(name: &'static str, op: u64, args: [String; 4], code: u64) -> Case {
    Case {
        name,
        op,
        args: args.into(),
        expected: Expected::Assertion(code),
    }
}

fn decimal(value: Fq) -> String {
    value.into_bigint().to_string()
}

fn zero_args() -> [String; 4] {
    std::array::from_fn(|_| "0".into())
}

pub fn word(value: &str) -> Value {
    json!({"type": "U256", "value": value})
}
