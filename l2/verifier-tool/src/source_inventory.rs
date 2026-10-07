//! Exact source closures, separate from public ABI selection.
#[derive(Clone, Copy)]
pub struct Source {
    pub filename: &'static str,
    pub origin: &'static str,
    pub contract: &'static str,
    pub bytes: &'static [u8],
}

pub(crate) const FP: Source = Source {
    filename: "fp.ral",
    origin: "l2/contracts/alephium/verifier/fp.ral",
    contract: "Bn254Fp",
    bytes: include_bytes!("../../contracts/alephium/verifier/fp.ral"),
};
pub(crate) const FP2: Source = Source {
    filename: "fp2.ral",
    origin: "l2/contracts/alephium/verifier/fp2.ral",
    contract: "Bn254Fp2",
    bytes: include_bytes!("../../contracts/alephium/verifier/fp2.ral"),
};
const FP12_ADDITIVE: Source = Source {
    filename: "fp12_additive.ral",
    origin: "l2/contracts/alephium/verifier/fp12_additive.ral",
    contract: "Bn254Fp12Additive",
    bytes: include_bytes!("../../contracts/alephium/verifier/fp12_additive.ral"),
};
pub(crate) const G1_VALIDATION: Source = Source {
    filename: "g1_validation.ral",
    origin: "l2/contracts/alephium/verifier/g1_validation.ral",
    contract: "Bn254G1Validation",
    bytes: include_bytes!("../../contracts/alephium/verifier/g1_validation.ral"),
};
pub(crate) const CYCLOTOMIC: Source = Source {
    filename: "cyclotomic.ral",
    origin: "l2/contracts/alephium/verifier/cyclotomic.ral",
    contract: "Bn254Cyclotomic",
    bytes: include_bytes!("../../contracts/alephium/verifier/cyclotomic.ral"),
};
pub(crate) const MILLER_CORE: Source = Source {
    filename: "miller_core.ral",
    origin: "l2/contracts/alephium/verifier/miller_core.ral",
    contract: "Bn254MillerCore",
    bytes: include_bytes!("../../contracts/alephium/verifier/miller_core.ral"),
};
pub(crate) const FIXED_PAIR: Source = Source {
    filename: "fixed_pair.ral",
    origin: "l2/contracts/alephium/verifier/fixed_pair.ral",
    contract: "Risc0FixedPair",
    bytes: include_bytes!("../../contracts/alephium/verifier/fixed_pair.ral"),
};
pub(crate) const BASE: &[Source] = &[
    FP,
    FP2,
    Source {
        filename: "field-probe.ral",
        origin: "l2/verifier-tool/fixtures/field-probe.ral",
        contract: "Bn254FieldProbe",
        bytes: include_bytes!("../fixtures/field-probe.ral"),
    },
];
pub(crate) const TOWER: &[Source] = &[
    FP,
    FP2,
    FP12_ADDITIVE,
    CYCLOTOMIC,
    Source {
        filename: "fp6.ral",
        origin: "l2/contracts/alephium/verifier/fp6.ral",
        contract: "Bn254Fp6",
        bytes: include_bytes!("../../contracts/alephium/verifier/fp6.ral"),
    },
    Source {
        filename: "fp12.ral",
        origin: "l2/contracts/alephium/verifier/fp12.ral",
        contract: "Bn254Fp12",
        bytes: include_bytes!("../../contracts/alephium/verifier/fp12.ral"),
    },
    Source {
        filename: "frobenius.ral",
        origin: "l2/contracts/alephium/verifier/frobenius.ral",
        contract: "Bn254Frobenius",
        bytes: include_bytes!("../../contracts/alephium/verifier/frobenius.ral"),
    },
    Source {
        filename: "tower-probe.ral",
        origin: "l2/verifier-tool/fixtures/tower-probe.ral",
        contract: "Bn254TowerProbe",
        bytes: include_bytes!("../fixtures/tower-probe.ral"),
    },
];

pub(crate) const PAIRING_ARITHMETIC: &[Source] = &[
    FP,
    FP2,
    FP12_ADDITIVE,
    CYCLOTOMIC,
    Source {
        filename: "fp6.ral",
        origin: "l2/contracts/alephium/verifier/fp6.ral",
        contract: "Bn254Fp6",
        bytes: include_bytes!("../../contracts/alephium/verifier/fp6.ral"),
    },
    Source {
        filename: "fp12.ral",
        origin: "l2/contracts/alephium/verifier/fp12.ral",
        contract: "Bn254Fp12",
        bytes: include_bytes!("../../contracts/alephium/verifier/fp12.ral"),
    },
    Source {
        filename: "frobenius.ral",
        origin: "l2/contracts/alephium/verifier/frobenius.ral",
        contract: "Bn254Frobenius",
        bytes: include_bytes!("../../contracts/alephium/verifier/frobenius.ral"),
    },
    Source {
        filename: "exponent.ral",
        origin: "l2/contracts/alephium/verifier/exponent.ral",
        contract: "Bn254Exponent",
        bytes: include_bytes!("../../contracts/alephium/verifier/exponent.ral"),
    },
    Source {
        filename: "sparse.ral",
        origin: "l2/contracts/alephium/verifier/sparse.ral",
        contract: "Bn254Sparse",
        bytes: include_bytes!("../../contracts/alephium/verifier/sparse.ral"),
    },
    Source {
        filename: "pairing-probe.ral",
        origin: "l2/verifier-tool/fixtures/pairing-probe.ral",
        contract: "Bn254PairingArithmeticProbe",
        bytes: include_bytes!("../fixtures/pairing-probe.ral"),
    },
];

pub(crate) const CURVES: &[Source] = &[
    FP,
    FP2,
    G1_VALIDATION,
    Source {
        filename: "g1.ral",
        origin: "l2/contracts/alephium/verifier/g1.ral",
        contract: "Bn254G1",
        bytes: include_bytes!("../../contracts/alephium/verifier/g1.ral"),
    },
    Source {
        filename: "g2.ral",
        origin: "l2/contracts/alephium/verifier/g2.ral",
        contract: "Bn254G2",
        bytes: include_bytes!("../../contracts/alephium/verifier/g2.ral"),
    },
    Source {
        filename: "g2_subgroup.ral",
        origin: "l2/contracts/alephium/verifier/g2_subgroup.ral",
        contract: "Bn254G2Subgroup",
        bytes: include_bytes!("../../contracts/alephium/verifier/g2_subgroup.ral"),
    },
    Source {
        filename: "curve-probe.ral",
        origin: "l2/verifier-tool/fixtures/curve-probe.ral",
        contract: "Bn254CurveProbe",
        bytes: include_bytes!("../fixtures/curve-probe.ral"),
    },
];

pub(crate) const MILLER: &[Source] = &[
    FP,
    FP2,
    G1_VALIDATION,
    MILLER_CORE,
    CYCLOTOMIC,
    Source {
        filename: "fp6.ral",
        origin: "l2/contracts/alephium/verifier/fp6.ral",
        contract: "Bn254Fp6",
        bytes: include_bytes!("../../contracts/alephium/verifier/fp6.ral"),
    },
    Source {
        filename: "fp12.ral",
        origin: "l2/contracts/alephium/verifier/fp12.ral",
        contract: "Bn254Fp12",
        bytes: include_bytes!("../../contracts/alephium/verifier/fp12.ral"),
    },
    Source {
        filename: "frobenius.ral",
        origin: "l2/contracts/alephium/verifier/frobenius.ral",
        contract: "Bn254Frobenius",
        bytes: include_bytes!("../../contracts/alephium/verifier/frobenius.ral"),
    },
    Source {
        filename: "exponent.ral",
        origin: "l2/contracts/alephium/verifier/exponent.ral",
        contract: "Bn254Exponent",
        bytes: include_bytes!("../../contracts/alephium/verifier/exponent.ral"),
    },
    Source {
        filename: "sparse.ral",
        origin: "l2/contracts/alephium/verifier/sparse.ral",
        contract: "Bn254Sparse",
        bytes: include_bytes!("../../contracts/alephium/verifier/sparse.ral"),
    },
    Source {
        filename: "g2.ral",
        origin: "l2/contracts/alephium/verifier/g2.ral",
        contract: "Bn254G2",
        bytes: include_bytes!("../../contracts/alephium/verifier/g2.ral"),
    },
    Source {
        filename: "g2_subgroup.ral",
        origin: "l2/contracts/alephium/verifier/g2_subgroup.ral",
        contract: "Bn254G2Subgroup",
        bytes: include_bytes!("../../contracts/alephium/verifier/g2_subgroup.ral"),
    },
    Source {
        filename: "miller_lines.ral",
        origin: "l2/contracts/alephium/verifier/miller_lines.ral",
        contract: "Bn254MillerLines",
        bytes: include_bytes!("../../contracts/alephium/verifier/miller_lines.ral"),
    },
    Source {
        filename: "miller_engine.ral",
        origin: "l2/contracts/alephium/verifier/miller_engine.ral",
        contract: "Bn254MillerEngine",
        bytes: include_bytes!("../../contracts/alephium/verifier/miller_engine.ral"),
    },
    Source {
        filename: "miller.ral",
        origin: "l2/contracts/alephium/verifier/miller.ral",
        contract: "Bn254Miller",
        bytes: include_bytes!("../../contracts/alephium/verifier/miller.ral"),
    },
    Source {
        filename: "miller-probe.ral",
        origin: "l2/verifier-tool/fixtures/miller-probe.ral",
        contract: "Bn254MillerProbe",
        bytes: include_bytes!("../fixtures/miller-probe.ral"),
    },
];
