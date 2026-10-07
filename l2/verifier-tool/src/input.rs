//! Explicit source and ABI inventories for the implemented verifier flows.
#[derive(Clone, Copy)]
pub enum Suite {
    Base,
    Tower,
    PairingArithmetic,
    Curves,
    Miller,
    Receipt,
    ResidueReceipt,
    ResidueDiagnostic,
    StagedReceipt,
    StagedFactory,
    StagedFactoryFlow,
    SettlementFactoryCompile,
    SettlementFactoryFlow,
    SettlementData,
}

use crate::receipt_sources::{RECEIPT, RESIDUE_DIAGNOSTIC, RESIDUE_RECEIPT};
pub use crate::source_inventory::Source;
use crate::source_inventory::{BASE, CURVES, MILLER, PAIRING_ARITHMETIC, TOWER};
use crate::staged_sources::{STAGED_FACTORY, STAGED_RECEIPT};

impl Suite {
    pub fn sources(self) -> Vec<Source> {
        let sources = match self {
            Self::Base => BASE,
            Self::Tower => TOWER,
            Self::PairingArithmetic => PAIRING_ARITHMETIC,
            Self::Curves => CURVES,
            Self::Miller => MILLER,
            Self::Receipt => RECEIPT,
            Self::ResidueReceipt => RESIDUE_RECEIPT,
            Self::ResidueDiagnostic => RESIDUE_DIAGNOSTIC,
            Self::StagedReceipt => STAGED_RECEIPT,
            Self::StagedFactory | Self::StagedFactoryFlow => STAGED_FACTORY,
            Self::SettlementFactoryCompile | Self::SettlementFactoryFlow | Self::SettlementData => {
                return crate::settlement_sources::sources();
            }
        };
        sources.to_vec()
    }

    pub fn probe(self) -> &'static str {
        match self {
            Self::Base => "Bn254FieldProbe",
            Self::Tower => "Bn254TowerProbe",
            Self::PairingArithmetic => "Bn254PairingArithmeticProbe",
            Self::Curves => "Bn254CurveProbe",
            Self::Miller => "Bn254MillerProbe",
            Self::Receipt => "Risc0ReceiptVerifier",
            Self::ResidueReceipt => "Risc0ResidueReceiptVerifier",
            Self::ResidueDiagnostic => "Risc0ResidueDiagnostics",
            Self::StagedReceipt => "Risc0StagedReceiptVerifier",
            Self::StagedFactory | Self::StagedFactoryFlow => "Risc0StagedReceiptFactory",
            Self::SettlementFactoryCompile | Self::SettlementFactoryFlow => {
                "Risc0BatchSettlementFactory"
            }
            Self::SettlementData => "Risc0BatchData",
        }
    }

    pub fn artifact(self) -> &'static str {
        match self {
            Self::Base => "field-probe.ral.json",
            Self::Tower => "tower-probe.ral.json",
            Self::PairingArithmetic => "pairing-probe.ral.json",
            Self::Curves => "curve-probe.ral.json",
            Self::Miller => "miller-probe.ral.json",
            Self::Receipt => "receipt.ral.json",
            Self::ResidueReceipt => "receipt_residue.ral.json",
            Self::ResidueDiagnostic => "residue-diagnostic.ral.json",
            Self::StagedReceipt => "staged_receipt.ral.json",
            Self::StagedFactory | Self::StagedFactoryFlow => "staged_factory.ral.json",
            Self::SettlementFactoryCompile | Self::SettlementFactoryFlow => {
                "settlement_factory.ral.json"
            }
            Self::SettlementData => "batch_data.ral.json",
        }
    }

    pub fn param_names(self) -> Vec<String> {
        if matches!(
            self,
            Self::StagedFactory
                | Self::StagedFactoryFlow
                | Self::SettlementData
                | Self::SettlementFactoryCompile
                | Self::SettlementFactoryFlow
        ) {
            return vec![];
        }
        if matches!(self, Self::StagedReceipt) {
            return ["seal", "imageId", "journalDigest", "auxiliary"]
                .map(String::from)
                .to_vec();
        }
        if matches!(self, Self::Receipt) {
            return ["seal", "imageId", "journalDigest"]
                .map(String::from)
                .to_vec();
        }
        let mut names = vec!["op".into()];
        if matches!(self, Self::ResidueDiagnostic) {
            return ["seal", "imageId", "journalDigest", "auxiliary", "stage"]
                .map(String::from)
                .to_vec();
        }
        if matches!(self, Self::ResidueReceipt) {
            return ["seal", "imageId", "journalDigest", "auxiliary"]
                .map(String::from)
                .to_vec();
        }
        let words = match self {
            Self::Base => 2,
            Self::Tower | Self::PairingArithmetic | Self::Curves | Self::Miller => 12,
            Self::Receipt
            | Self::ResidueReceipt
            | Self::ResidueDiagnostic
            | Self::StagedReceipt
            | Self::StagedFactory
            | Self::StagedFactoryFlow
            | Self::SettlementFactoryCompile
            | Self::SettlementFactoryFlow
            | Self::SettlementData => {
                unreachable!("Receipt parameters returned above")
            }
        };
        for prefix in ["a", "b"] {
            names.extend((0..words).map(|index| format!("{prefix}{index}")));
        }
        names
    }

    pub fn entry(self) -> &'static str {
        if matches!(
            self,
            Self::SettlementFactoryCompile | Self::SettlementFactoryFlow
        ) {
            return "getAnchor";
        }
        if matches!(self, Self::SettlementData) {
            return "getHash";
        }
        if matches!(self, Self::StagedReceipt) {
            return "begin";
        }
        if matches!(
            self,
            Self::StagedFactory
                | Self::StagedFactoryFlow
                | Self::SettlementFactoryCompile
                | Self::SettlementFactoryFlow
                | Self::SettlementData
        ) {
            return "create";
        }
        if matches!(self, Self::Receipt | Self::ResidueReceipt) {
            "verify"
        } else {
            "probe"
        }
    }

    pub fn param_types(self) -> Vec<&'static str> {
        if matches!(self, Self::StagedReceipt) {
            return vec!["ByteVec"; 4];
        }
        if matches!(self, Self::StagedFactory | Self::StagedFactoryFlow) {
            return vec![];
        }
        if matches!(self, Self::ResidueDiagnostic) {
            return vec!["ByteVec", "ByteVec", "ByteVec", "ByteVec", "U256"];
        }
        if matches!(self, Self::Receipt | Self::ResidueReceipt) {
            vec!["ByteVec"; self.param_names().len()]
        } else {
            vec!["U256"; self.param_names().len()]
        }
    }

    pub fn return_types(self) -> &'static [&'static str] {
        match self {
            Self::StagedReceipt | Self::StagedFactory | Self::StagedFactoryFlow => &["ByteVec"],
            Self::SettlementFactoryCompile | Self::SettlementFactoryFlow => {
                &["U256", "ByteVec", "ByteVec"]
            }
            Self::SettlementData => &["ByteVec"],
            Self::Base => &["U256", "U256"],
            Self::ResidueDiagnostic => &["[U256;24]"],
            Self::Tower
            | Self::PairingArithmetic
            | Self::Curves
            | Self::Miller
            | Self::Receipt
            | Self::ResidueReceipt => &["[U256;12]"],
        }
    }

    pub fn case_count(self) -> usize {
        match self {
            Self::Base => crate::cases::MAX_CASES,
            Self::Tower => crate::tower_cases::MAX_CASES,
            Self::PairingArithmetic => crate::pairing_cases::MAX_CASES,
            Self::Curves => crate::curve_cases::MAX_CASES,
            Self::Miller => crate::miller_cases::MAX_CASES,
            Self::Receipt => crate::receipt_cases::MAX_CASES,
            Self::ResidueReceipt => crate::residue_cases::MAX_CASES,
            Self::ResidueDiagnostic => crate::diagnostic_cases::MAX_CASES,
            Self::StagedReceipt => 39,
            Self::StagedFactory => 0,
            Self::StagedFactoryFlow => 32,
            Self::SettlementFactoryCompile | Self::SettlementData => 0,
            Self::SettlementFactoryFlow => crate::settlement::MAX_REQUESTS,
        }
    }

    pub fn scope(self) -> &'static str {
        match self {
            Self::Base => "bn254-fp-fp2-arithmetic-slice-only",
            Self::Tower => "bn254-fp6-fp12-core-tower-only",
            Self::PairingArithmetic => "bn254-sparse-fixed-exponent-layout-only",
            Self::Curves => "bn254-g1-g2-subgroup-msm-component-only",
            Self::Miller => "bn254-complete-four-pair-functional-profile",
            Self::Receipt => "risc0-fixed-vk-complete-historical-receipt",
            Self::ResidueReceipt => "risc0-fixed-vk-complete-receipt-residue-v1",
            Self::ResidueDiagnostic => "development-only-receipt-stage-diagnosis-no-acceptance",
            Self::StagedReceipt => "staged-verified-receipt-development-transition-chain",
            Self::StagedFactory => "canonical-staged-factory-compilation-only",
            Self::StagedFactoryFlow => {
                "canonical-staged-factory-synthetic-creation-and-receipt-gate"
            }
            Self::SettlementFactoryCompile | Self::SettlementData => {
                "canonical-settlement-data-source-compilation-only"
            }
            Self::SettlementFactoryFlow => {
                "p5-native-settlement-interface-and-synthetic-authority-boundaries"
            }
        }
    }

    pub fn oracle_fields(self) -> &'static str {
        match self {
            Self::Base => "Fq/Fq2",
            Self::Tower | Self::PairingArithmetic => "Fq/Fq2/Fq6/Fq12",
            Self::Curves => "Fq/Fq2/G1/G2",
            Self::Miller => "Fq12/G1/G2 general normalized pairing",
            Self::Receipt => "Arkworks BN254 pairing with independently derived receipt signals",
            Self::ResidueReceipt => "same BN254 receipt; target-verified untrusted residue witness",
            Self::ResidueDiagnostic => {
                "same proof admission/MSM and general witness inverse; stage results only"
            }
            Self::StagedReceipt | Self::StagedFactory | Self::StagedFactoryFlow => {
                "same BN254 receipt; exact mutable stage transition chain and canonical origin gate"
            }
            Self::SettlementFactoryCompile | Self::SettlementFactoryFlow | Self::SettlementData => {
                "pinned receipt; independent canonical journal, checkpoint, data and ancestry checks"
            }
        }
    }
}
