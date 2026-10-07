//! Pristine package identity and exact local dependency-source patch declarations.

use serde::{Deserialize, Serialize};

#[derive(Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyPatch {
    pub package: String,
    pub version: String,
    pub registry_source: String,
    pub package_checksum: String,
    pub patch_path: String,
    pub patch_sha256: String,
    pub source_path: String,
    pub original_source_sha256: String,
    pub patched_source_sha256: String,
}

impl DependencyPatch {
    pub(super) fn reviewed() -> [Self; 1] {
        [Self {
            package: "sppark".into(),
            version: "0.1.12".into(),
            registry_source: "registry+https://github.com/rust-lang/crates.io-index".into(),
            // This identifies the pristine crate archive, not the patched header.
            package_checksum: "6bdc4f02f557e3037bbe2a379cac8be6e014a67beb7bf0996b536979392f6361"
                .into(),
            patch_path: "l2/proof/patches/sppark-0.1.12-division-reader-completion.patch".into(),
            patch_sha256: "975ab1351c56d13f0b5056e7a16f8ccbdfba0c136123c0449479fa8ad576989a".into(),
            source_path: "sppark/polynomial/div_by_x_minus_z.cuh".into(),
            original_source_sha256:
                "5d167c13dc1efec1c557d2f221347735a508de0deaf79712adbcd89e54b2eaad".into(),
            patched_source_sha256:
                "ed242ab802b857baa21148c3a24cd310f47befd8a76fe50eb587976a8576e9af".into(),
        }]
    }
}
