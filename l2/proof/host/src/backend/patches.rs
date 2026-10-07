//! Exact ordered SDK patch declarations accepted by the CUDA provenance policy.

use serde::{Deserialize, Serialize};

/// An externally pinned build declaration, not a certificate of patch application.
#[derive(Clone, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SdkPatch {
    pub patch_path: String,
    pub patch_sha256: String,
    pub source_path: String,
    pub original_source_sha256: String,
    pub patched_source_sha256: String,
}

impl SdkPatch {
    pub(super) fn reviewed() -> [Self; 9] {
        [
            Self {
                patch_path: "l2/proof/patches/risc0-3.0.3-sppark-init.patch".into(),
                patch_sha256: "03e60baed43fd95408654228617dc8ecc573c84f95e2482cb4375d12e513816a"
                    .into(),
                source_path: "risc0/sys/kernels/zkp/cuda/supra/ntt.cu".into(),
                original_source_sha256:
                    "a3df61bb4d3936195d633effee685eb23d5ad24a57ff1b8c6a27d5c6c1327f1d".into(),
                patched_source_sha256:
                    "17f93126dfad207487b662e12911ffa8c5e947fa3a39d8ccc6cd4a2d6190c4bf".into(),
            },
            Self {
                patch_path: "l2/proof/patches/risc0-3.0.3-private-prove-error-chain.patch".into(),
                patch_sha256: "3474ddea0ff6e0a209d9ad9197c3863f43ff8d048225fb823534c29e96b0388d"
                    .into(),
                source_path: "risc0/zkvm/src/host/api/server.rs".into(),
                original_source_sha256:
                    "cb396ae88d2e15c093b0d82b81a72b1f6b2ca35ee5db452124d7d6db097201d0".into(),
                patched_source_sha256:
                    "2aa3bf92a391e73c6bb8dd98a26491c56a5aa6775f630f194f941d39aee0ddf0".into(),
            },
            Self {
                patch_path: "l2/proof/patches/risc0-3.0.3-combos-prepare-sync.patch".into(),
                patch_sha256: "d234a9b10b5c2ad053645ca916ef0560f1a257f94c0c4a19777c6654b70dd27b"
                    .into(),
                source_path: "risc0/sys/kernels/zkp/cuda/ffi.cu".into(),
                original_source_sha256:
                    "0e5b6e929259b7aa48a768d89ab2092ced92a76ae5c73aed04d4e18fc7055063".into(),
                patched_source_sha256:
                    "297f2022816f7e5e86493b630e7bda772fc4fb2aa2109bae79c2ca7cf5c329de".into(),
            },
            Self {
                patch_path: "l2/proof/patches/risc0-3.0.3-private-division-diagnostic.patch".into(),
                patch_sha256: "5691803090a6d0998f338ada115aa3cec871df431081e4d57584e08f7bdb617e"
                    .into(),
                source_path: "risc0/zkp/src/hal/cuda.rs".into(),
                original_source_sha256:
                    "d1a80c752aeaf08d6418617e96621877cf1f1a759b8d629ff0b8dded10defe25".into(),
                patched_source_sha256:
                    "e82f68273236b271562ca03640857c2c087c448ff443648887d2c8a75d6b72c9".into(),
            },
            Self {
                patch_path: "l2/proof/patches/risc0-3.0.3-zeroize-kernels.patch".into(),
                patch_sha256: "1ef2d21ec65bdfc257859f2c41dc3cf8334c36ce1fdb5decb11c00afbab7dae7"
                    .into(),
                source_path: "risc0/sys/kernels/zkp/cuda/eltwise.cu".into(),
                original_source_sha256:
                    "7f024d45ab9262a948275b19a3b271c3010ce5a87c1381cf9a88ac27c5856871".into(),
                patched_source_sha256:
                    "ffefafa6d50d62fafd3f0601a8eb81b782120a9df067fb38842e5b8fb983a7e6".into(),
            },
            Self {
                patch_path: "l2/proof/patches/risc0-3.0.3-zeroize-declarations.patch".into(),
                patch_sha256: "5e3570333039521d5a43dce30cc4127d0d27c924677d45930180f64a0818939b"
                    .into(),
                source_path: "risc0/sys/kernels/zkp/cuda/kernels.h".into(),
                original_source_sha256:
                    "1ae04deab8b0e35cb373d75f72799829df87c5e9f6bbda04cfd769e2f708bd5a".into(),
                patched_source_sha256:
                    "a4115ffcd9d499be24eede99c0ca3e276f76b92c94a3569141d252a9f03201bf".into(),
            },
            Self {
                patch_path: "l2/proof/patches/risc0-3.0.3-zeroize-ffi.patch".into(),
                patch_sha256: "5e41419febb4491d11a3c68cacc602449115c1a5cf38dd34c19704099ced9d47"
                    .into(),
                source_path: "risc0/sys/kernels/zkp/cuda/ffi.cu".into(),
                original_source_sha256:
                    "297f2022816f7e5e86493b630e7bda772fc4fb2aa2109bae79c2ca7cf5c329de".into(),
                patched_source_sha256:
                    "09ebd62e40ace53a338b04b1a5bd5ef64872deddb49b2f3b52c2dcce75629caa".into(),
            },
            Self {
                patch_path: "l2/proof/patches/risc0-3.0.3-production-private-division.patch".into(),
                patch_sha256: "f56112698ca4d93bbf3f889cd529ae1f6f6dab8e45374974ea539515cf39a518"
                    .into(),
                source_path: "risc0/zkp/src/hal/cuda.rs".into(),
                original_source_sha256:
                    "e82f68273236b271562ca03640857c2c087c448ff443648887d2c8a75d6b72c9".into(),
                patched_source_sha256:
                    "2dfb252cc0eebcc045f5ced3eb2c8b4c011a6dcc7ea0cdcf8d7585cff3031bf2".into(),
            },
            Self {
                patch_path: "l2/proof/patches/risc0-3.0.3-safe-proof-progress.patch".into(),
                patch_sha256: "484f353e21a49fb598c7ece1da77368d885d938d40234b276bc03362285e4d89"
                    .into(),
                source_path: "risc0/zkvm/src/host/server/prove/prover_impl.rs".into(),
                original_source_sha256:
                    "2b3e6e61cfaf07d78cb935d5db6a7c0053c3581cfdf1347705b39844e15209a5".into(),
                patched_source_sha256:
                    "ed7e65e192553529130196b7527504fa144692c6348c1cfbbe3d0237ec8c5e38".into(),
            },
        ]
    }
}
