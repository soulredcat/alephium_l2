//! Pinned backend provenance policy; matching artifacts do not qualify CUDA execution.

mod dependency_patches;
mod patches;

pub use dependency_patches::DependencyPatch;
pub use patches::SdkPatch;

use crate::{HostResult, cli, inputs};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    env,
    ffi::OsStr,
    fs,
    path::{Component, Path, PathBuf},
};

const MAX_MANIFEST_BYTES: usize = 16 * 1024;
// Streaming byte ceilings, not a claim about actual installed component sizes.
const MAX_COMPONENT_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const INSTALL_PREFIX: &str = "v0.1.0-risc0-groth16";

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    #[default]
    Cpu,
    Cuda,
}

impl Backend {
    pub fn parse(value: &OsStr) -> HostResult<Self> {
        match value.to_str() {
            Some("cpu") => Ok(Self::Cpu),
            Some("cuda") => Ok(Self::Cuda),
            _ => Err("Prover backend must be exactly cpu or cuda."),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Cuda => "cuda",
        }
    }
}

#[derive(Clone, Serialize)]
pub struct BackendEvidence {
    pub requested_backend: &'static str,
    pub provenance_status: &'static str,
    pub runtime_cuda_qualification: &'static str,
    pub build_manifest_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sdk_base_version: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sdk_base_revision: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sdk_patches: Option<Vec<SdkPatch>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dependency_patches: Option<Vec<DependencyPatch>>,
    pub groth16_component_directory: Option<PathBuf>,
    pub groth16_component_files_sha256: Option<ComponentPins>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentPins {
    #[serde(rename = "preprocessed_coeffs.bin")]
    pub preprocessed_coeffs: String,
    #[serde(rename = "fuzzed_msm_results.bin")]
    pub fuzzed_msm_results: String,
    #[serde(rename = "stark_verify_final.zkey")]
    pub stark_verify_final: String,
    #[serde(rename = "stark_verify_graph.bin")]
    pub stark_verify_graph: String,
}

impl ComponentPins {
    fn entries(&self) -> [(&'static str, &str); 4] {
        [
            ("preprocessed_coeffs.bin", &self.preprocessed_coeffs),
            ("fuzzed_msm_results.bin", &self.fuzzed_msm_results),
            ("stark_verify_final.zkey", &self.stark_verify_final),
            ("stark_verify_graph.bin", &self.stark_verify_graph),
        ]
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Groth16Component {
    component: String,
    version: String,
    component_directory: PathBuf,
    files_sha256: ComponentPins,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildManifest {
    schema: u32,
    sdk_version: String,
    sdk_revision: String,
    sdk_patches: Vec<SdkPatch>,
    dependency_patches: Vec<DependencyPatch>,
    prover_sha256: String,
    backend: Backend,
    cargo_features: Vec<String>,
    default_features: bool,
    circuit_debug: bool,
    groth16_component: Groth16Component,
}

/// CPU retains the caller's executable/version and Docker checks. CUDA can skip
/// Docker only after this validation; device use and actual proofs remain unproven.
pub fn validate(
    backend: Backend,
    manifest_path: Option<&Path>,
    manifest_sha256: Option<[u8; 32]>,
    selected_prover_sha256: [u8; 32],
) -> HostResult<BackendEvidence> {
    if backend == Backend::Cpu {
        if manifest_path.is_some() || manifest_sha256.is_some() {
            return Err("CUDA build provenance options require the explicit cuda backend.");
        }
        return Ok(BackendEvidence {
            requested_backend: backend.as_str(),
            provenance_status: "retained executable SHA/version pin; build-feature provenance not supplied",
            runtime_cuda_qualification: "not-requested",
            build_manifest_sha256: None,
            sdk_base_version: None,
            sdk_base_revision: None,
            sdk_patches: None,
            dependency_patches: None,
            groth16_component_directory: None,
            groth16_component_files_sha256: None,
        });
    }
    let path = manifest_path.ok_or("CUDA requires an externally pinned build manifest.")?;
    let pin = manifest_sha256.ok_or("CUDA requires an independent build manifest SHA-256 pin.")?;
    let path = checked_path(path, false)?;
    let bytes = inputs::read_bounded(&path, MAX_MANIFEST_BYTES)?;
    let manifest = match_manifest(&bytes, pin, selected_prover_sha256)?;
    let component = manifest.groth16_component;
    let directory = checked_path(&component.component_directory, true)?;
    if directory != installed_component_directory()? {
        return Err("Pinned Groth16 component is not the unique SDK-resolved installation.");
    }
    for (name, digest) in component.files_sha256.entries() {
        let path = checked_path(&directory.join(name), false)?;
        if inputs::sha256_bounded(&path, MAX_COMPONENT_BYTES)? != parse_digest(digest)? {
            return Err("Native CUDA Groth16 component differs from its pinned SHA-256.");
        }
    }
    Ok(BackendEvidence {
        requested_backend: backend.as_str(),
        provenance_status: "pinned CUDA profile, reviewed SDK/dependency patch declarations and native Groth16 component matched; patch application/build lineage not certified",
        runtime_cuda_qualification: "unproven",
        build_manifest_sha256: Some(hex::encode(pin)),
        sdk_base_version: Some(cli::SDK_VERSION),
        sdk_base_revision: Some(cli::SDK_REVISION),
        sdk_patches: Some(manifest.sdk_patches),
        dependency_patches: Some(manifest.dependency_patches),
        groth16_component_directory: Some(directory),
        groth16_component_files_sha256: Some(component.files_sha256),
    })
}

fn match_manifest(bytes: &[u8], pin: [u8; 32], prover: [u8; 32]) -> HostResult<BuildManifest> {
    if bytes.is_empty() || bytes.len() > MAX_MANIFEST_BYTES {
        return Err("CUDA build manifest is empty or exceeds its byte ceiling.");
    }
    let actual: [u8; 32] = Sha256::digest(bytes).into();
    if actual != pin {
        return Err("CUDA build manifest differs from its independent SHA-256 pin.");
    }
    let manifest: BuildManifest = serde_json::from_slice(bytes)
        .map_err(|_| "Invalid CUDA build manifest; values suppressed.")?;
    if manifest.schema != 2
        || manifest.sdk_version != cli::SDK_VERSION
        || manifest.sdk_revision != cli::SDK_REVISION
        || manifest.sdk_patches.as_slice() != SdkPatch::reviewed()
        || manifest.dependency_patches.as_slice() != DependencyPatch::reviewed()
        || manifest.backend != Backend::Cuda
        || manifest.cargo_features.as_slice() != ["cuda"]
        || manifest.default_features
        || manifest.circuit_debug
        || parse_digest(&manifest.prover_sha256)? != prover
    {
        return Err(
            "CUDA build manifest does not match the reviewed executable and build profile.",
        );
    }
    let component = &manifest.groth16_component;
    if component.component != "Risc0Groth16" || component.version != "0.1.0" {
        return Err("CUDA requires the pinned Risc0Groth16 0.1.0 component.");
    }
    validate_absolute_path(&component.component_directory)?;
    for (_, pin) in component.files_sha256.entries() {
        parse_digest(pin)?;
    }
    Ok(manifest)
}

fn parse_digest(value: &str) -> HostResult<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("CUDA provenance digests must be 64 lowercase hex characters.");
    }
    let mut digest = [0; 32];
    hex::decode_to_slice(value, &mut digest).map_err(|_| "Invalid CUDA provenance SHA-256 pin.")?;
    Ok(digest)
}

fn validate_absolute_path(path: &Path) -> HostResult<()> {
    let text = path
        .to_str()
        .ok_or("CUDA provenance paths must use valid Unicode.")?;
    if !path.is_absolute()
        || text.chars().any(char::is_control)
        || path
            .components()
            .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
    {
        return Err(
            "CUDA provenance paths must be absolute without traversal or control characters.",
        );
    }
    #[cfg(windows)]
    for component in path.components() {
        match component {
            Component::Prefix(prefix)
                if !matches!(
                    prefix.kind(),
                    std::path::Prefix::Disk(_) | std::path::Prefix::VerbatimDisk(_)
                ) =>
            {
                return Err(
                    "CUDA provenance requires local drive paths without device or UNC prefixes.",
                );
            }
            Component::Normal(name) if name.to_string_lossy().contains(':') => {
                return Err("CUDA provenance paths cannot contain alternate data streams.");
            }
            _ => {}
        }
    }
    Ok(())
}

fn checked_path(path: &Path, directory: bool) -> HostResult<PathBuf> {
    validate_absolute_path(path)?;
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)
            .map_err(|_| "Required CUDA provenance artifact or installation is missing.")?;
        let linked = metadata.file_type().is_symlink();
        #[cfg(windows)]
        let linked = {
            use std::os::windows::fs::MetadataExt;
            linked || metadata.file_attributes() & 0x400 != 0
        };
        if linked {
            return Err("CUDA provenance paths cannot traverse symlinks or reparse points.");
        }
        if ancestor == path
            && !(if directory {
                metadata.is_dir()
            } else {
                metadata.is_file()
            })
        {
            return Err("CUDA provenance requires the expected regular file or directory.");
        }
    }
    path.canonicalize()
        .map_err(|_| "Cannot resolve required CUDA provenance artifact.")
}

fn installed_component_directory() -> HostResult<PathBuf> {
    // Mirrors pinned rzup Environment and Paths without initializing it (which
    // creates directories and may inspect credentials). SDK chooses the first
    // matching version, so multiple eligible installations must fail closed.
    let root = sdk_root(env::var_os("RISC0_HOME"), env::var_os("HOME"))?;
    let extensions = checked_path(&root.join("extensions"), true)?;
    let mut selected = None;
    let entries =
        fs::read_dir(extensions).map_err(|_| "Cannot inspect SDK component installation.")?;
    for (index, entry) in entries.enumerate() {
        if index >= 256 {
            return Err("SDK component directory exceeds its inspection ceiling.");
        }
        let entry = entry.map_err(|_| "Cannot inspect SDK component installation.")?;
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with(INSTALL_PREFIX)
            && entry
                .file_type()
                .map_err(|_| "Cannot inspect SDK component installation.")?
                .is_dir()
        {
            let path = checked_path(&entry.path(), true)?;
            if selected.replace(path).is_some() {
                return Err("Multiple Groth16 0.1.0 installations make SDK selection ambiguous.");
            }
        }
    }
    selected.ok_or("Required native CUDA Risc0Groth16 0.1.0 installation is missing.")
}

fn sdk_root(
    risc0_home: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> HostResult<PathBuf> {
    let home = home
        .filter(|p| !p.is_empty())
        .ok_or("CUDA SDK component resolution requires HOME.")?;
    let root = match risc0_home {
        Some(root) if root.to_str().is_some() => PathBuf::from(root),
        Some(_) => return Err("CUDA SDK component root must use valid Unicode."),
        None => PathBuf::from(home).join(".risc0"),
    };
    validate_absolute_path(&root)?;
    Ok(root)
}

#[cfg(test)]
#[path = "backend_tests.rs"]
mod tests;
