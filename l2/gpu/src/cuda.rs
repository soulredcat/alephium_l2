use crate::host_staging::HostStaging;
use crate::{RecoveredKey, RecoveryInput};
use cudarc::{
    driver::{CudaContext, CudaFunction, CudaSlice, CudaStream, LaunchConfig, PushKernelArg, sys},
    nvrtc::Ptx,
};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::Arc,
};

const THREADS: usize = 128;
const WAVES: usize = 4;

struct Buffers {
    // Rust drops fields in declaration order: settle host DMA before device frees.
    host: HostStaging,
    hashes: CudaSlice<u8>,
    signatures: CudaSlice<u8>,
    recovery_ids: CudaSlice<i32>,
    public_keys: CudaSlice<u8>,
    addresses: CudaSlice<u8>,
    valid: CudaSlice<u8>,
    capacity: usize,
}

/// Owns a non-primary context and dedicated stream; no device-wide barrier.
pub struct GpuBackend {
    buffers: Option<Buffers>,
    stream: Arc<CudaStream>,
    kernel: CudaFunction,
    name: String,
    multiprocessors: usize,
    chunk: usize,
    poisoned: bool,
}

impl GpuBackend {
    pub fn new(device: usize) -> Result<Self, String> {
        catch_unwind(AssertUnwindSafe(|| Self::initialize(device)))
            .map_err(|_| "CUDA initialization failed while loading the driver".to_owned())?
    }

    fn initialize(device: usize) -> Result<Self, String> {
        i32::try_from(device).map_err(|_| "CUDA device ordinal exceeds the driver format")?;
        let context = CudaContext::new_non_primary(device, 0).map_err(error)?;
        let name = context.name().map_err(error)?;
        let major = context
            .attribute(sys::CUdevice_attribute::CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR)
            .map_err(error)?;
        let minor = context
            .attribute(sys::CUdevice_attribute::CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR)
            .map_err(error)?;
        if major < 7 || (major == 7 && minor < 5) {
            return Err("CUDA recovery requires compute capability 7.5 or newer".into());
        }
        let multiprocessors = usize::try_from(
            context
                .attribute(sys::CUdevice_attribute::CU_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT)
                .map_err(error)?,
        )
        .map_err(|_| "invalid CUDA multiprocessor count")?;
        if multiprocessors == 0 {
            return Err("CUDA device reports zero multiprocessors".into());
        }
        let chunk = multiprocessors
            .checked_mul(THREADS)
            .and_then(|n| n.checked_mul(WAVES))
            .filter(|n| *n <= i32::MAX as usize)
            .ok_or_else(|| "CUDA launch size overflow".to_owned())?;
        let stream = context.new_stream().map_err(error)?;
        // The nvrtc feature supplies the safe PTX container only. NVCC compiled
        // this artifact at build time; no runtime compiler or NVRTC call occurs.
        let module = context
            .load_module(Ptx::from_src(include_str!(concat!(
                env!("OUT_DIR"),
                "/recovery.ptx"
            ))))
            .map_err(error)?;
        let kernel = module
            .load_function("l2_recover_public_keys")
            .map_err(error)?;
        Ok(Self {
            stream,
            kernel,
            buffers: None,
            name,
            multiprocessors,
            chunk,
            poisoned: false,
        })
    }

    pub fn device_name(&self) -> &str {
        &self.name
    }

    pub fn suggested_chunk(&self) -> usize {
        self.chunk
    }

    pub fn multiprocessor_count(&self) -> usize {
        self.multiprocessors
    }

    pub fn recover(
        &mut self,
        inputs: &[RecoveryInput],
    ) -> Result<Vec<Option<RecoveredKey>>, String> {
        let count = inputs.len();
        if self.poisoned {
            return Err("CUDA stream failed; backend cannot be reused".into());
        }
        if count == 0 {
            return Ok(Vec::new());
        }
        if count > self.chunk {
            return Err("GPU recovery input exceeds the device-derived chunk".into());
        }
        let hash_bytes = count.checked_mul(32).ok_or("GPU hash size overflow")?;
        let signature_bytes = count.checked_mul(64).ok_or("GPU signature size overflow")?;
        let output_bytes = count.checked_mul(65).ok_or("GPU output size overflow")?;
        let address_bytes = count.checked_mul(20).ok_or("GPU address size overflow")?;
        let kernel_count = i32::try_from(count).map_err(|_| "GPU count overflow")?;
        for input in inputs {
            if !matches!(input.recovery_id, 0 | 1) {
                return Err("GPU recovery id must be zero or one".into());
            }
        }
        self.ensure_capacity(count)?;
        let buffers = self.buffers.as_mut().expect("capacity initialized");
        let hashes = buffers.host.hashes.prefix_mut(hash_bytes)?;
        let signatures = buffers.host.signatures.prefix_mut(signature_bytes)?;
        let recovery_ids = buffers.host.recovery_ids.prefix_mut(count)?;
        for (index, input) in inputs.iter().enumerate() {
            hashes[index * 32..(index + 1) * 32].copy_from_slice(&input.msg_hash);
            signatures[index * 64..(index + 1) * 64].copy_from_slice(&input.signature);
            recovery_ids[index] = input.recovery_id;
        }
        let config = LaunchConfig {
            grid_dim: (
                u32::try_from(count.div_ceil(THREADS)).map_err(|_| "GPU grid overflow")?,
                1,
                1,
            ),
            block_dim: (THREADS as u32, 1, 1),
            shared_mem_bytes: 0,
        };
        let submitted = (|| -> Result<(), String> {
            buffers
                .host
                .hashes
                .upload(hash_bytes, &mut buffers.hashes.slice_mut(..hash_bytes))?;
            buffers.host.signatures.upload(
                signature_bytes,
                &mut buffers.signatures.slice_mut(..signature_bytes),
            )?;
            buffers
                .host
                .recovery_ids
                .upload(count, &mut buffers.recovery_ids.slice_mut(..count))?;
            // All six device buffers cover `count`; the unchanged kernel
            // bounds-checks each thread and writes outputs before use.
            unsafe {
                self.stream
                    .launch_builder(&self.kernel)
                    .arg(&buffers.hashes)
                    .arg(&buffers.signatures)
                    .arg(&buffers.recovery_ids)
                    .arg(&mut buffers.public_keys)
                    .arg(&mut buffers.addresses)
                    .arg(&mut buffers.valid)
                    .arg(&kernel_count)
                    .launch(config)
                    .map_err(error)?;
            }
            buffers
                .host
                .public_keys
                .download(output_bytes, &buffers.public_keys.slice(..output_bytes))?;
            buffers
                .host
                .addresses
                .download(address_bytes, &buffers.addresses.slice(..address_bytes))?;
            buffers
                .host
                .valid
                .download(count, &buffers.valid.slice(..count))?;
            Ok(())
        })();
        // Always establish completion, including a partially submitted batch.
        // Exactly one final stream barrier precedes CPU reads on the normal path.
        if let Err(failure) = self.stream.synchronize() {
            self.poisoned = true;
            return Err(error(failure));
        }
        // SAFETY: the successful barrier covers every transfer on this stream.
        unsafe { buffers.host.completed() };
        submitted?;
        let public_keys = buffers.host.public_keys.prefix(output_bytes)?;
        let addresses = buffers.host.addresses.prefix(address_bytes)?;
        let valid = buffers.host.valid.prefix(count)?;
        let mut result = Vec::with_capacity(count);
        for (index, bytes) in public_keys.chunks_exact(65).enumerate() {
            match valid[index] {
                0 => result.push(None),
                1 if bytes[0] == 4 => result.push(Some(RecoveredKey {
                    public_key: bytes.try_into().map_err(|_| "invalid GPU key length")?,
                    address: addresses[index * 20..(index + 1) * 20]
                        .try_into()
                        .map_err(|_| "invalid GPU address length")?,
                })),
                _ => return Err("GPU recovery produced an invalid result marker".into()),
            }
        }
        Ok(result)
    }

    fn ensure_capacity(&mut self, count: usize) -> Result<(), String> {
        if self
            .buffers
            .as_ref()
            .is_some_and(|buffers| buffers.capacity >= count)
        {
            return Ok(());
        }
        // Construct independently. Any allocation failure drops the partial
        // buffers through cudarc RAII and leaves the old bounded buffers intact.
        let buffers = Buffers {
            host: HostStaging::new(&self.stream, count)?,
            hashes: self
                .stream
                .alloc_zeros(count.checked_mul(32).ok_or("GPU allocation overflow")?)
                .map_err(error)?,
            signatures: self
                .stream
                .alloc_zeros(count.checked_mul(64).ok_or("GPU allocation overflow")?)
                .map_err(error)?,
            recovery_ids: self.stream.alloc_zeros(count).map_err(error)?,
            public_keys: self
                .stream
                .alloc_zeros(count.checked_mul(65).ok_or("GPU allocation overflow")?)
                .map_err(error)?,
            addresses: self
                .stream
                .alloc_zeros(count.checked_mul(20).ok_or("GPU allocation overflow")?)
                .map_err(error)?,
            valid: self.stream.alloc_zeros(count).map_err(error)?,
            capacity: count,
        };
        self.buffers = Some(buffers);
        Ok(())
    }
}

fn error(error: impl std::fmt::Display) -> String {
    format!("CUDA recovery error: {error}")
}
