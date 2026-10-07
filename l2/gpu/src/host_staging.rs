//! Cacheable page-locked staging for one owned CUDA stream, never a global pool.
use cudarc::driver::{CudaStream, DevicePtr, DevicePtrMut, DeviceRepr, ValidAsZeroBits, result};
use std::{mem::size_of, ptr::NonNull, sync::Arc};

pub(crate) struct HostBuffer<T: DeviceRepr + ValidAsZeroBits> {
    pointer: NonNull<T>,
    len: usize,
    stream: Arc<CudaStream>,
    pending: bool,
}

// Ownership may move with the backend between CPU threads. No host reference
// survives a move, CUDA binds its context per call, and pending DMA blocks access.
unsafe impl<T: DeviceRepr + ValidAsZeroBits + Send> Send for HostBuffer<T> {}

impl<T: DeviceRepr + ValidAsZeroBits> HostBuffer<T> {
    pub(crate) fn new(stream: &Arc<CudaStream>, len: usize) -> Result<Self, String> {
        let bytes = len
            .checked_mul(size_of::<T>())
            .filter(|bytes| *bytes > 0 && *bytes <= isize::MAX as usize)
            .ok_or("Pinned host allocation size is invalid")?;
        stream.context().bind_to_thread().map_err(error)?;
        // flags=0 requests cacheable pinned memory. Write-combined output is
        // inappropriate because the CPU reads every recovered key/address.
        let raw = unsafe { result::malloc_host(bytes, 0) }.map_err(error)?;
        let pointer = NonNull::new(raw.cast::<T>()).ok_or("Pinned allocation returned null")?;
        if !pointer.as_ptr().is_aligned() {
            // Allocation has no queued DMA and is freed with its bound context.
            unsafe { result::free_host(raw) }.map_err(error)?;
            return Err("Pinned host allocation is misaligned".into());
        }
        // ValidAsZeroBits promises these initialized bytes are valid T values;
        // the allocation covers len items and is exclusively owned here.
        unsafe { pointer.as_ptr().write_bytes(0, len) };
        Ok(Self {
            pointer,
            len,
            stream: stream.clone(),
            pending: false,
        })
    }

    fn check_access(&self, count: usize) -> Result<(), String> {
        if self.pending {
            return Err("Pinned host memory still has pending CUDA work".into());
        }
        if count > self.len {
            return Err("Pinned host active prefix exceeds allocation".into());
        }
        Ok(())
    }

    pub(crate) fn prefix(&self, count: usize) -> Result<&[T], String> {
        self.check_access(count)?;
        // Initialized allocation, checked length, and no device writes in flight.
        Ok(unsafe { std::slice::from_raw_parts(self.pointer.as_ptr(), count) })
    }

    pub(crate) fn prefix_mut(&mut self, count: usize) -> Result<&mut [T], String> {
        self.check_access(count)?;
        // Exclusive borrow, initialized checked prefix, and no DMA in flight.
        Ok(unsafe { std::slice::from_raw_parts_mut(self.pointer.as_ptr(), count) })
    }

    pub(crate) fn upload<D: DevicePtrMut<T>>(
        &mut self,
        count: usize,
        destination: &mut D,
    ) -> Result<(), String> {
        self.check_access(count)?;
        if count > destination.len() {
            return Err("Pinned upload exceeds device allocation".into());
        }
        self.stream.context().bind_to_thread().map_err(error)?;
        let (device, _record) = destination.device_ptr_mut(&self.stream);
        // Conservatively mark pending even if submission reports an error.
        self.pending = true;
        // The owned page-locked allocation cannot move/free/reuse until a
        // successful stream barrier. DevicePtrMut keeps cudarc event tracking.
        unsafe {
            result::memcpy_htod_async(
                device,
                std::slice::from_raw_parts(self.pointer.as_ptr(), count),
                self.stream.cu_stream(),
            )
        }
        .map_err(error)
    }

    pub(crate) fn download<S: DevicePtr<T>>(
        &mut self,
        count: usize,
        source: &S,
    ) -> Result<(), String> {
        self.check_access(count)?;
        if count > source.len() {
            return Err("Pinned download exceeds device allocation".into());
        }
        self.stream.context().bind_to_thread().map_err(error)?;
        let (device, _record) = source.device_ptr(&self.stream);
        self.pending = true;
        // The initialized output is exclusively owned and inaccessible to CPU
        // callers until synchronization confirms this asynchronous write ended.
        unsafe {
            result::memcpy_dtoh_async(
                std::slice::from_raw_parts_mut(self.pointer.as_ptr(), count),
                device,
                self.stream.cu_stream(),
            )
        }
        .map_err(error)
    }

    /// Caller must have successfully synchronized this buffer's owned stream.
    pub(crate) unsafe fn completed(&mut self) {
        self.pending = false;
    }
}

impl<T: DeviceRepr + ValidAsZeroBits> Drop for HostBuffer<T> {
    fn drop(&mut self) {
        if self.pending && self.stream.synchronize().is_err() {
            // Completion cannot be established: retain both allocation and
            // stream/context rather than risk DMA into freed host memory.
            std::mem::forget(self.stream.clone());
            return;
        }
        if self.stream.context().bind_to_thread().is_ok() {
            // This pointer is uniquely owned, came from malloc_host, and no
            // transfer is pending. Failure conservatively leaves it allocated.
            let _ = unsafe { result::free_host(self.pointer.as_ptr().cast()) };
        }
    }
}

pub(crate) struct HostStaging {
    pub(crate) hashes: HostBuffer<u8>,
    pub(crate) signatures: HostBuffer<u8>,
    pub(crate) recovery_ids: HostBuffer<i32>,
    pub(crate) public_keys: HostBuffer<u8>,
    pub(crate) addresses: HostBuffer<u8>,
    pub(crate) valid: HostBuffer<u8>,
}

impl HostStaging {
    pub(crate) fn new(stream: &Arc<CudaStream>, count: usize) -> Result<Self, String> {
        let bytes = |width| {
            count
                .checked_mul(width)
                .ok_or("Pinned staging size overflow")
        };
        Ok(Self {
            hashes: HostBuffer::new(stream, bytes(32)?)?,
            signatures: HostBuffer::new(stream, bytes(64)?)?,
            recovery_ids: HostBuffer::new(stream, count)?,
            public_keys: HostBuffer::new(stream, bytes(65)?)?,
            addresses: HostBuffer::new(stream, bytes(20)?)?,
            valid: HostBuffer::new(stream, count)?,
        })
    }

    /// Called only after the backend's successful final stream synchronization.
    pub(crate) unsafe fn completed(&mut self) {
        unsafe {
            self.hashes.completed();
            self.signatures.completed();
            self.recovery_ids.completed();
            self.public_keys.completed();
            self.addresses.completed();
            self.valid.completed();
        }
    }
}

fn error(error: impl std::fmt::Display) -> String {
    format!("CUDA pinned staging error: {error}")
}
