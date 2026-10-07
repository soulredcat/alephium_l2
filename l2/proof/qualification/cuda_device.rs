//! Read-only attributes of the same CUDA device selected by the pinned HAL.
use cust::device::{Device, DeviceAttribute};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    cust::init(cust::CudaFlags::empty())?;
    let device = Device::get_device(0)?;
    println!(
        "device_index=0 name={} multiprocessors={}",
        device.name()?,
        device.get_attribute(DeviceAttribute::MultiprocessorCount)?
    );
    Ok(())
}
