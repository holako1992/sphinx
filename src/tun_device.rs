#[allow(unused_imports)]
use anyhow::{Context, Result};
use std::net::IpAddr;

#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;

/// TUN device for sending/receiving raw IP packets
pub struct TunDevice {
    #[cfg(target_os = "linux")]
    device: tun::platform::Device,
    #[cfg(not(target_os = "linux"))]
    #[allow(dead_code)]
    device: (),
    name: String,
}

impl TunDevice {
    /// Create a new TUN device with the given name and address
    pub fn new(name: &str, address: IpAddr, netmask: IpAddr) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let mut config = tun::Configuration::default();
            config
                .name(name)
                .address(address)
                .netmask(netmask)
                .up();

            let device = tun::create(&config)
                .context("Failed to create TUN device")?;

            log::info!("Created TUN device: {} ({})", name, address);

            Ok(Self {
                device,
                name: name.to_string(),
            })
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = (address, netmask); // Suppress unused warnings
            log::warn!("TUN device not supported on this platform, using stub");
            Ok(Self {
                device: (),
                name: name.to_string(),
            })
        }
    }

    /// Read a packet from the TUN device
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        #[cfg(target_os = "linux")]
        {
            use std::io::Read;
            self.device.read(buf)
                .context("Failed to read from TUN device")
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = buf; // Suppress unused warning
            anyhow::bail!("TUN read not supported on this platform")
        }
    }

    /// Write a packet to the TUN device
    pub fn write(&mut self, buf: &[u8]) -> Result<usize> {
        #[cfg(target_os = "linux")]
        {
            use std::io::Write;
            self.device.write(buf)
                .context("Failed to write to TUN device")
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = buf; // Suppress unused warning
            anyhow::bail!("TUN write not supported on this platform")
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(target_os = "linux")]
impl AsRawFd for TunDevice {
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        self.device.as_raw_fd()
    }
}
