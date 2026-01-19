#[allow(unused_imports)]
use anyhow::{Context, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Parsed IP packet information
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IpPacketInfo {
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub protocol: u8,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
}

/// Parse an IPv4 packet and extract header information
pub fn parse_ipv4_packet(packet: &[u8]) -> Result<IpPacketInfo> {
    if packet.len() < 20 {
        anyhow::bail!("Packet too short for IPv4 header");
    }

    let version = (packet[0] >> 4) & 0x0F;
    if version != 4 {
        anyhow::bail!("Not an IPv4 packet (version = {})", version);
    }

    let ihl = (packet[0] & 0x0F) as usize * 4; // Internet Header Length in bytes
    if packet.len() < ihl {
        anyhow::bail!("Packet too short for IPv4 header with IHL = {}", ihl);
    }

    let protocol = packet[9];
    
    let src_addr = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst_addr = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

    // Extract ports if TCP or UDP
    let (src_port, dst_port) = if packet.len() >= ihl + 4 {
        match protocol {
            6 | 17 => {  // TCP = 6, UDP = 17
                let src_port = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
                let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);
                (Some(src_port), Some(dst_port))
            }
            _ => (None, None),
        }
    } else {
        (None, None)
    };

    Ok(IpPacketInfo {
        src_addr: IpAddr::V4(src_addr),
        dst_addr: IpAddr::V4(dst_addr),
        protocol,
        src_port,
        dst_port,
    })
}

/// Parse an IPv6 packet and extract header information
pub fn parse_ipv6_packet(packet: &[u8]) -> Result<IpPacketInfo> {
    if packet.len() < 40 {
        anyhow::bail!("Packet too short for IPv6 header");
    }

    let version = (packet[0] >> 4) & 0x0F;
    if version != 6 {
        anyhow::bail!("Not an IPv6 packet (version = {})", version);
    }

    let protocol = packet[6];

    let mut src_bytes = [0u8; 16];
    let mut dst_bytes = [0u8; 16];
    src_bytes.copy_from_slice(&packet[8..24]);
    dst_bytes.copy_from_slice(&packet[24..40]);

    let src_addr = Ipv6Addr::from(src_bytes);
    let dst_addr = Ipv6Addr::from(dst_bytes);

    // Extract ports if TCP or UDP
    let (src_port, dst_port) = if packet.len() >= 44 {
        match protocol {
            6 | 17 => {  // TCP = 6, UDP = 17
                let src_port = u16::from_be_bytes([packet[40], packet[41]]);
                let dst_port = u16::from_be_bytes([packet[42], packet[43]]);
                (Some(src_port), Some(dst_port))
            }
            _ => (None, None),
        }
    } else {
        (None, None)
    };

    Ok(IpPacketInfo {
        src_addr: IpAddr::V6(src_addr),
        dst_addr: IpAddr::V6(dst_addr),
        protocol,
        src_port,
        dst_port,
    })
}

/// Parse an IP packet (v4 or v6) and extract header information
pub fn parse_ip_packet(packet: &[u8]) -> Result<IpPacketInfo> {
    if packet.is_empty() {
        anyhow::bail!("Empty packet");
    }

    let version = (packet[0] >> 4) & 0x0F;
    match version {
        4 => parse_ipv4_packet(packet),
        6 => parse_ipv6_packet(packet),
        _ => anyhow::bail!("Unknown IP version: {}", version),
    }
}

/// Modify source IP address in an IPv4 packet (for NAT)
pub fn modify_ipv4_src_addr(packet: &mut [u8], new_src: Ipv4Addr) -> Result<()> {
    if packet.len() < 20 {
        anyhow::bail!("Packet too short for IPv4 header");
    }

    let octets = new_src.octets();
    packet[12..16].copy_from_slice(&octets);

    // Recalculate checksum
    recalculate_ipv4_checksum(packet)?;

    Ok(())
}

/// Modify destination IP address in an IPv4 packet (for NAT)
pub fn modify_ipv4_dst_addr(packet: &mut [u8], new_dst: Ipv4Addr) -> Result<()> {
    if packet.len() < 20 {
        anyhow::bail!("Packet too short for IPv4 header");
    }

    let octets = new_dst.octets();
    packet[16..20].copy_from_slice(&octets);

    // Recalculate checksum
    recalculate_ipv4_checksum(packet)?;

    Ok(())
}

/// Recalculate IPv4 header checksum
fn recalculate_ipv4_checksum(packet: &mut [u8]) -> Result<()> {
    if packet.len() < 20 {
        anyhow::bail!("Packet too short for IPv4 header");
    }

    let ihl = ((packet[0] & 0x0F) as usize) * 4;
    if packet.len() < ihl {
        anyhow::bail!("Packet too short for IPv4 IHL");
    }

    // Clear existing checksum
    packet[10] = 0;
    packet[11] = 0;

    // Calculate checksum
    let mut sum: u32 = 0;
    for i in (0..ihl).step_by(2) {
        let word = u16::from_be_bytes([packet[i], packet[i + 1]]);
        sum += word as u32;
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    let checksum = !sum as u16;
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());

    Ok(())
}
