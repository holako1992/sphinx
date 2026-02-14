/// Payload format definitions for type-safe packet handling
/// 
/// This module defines strict payload formats to avoid fragile heuristic parsing.
/// All payloads start with a 1-byte packet type field, followed by type-specific data.

use crate::{Error, ErrorKind, Result};

/// Packet type discriminator (first byte of payload)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    /// Forward packet to exit node
    Forward = 0x01,
    /// SURB reply packet returning to client
    Reply = 0x02,
    /// Health check ping packet
    Ping = 0x03,
    /// Health check acknowledgment
    Ack = 0x04,
}

impl PacketType {
    pub fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            0x01 => Ok(PacketType::Forward),
            0x02 => Ok(PacketType::Reply),
            0x03 => Ok(PacketType::Ping),
            0x04 => Ok(PacketType::Ack),
            _ => Err(Error::new(
                ErrorKind::InvalidPayload,
                format!("Invalid packet type: 0x{:02x}", byte),
            )),
        }
    }

    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

/// Forward packet payload format:
/// [1 byte: type=0x01][2 bytes: sender_tag_len][sender_tag][1 byte: has_surb][surb_len: 2][surb][data]
#[derive(Debug, Clone)]
pub struct ForwardPayload {
    pub sender_tag: Vec<u8>,  // Random tag identifying the sender (not revealing identity)
    pub surb: Option<Vec<u8>>,  // Optional single SURB for reply
    pub data: Vec<u8>,
}

impl ForwardPayload {
    /// Create a new forward payload with an optional SURB
    pub fn new(sender_tag: Vec<u8>, surb: Option<Vec<u8>>, data: Vec<u8>) -> Self {
        Self {
            sender_tag,
            surb,
            data,
        }
    }

    /// Serialize to bytes with strict format
    pub fn to_bytes(&self) -> Vec<u8> {
        let sender_tag_len = (self.sender_tag.len() as u16).to_be_bytes();

        let mut bytes = Vec::new();
        bytes.push(PacketType::Forward.to_byte()); // Type field
        bytes.extend_from_slice(&sender_tag_len);  // Sender tag length
        bytes.extend_from_slice(&self.sender_tag); // Sender tag
        
        // Serialize optional SURB
        if let Some(surb) = &self.surb {
            bytes.push(1); // Has SURB
            let surb_len = (surb.len() as u16).to_be_bytes();
            bytes.extend_from_slice(&surb_len);
            bytes.extend_from_slice(surb);
        } else {
            bytes.push(0); // No SURB
        }
        
        bytes.extend_from_slice(&self.data);       // Data
        bytes
    }

    /// Parse from bytes with strict format validation
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidPayload,
                "Empty payload",
            ));
        }

        // Check packet type
        let packet_type = PacketType::from_byte(bytes[0])?;
        if packet_type != PacketType::Forward {
            return Err(Error::new(
                ErrorKind::InvalidPayload,
                format!("Expected Forward packet type, got {:?}", packet_type),
            ));
        }

        let mut offset = 1;

        // Parse sender tag length
        if bytes.len() < offset + 2 {
            return Err(Error::new(
                ErrorKind::InvalidPayload,
                "Payload too short for sender tag length",
            ));
        }
        let sender_tag_len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        offset += 2;

        // Parse sender tag
        if bytes.len() < offset + sender_tag_len {
            return Err(Error::new(
                ErrorKind::InvalidPayload,
                "Payload too short for sender tag",
            ));
        }
        let sender_tag = bytes[offset..offset + sender_tag_len].to_vec();
        offset += sender_tag_len;

        // Parse optional SURB
        if bytes.len() < offset + 1 {
            return Err(Error::new(
                ErrorKind::InvalidPayload,
                "Payload too short for SURB flag",
            ));
        }
        let has_surb = bytes[offset];
        offset += 1;

        let surb = if has_surb == 1 {
            // Parse SURB length
            if bytes.len() < offset + 2 {
                return Err(Error::new(
                    ErrorKind::InvalidPayload,
                    "Payload too short for SURB length",
                ));
            }
            let surb_len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
            offset += 2;

            // Parse SURB
            if bytes.len() < offset + surb_len {
                return Err(Error::new(
                    ErrorKind::InvalidPayload,
                    "Payload too short for SURB",
                ));
            }
            let surb_bytes = bytes[offset..offset + surb_len].to_vec();
            offset += surb_len;
            Some(surb_bytes)
        } else if has_surb == 0 {
            None
        } else {
            return Err(Error::new(
                ErrorKind::InvalidPayload,
                format!("Invalid SURB flag: {}", has_surb),
            ));
        };

        // Remaining bytes are data
        let data = bytes[offset..].to_vec();

        Ok(Self {
            sender_tag,
            surb,
            data,
        })
    }
}

/// Reply packet payload format:
/// [1 byte: type=0x02][data]
#[derive(Debug, Clone)]
pub struct ReplyPayload {
    pub data: Vec<u8>,
}

impl ReplyPayload {
    /// Create a new reply payload
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Serialize to bytes with strict format
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(PacketType::Reply.to_byte()); // Type field
        bytes.extend_from_slice(&self.data);      // Data
        bytes
    }

    /// Parse from bytes with strict format validation
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidPayload,
                "Empty payload",
            ));
        }

        // Check packet type
        let packet_type = PacketType::from_byte(bytes[0])?;
        if packet_type != PacketType::Reply {
            return Err(Error::new(
                ErrorKind::InvalidPayload,
                format!("Expected Reply packet type, got {:?}", packet_type),
            ));
        }

        // Remaining bytes are data
        let data = bytes[1..].to_vec();

        Ok(Self { data })
    }
}

/// Ping packet payload format (health check):
/// [1 byte: type=0x03][1 byte: hop_index][2 bytes: surb_count][surb1_len: 2][surb1]...
#[derive(Debug, Clone)]
pub struct PingPayload {
    pub hop_index: u8,        // Current hop index (0 for first hop)
    pub surbs: Vec<Vec<u8>>,  // SURBs for each hop to send ACK back
}

impl PingPayload {
    /// Create a new ping payload
    pub fn new(hop_index: u8, surbs: Vec<Vec<u8>>) -> Self {
        Self { hop_index, surbs }
    }

    /// Serialize to bytes with strict format
    pub fn to_bytes(&self) -> Vec<u8> {
        let surb_count = (self.surbs.len() as u16).to_be_bytes();

        let mut bytes = Vec::new();
        bytes.push(PacketType::Ping.to_byte()); // Type field
        bytes.push(self.hop_index);              // Hop index
        bytes.extend_from_slice(&surb_count);    // Number of SURBs
        
        // Serialize each SURB with its length
        for surb in &self.surbs {
            let surb_len = (surb.len() as u16).to_be_bytes();
            bytes.extend_from_slice(&surb_len);
            bytes.extend_from_slice(surb);
        }
        
        bytes
    }

    /// Parse from bytes with strict format validation
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidPayload,
                "Empty payload",
            ));
        }

        // Check packet type
        let packet_type = PacketType::from_byte(bytes[0])?;
        if packet_type != PacketType::Ping {
            return Err(Error::new(
                ErrorKind::InvalidPayload,
                format!("Expected Ping packet type, got {:?}", packet_type),
            ));
        }

        let mut offset = 1;

        // Parse hop index
        if bytes.len() < offset + 1 {
            return Err(Error::new(
                ErrorKind::InvalidPayload,
                "Payload too short for hop index",
            ));
        }
        let hop_index = bytes[offset];
        offset += 1;

        // Parse SURB count
        if bytes.len() < offset + 2 {
            return Err(Error::new(
                ErrorKind::InvalidPayload,
                "Payload too short for SURB count",
            ));
        }
        let surb_count = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        offset += 2;

        // Parse each SURB
        let mut surbs = Vec::new();
        for _ in 0..surb_count {
            // Parse SURB length
            if bytes.len() < offset + 2 {
                return Err(Error::new(
                    ErrorKind::InvalidPayload,
                    "Payload too short for SURB length",
                ));
            }
            let surb_len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
            offset += 2;

            // Parse SURB
            if bytes.len() < offset + surb_len {
                return Err(Error::new(
                    ErrorKind::InvalidPayload,
                    "Payload too short for SURB",
                ));
            }
            let surb_bytes = bytes[offset..offset + surb_len].to_vec();
            offset += surb_len;
            surbs.push(surb_bytes);
        }

        Ok(Self { hop_index, surbs })
    }
}

/// Ack packet payload format (health check response):
/// [1 byte: type=0x04][1 byte: hop_index][32 bytes: node_address]
#[derive(Debug, Clone)]
pub struct AckPayload {
    pub hop_index: u8,            // Which hop this ACK is from
    pub node_address: [u8; 32],   // Sphinx address of the responding node
}

impl AckPayload {
    /// Create a new ACK payload
    pub fn new(hop_index: u8, node_address: [u8; 32]) -> Self {
        Self {
            hop_index,
            node_address,
        }
    }

    /// Serialize to bytes with strict format
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(PacketType::Ack.to_byte());       // Type field
        bytes.push(self.hop_index);                   // Hop index
        bytes.extend_from_slice(&self.node_address);  // Node address
        bytes
    }

    /// Parse from bytes with strict format validation
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(Error::new(
                ErrorKind::InvalidPayload,
                "Empty payload",
            ));
        }

        // Check packet type
        let packet_type = PacketType::from_byte(bytes[0])?;
        if packet_type != PacketType::Ack {
            return Err(Error::new(
                ErrorKind::InvalidPayload,
                format!("Expected Ack packet type, got {:?}", packet_type),
            ));
        }

        // Expected size: 1 (type) + 1 (hop) + 32 (address) = 34 bytes
        if bytes.len() < 34 {
            return Err(Error::new(
                ErrorKind::InvalidPayload,
                format!("Ack payload too short: {} bytes, expected at least 34", bytes.len()),
            ));
        }

        let hop_index = bytes[1];
        
        let mut node_address = [0u8; 32];
        node_address.copy_from_slice(&bytes[2..34]);

        Ok(Self {
            hop_index,
            node_address,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_forward_payload_roundtrip_with_surb() {
        let original = ForwardPayload::new(
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            Some(vec![1, 2, 3, 4]),
            vec![5, 6, 7, 8, 9],
        );

        let bytes = original.to_bytes();
        let parsed = ForwardPayload::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.surb, Some(vec![1, 2, 3, 4]));
        assert_eq!(parsed.data, original.data);
    }

    #[test]
    fn test_forward_payload_roundtrip_no_surb() {
        let original = ForwardPayload::new(
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            None,
            vec![10, 11, 12],
        );

        let bytes = original.to_bytes();
        let parsed = ForwardPayload::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.surb, None);
        assert_eq!(parsed.data, original.data);
    }

    #[test]
    fn test_reply_payload_roundtrip() {
        let original = ReplyPayload::new(vec![1, 2, 3, 4, 5]);

        let bytes = original.to_bytes();
        let parsed = ReplyPayload::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.data, original.data);
    }

    #[test]
    fn test_packet_type_detection() {
        let forward = ForwardPayload::new(
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            None,
            vec![],
        );
        let forward_bytes = forward.to_bytes();
        assert_eq!(PacketType::from_byte(forward_bytes[0]).unwrap(), PacketType::Forward);

        let reply = ReplyPayload::new(vec![1, 2, 3]);
        let reply_bytes = reply.to_bytes();
        assert_eq!(PacketType::from_byte(reply_bytes[0]).unwrap(), PacketType::Reply);
    }

    #[test]
    fn test_wrong_type_parsing() {
        let forward = ForwardPayload::new(
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            None,
            vec![]);
        let bytes = forward.to_bytes();
        
        // Try to parse as reply - should fail
        assert!(ReplyPayload::from_bytes(&bytes).is_err());
    }
}
