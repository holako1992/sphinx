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
}

impl PacketType {
    pub fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            0x01 => Ok(PacketType::Forward),
            0x02 => Ok(PacketType::Reply),
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
/// [1 byte: type=0x01][2 bytes: sender_tag_len][sender_tag][2 bytes: dest_len][dest][2 bytes: surb_count][surb1_len: 2][surb1]...[data]
#[derive(Debug, Clone)]
pub struct ForwardPayload {
    pub sender_tag: Vec<u8>,  // Random tag identifying the sender (not revealing identity)
    pub destination: String,
    pub surbs: Vec<Vec<u8>>,  // Multiple SURBs for potential reply fragments
    pub data: Vec<u8>,
}

impl ForwardPayload {
    /// Create a new forward payload with a single SURB
    pub fn new(sender_tag: Vec<u8>, destination: String, surb_bytes: Vec<u8>, data: Vec<u8>) -> Self {
        Self {
            sender_tag,
            destination,
            surbs: vec![surb_bytes],
            data,
        }
    }

    /// Create a new forward payload with multiple SURBs
    pub fn new_with_surbs(sender_tag: Vec<u8>, destination: String, surbs: Vec<Vec<u8>>, data: Vec<u8>) -> Self {
        Self {
            sender_tag,
            destination,
            surbs,
            data,
        }
    }

    /// Serialize to bytes with strict format
    pub fn to_bytes(&self) -> Vec<u8> {
        let sender_tag_len = (self.sender_tag.len() as u16).to_be_bytes();
        let dest_bytes = self.destination.as_bytes();
        let dest_len = (dest_bytes.len() as u16).to_be_bytes();
        let surb_count = (self.surbs.len() as u16).to_be_bytes();

        let mut bytes = Vec::new();
        bytes.push(PacketType::Forward.to_byte()); // Type field
        bytes.extend_from_slice(&sender_tag_len);  // Sender tag length
        bytes.extend_from_slice(&self.sender_tag); // Sender tag
        bytes.extend_from_slice(&dest_len);        // Destination length
        bytes.extend_from_slice(dest_bytes);       // Destination
        bytes.extend_from_slice(&surb_count);      // Number of SURBs
        
        // Serialize each SURB with its length
        for surb in &self.surbs {
            let surb_len = (surb.len() as u16).to_be_bytes();
            bytes.extend_from_slice(&surb_len);
            bytes.extend_from_slice(surb);
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

        // Parse destination length
        if bytes.len() < offset + 2 {
            return Err(Error::new(
                ErrorKind::InvalidPayload,
                "Payload too short for destination length",
            ));
        }
        let dest_len = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]) as usize;
        offset += 2;

        // Parse destination
        if bytes.len() < offset + dest_len {
            return Err(Error::new(
                ErrorKind::InvalidPayload,
                "Payload too short for destination",
            ));
        }
        let destination = String::from_utf8(bytes[offset..offset + dest_len].to_vec())
            .map_err(|e| Error::new(ErrorKind::InvalidPayload, format!("Invalid UTF-8 in destination: {}", e)))?;
        offset += dest_len;

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

        // Remaining bytes are data
        let data = bytes[offset..].to_vec();

        Ok(Self {
            sender_tag,
            destination,
            surbs,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_forward_payload_roundtrip() {
        let original = ForwardPayload::new(
            "example.com:80".to_string(),
            vec![1, 2, 3, 4],
            vec![5, 6, 7, 8, 9],
        );

        let bytes = original.to_bytes();
        let parsed = ForwardPayload::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.destination, original.destination);
        assert_eq!(parsed.surbs.len(), 1);
        assert_eq!(parsed.surbs[0], vec![1, 2, 3, 4]);
        assert_eq!(parsed.data, original.data);
    }

    #[test]
    fn test_forward_payload_multiple_surbs() {
        let original = ForwardPayload::new_with_surbs(
            "example.com:80".to_string(),
            vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]],
            vec![10, 11, 12],
        );

        let bytes = original.to_bytes();
        let parsed = ForwardPayload::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.destination, original.destination);
        assert_eq!(parsed.surbs.len(), 3);
        assert_eq!(parsed.surbs[0], vec![1, 2, 3]);
        assert_eq!(parsed.surbs[1], vec![4, 5, 6]);
        assert_eq!(parsed.surbs[2], vec![7, 8, 9]);
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
            "test".to_string(),
            vec![],
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
        let forward = ForwardPayload::new("test".to_string(), vec![], vec![]);
        let bytes = forward.to_bytes();
        
        // Try to parse as reply - should fail
        assert!(ReplyPayload::from_bytes(&bytes).is_err());
    }
}
