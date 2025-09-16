//! NORC binary wire format implementation
//!
//! This module implements the binary wire format for NORC protocol messages,
//! including framing, encoding, decoding, and streaming support.

use crate::error::{NorcError, Result};
use crate::messages::{MessageType, NorcMessage};
use crate::types::Hash;
use crate::version::Version;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use tokio_util::codec::{Decoder, Encoder};
use bytes::BytesMut;
use uuid::Uuid;

/// Maximum frame size (64KB) to prevent DoS attacks
pub const MAX_FRAME_SIZE: usize = 65536;

/// Minimum frame header size
pub const MIN_HEADER_SIZE: usize = 64; // version(2) + type(1) + length(4) + id(16) + seq(8) + prev_hash(32) + reserved(1)

/// NORC binary wire format frame
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// ├─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┤
/// │  Ver  │   Type    │            Length (payload)               │
/// ├─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┤
/// │                          Message ID (128 bits)                │
/// ├─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┤
/// │                      Sequence Number (64 bits)                │
/// ├─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┤
/// │                   Prev Message Hash (256 bits)                │
/// ├─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┼─┤
/// │ Reserved  │                  Payload...                       │
/// └───────────────────────────────────────────────────────────────┘
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireFrame {
    /// Protocol version
    pub version: Version,
    /// Message type
    pub message_type: MessageType,
    /// Payload length
    pub length: u32,
    /// Message identifier
    pub message_id: Uuid,
    /// Sequence number
    pub sequence_number: u64,
    /// Previous message hash
    pub prev_message_hash: Hash,
    /// Reserved byte for future use
    pub reserved: u8,
    /// Message payload
    pub payload: Vec<u8>,
}

impl WireFrame {
    /// Create a new wire frame
    pub fn new(
        version: Version,
        message_type: MessageType,
        message_id: Uuid,
        sequence_number: u64,
        prev_message_hash: Hash,
        payload: Vec<u8>,
    ) -> Result<Self> {
        if payload.len() > MAX_FRAME_SIZE - MIN_HEADER_SIZE {
            return Err(NorcError::validation(format!(
                "Payload too large: {} bytes (max: {})",
                payload.len(),
                MAX_FRAME_SIZE - MIN_HEADER_SIZE
            )));
        }

        Ok(Self {
            version,
            message_type,
            length: payload.len() as u32,
            message_id,
            sequence_number,
            prev_message_hash,
            reserved: 0,
            payload,
        })
    }

    /// Encode frame to bytes
    pub fn encode(&self) -> Result<Vec<u8>> {
        let total_size = MIN_HEADER_SIZE + self.payload.len();
        let mut buf = Vec::with_capacity(total_size);

        // Version (2 bytes)
        buf.push(self.version.major);
        buf.push(self.version.minor);

        // Message type (1 byte)
        buf.push(self.message_type.as_byte());

        // Length (4 bytes, big-endian)
        buf.extend_from_slice(&self.length.to_be_bytes());

        // Message ID (16 bytes)
        buf.extend_from_slice(self.message_id.as_bytes());

        // Sequence number (8 bytes, big-endian)
        buf.extend_from_slice(&self.sequence_number.to_be_bytes());

        // Previous message hash (32 bytes)
        buf.extend_from_slice(&self.prev_message_hash);

        // Reserved (1 byte)
        buf.push(self.reserved);

        // Payload
        buf.extend_from_slice(&self.payload);

        Ok(buf)
    }

    /// Decode frame from bytes
    pub fn decode(mut data: &[u8]) -> Result<Self> {
        if data.len() < MIN_HEADER_SIZE {
            return Err(NorcError::codec(format!(
                "Frame too small: {} bytes (min: {})",
                data.len(),
                MIN_HEADER_SIZE
            )));
        }

        // Parse version
        let major = data[0];
        let minor = data[1];
        let version = Version::new(major, minor)?;
        data = &data[2..];

        // Parse message type
        let message_type = MessageType::from_byte(data[0])?;
        data = &data[1..];

        // Parse length
        let length = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        data = &data[4..];

        // Parse message ID
        let message_id_bytes: [u8; 16] = data[..16]
            .try_into()
            .map_err(|_| NorcError::codec("Invalid message ID"))?;
        let message_id = Uuid::from_bytes(message_id_bytes);
        data = &data[16..];

        // Parse sequence number
        let sequence_number = u64::from_be_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);
        data = &data[8..];

        // Parse previous message hash
        let prev_message_hash: Hash = data[..32]
            .try_into()
            .map_err(|_| NorcError::codec("Invalid previous message hash"))?;
        data = &data[32..];

        // Parse reserved byte
        let reserved = data[0];
        data = &data[1..];

        // Validate payload length
        if data.len() != length as usize {
            return Err(NorcError::codec(format!(
                "Payload length mismatch: expected {}, got {}",
                length,
                data.len()
            )));
        }

        if length as usize > MAX_FRAME_SIZE - MIN_HEADER_SIZE {
            return Err(NorcError::codec(format!(
                "Payload too large: {} bytes",
                length
            )));
        }

        let payload = data.to_vec();

        Ok(Self {
            version,
            message_type,
            length,
            message_id,
            sequence_number,
            prev_message_hash,
            reserved,
            payload,
        })
    }

    /// Get the total frame size including header
    pub fn total_size(&self) -> usize {
        MIN_HEADER_SIZE + self.payload.len()
    }

    /// Validate frame integrity
    pub fn validate(&self) -> Result<()> {
        if self.length as usize != self.payload.len() {
            return Err(NorcError::validation(
                "Payload length field does not match actual payload",
            ));
        }

        if self.payload.len() > MAX_FRAME_SIZE - MIN_HEADER_SIZE {
            return Err(NorcError::validation("Payload exceeds maximum size"));
        }

        if self.version.major == 0 {
            return Err(NorcError::validation("Invalid protocol version"));
        }

        Ok(())
    }
}

/// Wire format trait for serializable types
pub trait WireFormat: Sized {
    /// Encode to binary format
    fn encode(&self) -> Result<Vec<u8>>;

    /// Decode from binary format
    fn decode(data: &[u8]) -> Result<Self>;

    /// Get the encoded size (if known without encoding)
    fn encoded_size(&self) -> Option<usize> {
        None
    }
}

impl WireFormat for NorcMessage {
    fn encode(&self) -> Result<Vec<u8>> {
        // First serialize the message payload
        let payload = bincode::serialize(&self.payload)
            .map_err(|e| NorcError::codec(format!("Failed to encode message payload: {e}")))?;

        // Create wire frame
        let frame = WireFrame::new(
            self.version,
            self.message_type,
            self.message_id,
            self.sequence_number,
            self.prev_message_hash,
            payload,
        )?;

        frame.encode()
    }

    fn decode(data: &[u8]) -> Result<Self> {
        // Decode wire frame
        let frame = WireFrame::decode(data)?;

        // Deserialize payload
        let payload = bincode::deserialize(&frame.payload)
            .map_err(|e| NorcError::codec(format!("Failed to decode message payload: {e}")))?;

        let message = Self {
            version: frame.version,
            message_type: frame.message_type,
            message_id: frame.message_id,
            sequence_number: frame.sequence_number,
            prev_message_hash: frame.prev_message_hash,
            timestamp: chrono::Utc::now(), // Will be overridden by actual timestamp from payload
            payload,
        };

        // TODO: integrate HashChainValidator (framing.rs) here once higher layer supplies context.
        // This requires external state; keeping pure decode side-effect free for now.

        // Validate the decoded message
        message.validate()?;

        Ok(message)
    }
}

/// Tokio codec for streaming NORC frames
#[derive(Debug)]
pub struct FrameCodec {
    /// Maximum frame size to accept
    max_frame_size: usize,
    /// Current state of decoder
    state: DecodeState,
}

#[derive(Debug, Clone)]
enum DecodeState {
    /// Waiting for frame header
    WaitingForHeader,
    /// Waiting for payload (header_size, payload_size)
    WaitingForPayload(usize, usize),
}

impl FrameCodec {
    /// Create a new frame codec with default settings
    pub fn new() -> Self {
        Self::with_max_size(MAX_FRAME_SIZE)
    }

    /// Create a new frame codec with custom maximum frame size
    pub fn with_max_size(max_frame_size: usize) -> Self {
        Self {
            max_frame_size,
            state: DecodeState::WaitingForHeader,
        }
    }
}

impl Default for FrameCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for FrameCodec {
    type Item = WireFrame;
    type Error = NorcError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>> {
        loop {
            match &self.state {
                DecodeState::WaitingForHeader => {
                    if src.len() < MIN_HEADER_SIZE {
                        // Not enough data for header
                        return Ok(None);
                    }

                    // Peek at the length field to determine total frame size
                    let length_bytes = &src[3..7]; // Skip version(2) + type(1)
                    let payload_length = u32::from_be_bytes([
                        length_bytes[0],
                        length_bytes[1],
                        length_bytes[2],
                        length_bytes[3],
                    ]) as usize;

                    let total_frame_size = MIN_HEADER_SIZE + payload_length;

                    if total_frame_size > self.max_frame_size {
                        return Err(NorcError::codec(format!(
                            "Frame too large: {} bytes (max: {})",
                            total_frame_size, self.max_frame_size
                        )));
                    }

                    self.state = DecodeState::WaitingForPayload(MIN_HEADER_SIZE, payload_length);
                }

                DecodeState::WaitingForPayload(header_size, payload_size) => {
                    let total_size = header_size + payload_size;

                    if src.len() < total_size {
                        // Not enough data for complete frame
                        return Ok(None);
                    }

                    // Extract complete frame
                    let frame_bytes = src.split_to(total_size);
                    self.state = DecodeState::WaitingForHeader;

                    // Decode the frame
                    let frame = WireFrame::decode(&frame_bytes)?;
                    return Ok(Some(frame));
                }
            }
        }
    }
}

impl Encoder<WireFrame> for FrameCodec {
    type Error = NorcError;

    fn encode(&mut self, item: WireFrame, dst: &mut BytesMut) -> Result<()> {
        let encoded = item.encode()?;

        if encoded.len() > self.max_frame_size {
            return Err(NorcError::codec(format!(
                "Frame too large to encode: {} bytes (max: {})",
                encoded.len(),
                self.max_frame_size
            )));
        }

        dst.extend_from_slice(&encoded);
        Ok(())
    }
}

impl Encoder<NorcMessage> for FrameCodec {
    type Error = NorcError;

    fn encode(&mut self, item: NorcMessage, dst: &mut BytesMut) -> Result<()> {
        let encoded = item.encode()?;
        let frame = WireFrame::decode(&encoded)?;
        self.encode(frame, dst)
    }
}

/// Frame encoder for synchronous encoding
#[derive(Debug)]
pub struct FrameEncoder;

impl FrameEncoder {
    /// Encode a message to a writer
    pub fn encode_to_writer<W: Write>(message: &NorcMessage, writer: &mut W) -> Result<()> {
        let encoded = message.encode()?;
        writer
            .write_all(&encoded)
            .map_err(|e| NorcError::transport(format!("Failed to write frame: {e}")))?;
        Ok(())
    }

    /// Encode multiple messages to a writer  
    pub fn encode_batch_to_writer<W: Write>(
        messages: &[NorcMessage],
        writer: &mut W,
    ) -> Result<()> {
        for message in messages {
            Self::encode_to_writer(message, writer)?;
        }
        Ok(())
    }
}

/// Frame decoder for synchronous decoding
#[derive(Debug)]
pub struct FrameDecoder {
    /// Buffer for partial frames
    buffer: Vec<u8>,
    /// Maximum frame size
    max_frame_size: usize,
}

impl FrameDecoder {
    /// Create a new frame decoder
    pub fn new() -> Self {
        Self::with_max_size(MAX_FRAME_SIZE)
    }

    /// Create a new frame decoder with custom maximum frame size
    pub fn with_max_size(max_frame_size: usize) -> Self {
        Self {
            buffer: Vec::new(),
            max_frame_size,
        }
    }

    /// Decode frames from a reader
    pub fn decode_from_reader<R: Read>(
        &mut self,
        reader: &mut R,
    ) -> Result<Vec<NorcMessage>> {
        let mut read_buf = [0u8; 8192];
        let bytes_read = reader
            .read(&mut read_buf)
            .map_err(|e| NorcError::transport(format!("Failed to read from stream: {e}")))?;

        if bytes_read == 0 {
            return Ok(Vec::new()); // EOF
        }

        self.buffer.extend_from_slice(&read_buf[..bytes_read]);
        self.decode_buffered()
    }

    /// Decode complete frames from the internal buffer
    pub fn decode_buffered(&mut self) -> Result<Vec<NorcMessage>> {
        let mut messages = Vec::new();
        let mut offset = 0;

        while offset + MIN_HEADER_SIZE <= self.buffer.len() {
            // Check if we have enough data for the frame
            let length_offset = offset + 3; // Skip version(2) + type(1)
            if length_offset + 4 > self.buffer.len() {
                break; // Not enough data for length field
            }

            let payload_length = u32::from_be_bytes([
                self.buffer[length_offset],
                self.buffer[length_offset + 1],
                self.buffer[length_offset + 2],
                self.buffer[length_offset + 3],
            ]) as usize;

            let total_frame_size = MIN_HEADER_SIZE + payload_length;

            if total_frame_size > self.max_frame_size {
                return Err(NorcError::codec(format!(
                    "Frame too large: {} bytes",
                    total_frame_size
                )));
            }

            if offset + total_frame_size > self.buffer.len() {
                break; // Not enough data for complete frame
            }

            // Extract and decode the frame
            let frame_data = &self.buffer[offset..offset + total_frame_size];
            let message = NorcMessage::decode(frame_data)?;
            messages.push(message);

            offset += total_frame_size;
        }

        // Remove processed data from buffer
        if offset > 0 {
            self.buffer.drain(..offset);
        }

        Ok(messages)
    }

    /// Clear the internal buffer
    pub fn clear(&mut self) {
        self.buffer.clear();
    }

    /// Get the current buffer size
    pub fn buffer_size(&self) -> usize {
        self.buffer.len()
    }
}

impl Default for FrameDecoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::{ConnectionRequestMessage, Message};
    use crate::types::Capability;
    use crate::version::Version;

    fn create_test_message() -> NorcMessage {
        let version = Version::V2_0;
        let payload = Message::ConnectionRequest(ConnectionRequestMessage {
            client_versions: vec![version],
            preferred_version: version,
            capabilities: vec![Capability::Messaging],
            client_nonce: vec![1, 2, 3, 4],
            ephemeral_public_key: [0u8; 32],
            pq_public_key: None,
        });

        NorcMessage::new(
            version,
            MessageType::ConnectionRequest,
            1,
            [0u8; 32],
            payload,
        )
    }

    #[test]
    fn test_wire_frame_roundtrip() {
        let message = create_test_message();
        let encoded = message.encode().unwrap();
        let decoded = NorcMessage::decode(&encoded).unwrap();

        assert_eq!(message.version, decoded.version);
        assert_eq!(message.message_type, decoded.message_type);
        assert_eq!(message.message_id, decoded.message_id);
        assert_eq!(message.sequence_number, decoded.sequence_number);
    }

    #[test]
    fn test_wire_frame_validation() {
        let frame = WireFrame {
            version: Version::V2_0,
            message_type: MessageType::MessageSend,
            length: 5,
            message_id: Uuid::new_v4(),
            sequence_number: 1,
            prev_message_hash: [0u8; 32],
            reserved: 0,
            payload: vec![1, 2, 3], // Length mismatch
        };

        assert!(frame.validate().is_err());
    }

    #[test]
    fn test_frame_codec() {
        let mut codec = FrameCodec::new();
        let mut buf = BytesMut::new();

        let message = create_test_message();
        let encoded = message.encode().unwrap();
        let frame = WireFrame::decode(&encoded).unwrap();

        // Encode
        codec.encode(frame.clone(), &mut buf).unwrap();

        // Decode
        let decoded = codec.decode(&mut buf).unwrap();
        assert!(decoded.is_some());
        let decoded_frame = decoded.unwrap();

        assert_eq!(frame.version, decoded_frame.version);
        assert_eq!(frame.message_type, decoded_frame.message_type);
        assert_eq!(frame.message_id, decoded_frame.message_id);
    }

    #[test]
    fn test_partial_frame_decoding() {
        let mut codec = FrameCodec::new();
        let mut buf = BytesMut::new();

        let message = create_test_message();
        let encoded = message.encode().unwrap();

        // Add partial frame
        buf.extend_from_slice(&encoded[..MIN_HEADER_SIZE / 2]);
        assert!(codec.decode(&mut buf).unwrap().is_none());

        // Add rest of header
        buf.extend_from_slice(&encoded[MIN_HEADER_SIZE / 2..MIN_HEADER_SIZE]);
        assert!(codec.decode(&mut buf).unwrap().is_none());

        // Add payload
        buf.extend_from_slice(&encoded[MIN_HEADER_SIZE..]);
        let decoded = codec.decode(&mut buf).unwrap();
        assert!(decoded.is_some());
    }

    #[test]
    fn test_frame_size_limit() {
        let mut codec = FrameCodec::with_max_size(100);
        
        // Create a frame with payload that would exceed the codec's limit when encoded
        let payload = vec![0u8; 50]; // Should be fine for creation
        let frame = WireFrame::new(
            Version::V2_0,
            MessageType::MessageSend,
            Uuid::new_v4(),
            1,
            [0u8; 32],
            payload,
        ).unwrap();

        // The frame creation should succeed, but encoding should respect codec limits
        let encoded = frame.encode().unwrap();
        let mut buf = BytesMut::from(&encoded[..]);
        
        // This should fail because the encoded frame exceeds the codec limit
        let result = codec.decode(&mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_synchronous_decoder() {
        let mut decoder = FrameDecoder::new();
        let message = create_test_message();
        let encoded = message.encode().unwrap();

        let mut reader = std::io::Cursor::new(encoded);
        let messages = decoder.decode_from_reader(&mut reader).unwrap();

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].version, message.version);
        assert_eq!(messages[0].message_type, message.message_type);
    }
}