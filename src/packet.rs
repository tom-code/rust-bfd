use crate::error::PacketError;
use crate::state::{BfdState, Diagnostic};

/// BFD control packet (RFC 5880 Section 4.1), no authentication, 24 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BfdPacket {
    /// BFD protocol version; must be 1.
    pub version: u8,
    /// Local diagnostic code describing the reason for the last state change.
    pub diagnostic: Diagnostic,
    /// Local session state at the time this packet was sent.
    pub state: BfdState,
    /// Poll (P) flag — set when the sender wants a Final reply from the remote.
    pub poll: bool,
    /// Final (F) flag — set in response to a Poll packet.
    pub finalize: bool,
    /// Control Plane Independent (C) flag — set if BFD is implemented in the
    /// forwarding plane independently of the control plane.
    pub control_plane_independent: bool,
    /// Authentication Present (A) flag — always false; authentication is not supported.
    pub authentication_present: bool,
    /// Demand (D) flag — demand mode is not implemented; always false.
    pub demand: bool,
    /// Multipoint (M) flag — must be zero for point-to-point BFD.
    pub multipoint: bool,
    /// Number of missed packets before the session is declared down.
    pub detect_mult: u8,
    /// Sender's discriminator — a locally unique, non-zero handle for this session.
    pub my_discriminator: u32,
    /// The sender's view of the remote discriminator (0 until the session is established).
    pub your_discriminator: u32,
    /// Minimum TX interval the sender can support, in microseconds.
    pub desired_min_tx_interval: u32,
    /// Minimum RX interval the sender requires, in microseconds.
    pub required_min_rx_interval: u32,
    /// Minimum echo RX interval the sender will accept; 0 if echo loopback is not supported.
    pub required_min_echo_rx_interval: u32,
}

impl BfdPacket {
    /// Serialize this packet into a 24-byte wire-format buffer.
    pub fn encode(&self) -> [u8; 24] {
        let mut buf = [0u8; 24];

        // Byte 0: version (3 bits) | diagnostic (5 bits)
        buf[0] = (self.version << 5) | (self.diagnostic as u8 & 0x1F);

        // Byte 1: state (2 bits) | P | F | C | A | D | M
        buf[1] = ((self.state as u8) << 6)
            | (if self.poll { 0x20 } else { 0 })
            | (if self.finalize { 0x10 } else { 0 })
            | (if self.control_plane_independent { 0x08 } else { 0 })
            | (if self.authentication_present { 0x04 } else { 0 })
            | (if self.demand { 0x02 } else { 0 })
            | (if self.multipoint { 0x01 } else { 0 });

        buf[2] = self.detect_mult;
        buf[3] = 24; // length, no auth

        buf[4..8].copy_from_slice(&self.my_discriminator.to_be_bytes());
        buf[8..12].copy_from_slice(&self.your_discriminator.to_be_bytes());
        buf[12..16].copy_from_slice(&self.desired_min_tx_interval.to_be_bytes());
        buf[16..20].copy_from_slice(&self.required_min_rx_interval.to_be_bytes());
        buf[20..24].copy_from_slice(&self.required_min_echo_rx_interval.to_be_bytes());

        buf
    }

    /// Decode a BFD control packet from a byte slice, validating all fields per RFC 5880 §6.8.6.
    ///
    /// Returns [`PacketError`] if any mandatory field is out of range or if an
    /// unsupported feature (authentication, multipoint) is present.
    pub fn decode(buf: &[u8]) -> Result<Self, PacketError> {
        if buf.len() < 24 {
            return Err(PacketError::TooShort(buf.len()));
        }

        let version = buf[0] >> 5;
        if version != 1 {
            return Err(PacketError::InvalidVersion(version));
        }

        // RFC 5880 §6.8.6: discard if Length field < 24
        let length = buf[3];
        if (length as usize) < 24 {
            return Err(PacketError::InvalidLength(length));
        }
        if (length as usize) > buf.len() {
            return Err(PacketError::LengthExceedsPayload { length, actual: buf.len() });
        }

        let diagnostic = Diagnostic::from(buf[0] & 0x1F);
        let state = BfdState::from(buf[1] >> 6);
        let poll = buf[1] & 0x20 != 0;
        let finalize = buf[1] & 0x10 != 0;
        let control_plane_independent = buf[1] & 0x08 != 0;
        let authentication_present = buf[1] & 0x04 != 0;
        let demand = buf[1] & 0x02 != 0;
        let multipoint = buf[1] & 0x01 != 0;

        // RFC 5880 §6.8.6: discard if both P and F bits are set
        if poll && finalize {
            return Err(PacketError::PollAndFinalSet);
        }

        if multipoint {
            return Err(PacketError::InvalidMultipoint);
        }

        // RFC 5880 §6.8.6: discard if A bit set and auth is not in use
        if authentication_present {
            return Err(PacketError::AuthNotSupported);
        }

        let detect_mult = buf[2];
        if detect_mult == 0 {
            return Err(PacketError::InvalidDetectMult);
        }

        let my_discriminator = u32::from_be_bytes(buf[4..8].try_into().unwrap());
        if my_discriminator == 0 {
            return Err(PacketError::ZeroMyDiscriminator);
        }

        let your_discriminator = u32::from_be_bytes(buf[8..12].try_into().unwrap());
        let desired_min_tx_interval = u32::from_be_bytes(buf[12..16].try_into().unwrap());

        // RFC 5880 §6.8.6: desired_min_tx_interval must not be zero
        if desired_min_tx_interval == 0 {
            return Err(PacketError::ZeroDesiredMinTxInterval);
        }

        let required_min_rx_interval = u32::from_be_bytes(buf[16..20].try_into().unwrap());
        let required_min_echo_rx_interval = u32::from_be_bytes(buf[20..24].try_into().unwrap());

        Ok(BfdPacket {
            version,
            diagnostic,
            state,
            poll,
            finalize,
            control_plane_independent,
            authentication_present,
            demand,
            multipoint,
            detect_mult,
            my_discriminator,
            your_discriminator,
            desired_min_tx_interval,
            required_min_rx_interval,
            required_min_echo_rx_interval,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_packet() -> BfdPacket {
        BfdPacket {
            version: 1,
            diagnostic: Diagnostic::NoDiagnostic,
            state: BfdState::Down,
            poll: false,
            finalize: false,
            control_plane_independent: false,
            authentication_present: false,
            demand: false,
            multipoint: false,
            detect_mult: 3,
            my_discriminator: 1,
            your_discriminator: 0,
            desired_min_tx_interval: 250_000,
            required_min_rx_interval: 250_000,
            required_min_echo_rx_interval: 0,
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let pkt = make_packet();
        let encoded = pkt.encode();
        let decoded = BfdPacket::decode(&encoded).unwrap();
        assert_eq!(pkt, decoded);
    }

    #[test]
    fn known_byte_pattern() {
        let pkt = make_packet();
        let buf = pkt.encode();

        // Byte 0: version=1 (001) | diag=0 (00000) => 0x20
        assert_eq!(buf[0], 0x20);
        // Byte 1: state=Down(1) (01) | all flags 0 => 0x40
        assert_eq!(buf[1], 0x40);
        // Byte 2: detect_mult = 3
        assert_eq!(buf[2], 3);
        // Byte 3: length = 24
        assert_eq!(buf[3], 24);
        // Bytes 4-7: my_discriminator = 1
        assert_eq!(&buf[4..8], &[0, 0, 0, 1]);
        // Bytes 8-11: your_discriminator = 0
        assert_eq!(&buf[8..12], &[0, 0, 0, 0]);
        // 250_000 = 0x0003_D090
        assert_eq!(&buf[12..16], &[0x00, 0x03, 0xD0, 0x90]);
        assert_eq!(&buf[16..20], &[0x00, 0x03, 0xD0, 0x90]);
        assert_eq!(&buf[20..24], &[0, 0, 0, 0]);
    }

    #[test]
    fn decode_too_short() {
        assert!(matches!(BfdPacket::decode(&[0u8; 23]), Err(PacketError::TooShort(23))));
    }

    #[test]
    fn decode_bad_version() {
        let mut buf = make_packet().encode();
        buf[0] = (2 << 5) | (buf[0] & 0x1F); // version=2
        assert!(matches!(BfdPacket::decode(&buf), Err(PacketError::InvalidVersion(2))));
    }

    #[test]
    fn decode_invalid_length_field() {
        let mut buf = make_packet().encode();
        buf[3] = 20; // length field < 24
        assert!(matches!(BfdPacket::decode(&buf), Err(PacketError::InvalidLength(20))));
    }

    #[test]
    fn decode_length_exceeds_payload() {
        let base = make_packet().encode();
        // Extend buffer to 26 bytes but claim length=28
        let mut buf = base.to_vec();
        buf.push(0);
        buf.push(0);
        buf[3] = 28; // length field > buf.len()
        assert!(matches!(BfdPacket::decode(&buf), Err(PacketError::LengthExceedsPayload { .. })));
    }

    #[test]
    fn decode_zero_discriminator() {
        let mut buf = make_packet().encode();
        buf[4..8].copy_from_slice(&[0, 0, 0, 0]);
        assert!(matches!(BfdPacket::decode(&buf), Err(PacketError::ZeroMyDiscriminator)));
    }

    #[test]
    fn decode_zero_detect_mult() {
        let mut buf = make_packet().encode();
        buf[2] = 0;
        assert!(matches!(BfdPacket::decode(&buf), Err(PacketError::InvalidDetectMult)));
    }

    #[test]
    fn decode_auth_bit_rejected() {
        let mut buf = make_packet().encode();
        buf[1] |= 0x04; // A bit
        assert!(matches!(BfdPacket::decode(&buf), Err(PacketError::AuthNotSupported)));
    }

    #[test]
    fn decode_multipoint_rejected() {
        let mut buf = make_packet().encode();
        buf[1] |= 0x01; // M bit
        assert!(matches!(BfdPacket::decode(&buf), Err(PacketError::InvalidMultipoint)));
    }

    #[test]
    fn decode_zero_desired_min_tx() {
        let mut buf = make_packet().encode();
        buf[12..16].copy_from_slice(&[0, 0, 0, 0]);
        assert!(matches!(BfdPacket::decode(&buf), Err(PacketError::ZeroDesiredMinTxInterval)));
    }

    #[test]
    fn poll_only_flag() {
        let mut pkt = make_packet();
        pkt.poll = true;
        let buf = pkt.encode();
        assert_eq!(buf[1] & 0x20, 0x20);
        let decoded = BfdPacket::decode(&buf).unwrap();
        assert!(decoded.poll);
        assert!(!decoded.finalize);
    }

    #[test]
    fn final_only_flag() {
        let mut pkt = make_packet();
        pkt.finalize = true;
        let buf = pkt.encode();
        assert_eq!(buf[1] & 0x10, 0x10);
        let decoded = BfdPacket::decode(&buf).unwrap();
        assert!(!decoded.poll);
        assert!(decoded.finalize);
    }

    #[test]
    fn poll_and_final_both_set_rejected() {
        let mut pkt = make_packet();
        pkt.poll = true;
        pkt.finalize = true;
        let buf = pkt.encode();
        assert_eq!(buf[1] & 0x30, 0x30);
        assert!(matches!(BfdPacket::decode(&buf), Err(PacketError::PollAndFinalSet)));
    }

    #[test]
    fn state_up_encoded() {
        let mut pkt = make_packet();
        pkt.state = BfdState::Up;
        let buf = pkt.encode();
        assert_eq!(buf[1] >> 6, 3);
    }
}
