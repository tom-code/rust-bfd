//! Error types for BFD packet decoding and daemon operations.

use thiserror::Error;

/// Errors that can occur while decoding a BFD control packet (RFC 5880 §6.8.6).
///
/// All variants correspond to a specific discard rule in the RFC. The packet
/// is always dropped on error; there is no partial-decode path.
#[derive(Debug, Error)]
pub enum PacketError {
    /// The byte slice is shorter than the minimum 24-byte BFD header.
    #[error("packet too short: got {0} bytes, need 24")]
    TooShort(usize),
    /// The version field in byte 0 is not 1.
    #[error("invalid BFD version: {0}")]
    InvalidVersion(u8),
    /// The Length field is less than 24 (the minimum mandatory header size).
    #[error("invalid length field: {0} (must be >= 24)")]
    InvalidLength(u8),
    /// The Length field claims more bytes than the supplied slice contains.
    #[error("length field ({length}) exceeds payload size ({actual})")]
    LengthExceedsPayload { length: u8, actual: usize },
    /// `detect_mult` is 0, which is forbidden by the RFC.
    #[error("detect_mult must be non-zero")]
    InvalidDetectMult,
    /// The multipoint (M) bit is set; this library only supports point-to-point BFD.
    #[error("multipoint bit must be zero")]
    InvalidMultipoint,
    /// `my_discriminator` is 0; the RFC requires a non-zero value.
    #[error("my_discriminator must be non-zero")]
    ZeroMyDiscriminator,
    /// The authentication (A) bit is set; this library does not implement BFD authentication.
    #[error("authentication not supported")]
    AuthNotSupported,
    /// `desired_min_tx_interval` is 0, which is forbidden by the RFC.
    #[error("desired_min_tx_interval must be non-zero")]
    ZeroDesiredMinTxInterval,
    /// Both Poll (P) and Final (F) bits are set; RFC 5880 §6.8.6 requires discarding such packets.
    #[error("poll and final bits must not both be set")]
    PollAndFinalSet,
}

/// Top-level errors returned by [`BfdDaemon`](crate::BfdDaemon) operations.
#[derive(Debug, Error)]
pub enum BfdError {
    /// An underlying I/O error from the OS (socket creation, send, recv, etc.).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// A received packet failed to decode.
    #[error("packet error: {0}")]
    Packet(#[from] PacketError),
    /// The requested peer has no active session.
    #[error("session not found for peer {0}")]
    SessionNotFound(std::net::SocketAddr),
    /// Attempted to add a peer that already has an active session.
    #[error("session already exists for peer {0}")]
    SessionExists(std::net::SocketAddr),
    /// A [`BfdConfig`](crate::BfdConfig) argument is invalid.
    #[error("invalid configuration: {0}")]
    InvalidConfig(&'static str),
    /// A Poll sequence is already in progress for the session; only one at a time is allowed.
    #[error("poll sequence already in progress for peer {0}")]
    PollInProgress(std::net::SocketAddr),
}
