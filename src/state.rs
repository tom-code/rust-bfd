//! BFD session states, diagnostics, and operating modes per RFC 5880.

/// Local session state, as defined in RFC 5880 §4.1.
///
/// The state machine transitions between these values based on received
/// control packets and timer events. Both sides independently track their
/// own state; the remote state is carried in every control packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BfdState {
    /// The session is being held administratively down. The local system
    /// will not participate in BFD for this peer until explicitly re-enabled.
    AdminDown = 0,
    /// The session is down. The system is attempting to establish a session
    /// by sending control packets.
    Down = 1,
    /// The local system has received a `Down` packet from the remote and is
    /// waiting for the remote to acknowledge the session.
    Init = 2,
    /// The session is established and both sides are exchanging control packets.
    Up = 3,
}

impl From<u8> for BfdState {
    fn from(v: u8) -> Self {
        match v {
            0 => BfdState::AdminDown,
            1 => BfdState::Down,
            2 => BfdState::Init,
            3 => BfdState::Up,
            _ => BfdState::Down,
        }
    }
}

/// Diagnostic code indicating the reason for the last state change, per RFC 5880 §4.1.
///
/// The local diagnostic is included in every outgoing control packet so the
/// remote peer can understand why a session went down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Diagnostic {
    /// No diagnostic; the session has not experienced a failure.
    NoDiagnostic = 0,
    /// The session went down because the control detection timer expired.
    ControlDetectionTimeExpired = 1,
    /// The BFD echo function failed.
    EchoFunctionFailed = 2,
    /// The remote signaled that its session is down (received `Down` or `AdminDown`).
    NeighborSignaledSessionDown = 3,
    /// A forwarding plane reset was detected.
    ForwardingPlaneReset = 4,
    /// The path to the remote is down.
    PathDown = 5,
    /// A concatenated path is down.
    ConcatenatedPathDown = 6,
    /// The session was administratively taken down.
    AdminDown = 7,
    /// A reverse concatenated path is down.
    ReverseConcatenatedPathDown = 8,
}

impl From<u8> for Diagnostic {
    fn from(v: u8) -> Self {
        match v {
            0 => Diagnostic::NoDiagnostic,
            1 => Diagnostic::ControlDetectionTimeExpired,
            2 => Diagnostic::EchoFunctionFailed,
            3 => Diagnostic::NeighborSignaledSessionDown,
            4 => Diagnostic::ForwardingPlaneReset,
            5 => Diagnostic::PathDown,
            6 => Diagnostic::ConcatenatedPathDown,
            7 => Diagnostic::AdminDown,
            8 => Diagnostic::ReverseConcatenatedPathDown,
            _ => Diagnostic::NoDiagnostic,
        }
    }
}

/// Per-peer operating mode, determining which RFC governs TTL validation.
///
/// A single daemon can mix single-hop and multi-hop peers. The mode is set
/// when a peer is added and controls how strictly incoming TTL values are
/// checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive(Default)]
pub enum BfdMode {
    /// Single-hop BFD per RFC 5881.
    ///
    /// Packets must arrive with IP TTL = 255 (the sender sets TTL = 255;
    /// any decrement means the packet crossed a router and is rejected).
    #[default]
    SingleHop,
    /// Multi-hop BFD per RFC 5883.
    ///
    /// `max_hops` is the maximum number of IP hops to the peer. Incoming
    /// packets must arrive with TTL ≥ 255 − `max_hops`. Must be ≥ 1.
    MultiHop { max_hops: u8 },
}


/// Notification that a BFD session changed state.
///
/// Published on the [`BfdDaemon`](crate::BfdDaemon) broadcast channel every
/// time a session transitions to a new state. Multiple subscribers each
/// receive their own copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateChange {
    /// The remote peer whose session changed.
    pub peer: std::net::SocketAddr,
    /// The state the session was in before this transition.
    pub old_state: BfdState,
    /// The state the session moved to.
    pub new_state: BfdState,
    /// Local diagnostic code explaining why the transition occurred.
    pub diagnostic: Diagnostic,
}
