//! Per-peer BFD session state machine (RFC 5880 §6.8.6).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::packet::BfdPacket;
use crate::state::{BfdMode, BfdState, Diagnostic, StateChange};

/// Operational counters for a single BFD session.
///
/// All fields are monotonically increasing; they are never reset while the
/// session exists. Retrieve via [`BfdDaemon::get_peer_counters`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionCounters {
    /// Control packets sent successfully.
    pub control_tx: u64,
    /// Control packets received and processed.
    pub control_rx: u64,
    /// Incoming control packets discarded after session lookup (TTL fail, source mismatch).
    pub control_rx_error: u64,
    /// Echo packets sent successfully.
    pub echo_tx: u64,
    /// Echo packets received (our own echo returning).
    pub echo_rx: u64,
    /// Number of local state transitions.
    pub state_transitions: u64,
    /// Number of control detection timeouts that drove the session Down.
    pub detection_timeouts: u64,
    /// Number of echo detection timeouts that drove the session Down.
    pub echo_detection_timeouts: u64,
    /// Number of Poll sequences initiated.
    pub poll_sequences: u64,
    /// Number of send errors (control or echo).
    pub send_errors: u64,
}

/// Per-peer BFD session, holding all state required by RFC 5880.
///
/// Sessions are created by [`BfdDaemon`](crate::BfdDaemon) when a peer is
/// added and driven by the daemon's single event loop. All fields are `pub`
/// so the event loop can read negotiated values directly; callers outside this
/// crate should treat them as read-only.
pub struct BfdSession {
    /// Address of the remote peer.
    pub peer_addr: SocketAddr,
    /// Locally assigned discriminator, unique within this daemon.
    pub local_discriminator: u32,
    /// The remote's discriminator (0 until the session reaches Init/Up).
    pub remote_discriminator: u32,
    /// Current local session state.
    pub local_state: BfdState,
    /// Most recently received remote session state.
    pub remote_state: BfdState,
    /// Local diagnostic code for the last state transition.
    pub local_diag: Diagnostic,
    /// Operating mode (single-hop or multi-hop) governing TTL validation.
    pub mode: BfdMode,

    // Timer configuration (microseconds)
    /// Local desired minimum TX interval, in microseconds.
    pub desired_min_tx_us: u32,
    /// Local required minimum RX interval, in microseconds.
    pub required_min_rx_us: u32,
    /// Local detection multiplier.
    pub detect_mult: u8,

    // Negotiated values from remote
    /// Remote's desired minimum TX interval (from the last received packet).
    pub remote_min_tx_us: u32,
    /// Remote's required minimum RX interval (from the last received packet).
    pub remote_min_rx_us: u32,
    /// Remote's detection multiplier (from the last received packet).
    pub remote_detect_mult: u8,

    /// Timestamp of the most recently received packet (`None` until first RX).
    pub last_rx: Option<Instant>,
    /// Absolute time at which the next TX packet should be sent.
    pub next_tx_at: Instant,

    // Poll sequence fields (RFC 5880 §6.8.3)
    /// Whether a Poll sequence is currently in progress.
    pub poll_active: bool,
    /// Deferred `desired_min_tx` value applied after Final is received (when decreasing).
    pub poll_pending_tx_us: Option<u32>,
    /// Deferred `required_min_rx` value applied after Final is received (when increasing).
    pub poll_pending_rx_us: Option<u32>,
    /// When the current Poll sequence started (for timeout detection).
    pub poll_started_at: Option<Instant>,

    // Echo mode fields
    /// Whether this session has echo TX configured locally.
    pub echo_configured: bool,
    /// Local desired minimum echo TX interval, in microseconds (0 if echo disabled).
    pub desired_min_echo_tx_us: u32,
    /// Local required minimum echo RX interval we advertise (willingness to loop back).
    pub required_min_echo_rx_us: u32,
    /// Remote's required minimum echo RX interval (from received control packets).
    pub remote_min_echo_rx_us: u32,
    /// Control TX interval to use when echo is active, in microseconds.
    pub echo_slow_timer_us: u32,
    /// Absolute time for the next echo TX (`None` when echo is inactive).
    pub next_echo_tx_at: Option<Instant>,
    /// Timestamp of the most recently received echo reply (`None` until first echo RX).
    pub last_echo_rx: Option<Instant>,
    /// When echo was last activated (`None` when echo is inactive).
    pub echo_activated_at: Option<Instant>,

    /// Operational counters for this session.
    pub counters: SessionCounters,

    /// Per-session xorshift64 PRNG state for TX jitter (RFC 5880 §6.8.7 per-packet jitter).
    /// Relaxed atomics allow interior mutability without requiring `&mut self` on `tx_interval`.
    jitter_state: AtomicU64,
}

/// Xorshift64 PRNG — advances `state` and returns the next pseudo-random u64.
/// Used for per-packet jitter per RFC 5880 §6.8.7.
fn xorshift64(state: u64) -> u64 {
    let x = state ^ (state << 13);
    let x = x ^ (x >> 7);
    x ^ (x << 17)
}

/// Initial PRNG seed from a discriminator (applies Knuth multiplicative hash for mixing).
fn jitter_seed(discriminator: u32) -> u64 {
    (discriminator as u64).wrapping_mul(0x9e3779b97f4a7c15) | 1
}

impl BfdSession {
    /// Create a new session in the `Down` state with no prior RX and an immediate TX deadline.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        peer_addr: SocketAddr,
        local_discriminator: u32,
        desired_min_tx_us: u32,
        required_min_rx_us: u32,
        detect_mult: u8,
        mode: BfdMode,
        echo_configured: bool,
        desired_min_echo_tx_us: u32,
        required_min_echo_rx_us: u32,
        echo_slow_timer_us: u32,
    ) -> Self {
        BfdSession {
            peer_addr,
            local_discriminator,
            remote_discriminator: 0,
            local_state: BfdState::Down,
            remote_state: BfdState::Down,
            local_diag: Diagnostic::NoDiagnostic,
            mode,
            desired_min_tx_us,
            required_min_rx_us,
            detect_mult,
            remote_min_tx_us: 1,
            remote_min_rx_us: 0,
            remote_detect_mult: 0,
            last_rx: None,
            next_tx_at: Instant::now(),
            poll_active: false,
            poll_pending_tx_us: None,
            poll_pending_rx_us: None,
            poll_started_at: None,
            echo_configured,
            desired_min_echo_tx_us,
            required_min_echo_rx_us,
            remote_min_echo_rx_us: 0,
            echo_slow_timer_us,
            next_echo_tx_at: None,
            last_echo_rx: None,
            echo_activated_at: None,
            counters: SessionCounters::default(),
            jitter_state: AtomicU64::new(jitter_seed(local_discriminator)),
        }
    }

    /// Minimum TTL (IPv4) or hop-limit (IPv6) required on incoming packets.
    ///
    /// Returns 255 for single-hop sessions and 255 − `max_hops` for multi-hop sessions.
    pub fn min_ttl(&self) -> u8 {
        match self.mode {
            BfdMode::SingleHop => 255,
            BfdMode::MultiHop { max_hops } => 255u8.saturating_sub(max_hops),
        }
    }

    /// Returns `true` when echo mode is active for this session.
    ///
    /// All conditions must hold: echo TX is configured locally, the session is Up,
    /// the mode is SingleHop (RFC 5881), and the remote has advertised a non-zero
    /// `required_min_echo_rx_interval` (i.e., it is willing to loop back echo packets).
    pub fn echo_active(&self) -> bool {
        self.echo_configured
            && self.local_state == BfdState::Up
            && self.mode == BfdMode::SingleHop
            && self.remote_min_echo_rx_us > 0
    }

    /// Effective TX interval: max(our desired_min_tx, remote's required_min_rx).
    /// When echo is active, slows to echo_slow_timer_us per RFC 5880 §6.8.9.
    /// Enforces ≥ 1 second when not Up (RFC 5880 §6.8.3).
    ///
    /// Jitter per RFC 5880 §6.8.7:
    /// - detect_mult > 1: reduce by 0–25% (interval in [75%, 100%] of base)
    /// - detect_mult = 1: reduce by 10–25% (interval in [75%, 90%] of base)
    pub fn tx_interval(&self) -> Duration {
        let base = if self.echo_active() {
            // Control TX slows down when echo takes over failure detection
            self.echo_slow_timer_us.max(self.remote_min_rx_us)
        } else {
            self.desired_min_tx_us.max(self.remote_min_rx_us)
        };
        // RFC 5880 §6.8.3: when not Up, interval must be >= 1 second
        let base = if self.local_state != BfdState::Up {
            base.max(1_000_000)
        } else {
            base
        };
        let j = self.next_jitter_pct();
        let jittered = base as u64 * (100 - j) / 100;
        Duration::from_micros(jittered.max(1))
    }

    /// Echo TX interval: max(desired_min_echo_tx_us, remote_min_echo_rx_us) with jitter.
    pub fn echo_tx_interval(&self) -> Duration {
        let base = self.desired_min_echo_tx_us.max(self.remote_min_echo_rx_us);
        let j = self.next_jitter_pct();
        let jittered = base as u64 * (100 - j) / 100;
        Duration::from_micros(jittered.max(1))
    }

    /// Advance the per-session PRNG and return a jitter percentage to subtract from the base
    /// interval:
    /// - detect_mult > 1 → 0–25 (interval in [75%, 100%] of base)
    /// - detect_mult = 1 → 10–25 (interval in [75%, 90%] of base)
    fn next_jitter_pct(&self) -> u64 {
        let prev = self.jitter_state.load(Ordering::Relaxed);
        let next = xorshift64(prev);
        self.jitter_state.store(next, Ordering::Relaxed);
        if self.detect_mult == 1 {
            10 + (next % 16) // [10, 25]
        } else {
            next % 26 // [0, 25]
        }
    }

    /// Echo detection time: detect_mult × max(desired_min_echo_tx_us, remote_min_echo_rx_us).
    /// No jitter — detection time is a fixed multiple of the negotiated interval.
    pub fn echo_detection_time(&self) -> Duration {
        let interval = self.desired_min_echo_tx_us.max(self.remote_min_echo_rx_us);
        Duration::from_micros(self.detect_mult as u64 * interval as u64)
    }

    /// Detection time = remote detect_mult * max(required_min_rx, remote desired_min_tx).
    pub fn detection_time(&self) -> Duration {
        let mult = if self.remote_detect_mult > 0 {
            self.remote_detect_mult
        } else {
            self.detect_mult
        };
        let interval = self.required_min_rx_us.max(self.remote_min_tx_us);
        Duration::from_micros(mult as u64 * interval as u64)
    }

    /// Returns the absolute time at which the next TX packet must be sent.
    pub fn next_tx_deadline(&self) -> Instant {
        self.next_tx_at
    }

    /// Next detection expiry deadline, if session is Up and has received a packet.
    /// Used to wake the event loop independently of the TX timer.
    pub fn detection_deadline(&self) -> Option<Instant> {
        if self.local_state != BfdState::Up {
            return None;
        }
        self.last_rx.map(|t| t + self.detection_time())
    }

    /// Next echo TX deadline if echo is active.
    pub fn next_echo_tx_deadline(&self) -> Option<Instant> {
        if self.echo_active() { self.next_echo_tx_at } else { None }
    }

    /// Echo detection deadline: last echo RX (or activation time) + echo_detection_time().
    /// Returns `None` when echo is not active.
    pub fn echo_detection_deadline(&self) -> Option<Instant> {
        if !self.echo_active() {
            return None;
        }
        // Use last_echo_rx if available, otherwise use when echo was activated
        let base = self.last_echo_rx.or(self.echo_activated_at)?;
        Some(base + self.echo_detection_time())
    }

    /// Advance `next_tx_at` to `now + tx_interval()`, applying fresh jitter.
    pub fn advance_tx_deadline(&mut self) {
        self.next_tx_at = Instant::now() + self.tx_interval();
    }

    /// Schedule an immediate TX (e.g., after state change per RFC 5880 §6.8.7).
    pub fn schedule_immediate_tx(&mut self) {
        self.next_tx_at = Instant::now();
    }

    /// Advance the echo TX deadline by one echo interval.
    pub fn advance_echo_tx_deadline(&mut self) {
        self.next_echo_tx_at = Some(Instant::now() + self.echo_tx_interval());
    }

    /// Record receipt of an echo reply, resetting the echo detection timer.
    pub fn echo_received(&mut self) {
        self.last_echo_rx = Some(Instant::now());
    }

    /// Returns `true` if the session is `Up` and the detection timer has expired.
    pub fn is_detection_expired(&self) -> bool {
        if self.local_state != BfdState::Up {
            return false;
        }
        match self.last_rx {
            Some(t) => t.elapsed() > self.detection_time(),
            None => false,
        }
    }

    /// Returns `true` if echo is active and the echo detection timer has expired.
    pub fn is_echo_detection_expired(&self) -> bool {
        match self.echo_detection_deadline() {
            Some(deadline) => Instant::now() >= deadline,
            None => false,
        }
    }

    /// Activate echo mode: schedule the first echo TX and record activation time.
    fn activate_echo(&mut self) {
        self.next_echo_tx_at = Some(Instant::now());
        self.last_echo_rx = None;
        self.echo_activated_at = Some(Instant::now());
    }

    /// Deactivate echo mode: clear all echo timer state.
    fn deactivate_echo(&mut self) {
        self.next_echo_tx_at = None;
        self.last_echo_rx = None;
        self.echo_activated_at = None;
    }

    /// Reset all Poll sequence state. Called when transitioning to Down or AdminDown.
    fn clear_poll(&mut self) {
        self.poll_active = false;
        self.poll_pending_tx_us = None;
        self.poll_pending_rx_us = None;
        self.poll_started_at = None;
    }

    /// Trigger immediate TX and mark the Poll sequence as started.
    fn start_poll(&mut self) {
        self.poll_active = true;
        self.poll_started_at = Some(Instant::now());
        self.next_tx_at = Instant::now();
        self.counters.poll_sequences += 1;
    }

    /// RFC 5880 §6.8.3: change `desired_min_tx_interval` with Poll/Final negotiation.
    ///
    /// If increasing, the new value is applied immediately and a Poll sequence is
    /// started. If decreasing, the new value is deferred until the remote acknowledges
    /// with a Final packet (the old, larger, value continues to be advertised).
    ///
    /// Returns `Err` if a Poll sequence is already in progress.
    pub fn set_desired_min_tx(&mut self, new_us: u32) -> Result<(), &'static str> {
        if self.poll_active {
            return Err("poll sequence already in progress");
        }
        if new_us == self.desired_min_tx_us {
            return Ok(());
        }
        if new_us > self.desired_min_tx_us {
            // Increasing: apply immediately so the remote can adjust its detection timer.
            self.desired_min_tx_us = new_us;
        } else {
            // Decreasing: defer until Final so the remote keeps a valid detection window.
            self.poll_pending_tx_us = Some(new_us);
        }
        self.start_poll();
        Ok(())
    }

    /// RFC 5880 §6.8.3: change `required_min_rx_interval` with Poll/Final negotiation.
    ///
    /// If decreasing, the new value is applied immediately. If increasing, the new
    /// value is deferred until Final so the remote has time to slow its TX rate.
    ///
    /// Returns `Err` if a Poll sequence is already in progress.
    pub fn set_required_min_rx(&mut self, new_us: u32) -> Result<(), &'static str> {
        if self.poll_active {
            return Err("poll sequence already in progress");
        }
        if new_us == self.required_min_rx_us {
            return Ok(());
        }
        if new_us < self.required_min_rx_us {
            // Decreasing: apply immediately.
            self.required_min_rx_us = new_us;
        } else {
            // Increasing: defer until Final.
            self.poll_pending_rx_us = Some(new_us);
        }
        self.start_poll();
        Ok(())
    }

    /// Apply any deferred Poll values and clear Poll state on receipt of a Final packet.
    fn receive_final(&mut self) {
        if let Some(tx_us) = self.poll_pending_tx_us.take() {
            self.desired_min_tx_us = tx_us;
        }
        if let Some(rx_us) = self.poll_pending_rx_us.take() {
            self.required_min_rx_us = rx_us;
        }
        self.poll_active = false;
        self.poll_started_at = None;
    }

    /// Generous timeout for a Poll sequence: 3 × detection time.
    ///
    /// The RFC does not specify a Poll timeout; we use 3 × detection time as a
    /// heuristic that gives the remote ample time to respond under load.
    pub fn poll_timeout_duration(&self) -> Duration {
        self.detection_time() * 3
    }

    /// Returns `true` when a Poll sequence has been running longer than `poll_timeout_duration`.
    pub fn is_poll_timed_out(&self) -> bool {
        if !self.poll_active {
            return false;
        }
        match self.poll_started_at {
            Some(t) => t.elapsed() > self.poll_timeout_duration(),
            None => false,
        }
    }

    /// Apply deferred Poll values and clear Poll state after a timeout.
    ///
    /// It is safe to apply deferred values unconditionally: the remote will
    /// eventually adapt its timers via its own detection mechanism.
    pub fn poll_timed_out(&mut self) {
        if let Some(tx_us) = self.poll_pending_tx_us.take() {
            self.desired_min_tx_us = tx_us;
        }
        if let Some(rx_us) = self.poll_pending_rx_us.take() {
            self.required_min_rx_us = rx_us;
        }
        self.poll_active = false;
        self.poll_started_at = None;
    }

    /// RFC 5880 Section 6.8.6 state machine on receipt of a control packet.
    pub fn receive_packet(&mut self, pkt: &BfdPacket) -> Option<StateChange> {
        let echo_was_active = self.echo_active();

        // Update remote discriminator and negotiated values
        self.remote_discriminator = pkt.my_discriminator;
        self.remote_min_tx_us = pkt.desired_min_tx_interval;
        self.remote_min_rx_us = pkt.required_min_rx_interval;
        self.remote_detect_mult = pkt.detect_mult;
        self.remote_state = pkt.state;
        self.remote_min_echo_rx_us = pkt.required_min_echo_rx_interval;
        self.last_rx = Some(Instant::now());

        // If remote sent Final in response to our Poll, apply deferred parameter changes.
        if pkt.finalize && self.poll_active {
            self.receive_final();
        }

        let old_state = self.local_state;
        let new_state = self.next_state(pkt);
        self.local_state = new_state;

        // Check echo activation after state and remote values are updated
        let echo_is_active = self.echo_active();
        if echo_was_active && !echo_is_active {
            self.deactivate_echo();
        } else if !echo_was_active && echo_is_active {
            self.activate_echo();
        }

        if new_state == old_state {
            return None;
        }

        self.counters.state_transitions += 1;
        Some(StateChange {
            peer: self.peer_addr,
            old_state,
            new_state,
            diagnostic: self.local_diag,
        })
    }

    fn next_state(&mut self, pkt: &BfdPacket) -> BfdState {
        // Local AdminDown is sticky -- ignore all remote state
        if self.local_state == BfdState::AdminDown {
            return BfdState::AdminDown;
        }
        // AdminDown from remote always drives us Down
        if pkt.state == BfdState::AdminDown {
            self.local_diag = Diagnostic::NeighborSignaledSessionDown;
            self.remote_discriminator = 0;
            self.clear_poll();
            return BfdState::Down;
        }

        match self.local_state {
            BfdState::Down => match pkt.state {
                BfdState::Down => BfdState::Init,
                BfdState::Init => {
                    self.local_diag = Diagnostic::NoDiagnostic;
                    BfdState::Up
                }
                _ => BfdState::Down,
            },
            BfdState::Init => match pkt.state {
                BfdState::Init | BfdState::Up => {
                    self.local_diag = Diagnostic::NoDiagnostic;
                    BfdState::Up
                }
                _ => BfdState::Init,
            },
            BfdState::Up => match pkt.state {
                BfdState::Down => {
                    self.local_diag = Diagnostic::NeighborSignaledSessionDown;
                    self.remote_discriminator = 0;
                    self.clear_poll();
                    BfdState::Down
                }
                _ => BfdState::Up,
            },
            BfdState::AdminDown => unreachable!(),
        }
    }

    /// Called when the control detection timer expires while in Up state.
    pub fn detection_expired(&mut self) -> Option<StateChange> {
        if self.local_state != BfdState::Up {
            return None;
        }
        let old_state = self.local_state;
        self.local_diag = Diagnostic::ControlDetectionTimeExpired;
        self.local_state = BfdState::Down;
        self.remote_discriminator = 0;
        self.deactivate_echo();
        self.clear_poll();
        self.counters.detection_timeouts += 1;
        self.counters.state_transitions += 1;
        Some(StateChange {
            peer: self.peer_addr,
            old_state,
            new_state: BfdState::Down,
            diagnostic: self.local_diag,
        })
    }

    /// Called when the echo detection timer expires while echo is active.
    pub fn echo_detection_expired(&mut self) -> Option<StateChange> {
        if self.local_state != BfdState::Up {
            return None;
        }
        let old_state = self.local_state;
        self.local_diag = Diagnostic::EchoFunctionFailed;
        self.local_state = BfdState::Down;
        self.remote_discriminator = 0;
        self.deactivate_echo();
        self.clear_poll();
        self.counters.echo_detection_timeouts += 1;
        self.counters.state_transitions += 1;
        Some(StateChange {
            peer: self.peer_addr,
            old_state,
            new_state: BfdState::Down,
            diagnostic: self.local_diag,
        })
    }

    /// Transition session to AdminDown, notifying the peer.
    pub fn set_admin_down(&mut self) -> Option<StateChange> {
        if self.local_state == BfdState::AdminDown {
            return None;
        }
        let old_state = self.local_state;
        self.local_state = BfdState::AdminDown;
        self.local_diag = Diagnostic::AdminDown;
        self.deactivate_echo();
        self.clear_poll();
        self.counters.state_transitions += 1;
        Some(StateChange {
            peer: self.peer_addr,
            old_state,
            new_state: BfdState::AdminDown,
            diagnostic: self.local_diag,
        })
    }

    /// RFC 5880 §6.8.18: suppress TX if remote sets RequiredMinRxInterval to 0
    /// (intentional signal that it does not want to receive BFD packets).
    pub fn should_send(&self) -> bool {
        if self.remote_min_rx_us == 0 && self.last_rx.is_some() {
            return false;
        }
        true
    }

    /// Build the outgoing control packet reflecting current local state.
    pub fn build_tx_packet(&self) -> BfdPacket {
        BfdPacket {
            version: 1,
            diagnostic: self.local_diag,
            state: self.local_state,
            poll: self.poll_active,
            finalize: false,
            control_plane_independent: false,
            authentication_present: false,
            demand: false,
            multipoint: false,
            detect_mult: self.detect_mult,
            my_discriminator: self.local_discriminator,
            your_discriminator: self.remote_discriminator,
            desired_min_tx_interval: self.desired_min_tx_us,
            required_min_rx_interval: self.required_min_rx_us,
            required_min_echo_rx_interval: self.required_min_echo_rx_us,
        }
    }

    /// Build an echo packet for this session.
    ///
    /// Both `my_discriminator` and `your_discriminator` are set to the local discriminator
    /// so that when the packet returns, we can identify it via `disc_map` lookup.
    pub fn build_echo_packet(&self) -> BfdPacket {
        BfdPacket {
            version: 1,
            diagnostic: Diagnostic::NoDiagnostic,
            state: BfdState::Up,
            poll: false,
            finalize: false,
            control_plane_independent: false,
            authentication_present: false,
            demand: false,
            multipoint: false,
            detect_mult: self.detect_mult,
            my_discriminator: self.local_discriminator,
            your_discriminator: self.local_discriminator,
            desired_min_tx_interval: self.desired_min_tx_us,
            required_min_rx_interval: 0,
            required_min_echo_rx_interval: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::BfdPacket;
    use crate::state::{BfdMode, BfdState, Diagnostic};

    fn make_session() -> BfdSession {
        BfdSession::new(
            "127.0.0.1:13785".parse().unwrap(),
            1,
            250_000,
            250_000,
            3,
            BfdMode::SingleHop,
            false,
            0,
            0,
            1_000_000,
        )
    }

    fn make_session_with_echo() -> BfdSession {
        BfdSession::new(
            "127.0.0.1:13785".parse().unwrap(),
            1,
            250_000,
            250_000,
            3,
            BfdMode::SingleHop,
            true,        // echo_configured
            100_000,     // desired_min_echo_tx_us
            100_000,     // required_min_echo_rx_us
            1_000_000,   // echo_slow_timer_us
        )
    }

    fn make_rx_packet(state: BfdState, your_disc: u32) -> BfdPacket {
        BfdPacket {
            version: 1,
            diagnostic: Diagnostic::NoDiagnostic,
            state,
            poll: false,
            finalize: false,
            control_plane_independent: false,
            authentication_present: false,
            demand: false,
            multipoint: false,
            detect_mult: 3,
            my_discriminator: 42,
            your_discriminator: your_disc,
            desired_min_tx_interval: 250_000,
            required_min_rx_interval: 250_000,
            required_min_echo_rx_interval: 0,
        }
    }

    fn make_rx_packet_with_echo(state: BfdState, your_disc: u32, echo_rx: u32) -> BfdPacket {
        let mut pkt = make_rx_packet(state, your_disc);
        pkt.required_min_echo_rx_interval = echo_rx;
        pkt
    }

    #[test]
    fn down_plus_down_goes_to_init() {
        let mut s = make_session();
        let pkt = make_rx_packet(BfdState::Down, 0);
        let change = s.receive_packet(&pkt);
        assert!(change.is_some());
        let c = change.unwrap();
        assert_eq!(c.old_state, BfdState::Down);
        assert_eq!(c.new_state, BfdState::Init);
        assert_eq!(s.local_state, BfdState::Init);
    }

    #[test]
    fn down_plus_init_goes_to_up() {
        let mut s = make_session();
        let pkt = make_rx_packet(BfdState::Init, 0);
        let change = s.receive_packet(&pkt).unwrap();
        assert_eq!(change.new_state, BfdState::Up);
    }

    #[test]
    fn down_plus_up_stays_down() {
        let mut s = make_session();
        let pkt = make_rx_packet(BfdState::Up, 0);
        let change = s.receive_packet(&pkt);
        assert!(change.is_none());
        assert_eq!(s.local_state, BfdState::Down);
    }

    #[test]
    fn init_plus_init_goes_to_up() {
        let mut s = make_session();
        s.local_state = BfdState::Init;
        let pkt = make_rx_packet(BfdState::Init, 1);
        let change = s.receive_packet(&pkt).unwrap();
        assert_eq!(change.new_state, BfdState::Up);
    }

    #[test]
    fn init_plus_up_goes_to_up() {
        let mut s = make_session();
        s.local_state = BfdState::Init;
        let pkt = make_rx_packet(BfdState::Up, 1);
        let change = s.receive_packet(&pkt).unwrap();
        assert_eq!(change.new_state, BfdState::Up);
    }

    #[test]
    fn init_plus_down_stays_init() {
        let mut s = make_session();
        s.local_state = BfdState::Init;
        let pkt = make_rx_packet(BfdState::Down, 1);
        let change = s.receive_packet(&pkt);
        assert!(change.is_none());
        assert_eq!(s.local_state, BfdState::Init);
    }

    #[test]
    fn up_plus_down_goes_to_down() {
        let mut s = make_session();
        s.local_state = BfdState::Up;
        let pkt = make_rx_packet(BfdState::Down, 1);
        let change = s.receive_packet(&pkt).unwrap();
        assert_eq!(change.new_state, BfdState::Down);
        assert_eq!(s.local_diag as u8, Diagnostic::NeighborSignaledSessionDown as u8);
    }

    #[test]
    fn admin_down_remote_drives_down() {
        let mut s = make_session();
        s.local_state = BfdState::Up;
        let pkt = make_rx_packet(BfdState::AdminDown, 1);
        let change = s.receive_packet(&pkt).unwrap();
        assert_eq!(change.new_state, BfdState::Down);
    }

    #[test]
    fn detection_expired_up_to_down() {
        let mut s = make_session();
        s.local_state = BfdState::Up;
        let change = s.detection_expired().unwrap();
        assert_eq!(change.old_state, BfdState::Up);
        assert_eq!(change.new_state, BfdState::Down);
    }

    #[test]
    fn detection_expired_no_change_when_not_up() {
        let mut s = make_session();
        assert!(s.detection_expired().is_none());
    }

    #[test]
    fn no_change_on_same_state() {
        let mut s = make_session();
        s.local_state = BfdState::Up;
        s.remote_discriminator = 42;
        s.remote_state = BfdState::Up;
        let pkt = make_rx_packet(BfdState::Up, 1);
        let change = s.receive_packet(&pkt);
        assert!(change.is_none());
    }

    #[test]
    fn tx_interval_minimum_when_not_up() {
        let mut s = make_session();
        s.desired_min_tx_us = 100;
        s.remote_min_rx_us = 100;
        // Down state: must be >= 1 second (after jitter, still >= 100ms)
        let interval = s.tx_interval();
        // With max 25% jitter, minimum is 75% of 1_000_000 = 750ms
        assert!(interval >= Duration::from_millis(750));
        // When Up, can use the configured fast rate
        s.local_state = BfdState::Up;
        assert!(s.tx_interval() < Duration::from_millis(750));
    }

    #[test]
    fn detection_time_calculation() {
        let mut s = make_session();
        s.remote_detect_mult = 3;
        s.remote_min_tx_us = 250_000;
        // detection_time = 3 * max(250_000, 250_000) = 750_000 us
        assert_eq!(s.detection_time(), Duration::from_micros(750_000));
    }

    #[test]
    fn detection_deadline_only_when_up() {
        let mut s = make_session();
        s.last_rx = Some(Instant::now());
        assert!(s.detection_deadline().is_none());
        s.local_state = BfdState::Up;
        assert!(s.detection_deadline().is_some());
    }

    #[test]
    fn set_admin_down_from_up() {
        let mut s = make_session();
        s.local_state = BfdState::Up;
        let change = s.set_admin_down().unwrap();
        assert_eq!(change.old_state, BfdState::Up);
        assert_eq!(change.new_state, BfdState::AdminDown);
        assert_eq!(s.local_state, BfdState::AdminDown);
        assert_eq!(s.local_diag, Diagnostic::AdminDown);
    }

    #[test]
    fn set_admin_down_already_admin_down() {
        let mut s = make_session();
        s.local_state = BfdState::AdminDown;
        assert!(s.set_admin_down().is_none());
    }

    #[test]
    fn admin_down_local_ignores_remote_admin_down() {
        let mut s = make_session();
        s.local_state = BfdState::AdminDown;
        let pkt = make_rx_packet(BfdState::AdminDown, 0);
        let change = s.receive_packet(&pkt);
        assert!(change.is_none());
        assert_eq!(s.local_state, BfdState::AdminDown);
    }

    #[test]
    fn tx_suppressed_when_remote_min_rx_zero() {
        let mut s = make_session();
        // No RX yet: should_send is true (0 is just the default, not intentional)
        assert!(s.should_send());
        // After receiving a packet where remote_min_rx_us=0: suppress TX
        s.remote_min_rx_us = 0;
        s.last_rx = Some(Instant::now());
        assert!(!s.should_send());
        // Non-zero remote_min_rx_us: send normally
        s.remote_min_rx_us = 250_000;
        assert!(s.should_send());
    }

    // --- Echo mode tests ---

    #[test]
    fn echo_active_requires_all_conditions() {
        let mut s = make_session_with_echo();
        // Not active: state is Down
        assert!(!s.echo_active());

        // Not active: state is Up but remote hasn't advertised echo support
        s.local_state = BfdState::Up;
        s.remote_min_echo_rx_us = 0;
        assert!(!s.echo_active());

        // Active: all conditions met
        s.remote_min_echo_rx_us = 100_000;
        assert!(s.echo_active());

        // Not active: echo not configured
        s.echo_configured = false;
        assert!(!s.echo_active());
    }

    #[test]
    fn echo_not_active_for_multihop() {
        let mut s = BfdSession::new(
            "127.0.0.1:13785".parse().unwrap(),
            1,
            250_000,
            250_000,
            3,
            BfdMode::MultiHop { max_hops: 3 },
            true,
            100_000,
            100_000,
            1_000_000,
        );
        s.local_state = BfdState::Up;
        s.remote_min_echo_rx_us = 100_000;
        // MultiHop never activates echo regardless of config
        assert!(!s.echo_active());
    }

    #[test]
    fn echo_tx_interval_negotiation() {
        let mut s = make_session_with_echo();
        s.local_state = BfdState::Up;
        s.remote_min_echo_rx_us = 200_000;
        // negotiated = max(100_000, 200_000) = 200_000 (before jitter)
        let interval = s.echo_tx_interval();
        // After jitter (max 25% reduction): >= 150_000 µs
        assert!(interval >= Duration::from_micros(150_000));
        assert!(interval <= Duration::from_micros(200_000));
    }

    #[test]
    fn echo_detection_expired_uses_echo_diagnostic() {
        let mut s = make_session_with_echo();
        s.local_state = BfdState::Up;
        let change = s.echo_detection_expired().unwrap();
        assert_eq!(change.old_state, BfdState::Up);
        assert_eq!(change.new_state, BfdState::Down);
        assert_eq!(change.diagnostic, Diagnostic::EchoFunctionFailed);
        assert_eq!(s.local_diag, Diagnostic::EchoFunctionFailed);
        assert!(!s.echo_active());
    }

    #[test]
    fn echo_detection_expired_no_change_when_not_up() {
        let mut s = make_session_with_echo();
        assert!(s.echo_detection_expired().is_none());
    }

    #[test]
    fn tx_interval_slows_when_echo_active() {
        let mut s = make_session_with_echo();
        s.local_state = BfdState::Up;
        s.remote_min_echo_rx_us = 100_000;
        // Echo is active; control TX should use echo_slow_timer_us = 1_000_000
        // Normal TX would be max(250_000, 0) = 250_000
        let slow_interval = s.tx_interval();
        // Should be ~1_000_000 µs (after jitter), much larger than 250_000
        assert!(slow_interval >= Duration::from_millis(750));

        // Without echo active:
        let mut s2 = make_session();
        s2.local_state = BfdState::Up;
        s2.remote_min_echo_rx_us = 0;
        let fast_interval = s2.tx_interval();
        // Should be ~250_000 µs (after jitter)
        assert!(fast_interval < Duration::from_millis(500));
    }

    #[test]
    fn echo_activation_on_receive_packet() {
        let mut s = make_session_with_echo();
        // Bring session to Up state first
        s.local_state = BfdState::Up;
        assert!(!s.echo_active());
        // Receive packet with non-zero remote echo RX → echo activates
        let pkt = make_rx_packet_with_echo(BfdState::Up, 1, 100_000);
        s.remote_discriminator = 42;
        s.receive_packet(&pkt);
        assert!(s.echo_active());
        assert!(s.next_echo_tx_at.is_some());
        assert!(s.echo_activated_at.is_some());

        // Receive packet with zero echo RX → echo deactivates
        let pkt_no_echo = make_rx_packet_with_echo(BfdState::Up, 1, 0);
        s.receive_packet(&pkt_no_echo);
        assert!(!s.echo_active());
        assert!(s.next_echo_tx_at.is_none());
        assert!(s.echo_activated_at.is_none());
    }

    #[test]
    fn detection_expired_deactivates_echo() {
        let mut s = make_session_with_echo();
        s.local_state = BfdState::Up;
        s.remote_min_echo_rx_us = 100_000;
        s.activate_echo();
        assert!(s.echo_activated_at.is_some());

        s.detection_expired();
        assert!(s.echo_activated_at.is_none());
        assert!(s.next_echo_tx_at.is_none());
    }

    #[test]
    fn admin_down_deactivates_echo() {
        let mut s = make_session_with_echo();
        s.local_state = BfdState::Up;
        s.remote_min_echo_rx_us = 100_000;
        s.activate_echo();
        assert!(s.echo_activated_at.is_some());

        s.set_admin_down();
        assert!(s.echo_activated_at.is_none());
        assert!(s.next_echo_tx_at.is_none());
    }

    #[test]
    fn echo_detection_deadline_uses_activation_time_initially() {
        let mut s = make_session_with_echo();
        s.local_state = BfdState::Up;
        s.remote_min_echo_rx_us = 100_000;
        s.activate_echo();
        // Before any echo RX, deadline is based on activation time
        let deadline = s.echo_detection_deadline();
        assert!(deadline.is_some());
        // Should be roughly echo_detection_time() from now
        let expected = s.echo_detection_time();
        let actual = deadline.unwrap().duration_since(s.echo_activated_at.unwrap());
        assert_eq!(actual, expected);
    }

    #[test]
    fn echo_detection_deadline_uses_last_rx_after_echo_received() {
        let mut s = make_session_with_echo();
        s.local_state = BfdState::Up;
        s.remote_min_echo_rx_us = 100_000;
        s.activate_echo();
        s.echo_received();
        // After echo RX, deadline is based on last_echo_rx
        let deadline = s.echo_detection_deadline();
        assert!(deadline.is_some());
        let last_rx = s.last_echo_rx.unwrap();
        let expected_deadline = last_rx + s.echo_detection_time();
        assert_eq!(deadline.unwrap(), expected_deadline);
    }

    #[test]
    fn build_echo_packet_uses_local_discriminator() {
        let s = make_session_with_echo();
        let pkt = s.build_echo_packet();
        assert_eq!(pkt.my_discriminator, s.local_discriminator);
        assert_eq!(pkt.your_discriminator, s.local_discriminator);
    }

    #[test]
    fn build_tx_packet_includes_echo_rx_interval() {
        let s = make_session_with_echo();
        let pkt = s.build_tx_packet();
        assert_eq!(pkt.required_min_echo_rx_interval, s.required_min_echo_rx_us);
    }

    // --- Poll sequence tests ---

    #[test]
    fn poll_set_tx_increasing_applies_immediately() {
        let mut s = make_session();
        assert!(!s.poll_active);
        s.set_desired_min_tx(500_000).unwrap();
        // Larger value applied immediately
        assert_eq!(s.desired_min_tx_us, 500_000);
        assert!(s.poll_active);
        assert!(s.poll_pending_tx_us.is_none());
        // Immediate TX scheduled
        assert!(s.next_tx_at <= Instant::now() + Duration::from_millis(10));
    }

    #[test]
    fn poll_set_tx_decreasing_defers_value() {
        let mut s = make_session();
        s.set_desired_min_tx(100_000).unwrap();
        // Old value still in effect; new value deferred
        assert_eq!(s.desired_min_tx_us, 250_000);
        assert_eq!(s.poll_pending_tx_us, Some(100_000));
        assert!(s.poll_active);
        // TX packet should still advertise old value
        let pkt = s.build_tx_packet();
        assert_eq!(pkt.desired_min_tx_interval, 250_000);
        assert!(pkt.poll);
    }

    #[test]
    fn poll_set_rx_decreasing_applies_immediately() {
        let mut s = make_session();
        s.set_required_min_rx(100_000).unwrap();
        assert_eq!(s.required_min_rx_us, 100_000);
        assert!(s.poll_active);
        assert!(s.poll_pending_rx_us.is_none());
    }

    #[test]
    fn poll_set_rx_increasing_defers_value() {
        let mut s = make_session();
        s.set_required_min_rx(500_000).unwrap();
        // Old value still in effect; new value deferred
        assert_eq!(s.required_min_rx_us, 250_000);
        assert_eq!(s.poll_pending_rx_us, Some(500_000));
        assert!(s.poll_active);
        // TX packet should advertise old (smaller) value until Final
        let pkt = s.build_tx_packet();
        assert_eq!(pkt.required_min_rx_interval, 250_000);
    }

    #[test]
    fn poll_receive_final_applies_pending_tx() {
        let mut s = make_session();
        s.set_desired_min_tx(100_000).unwrap(); // deferred
        assert_eq!(s.desired_min_tx_us, 250_000);
        // Simulate receiving a Final from the peer
        let mut pkt = make_rx_packet(BfdState::Up, 1);
        pkt.finalize = true;
        s.local_state = BfdState::Up;
        s.remote_discriminator = 42;
        s.receive_packet(&pkt);
        assert_eq!(s.desired_min_tx_us, 100_000);
        assert!(!s.poll_active);
        assert!(s.poll_pending_tx_us.is_none());
    }

    #[test]
    fn poll_receive_final_applies_pending_rx() {
        let mut s = make_session();
        s.set_required_min_rx(500_000).unwrap(); // deferred
        assert_eq!(s.required_min_rx_us, 250_000);
        let mut pkt = make_rx_packet(BfdState::Up, 1);
        pkt.finalize = true;
        s.local_state = BfdState::Up;
        s.remote_discriminator = 42;
        s.receive_packet(&pkt);
        assert_eq!(s.required_min_rx_us, 500_000);
        assert!(!s.poll_active);
        assert!(s.poll_pending_rx_us.is_none());
    }

    #[test]
    fn poll_rejected_when_already_active() {
        let mut s = make_session();
        s.set_desired_min_tx(500_000).unwrap();
        assert!(s.poll_active);
        // Second set_* while poll is active must fail
        assert!(s.set_desired_min_tx(100_000).is_err());
        assert!(s.set_required_min_rx(100_000).is_err());
    }

    #[test]
    fn poll_noop_when_value_unchanged() {
        let mut s = make_session();
        s.set_desired_min_tx(250_000).unwrap(); // same as current
        assert!(!s.poll_active);
        s.set_required_min_rx(250_000).unwrap();
        assert!(!s.poll_active);
    }

    #[test]
    fn poll_cleared_on_detection_expired() {
        let mut s = make_session();
        s.local_state = BfdState::Up;
        s.set_desired_min_tx(500_000).unwrap();
        assert!(s.poll_active);
        s.detection_expired();
        assert!(!s.poll_active);
        assert!(s.poll_pending_tx_us.is_none());
    }

    #[test]
    fn poll_cleared_on_admin_down() {
        let mut s = make_session();
        s.local_state = BfdState::Up;
        s.set_desired_min_tx(500_000).unwrap();
        assert!(s.poll_active);
        s.set_admin_down();
        assert!(!s.poll_active);
    }

    #[test]
    fn poll_cleared_on_remote_down() {
        let mut s = make_session();
        s.local_state = BfdState::Up;
        s.remote_discriminator = 42;
        s.set_desired_min_tx(500_000).unwrap();
        assert!(s.poll_active);
        let pkt = make_rx_packet(BfdState::Down, 1);
        s.receive_packet(&pkt);
        assert_eq!(s.local_state, BfdState::Down);
        assert!(!s.poll_active);
    }

    #[test]
    fn poll_cleared_on_remote_admin_down() {
        let mut s = make_session();
        s.local_state = BfdState::Up;
        s.remote_discriminator = 42;
        s.set_desired_min_tx(500_000).unwrap();
        let pkt = make_rx_packet(BfdState::AdminDown, 1);
        s.receive_packet(&pkt);
        assert_eq!(s.local_state, BfdState::Down);
        assert!(!s.poll_active);
    }

    #[test]
    fn poll_timeout_detection() {
        let mut s = make_session();
        s.remote_detect_mult = 3;
        s.remote_min_tx_us = 250_000;
        // Manually set up a poll that started far in the past
        s.poll_active = true;
        s.poll_started_at = Some(Instant::now() - Duration::from_secs(100));
        assert!(s.is_poll_timed_out());
        // Apply timeout: pending values cleared
        s.poll_pending_tx_us = Some(100_000);
        s.poll_timed_out();
        assert_eq!(s.desired_min_tx_us, 100_000);
        assert!(!s.poll_active);
        assert!(s.poll_started_at.is_none());
    }

    #[test]
    fn poll_not_timed_out_when_just_started() {
        let mut s = make_session();
        s.set_desired_min_tx(500_000).unwrap();
        assert!(s.poll_active);
        // Immediately after starting, should not be timed out
        assert!(!s.is_poll_timed_out());
    }

    // --- Counter tests ---

    #[test]
    fn counter_state_transitions_on_receive_packet() {
        let mut s = make_session();
        assert_eq!(s.counters.state_transitions, 0);
        // Down -> Init
        let pkt = make_rx_packet(BfdState::Down, 0);
        s.receive_packet(&pkt);
        assert_eq!(s.counters.state_transitions, 1);
        // Init -> Up
        let pkt = make_rx_packet(BfdState::Init, 0);
        s.receive_packet(&pkt);
        assert_eq!(s.counters.state_transitions, 2);
        // No-op (already Up, remote Up)
        let pkt = make_rx_packet(BfdState::Up, 1);
        s.receive_packet(&pkt);
        assert_eq!(s.counters.state_transitions, 2);
    }

    #[test]
    fn counter_detection_expired() {
        let mut s = make_session();
        s.local_state = BfdState::Up;
        s.last_rx = Some(Instant::now() - Duration::from_secs(100));
        let change = s.detection_expired();
        assert!(change.is_some());
        assert_eq!(s.counters.detection_timeouts, 1);
        assert_eq!(s.counters.state_transitions, 1);
    }

    #[test]
    fn counter_detection_expired_no_change_when_not_up() {
        let mut s = make_session();
        // session is Down, detection_expired should be no-op
        let change = s.detection_expired();
        assert!(change.is_none());
        assert_eq!(s.counters.detection_timeouts, 0);
        assert_eq!(s.counters.state_transitions, 0);
    }

    #[test]
    fn counter_echo_detection_expired() {
        let mut s = make_session_with_echo();
        s.local_state = BfdState::Up;
        // Simulate echo active
        s.remote_min_echo_rx_us = 100_000;
        let change = s.echo_detection_expired();
        assert!(change.is_some());
        assert_eq!(s.counters.echo_detection_timeouts, 1);
        assert_eq!(s.counters.state_transitions, 1);
    }

    #[test]
    fn counter_set_admin_down() {
        let mut s = make_session();
        s.local_state = BfdState::Up;
        s.set_admin_down();
        assert_eq!(s.counters.state_transitions, 1);
        // Second call (already AdminDown) should not increment
        s.set_admin_down();
        assert_eq!(s.counters.state_transitions, 1);
    }

    #[test]
    fn counter_poll_sequences() {
        let mut s = make_session();
        s.local_state = BfdState::Up;
        assert_eq!(s.counters.poll_sequences, 0);
        s.set_desired_min_tx(500_000).unwrap();
        assert_eq!(s.counters.poll_sequences, 1);
    }

    #[test]
    fn build_tx_packet_poll_bit() {
        let mut s = make_session();
        // No poll active: poll bit should be false
        let pkt = s.build_tx_packet();
        assert!(!pkt.poll);
        // Start a poll: poll bit should be true
        s.set_desired_min_tx(500_000).unwrap();
        let pkt = s.build_tx_packet();
        assert!(pkt.poll);
    }

    // --- Jitter range tests (RFC 5880 §6.8.7) ---

    /// detect_mult > 1: interval must be in [75%, 100%] of base (jitter 0-25%).
    #[test]
    fn jitter_range_detect_mult_gt1() {
        let mut s = BfdSession::new(
            "127.0.0.1:3784".parse().unwrap(),
            0xDEAD_BEEF,
            1_000_000,
            1_000_000,
            3,
            BfdMode::SingleHop,
            false,
            0,
            0,
            1_000_000,
        );
        s.local_state = BfdState::Up;
        s.remote_min_rx_us = 1_000_000;
        for _ in 0..200 {
            let t = s.tx_interval();
            assert!(
                t >= Duration::from_micros(750_000) && t <= Duration::from_micros(1_000_000),
                "detect_mult=3 interval out of [75%,100%] range: {t:?}"
            );
        }
    }

    /// detect_mult = 1: interval must be in [75%, 90%] of base (jitter 10-25%).
    #[test]
    fn jitter_range_detect_mult_1() {
        let mut s = BfdSession::new(
            "127.0.0.1:3784".parse().unwrap(),
            0xABCD_1234,
            1_000_000,
            1_000_000,
            1, // detect_mult = 1
            BfdMode::SingleHop,
            false,
            0,
            0,
            1_000_000,
        );
        s.local_state = BfdState::Up;
        s.remote_min_rx_us = 1_000_000;
        for _ in 0..200 {
            let t = s.tx_interval();
            assert!(
                t >= Duration::from_micros(750_000) && t <= Duration::from_micros(900_000),
                "detect_mult=1 interval out of [75%,90%] range: {t:?}"
            );
        }
    }

    /// Verify that the PRNG produces different values across calls (per-packet jitter).
    #[test]
    fn jitter_varies_per_packet() {
        let mut s = BfdSession::new(
            "127.0.0.1:3784".parse().unwrap(),
            12345,
            1_000_000,
            1_000_000,
            3,
            BfdMode::SingleHop,
            false,
            0,
            0,
            1_000_000,
        );
        s.local_state = BfdState::Up;
        s.remote_min_rx_us = 1_000_000;
        let intervals: Vec<_> = (0..16).map(|_| s.tx_interval()).collect();
        // At least some values should differ (probability of all equal is negligible)
        let all_same = intervals.windows(2).all(|w| w[0] == w[1]);
        assert!(!all_same, "all 16 jittered intervals were identical — PRNG may be broken");
    }
}
