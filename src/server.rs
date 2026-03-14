//! BFD daemon: async event loop, peer management, and state change notifications.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::time::Instant;

use tokio::io::Interest;
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, mpsc, oneshot};
use tracing::{debug, info, warn};

use crate::error::BfdError;
use crate::net;
use crate::session::{BfdSession, SessionCounters};
use crate::state::{BfdMode, BfdState, Diagnostic, StateChange};

/// Generate a cryptographically random discriminator that is non-zero and not
/// already present in `disc_map` (collision is astronomically unlikely but we
/// loop just in case).
/// Returns `None` if the OS entropy source is unavailable.
fn next_discriminator(disc_map: &HashMap<u32, SocketAddr>) -> Option<u32> {
    loop {
        let mut buf = [0u8; 4];
        getrandom::fill(&mut buf).ok()?;
        let disc = u32::from_ne_bytes(buf);
        if disc != 0 && !disc_map.contains_key(&disc) {
            return Some(disc);
        }
    }
}

/// Configuration for a [`BfdDaemon`].
///
/// All timer values are in **microseconds**. Pass this to [`BfdDaemon::start`]
/// to bind a socket and launch the event loop.
///
/// # Defaults
///
/// ```
/// use bfd::BfdConfig;
/// let cfg = BfdConfig::default();
/// assert_eq!(cfg.desired_min_tx_interval_us, 1_000_000);
/// assert_eq!(cfg.required_min_rx_interval_us, 1_000_000);
/// assert_eq!(cfg.detect_mult, 3);
/// assert_eq!(cfg.desired_min_echo_tx_interval_us, None);
/// assert_eq!(cfg.required_min_echo_rx_interval_us, 0);
/// ```
#[derive(Debug, Clone)]
pub struct BfdConfig {
    /// UDP address the daemon binds to (e.g. `"0.0.0.0:3784"`).
    ///
    /// Use port `0` to let the OS assign an ephemeral port; retrieve the
    /// actual address afterwards with [`BfdDaemon::local_addr`].
    pub listen_addr: SocketAddr,
    /// Minimum TX interval this daemon desires, in microseconds. Must be > 0.
    pub desired_min_tx_interval_us: u32,
    /// Minimum RX interval this daemon requires, in microseconds. Must be > 0.
    pub required_min_rx_interval_us: u32,
    /// Number of missed packets before the session is declared down. Must be > 0.
    pub detect_mult: u8,
    /// Default operating mode for peers added via [`BfdDaemon::add_peer`].
    ///
    /// Can be overridden per-peer with [`BfdDaemon::add_peer_with_mode`].
    /// `MultiHop { max_hops: 0 }` is rejected at startup.
    pub default_mode: BfdMode,
    /// Desired minimum echo TX interval in microseconds, or `None` to disable echo TX.
    ///
    /// When `Some(n)`, the daemon sends BFD echo packets at the negotiated rate (at least
    /// every `n` µs). Echo only activates for `SingleHop` sessions where the remote also
    /// advertises a non-zero `required_min_echo_rx_interval_us`. Must be `> 0` if `Some`.
    pub desired_min_echo_tx_interval_us: Option<u32>,
    /// Minimum echo RX interval this daemon will accept, in microseconds.
    ///
    /// Advertised in outgoing control packets as `required_min_echo_rx_interval`. Set to
    /// `> 0` to signal willingness to loop back echo packets from the peer. Default `0`
    /// means no echo loopback.
    pub required_min_echo_rx_interval_us: u32,
    /// Control TX interval (µs) to use when echo mode is active (RFC 5880 §6.8.9).
    ///
    /// When echo takes over failure detection, control packets can be sent more slowly.
    /// Default: 1 000 000 µs (1 second).
    pub echo_slow_timer_us: u32,
    /// UDP port for the echo socket. Default `3785` (RFC 5881).
    ///
    /// Use `0` to let the OS assign an ephemeral port; retrieve the actual address
    /// with [`BfdDaemon::echo_local_addr`].
    pub echo_port: u16,
}

impl Default for BfdConfig {
    fn default() -> Self {
        BfdConfig {
            listen_addr: "0.0.0.0:3784".parse().unwrap(),
            desired_min_tx_interval_us: 1_000_000,
            required_min_rx_interval_us: 1_000_000,
            detect_mult: 3,
            default_mode: BfdMode::SingleHop,
            desired_min_echo_tx_interval_us: None,
            required_min_echo_rx_interval_us: 0,
            echo_slow_timer_us: 1_000_000,
            echo_port: 3785,
        }
    }
}

/// Daemon-wide operational counters.
///
/// Retrieve via [`BfdDaemon::get_daemon_counters`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DaemonCounters {
    /// Total peers successfully added.
    pub peers_added: u64,
    /// Total peers successfully removed.
    pub peers_removed: u64,
    /// Errors reading from the control UDP socket.
    pub udp_rx_errors: u64,
    /// Errors reading from the echo UDP socket.
    pub echo_rx_errors: u64,
    /// Control packets discarded before session lookup (decode error, no session found).
    pub control_rx_discarded: u64,
    /// Echo packets looped back to peers.
    pub echo_loopback: u64,
}

enum Command {
    AddPeer {
        addr: SocketAddr,
        mode: Option<BfdMode>,
        reply: oneshot::Sender<Result<(), BfdError>>,
    },
    RemovePeer {
        addr: SocketAddr,
        reply: oneshot::Sender<Result<(), BfdError>>,
    },
    AdminDown {
        addr: SocketAddr,
        reply: oneshot::Sender<Result<(), BfdError>>,
    },
    GetState {
        addr: SocketAddr,
        reply: oneshot::Sender<Option<BfdState>>,
    },
    SetDesiredMinTx {
        addr: SocketAddr,
        interval_us: u32,
        reply: oneshot::Sender<Result<(), BfdError>>,
    },
    SetRequiredMinRx {
        addr: SocketAddr,
        interval_us: u32,
        reply: oneshot::Sender<Result<(), BfdError>>,
    },
    GetPeerCounters {
        addr: SocketAddr,
        reply: oneshot::Sender<Option<SessionCounters>>,
    },
    GetDaemonCounters {
        reply: oneshot::Sender<DaemonCounters>,
    },
    /// Graceful shutdown. `done` is signalled after the event loop exits.
    Shutdown { done: Option<oneshot::Sender<()>> },
}

/// Handle to a running BFD daemon.
///
/// The daemon owns a single UDP socket and a single tokio task running the
/// event loop. All peer management is done through `async` methods that send
/// commands to that task over an mpsc channel.
///
/// `BfdDaemon` is `Clone` — all clones share the same underlying event loop.
/// When every clone is dropped the daemon shuts down automatically (best-effort).
/// For a guaranteed, synchronous shutdown use [`BfdDaemon::shutdown`].
#[derive(Clone)]
pub struct BfdDaemon {
    cmd_tx: mpsc::Sender<Command>,
    notify_tx: broadcast::Sender<StateChange>,
    /// The address actually bound by the control UDP socket (useful when `listen_addr` used port 0).
    local_addr: SocketAddr,
    /// The address actually bound by the echo UDP socket (`None` if echo socket not created).
    echo_local_addr: Option<SocketAddr>,
}

impl BfdDaemon {
    /// Start a BFD daemon: validate config, bind the UDP socket, and spawn the event loop.
    ///
    /// Returns an error if the configuration is invalid or if the socket cannot be bound.
    pub async fn start(config: BfdConfig) -> Result<Self, BfdError> {
        if config.detect_mult == 0 {
            return Err(BfdError::InvalidConfig("detect_mult must be non-zero"));
        }
        if config.desired_min_tx_interval_us == 0 {
            return Err(BfdError::InvalidConfig("desired_min_tx_interval_us must be non-zero"));
        }
        if config.required_min_rx_interval_us == 0 {
            return Err(BfdError::InvalidConfig("required_min_rx_interval_us must be non-zero"));
        }
        if let BfdMode::MultiHop { max_hops } = config.default_mode
            && max_hops == 0 {
                return Err(BfdError::InvalidConfig("max_hops must be non-zero in MultiHop mode; use SingleHop for directly connected peers"));
            }
        if config.desired_min_echo_tx_interval_us == Some(0) {
            return Err(BfdError::InvalidConfig("desired_min_echo_tx_interval_us must be non-zero if set"));
        }

        let rx_std = net::create_bfd_socket(config.listen_addr)?;
        let rx_socket = Arc::new(UdpSocket::from_std(rx_std)?);
        let local_addr = rx_socket.local_addr()?;

        let tx_std = net::create_bfd_send_socket(config.listen_addr)?;
        let tx_socket = Arc::new(UdpSocket::from_std(tx_std)?);
        info!("BFD TX socket bound to {}", tx_socket.local_addr()?);

        // Create echo socket if echo TX or RX is configured.
        let echo_socket_and_addr = if config.desired_min_echo_tx_interval_us.is_some()
            || config.required_min_echo_rx_interval_us > 0
        {
            let echo_std = net::create_echo_socket(config.listen_addr, config.echo_port)?;
            let echo_sock = Arc::new(UdpSocket::from_std(echo_std)?);
            let echo_addr = echo_sock.local_addr()?;
            info!("BFD echo socket bound to {echo_addr}");
            Some((echo_sock, echo_addr))
        } else {
            None
        };

        let echo_local_addr = echo_socket_and_addr.as_ref().map(|(_, a)| *a);
        let echo_socket = echo_socket_and_addr.map(|(s, _)| s);

        let (cmd_tx, cmd_rx) = mpsc::channel(64);
        let (notify_tx, _) = broadcast::channel(256);

        let daemon = BfdDaemon {
            cmd_tx,
            notify_tx: notify_tx.clone(),
            local_addr,
            echo_local_addr,
        };

        tokio::spawn(run_event_loop(rx_socket, tx_socket, echo_socket, config, cmd_rx, notify_tx));

        Ok(daemon)
    }

    /// Add a peer using the daemon's `default_mode`.
    ///
    /// Returns [`BfdError::SessionExists`] if a session for this address is already active.
    pub async fn add_peer(&self, addr: SocketAddr) -> Result<(), BfdError> {
        self.add_peer_with_mode(addr, None).await
    }

    /// Add a peer with an explicit mode, overriding `default_mode`.
    ///
    /// Pass `None` to use `default_mode`. Pass `Some(mode)` to set a per-peer
    /// mode. `MultiHop { max_hops: 0 }` is rejected.
    ///
    /// Returns [`BfdError::SessionExists`] if a session already exists.
    pub async fn add_peer_with_mode(&self, addr: SocketAddr, mode: Option<BfdMode>) -> Result<(), BfdError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::AddPeer { addr, mode, reply: reply_tx })
            .await
            .ok();
        reply_rx.await.unwrap_or(Err(BfdError::Io(std::io::Error::other("daemon gone"))))
    }

    /// Remove a peer and send an AdminDown packet to signal the remote gracefully.
    ///
    /// Returns [`BfdError::SessionNotFound`] if no session exists for this address.
    pub async fn remove_peer(&self, addr: SocketAddr) -> Result<(), BfdError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::RemovePeer { addr, reply: reply_tx })
            .await
            .ok();
        reply_rx.await.unwrap_or(Err(BfdError::Io(std::io::Error::other("daemon gone"))))
    }

    /// Transition a peer session to AdminDown, signaling the peer gracefully.
    pub async fn admin_down_peer(&self, addr: SocketAddr) -> Result<(), BfdError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::AdminDown { addr, reply: reply_tx })
            .await
            .ok();
        reply_rx.await.unwrap_or(Err(BfdError::Io(std::io::Error::other("daemon gone"))))
    }

    /// Query the current local BFD state for a peer. Returns `None` if no session exists.
    pub async fn get_state(&self, addr: SocketAddr) -> Result<Option<BfdState>, BfdError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::GetState { addr, reply: reply_tx })
            .await
            .ok();
        reply_rx.await.map_err(|_| BfdError::Io(std::io::Error::other("daemon gone")))
    }

    /// Change `desired_min_tx_interval` for a live session via RFC 5880 §6.8.3 Poll/Final.
    ///
    /// If `new_us` is greater than the current value the change is applied immediately and
    /// a Poll sequence is started. If smaller, the old value is advertised until the remote
    /// acknowledges with a Final packet. Returns [`BfdError::PollInProgress`] if a Poll is
    /// already running for this session, or [`BfdError::SessionNotFound`] if no session exists.
    pub async fn set_desired_min_tx(&self, addr: SocketAddr, interval_us: u32) -> Result<(), BfdError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::SetDesiredMinTx { addr, interval_us, reply: reply_tx })
            .await
            .ok();
        reply_rx.await.unwrap_or(Err(BfdError::Io(std::io::Error::other("daemon gone"))))
    }

    /// Change `required_min_rx_interval` for a live session via RFC 5880 §6.8.3 Poll/Final.
    ///
    /// If `new_us` is less than the current value the change is applied immediately. If greater,
    /// the old value is advertised until the remote acknowledges with a Final packet.
    /// Returns [`BfdError::PollInProgress`] or [`BfdError::SessionNotFound`] on error.
    pub async fn set_required_min_rx(&self, addr: SocketAddr, interval_us: u32) -> Result<(), BfdError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::SetRequiredMinRx { addr, interval_us, reply: reply_tx })
            .await
            .ok();
        reply_rx.await.unwrap_or(Err(BfdError::Io(std::io::Error::other("daemon gone"))))
    }

    /// Subscribe to state-change notifications.
    ///
    /// Each subscriber receives every [`StateChange`] event independently via
    /// a `broadcast` channel. The channel holds up to 256 events; slower
    /// receivers may see a `RecvError::Lagged` gap.
    pub fn subscribe(&self) -> broadcast::Receiver<StateChange> {
        self.notify_tx.subscribe()
    }

    /// Returns the address the daemon's control UDP socket is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Returns the address the daemon's echo UDP socket is bound to, or `None` if the
    /// echo socket was not created (both `desired_min_echo_tx_interval_us` and
    /// `required_min_echo_rx_interval_us` are absent/zero in the config).
    pub fn echo_local_addr(&self) -> Option<SocketAddr> {
        self.echo_local_addr
    }

    /// Query per-session counters for a peer. Returns `None` if no session exists.
    pub async fn get_peer_counters(&self, addr: SocketAddr) -> Result<Option<SessionCounters>, BfdError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::GetPeerCounters { addr, reply: reply_tx })
            .await
            .ok();
        reply_rx.await.map_err(|_| BfdError::Io(std::io::Error::other("daemon gone")))
    }

    /// Query daemon-wide counters.
    pub async fn get_daemon_counters(&self) -> Result<DaemonCounters, BfdError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .send(Command::GetDaemonCounters { reply: reply_tx })
            .await
            .ok();
        reply_rx.await.map_err(|_| BfdError::Io(std::io::Error::other("daemon gone")))
    }

    /// Gracefully shut down: sends AdminDown to all peers, stops the event loop,
    /// and waits for the event loop task to finish before returning.
    pub async fn shutdown(&self) {
        let (done_tx, done_rx) = oneshot::channel();
        self.cmd_tx.send(Command::Shutdown { done: Some(done_tx) }).await.ok();
        done_rx.await.ok();
    }
}

impl Drop for BfdDaemon {
    fn drop(&mut self) {
        // Best-effort: send Shutdown if the event loop is still running.
        // Errors are ignored (loop may already be gone).
        self.cmd_tx.try_send(Command::Shutdown { done: None }).ok();
    }
}

/// Send an AdminDown control packet to `addr` and update session counters.
async fn send_admin_down_packet(
    tx_socket: &UdpSocket,
    session: &mut BfdSession,
    addr: SocketAddr,
) {
    let mut pkt = session.build_tx_packet();
    pkt.state = BfdState::AdminDown;
    pkt.diagnostic = Diagnostic::AdminDown;
    match tx_socket.send_to(&pkt.encode(), addr).await {
        Ok(_) => session.counters.control_tx += 1,
        Err(_) => session.counters.send_errors += 1,
    }
}

/// Emit AdminDown notifications and send AdminDown packets to all sessions.
///
/// Called from both the `Shutdown` command and `None` (channel-closed) paths.
async fn shutdown_all_sessions(
    sessions: &mut HashMap<SocketAddr, BfdSession>,
    tx_socket: &UdpSocket,
    notify_tx: &broadcast::Sender<StateChange>,
) {
    for (peer, session) in sessions.iter() {
        if session.local_state != BfdState::AdminDown {
            notify_tx.send(StateChange {
                peer: *peer,
                old_state: session.local_state,
                new_state: BfdState::AdminDown,
                diagnostic: Diagnostic::AdminDown,
            }).ok();
        }
    }
    let peers: Vec<SocketAddr> = sessions.keys().copied().collect();
    for peer in peers {
        let session = sessions.get_mut(&peer).unwrap();
        send_admin_down_packet(tx_socket, session, peer).await;
    }
}

/// Process one timer tick: check detection/poll timeouts and send due TX packets.
async fn handle_timer(
    sessions: &mut HashMap<SocketAddr, BfdSession>,
    tx_socket: &UdpSocket,
    echo_socket: &Option<Arc<UdpSocket>>,
    notify_tx: &broadcast::Sender<StateChange>,
    config: &BfdConfig,
) {
    let now = Instant::now();
    let peers: Vec<SocketAddr> = sessions.keys().copied().collect();
    for peer in peers {
        let session = sessions.get_mut(&peer).unwrap();

        // Check control detection timeout
        if session.is_detection_expired() {
            if let Some(change) = session.detection_expired() {
                info!("Detection timeout for {peer}: {:?} -> {:?}", change.old_state, change.new_state);
                notify_tx.send(change).ok();
            }
        }

        // Check echo detection timeout
        if session.is_echo_detection_expired() {
            if let Some(change) = session.echo_detection_expired() {
                info!("Echo detection timeout for {peer}: {:?} -> {:?}", change.old_state, change.new_state);
                notify_tx.send(change).ok();
            }
        }

        // Check Poll sequence timeout (no RFC-specified timeout; heuristic: 3× detection time)
        if session.is_poll_timed_out() {
            warn!("Poll sequence timed out for {peer}");
            session.poll_timed_out();
        }

        // Send control TX if deadline reached and remote wants packets
        if session.next_tx_deadline() <= now {
            if session.should_send() {
                let pkt = session.build_tx_packet();
                let encoded = pkt.encode();
                match tx_socket.send_to(&encoded, peer).await {
                    Ok(_) => {
                        debug!("TX to {peer}: state={:?}", pkt.state);
                        session.counters.control_tx += 1;
                    }
                    Err(e) => {
                        warn!("UDP send error to {peer}: {e}");
                        session.counters.send_errors += 1;
                    }
                }
            }
            session.advance_tx_deadline();
        }

        // Send echo TX if deadline reached and echo is active
        if let Some(next_echo) = session.next_echo_tx_deadline() {
            if next_echo <= now {
                if let Some(echo_sock) = echo_socket {
                    let pkt = session.build_echo_packet();
                    let encoded = pkt.encode();
                    let target = SocketAddr::new(peer.ip(), config.echo_port);
                    match echo_sock.send_to(&encoded, target).await {
                        Ok(_) => {
                            debug!("Echo TX to {peer}");
                            session.counters.echo_tx += 1;
                        }
                        Err(e) => {
                            warn!("Echo send error to {peer}: {e}");
                            session.counters.send_errors += 1;
                        }
                    }
                }
                session.advance_echo_tx_deadline();
            }
        }
    }
}

/// Process one incoming command. Returns `true` if the event loop should exit.
async fn handle_command(
    cmd: Option<Command>,
    sessions: &mut HashMap<SocketAddr, BfdSession>,
    disc_map: &mut HashMap<u32, SocketAddr>,
    daemon_counters: &mut DaemonCounters,
    tx_socket: &UdpSocket,
    notify_tx: &broadcast::Sender<StateChange>,
    config: &BfdConfig,
) -> bool {
    match cmd {
        Some(Command::GetPeerCounters { addr, reply }) => {
            let counters = sessions.get(&addr).map(|s| s.counters);
            reply.send(counters).ok();
        }
        Some(Command::GetDaemonCounters { reply }) => {
            reply.send(*daemon_counters).ok();
        }
        Some(Command::AddPeer { addr, mode, reply }) => {
            let result = if let std::collections::hash_map::Entry::Vacant(e) = sessions.entry(addr) {
                let peer_mode = mode.unwrap_or(config.default_mode);
                if let BfdMode::MultiHop { max_hops } = peer_mode
                    && max_hops == 0 {
                        reply.send(Err(BfdError::InvalidConfig("max_hops must be non-zero in MultiHop mode"))).ok();
                        return false;
                    }
                let disc = match next_discriminator(disc_map) {
                    Some(d) => d,
                    None => {
                        reply.send(Err(BfdError::Io(std::io::Error::other("getrandom unavailable")))).ok();
                        return false;
                    }
                };
                let echo_configured = config.desired_min_echo_tx_interval_us.is_some();
                let session = BfdSession::new(
                    addr,
                    disc,
                    config.desired_min_tx_interval_us,
                    config.required_min_rx_interval_us,
                    config.detect_mult,
                    peer_mode,
                    echo_configured,
                    config.desired_min_echo_tx_interval_us.unwrap_or(0),
                    config.required_min_echo_rx_interval_us,
                    config.echo_slow_timer_us,
                );
                disc_map.insert(disc, addr);
                e.insert(session);
                info!("Added peer {addr} (mode={peer_mode:?}) with discriminator {disc}");
                daemon_counters.peers_added += 1;
                Ok(())
            } else {
                Err(BfdError::SessionExists(addr))
            };
            reply.send(result).ok();
        }
        Some(Command::RemovePeer { addr, reply }) => {
            let result = if let Some(session) = sessions.get_mut(&addr) {
                // Send AdminDown to peer before removing
                send_admin_down_packet(tx_socket, session, addr).await;

                // Notify subscribers
                let old_state = session.local_state;
                if old_state != BfdState::AdminDown {
                    notify_tx.send(StateChange {
                        peer: addr,
                        old_state,
                        new_state: BfdState::AdminDown,
                        diagnostic: Diagnostic::AdminDown,
                    }).ok();
                }

                let session = sessions.remove(&addr).unwrap();
                disc_map.remove(&session.local_discriminator);
                info!("Removed peer {addr}");
                daemon_counters.peers_removed += 1;
                Ok(())
            } else {
                Err(BfdError::SessionNotFound(addr))
            };
            reply.send(result).ok();
        }
        Some(Command::AdminDown { addr, reply }) => {
            let result = if let Some(session) = sessions.get_mut(&addr) {
                if let Some(change) = session.set_admin_down() {
                    info!("AdminDown for {addr}: {:?} -> {:?}", change.old_state, change.new_state);
                    notify_tx.send(change).ok();
                }
                // Send AdminDown packet to peer so it can react immediately
                send_admin_down_packet(tx_socket, session, addr).await;
                Ok(())
            } else {
                Err(BfdError::SessionNotFound(addr))
            };
            reply.send(result).ok();
        }
        Some(Command::GetState { addr, reply }) => {
            let state = sessions.get(&addr).map(|s| s.local_state);
            reply.send(state).ok();
        }
        Some(Command::SetDesiredMinTx { addr, interval_us, reply }) => {
            let result = if interval_us == 0 {
                Err(BfdError::InvalidConfig("interval_us must be non-zero"))
            } else if let Some(session) = sessions.get_mut(&addr) {
                session.set_desired_min_tx(interval_us)
                    .map_err(|_| BfdError::PollInProgress(addr))
            } else {
                Err(BfdError::SessionNotFound(addr))
            };
            reply.send(result).ok();
        }
        Some(Command::SetRequiredMinRx { addr, interval_us, reply }) => {
            let result = if interval_us == 0 {
                Err(BfdError::InvalidConfig("interval_us must be non-zero"))
            } else if let Some(session) = sessions.get_mut(&addr) {
                session.set_required_min_rx(interval_us)
                    .map_err(|_| BfdError::PollInProgress(addr))
            } else {
                Err(BfdError::SessionNotFound(addr))
            };
            reply.send(result).ok();
        }
        Some(Command::Shutdown { done }) => {
            info!("BFD daemon shutting down");
            shutdown_all_sessions(sessions, tx_socket, notify_tx).await;
            if let Some(done) = done {
                done.send(()).ok();
            }
            return true;
        }
        None => {
            // Command channel closed (all BfdDaemon handles dropped).
            info!("BFD daemon shutting down (channel closed)");
            shutdown_all_sessions(sessions, tx_socket, notify_tx).await;
            return true;
        }
    }
    false
}

async fn run_event_loop(
    rx_socket: Arc<UdpSocket>,
    tx_socket: Arc<UdpSocket>,
    echo_socket: Option<Arc<UdpSocket>>,
    config: BfdConfig,
    mut cmd_rx: mpsc::Receiver<Command>,
    notify_tx: broadcast::Sender<StateChange>,
) {
    // sessions keyed by peer SocketAddr
    let mut sessions: HashMap<SocketAddr, BfdSession> = HashMap::new();
    // discriminator → peer addr for incoming packet routing
    let mut disc_map: HashMap<u32, SocketAddr> = HashMap::new();
    let mut daemon_counters = DaemonCounters::default();

    let mut recv_buf = [0u8; 1500];
    let mut echo_recv_buf = [0u8; 1500];
    let raw_fd = rx_socket.as_raw_fd();
    let echo_raw_fd = echo_socket.as_ref().map(|s| s.as_raw_fd());

    let sleep = tokio::time::sleep(std::time::Duration::from_secs(1));
    tokio::pin!(sleep);

    loop {
        // Compute the soonest deadline across control TX, detection, echo TX, and echo detection.
        let next_deadline = sessions
            .values()
            .flat_map(|s| {
                std::iter::once(s.next_tx_deadline())
                    .chain(s.detection_deadline())
                    .chain(s.next_echo_tx_deadline())
                    .chain(s.echo_detection_deadline())
            })
            .min()
            .unwrap_or_else(|| Instant::now() + std::time::Duration::from_secs(1));

        // Reset the pinned sleep to the absolute deadline so incoming packets
        // don't push the TX timer forward (the key fix for session flapping).
        let tokio_deadline = tokio::time::Instant::now()
            + next_deadline.saturating_duration_since(Instant::now());
        sleep.as_mut().reset(tokio_deadline);

        tokio::select! {
            // Incoming control UDP packet — use try_io to get raw recvmsg with TTL ancillary data
            _ = rx_socket.readable() => {
                match rx_socket.try_io(Interest::READABLE, || net::recv_with_ttl(raw_fd, &mut recv_buf)) {
                    Ok((len, src, ttl)) => {
                        handle_rx(
                            &tx_socket,
                            &mut sessions,
                            &mut disc_map,
                            &notify_tx,
                            &mut daemon_counters,
                            &recv_buf[..len],
                            src,
                            ttl,
                        ).await;
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        // spurious wakeup; loop and wait for readable again
                    }
                    Err(e) => {
                        warn!("UDP recv error: {e}");
                        daemon_counters.udp_rx_errors += 1;
                    }
                }
            }

            // Incoming echo UDP packet (or pending() when echo socket not present)
            _ = async {
                if let Some(ref s) = echo_socket {
                    let _ = s.readable().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                if let (Some(echo_sock), Some(fd)) = (&echo_socket, echo_raw_fd) {
                    match echo_sock.try_io(Interest::READABLE, || net::recv_with_ttl(fd, &mut echo_recv_buf)) {
                        Ok((len, src, ttl)) => {
                            handle_echo_rx(echo_sock, &mut sessions, &disc_map, &mut daemon_counters, &echo_recv_buf[..len], src, ttl).await;
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(e) => {
                            warn!("Echo UDP recv error: {e}");
                            daemon_counters.echo_rx_errors += 1;
                        }
                    }
                }
            }

            // Timer fires (TX deadline, detection deadline, echo TX, or echo detection)
            _ = &mut sleep => {
                handle_timer(&mut sessions, &tx_socket, &echo_socket, &notify_tx, &config).await;
            }

            // Control commands
            cmd = cmd_rx.recv() => {
                if handle_command(cmd, &mut sessions, &mut disc_map, &mut daemon_counters, &tx_socket, &notify_tx, &config).await {
                    break;
                }
            }
        }
    }
}

/// Handle an incoming echo packet.
///
/// If `pkt.my_discriminator` matches a local session discriminator, the packet is our own
/// echo returning — validate TTL and record receipt. Otherwise, loop the raw bytes back to
/// the sender so the remote peer's echo detection timer is refreshed.
async fn handle_echo_rx(
    echo_socket: &Arc<UdpSocket>,
    sessions: &mut HashMap<SocketAddr, BfdSession>,
    disc_map: &HashMap<u32, SocketAddr>,
    daemon_counters: &mut DaemonCounters,
    buf: &[u8],
    src: SocketAddr,
    ttl: Option<u8>,
) {
    let pkt = match crate::packet::BfdPacket::decode(buf) {
        Ok(p) => p,
        Err(e) => {
            warn!("Bad echo packet from {src}: {e}");
            return;
        }
    };

    if let Some(&peer_addr) = disc_map.get(&pkt.my_discriminator) {
        // Our own echo returning: validate TTL (must have crossed ≤1 hop, RFC 5881 §4)
        if ttl.is_none_or(|t| t < 254) {
            warn!("Dropping echo from {src}: TTL={ttl:?}, minimum 254");
            return;
        }
        if let Some(session) = sessions.get_mut(&peer_addr) {
            debug!("Echo RX from {src} (session {})", session.local_discriminator);
            session.echo_received();
            session.counters.echo_rx += 1;
        }
    } else {
        // Peer's echo packet: loop it back to the sender
        debug!("Looping back echo from {src}");
        if echo_socket.send_to(buf, src).await.is_ok() {
            daemon_counters.echo_loopback += 1;
        }
    }
}

async fn handle_rx(
    tx_socket: &Arc<UdpSocket>,
    sessions: &mut HashMap<SocketAddr, BfdSession>,
    disc_map: &mut HashMap<u32, SocketAddr>,
    notify_tx: &broadcast::Sender<StateChange>,
    daemon_counters: &mut DaemonCounters,
    buf: &[u8],
    src: SocketAddr,
    ttl: Option<u8>,
) {
    let pkt = match crate::packet::BfdPacket::decode(buf) {
        Ok(p) => p,
        Err(e) => {
            warn!("Bad BFD packet from {src}: {e}");
            daemon_counters.control_rx_discarded += 1;
            return;
        }
    };

    debug!("RX from {src}: state={:?} my_disc={} your_disc={}", pkt.state, pkt.my_discriminator, pkt.your_discriminator);

    // RFC 5880 §6.8.6: if your_discriminator is 0 and state is not Down or AdminDown, discard.
    if pkt.your_discriminator == 0
        && pkt.state != BfdState::Down
        && pkt.state != BfdState::AdminDown
    {
        warn!("Discarding packet from {src}: your_discriminator=0 but state={:?}", pkt.state);
        daemon_counters.control_rx_discarded += 1;
        return;
    }

    // Locate session: by your_discriminator if set, else by src addr.
    // When routing by discriminator, verify the source address matches the expected peer
    // to prevent discriminator-spoofing attacks.
    let session = if pkt.your_discriminator != 0 {
        match disc_map.get(&pkt.your_discriminator) {
            Some(&expected) => {
                if expected.ip() != src.ip() {
                    warn!(
                        "Dropping packet from {src}: discriminator {} belongs to {expected}",
                        pkt.your_discriminator
                    );
                    // Source mismatch — count as per-session error if we can find the session
                    if let Some(session) = sessions.get_mut(&expected) {
                        session.counters.control_rx_error += 1;
                    }
                    return;
                }
                sessions.get_mut(&expected)
            }
            None => {
                // Unknown discriminator — remote may have a stale discriminator from a
                // previous session (e.g. after our daemon restarted). Fall back to IP
                // lookup so the session can recover without requiring a remote restart.
                warn!("Unknown discriminator {} from {src}, falling back to IP lookup", pkt.your_discriminator);
                let key = sessions.keys().find(|k| k.ip() == src.ip()).copied();
                key.and_then(|k| sessions.get_mut(&k))
            }
        }
    } else {
        // RFC 5881 peers send from ephemeral source ports, so match by IP only
        // when your_discriminator is 0 (session not yet established).
        let key = sessions.keys().find(|k| k.ip() == src.ip()).copied();
        key.and_then(|k| sessions.get_mut(&k))
    };

    let session = match session {
        Some(s) => s,
        None => {
            warn!("No session for packet from {src}");
            daemon_counters.control_rx_discarded += 1;
            return;
        }
    };

    // Per-session TTL validation (RFC 5881 §5 / RFC 5883)
    let min_ttl = session.min_ttl();
    if ttl.is_none_or(|t| t < min_ttl) {
        warn!("Dropping BFD packet from {src}: TTL/hop-limit={ttl:?}, minimum required={min_ttl}");
        session.counters.control_rx_error += 1;
        return;
    }

    session.counters.control_rx += 1;
    if let Some(change) = session.receive_packet(&pkt) {
        info!("State change for {src}: {:?} -> {:?}", change.old_state, change.new_state);
        notify_tx.send(change).ok();
        // RFC 5880 §6.8.7: transmit as soon as practical on state change
        session.schedule_immediate_tx();
    }

    // Respond to Poll with Final immediately (RFC 5880 §6.8.7)
    if pkt.poll {
        let mut reply = session.build_tx_packet();
        reply.poll = false;
        reply.finalize = true;
        let encoded = reply.encode();
        match tx_socket.send_to(&encoded, session.peer_addr).await {
            Ok(_) => session.counters.control_tx += 1,
            Err(_) => session.counters.send_errors += 1,
        }
        session.advance_tx_deadline();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_validation_single_hop() {
        use crate::session::BfdSession;
        let session = BfdSession::new(
            "127.0.0.1:3784".parse().unwrap(), 1, 1_000_000, 1_000_000, 3,
            BfdMode::SingleHop, false, 0, 0, 1_000_000,
        );
        let min_ttl = session.min_ttl();
        assert_eq!(min_ttl, 255);
        assert!(Some(255u8).is_some_and(|t| t >= min_ttl));
        assert!(Some(254u8).is_none_or(|t| t < min_ttl));
        assert!(None::<u8>.is_none_or(|t| t < min_ttl));
    }

    #[test]
    fn ttl_validation_multihop() {
        use crate::session::BfdSession;
        let session = BfdSession::new(
            "127.0.0.1:4784".parse().unwrap(), 1, 1_000_000, 1_000_000, 3,
            BfdMode::MultiHop { max_hops: 2 }, false, 0, 0, 1_000_000,
        );
        let min_ttl = session.min_ttl();
        assert_eq!(min_ttl, 253);
        assert!(Some(255u8).is_some_and(|t| t >= min_ttl));
        assert!(Some(254u8).is_some_and(|t| t >= min_ttl));
        assert!(Some(253u8).is_some_and(|t| t >= min_ttl));
        assert!(Some(252u8).is_none_or(|t| t < min_ttl));
    }

    #[tokio::test]
    async fn config_validation_multihop_zero_hops() {
        let config = BfdConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            desired_min_tx_interval_us: 1_000_000,
            required_min_rx_interval_us: 1_000_000,
            detect_mult: 3,
            default_mode: BfdMode::MultiHop { max_hops: 0 },
            ..Default::default()
        };
        let result = BfdDaemon::start(config).await;
        assert!(matches!(result, Err(BfdError::InvalidConfig(_))));
    }

    #[tokio::test]
    async fn add_peer_with_mode_rejects_zero_hops() {
        let config = BfdConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            desired_min_tx_interval_us: 1_000_000,
            required_min_rx_interval_us: 1_000_000,
            detect_mult: 3,
            default_mode: BfdMode::SingleHop,
            ..Default::default()
        };
        let daemon = BfdDaemon::start(config).await.unwrap();
        let result = daemon.add_peer_with_mode(
            "127.0.0.1:3784".parse().unwrap(),
            Some(BfdMode::MultiHop { max_hops: 0 }),
        ).await;
        assert!(matches!(result, Err(BfdError::InvalidConfig(_))));
        daemon.shutdown().await;
    }

    #[tokio::test]
    async fn echo_config_zero_tx_interval_rejected() {
        let config = BfdConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            desired_min_echo_tx_interval_us: Some(0),
            ..Default::default()
        };
        let result = BfdDaemon::start(config).await;
        assert!(matches!(result, Err(BfdError::InvalidConfig(_))));
    }

    #[tokio::test]
    async fn echo_socket_created_when_rx_configured() {
        let config = BfdConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            required_min_echo_rx_interval_us: 100_000,
            echo_port: 0,
            ..Default::default()
        };
        let daemon = BfdDaemon::start(config).await.unwrap();
        assert!(daemon.echo_local_addr().is_some(), "echo socket should be created");
        daemon.shutdown().await;
    }

    #[tokio::test]
    async fn echo_socket_not_created_by_default() {
        let config = BfdConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            ..Default::default()
        };
        let daemon = BfdDaemon::start(config).await.unwrap();
        assert!(daemon.echo_local_addr().is_none(), "echo socket should not be created by default");
        daemon.shutdown().await;
    }
}
