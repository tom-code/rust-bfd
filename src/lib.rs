//! Bidirectional Forwarding Detection (BFD) library for link-state detection.
//!
//! This crate implements BFD control-plane sessions per
//! [RFC 5880] (base protocol), [RFC 5881] (single-hop IPv4/IPv6), and
//! [RFC 5883] (multi-hop).  A single tokio task runs the entire event loop —
//! there are no per-session tasks.  State transitions are broadcast to all
//! subscribers via a [`tokio::sync::broadcast`] channel so multiple consumers
//! (routing daemons, health checkers, metrics) can each receive every event.
//!
//! [RFC 5880]: https://www.rfc-editor.org/rfc/rfc5880
//! [RFC 5881]: https://www.rfc-editor.org/rfc/rfc5881
//! [RFC 5883]: https://www.rfc-editor.org/rfc/rfc5883
//!
//! # Quick start
//!
//! ```no_run
//! use bfd::{BfdConfig, BfdDaemon, BfdState};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let daemon = BfdDaemon::start(BfdConfig {
//!         listen_addr: "0.0.0.0:3784".parse().unwrap(),
//!         desired_min_tx_interval_us: 300_000,
//!         required_min_rx_interval_us: 300_000,
//!         detect_mult: 3,
//!         ..Default::default()
//!     }).await?;
//!
//!     // Subscribe before adding peers so no events are missed.
//!     let mut events = daemon.subscribe();
//!
//!     daemon.add_peer("192.0.2.1:3784".parse().unwrap()).await?;
//!
//!     while let Ok(change) = events.recv().await {
//!         println!(
//!             "peer={} {:?} -> {:?} (diag={:?})",
//!             change.peer, change.old_state, change.new_state, change.diagnostic
//!         );
//!         if change.new_state == BfdState::Up {
//!             break;
//!         }
//!     }
//!
//!     daemon.shutdown().await;
//!     Ok(())
//! }
//! ```
//!
//! # Echo function (RFC 5880 §6.8.9 / RFC 5881 §4)
//!
//! Echo mode offloads liveness detection to the forwarding plane: the local
//! daemon sends echo packets that the *remote* peer loops back unchanged.
//! Because the packets travel the same data-plane path in both directions,
//! failures are detected faster and with less control-plane overhead.
//!
//! Echo is **single-hop only** and activates automatically once both sides
//! signal willingness:
//!
//! - Set [`BfdConfig::desired_min_echo_tx_interval_us`] to the echo TX rate
//!   you want (e.g. `50_000` for 50 ms).  This enables sending echo packets.
//! - Set [`BfdConfig::required_min_echo_rx_interval_us`] to a non-zero value
//!   to advertise that *this* daemon is willing to loop back the peer's echo
//!   packets.
//!
//! Both must be non-zero on both ends for echo to become active on a session.
//! While echo is active, control packet TX slows to
//! [`BfdConfig::echo_slow_timer_us`] (default 1 s) to reduce overhead, while
//! the echo stream provides the real detection.
//!
//! ```no_run
//! use bfd::{BfdConfig, BfdDaemon};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // Both sides send and loop back echo packets.
//!     let daemon = BfdDaemon::start(BfdConfig {
//!         listen_addr: "0.0.0.0:3784".parse().unwrap(),
//!         desired_min_tx_interval_us: 300_000,
//!         required_min_rx_interval_us: 300_000,
//!         detect_mult: 3,
//!         desired_min_echo_tx_interval_us: Some(50_000),   // send echo every 50 ms
//!         required_min_echo_rx_interval_us: 50_000,        // willing to loop back
//!         ..Default::default()
//!     }).await?;
//!
//!     if let Some(echo_addr) = daemon.echo_local_addr() {
//!         println!("echo socket bound to {echo_addr}");
//!     }
//!
//!     daemon.add_peer("192.0.2.1:3784".parse().unwrap()).await?;
//!     // ...
//!     daemon.shutdown().await;
//!     Ok(())
//! }
//! ```
//!
//! # Mid-session parameter changes (Poll/Final)
//!
//! TX and RX intervals can be changed on a live session via
//! [`BfdDaemon::set_desired_min_tx`] and [`BfdDaemon::set_required_min_rx`].
//! Changes are negotiated with the remote peer using the RFC 5880 §6.8.3
//! Poll/Final mechanism — only one change at a time is allowed per session.
//!
//! # Counters
//!
//! Per-session and daemon-wide operational counters are available for monitoring:
//!
//! ```no_run
//! use bfd::{BfdConfig, BfdDaemon};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let daemon = BfdDaemon::start(BfdConfig {
//!         listen_addr: "0.0.0.0:3784".parse().unwrap(),
//!         ..Default::default()
//!     }).await?;
//!     let peer = "192.0.2.1:3784".parse().unwrap();
//!     daemon.add_peer(peer).await?;
//!
//!     // Per-session counters (None if session does not exist)
//!     if let Some(c) = daemon.get_peer_counters(peer).await? {
//!         println!("TX={} RX={} transitions={}", c.control_tx, c.control_rx, c.state_transitions);
//!     }
//!
//!     // Daemon-wide counters
//!     let dc = daemon.get_daemon_counters().await?;
//!     println!("peers_added={} discarded={}", dc.peers_added, dc.control_rx_discarded);
//!
//!     daemon.shutdown().await;
//!     Ok(())
//! }
//! ```
//!
//! # Limitations
//!
//! - **No authentication** — RFC 5880 §6.7 authentication extensions are not implemented.
//!   The A bit is always 0; packets with the A bit set are rejected.

pub(crate) mod error;
pub(crate) mod state;
pub(crate) mod packet;
pub(crate) mod session;
pub(crate) mod net;
pub(crate) mod server;

pub use server::{BfdConfig, BfdDaemon, DaemonCounters};
pub use session::SessionCounters;
pub use state::{BfdMode, BfdState, Diagnostic, StateChange};
pub use error::{BfdError, PacketError};
