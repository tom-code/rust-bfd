# rust-bfd

![AI](https://img.shields.io/badge/note-fully_generated_by_ai-blue.svg)

A Rust library implementing **Bidirectional Forwarding Detection (BFD)** per [RFC 5880](https://www.rfc-editor.org/rfc/rfc5880), [RFC 5881](https://www.rfc-editor.org/rfc/rfc5881), and [RFC 5883](https://www.rfc-editor.org/rfc/rfc5883). Designed for link state detection in routing daemons and network appliances.

## Features

- Full BFD control packet state machine (RFC 5880 §6.8.6)
- Single-hop (RFC 5881) and multi-hop (RFC 5883) sessions on the same daemon
- Echo mode (RFC 5880 §6.8.9 / RFC 5881 §4) for sub-millisecond detection
- RFC-compliant source port (49152–65535) via two-socket model
- TTL=255 enforcement for single-hop; configurable TTL threshold for multi-hop
- Source address verification on established sessions
- TX jitter per RFC 5880 §6.8.7
- Async, single event loop — no per-session tasks
- `broadcast` notifications for state transitions

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
rust-bfd = "0.1"
```

## Quick Start

```rust
use bfd::{BfdDaemon, BfdConfig, BfdMode};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let daemon = BfdDaemon::start(BfdConfig {
        listen_addr: "0.0.0.0:3784".parse()?,
        desired_min_tx_interval_us: 300_000,   // 300ms
        required_min_rx_interval_us: 300_000,
        detect_mult: 3,
        ..Default::default()
    }).await?;

    // Subscribe to state change notifications
    let mut events = daemon.subscribe();

    // Add a peer
    daemon.add_peer("192.0.2.1:3784".parse()?).await?;

    // React to state changes
    while let Ok(change) = events.recv().await {
        println!("{:?} -> {:?}", change.peer, change.new_state);
    }

    Ok(())
}
```

## API

### `BfdDaemon::start(config)`

Starts the async event loop and binds the UDP socket. Returns a `BfdDaemon` handle.

### `BfdConfig`

| Field | Type | Description |
|-------|------|-------------|
| `listen_addr` | `SocketAddr` | Local address to bind the RX socket |
| `desired_min_tx_interval_us` | `u32` | Desired TX interval in microseconds (must be > 0) |
| `required_min_rx_interval_us` | `u32` | Minimum acceptable RX interval in microseconds (must be > 0) |
| `detect_mult` | `u8` | Detection multiplier (must be > 0) |
| `mode` | `BfdMode` | Operating mode for all peers (default: `SingleHop`) |
| `desired_min_echo_tx_interval_us` | `Option<u32>` | Echo TX interval; `None` disables echo TX |
| `required_min_echo_rx_interval_us` | `u32` | Echo RX interval advertised to peers; `0` = won't loop back |
| `echo_slow_timer_us` | `u32` | Control TX interval when echo is active (default: 1,000,000 μs) |
| `echo_port` | `u16` | UDP port for the echo socket (default: 3785; `0` = OS-assigned) |

### Daemon Methods

```rust
// Peer management
daemon.add_peer(addr: SocketAddr).await?;
daemon.remove_peer(addr: SocketAddr).await?;

// State queries
let state: Option<BfdState> = daemon.get_state(addr).await?;
let local: SocketAddr = daemon.local_addr();
let echo: Option<SocketAddr> = daemon.echo_local_addr();

// Mid-session parameter changes (RFC 5880 §6.8.3 Poll/Final)
daemon.set_desired_min_tx(addr, interval_us).await?;
daemon.set_required_min_rx(addr, interval_us).await?;

// Counters
let counters: Option<SessionCounters> = daemon.get_peer_counters(addr).await?;
let dc: DaemonCounters = daemon.get_daemon_counters().await?;

// Notifications
let mut rx: broadcast::Receiver<StateChange> = daemon.subscribe();

// Shutdown (waits for event loop to stop)
daemon.shutdown().await;
```

### `SessionCounters`

Per-session counters retrieved via `daemon.get_peer_counters(addr).await?` (returns `None` if no session):

| Field | Description |
|-------|-------------|
| `control_tx` | Control packets sent |
| `control_rx` | Control packets received and processed |
| `control_rx_error` | Packets discarded after session lookup (TTL fail, source mismatch) |
| `echo_tx` | Echo packets sent |
| `echo_rx` | Echo packets received (returning echo) |
| `state_transitions` | Total local state transitions |
| `detection_timeouts` | Control detection timeouts that drove the session Down |
| `echo_detection_timeouts` | Echo detection timeouts that drove the session Down |
| `poll_sequences` | Poll sequences initiated |
| `send_errors` | Send errors on control or echo socket |

### `DaemonCounters`

Daemon-wide counters retrieved via `daemon.get_daemon_counters().await?`:

| Field | Description |
|-------|-------------|
| `peers_added` | Total peers successfully added |
| `peers_removed` | Total peers successfully removed |
| `udp_rx_errors` | Errors reading from the control socket |
| `echo_rx_errors` | Errors reading from the echo socket |
| `control_rx_discarded` | Packets discarded before session lookup (decode error, no session) |
| `echo_loopback` | Echo packets looped back to peers |

### `BfdMode`

```rust
BfdMode::SingleHop                         // RFC 5881 — TTL must be 255
BfdMode::MultiHop { max_hops: u8 }         // RFC 5883 — TTL must be ≥ 255 - max_hops
```

Mode is set once at daemon startup and applies to all peers. To run both single-hop and multi-hop sessions, start two separate `BfdDaemon` instances.

### `BfdState`

```rust
BfdState::AdminDown
BfdState::Down
BfdState::Init
BfdState::Up
```

### `StateChange`

Emitted on every state transition:

```rust
pub struct StateChange {
    pub peer: SocketAddr,
    pub old_state: BfdState,
    pub new_state: BfdState,
    pub diagnostic: Diagnostic,
}
```

## Echo Mode

Echo mode enables fast failure detection by bouncing packets off the peer rather than relying on control packet timing. It is only active for `SingleHop` sessions.

```rust
let daemon = BfdDaemon::start(BfdConfig {
    listen_addr: "0.0.0.0:3784".parse()?,
    desired_min_tx_interval_us: 300_000,
    required_min_rx_interval_us: 300_000,
    detect_mult: 3,
    desired_min_echo_tx_interval_us: Some(50_000),  // send echo every 50ms
    required_min_echo_rx_interval_us: 50_000,        // willing to loop back echo
    echo_slow_timer_us: 1_000_000,                   // slow control TX to 1s when echo active
    echo_port: 3785,
    ..Default::default()
}).await?;
```

Echo is active when the session is `Up`, echo is locally configured, and the remote peer advertises a non-zero `required_min_echo_rx_interval`. Control TX automatically slows to `echo_slow_timer_us` while echo is running. A detection timeout fires `Diagnostic::EchoFunctionFailed`.

## Multi-hop

```rust
use bfd::{BfdDaemon, BfdConfig, BfdMode};

let daemon = BfdDaemon::start(BfdConfig {
    listen_addr: "0.0.0.0:4784".parse()?,
    desired_min_tx_interval_us: 1_000_000,
    required_min_rx_interval_us: 1_000_000,
    detect_mult: 3,
    mode: BfdMode::MultiHop { max_hops: 10 },
    ..Default::default()
}).await?;

daemon.add_peer("10.0.0.1:4784".parse()?).await?;
```

## State Machine

```
Down  + remote Down  → Init
Down  + remote Init  → Up
Init  + remote Init  → Up
Init  + remote Up    → Up
Up    + remote Down  → Down
any   + remote AdminDown → Down
control detection timeout (Up) → Down  [Diagnostic::ControlDetectionTimeExpired]
echo detection timeout (Up + echo active) → Down  [Diagnostic::EchoFunctionFailed]
```

## Examples

```bash
# Two peers on loopback (single-hop)
cargo run --example two_peers

# Two peers on loopback (multi-hop)
cargo run --example multihop

# Single peer with CLI configuration
cargo run --example single_peer -- --help
cargo run --example single_peer -- -l 127.0.0.1:3784 -p 127.0.0.1:3785
cargo run --example single_peer -- \
    -l 127.0.0.1:3784 -p 127.0.0.1:3785 \
    --echo-tx-interval 50000 --echo-rx-interval 50000
```

## Design Notes

- **Two-socket model**: RX socket bound to the configured listen port; TX socket uses an OS-assigned ephemeral port. This satisfies RFC 5881 §4's requirement that control packets originate from port 49152–65535, ensuring compatibility with FRR, BIRD, and IOS-XE.
- **Single event loop**: `tokio::select!` over UDP recv, echo recv, TX timer, and command channel. No per-session tasks or threads.
- **Two-socket TX port guarantee**: `create_bfd_send_socket` binds to a random port in 49152–65535 (RFC 5881 §4 MUST). If the OS would assign a port below that range, the library retries with an explicit port in the required range.
- **TX jitter**: per-packet xorshift64 PRNG seeded from the local discriminator. detect_mult>1: 0–25% reduction (interval in [75%, 100%]); detect_mult=1: 10–25% reduction (interval in [75%, 90%]) per RFC 5880 §6.8.7.
- **DSCP CS6**: TX sockets set `IP_TOS`/`IPV6_TCLASS` to 0xC0 (CS6) per RFC 5881 §4 SHOULD.
- **Source port validation**: incoming SingleHop control packets with source port < 49152 are discarded per RFC 5881 §4.
- **No authentication**: The Auth bit is always 0; RFC 5880 §6.7 authentication is not implemented.

## Limitations

- **Demand mode**: RFC 5880 §6.6 demand mode (D bit) is not handled. A remote peer setting D=1 will not suppress the local detection timer.
- No authentication (RFC 5880 §6.7)

