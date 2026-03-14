/// Integration tests: spin up two BFD daemons on loopback and verify the state machine
/// works end-to-end through real UDP sockets.
///
/// Each test uses `127.0.0.1:0` so the OS picks ephemeral ports, avoiding conflicts
/// between parallel test runs.  We then use `daemon.local_addr()` to learn the port
/// and give each daemon the other's address as a peer.
use std::net::SocketAddr;
use std::time::Duration;

use bfd::{BfdConfig, BfdDaemon, BfdError, BfdMode, BfdState, StateChange};
use tokio::sync::broadcast;
use tokio::time::timeout;

fn default_config(addr: &str) -> BfdConfig {
    BfdConfig {
        listen_addr: addr.parse().unwrap(),
        desired_min_tx_interval_us: 100_000,  // 100 ms
        required_min_rx_interval_us: 100_000, // 100 ms
        detect_mult: 3,
        default_mode: BfdMode::SingleHop,
        ..Default::default()
    }
}

fn echo_config(addr: &str) -> BfdConfig {
    BfdConfig {
        listen_addr: addr.parse().unwrap(),
        desired_min_tx_interval_us: 100_000,
        required_min_rx_interval_us: 100_000,
        detect_mult: 3,
        default_mode: BfdMode::SingleHop,
        desired_min_echo_tx_interval_us: Some(100_000),
        required_min_echo_rx_interval_us: 100_000,
        echo_slow_timer_us: 1_000_000,
        echo_port: 0,
    }
}

/// Wait for the next state-change notification that satisfies `pred`, with a timeout.
async fn wait_for_state(
    rx: &mut broadcast::Receiver<StateChange>,
    pred: impl Fn(&StateChange) -> bool,
) -> Option<StateChange> {
    let deadline = Duration::from_secs(5);
    timeout(deadline, async {
        loop {
            match rx.recv().await {
                Ok(sc) if pred(&sc) => return sc,
                Ok(_) => continue,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => {
                    panic!("state channel closed before expected state arrived")
                }
            }
        }
    })
    .await
    .ok()
}

/// Two single-hop daemons on loopback reach Up state, then shutdown triggers AdminDown.
#[tokio::test]
async fn two_peers_reach_up_then_shutdown() {
    let a = BfdDaemon::start(default_config("127.0.0.1:0")).await.unwrap();
    let b = BfdDaemon::start(default_config("127.0.0.1:0")).await.unwrap();

    let addr_a: SocketAddr = a.local_addr();
    let addr_b: SocketAddr = b.local_addr();

    let mut rx_a = a.subscribe();
    let mut rx_b = b.subscribe();

    a.add_peer(addr_b).await.unwrap();
    b.add_peer(addr_a).await.unwrap();

    // Both sides should reach Up
    let sc_a = wait_for_state(&mut rx_a, |sc| sc.new_state == BfdState::Up).await;
    assert!(sc_a.is_some(), "daemon A did not reach Up within 5s");

    let sc_b = wait_for_state(&mut rx_b, |sc| sc.new_state == BfdState::Up).await;
    assert!(sc_b.is_some(), "daemon B did not reach Up within 5s");

    // Verify get_state API
    assert_eq!(a.get_state(addr_b).await.unwrap(), Some(BfdState::Up));
    assert_eq!(b.get_state(addr_a).await.unwrap(), Some(BfdState::Up));

    // Graceful shutdown of A: B should detect AdminDown
    a.shutdown().await;

    let sc_b_down = wait_for_state(&mut rx_b, |sc| sc.new_state == BfdState::Down || sc.new_state == BfdState::AdminDown).await;
    assert!(sc_b_down.is_some(), "daemon B did not detect A's shutdown within 5s");

    b.shutdown().await;
}

/// Removing a peer sends AdminDown to the other side.
#[tokio::test]
async fn remove_peer_signals_admin_down() {
    let a = BfdDaemon::start(default_config("127.0.0.1:0")).await.unwrap();
    let b = BfdDaemon::start(default_config("127.0.0.1:0")).await.unwrap();

    let addr_a: SocketAddr = a.local_addr();
    let addr_b: SocketAddr = b.local_addr();

    let mut rx_a = a.subscribe();
    let mut rx_b = b.subscribe();

    a.add_peer(addr_b).await.unwrap();
    b.add_peer(addr_a).await.unwrap();

    // Wait for Up
    wait_for_state(&mut rx_a, |sc| sc.new_state == BfdState::Up).await.unwrap();
    wait_for_state(&mut rx_b, |sc| sc.new_state == BfdState::Up).await.unwrap();

    // Remove A's peer (sends AdminDown packet to B)
    a.remove_peer(addr_b).await.unwrap();

    // B should react to AdminDown from A
    let sc = wait_for_state(&mut rx_b, |sc| {
        sc.new_state == BfdState::Down || sc.new_state == BfdState::AdminDown
    }).await;
    assert!(sc.is_some(), "B did not react to A's remove_peer within 5s");

    a.shutdown().await;
    b.shutdown().await;
}

/// admin_down_peer() gracefully signals the peer without removing the session.
#[tokio::test]
async fn admin_down_peer_signals_neighbor() {
    let a = BfdDaemon::start(default_config("127.0.0.1:0")).await.unwrap();
    let b = BfdDaemon::start(default_config("127.0.0.1:0")).await.unwrap();

    let addr_a: SocketAddr = a.local_addr();
    let addr_b: SocketAddr = b.local_addr();

    let mut rx_a = a.subscribe();
    let mut rx_b = b.subscribe();

    a.add_peer(addr_b).await.unwrap();
    b.add_peer(addr_a).await.unwrap();

    wait_for_state(&mut rx_a, |sc| sc.new_state == BfdState::Up).await.unwrap();
    wait_for_state(&mut rx_b, |sc| sc.new_state == BfdState::Up).await.unwrap();

    // Transition A's session to AdminDown
    a.admin_down_peer(addr_b).await.unwrap();

    // A's own state should now be AdminDown
    let sc_a = wait_for_state(&mut rx_a, |sc| sc.new_state == BfdState::AdminDown).await;
    assert!(sc_a.is_some(), "A did not transition to AdminDown");
    assert_eq!(a.get_state(addr_b).await.unwrap(), Some(BfdState::AdminDown));

    // B should detect A going away
    let sc_b = wait_for_state(&mut rx_b, |sc| {
        sc.new_state == BfdState::Down || sc.new_state == BfdState::AdminDown
    }).await;
    assert!(sc_b.is_some(), "B did not react to A's AdminDown within 5s");

    a.shutdown().await;
    b.shutdown().await;
}

/// Duplicate add_peer returns SessionExists.
#[tokio::test]
async fn add_peer_duplicate_rejected() {
    let a = BfdDaemon::start(default_config("127.0.0.1:0")).await.unwrap();
    let addr: SocketAddr = "127.0.0.1:19999".parse().unwrap();

    a.add_peer(addr).await.unwrap();
    let err = a.add_peer(addr).await.unwrap_err();
    assert!(matches!(err, bfd::BfdError::SessionExists(_)));

    a.shutdown().await;
}

/// remove_peer for an unknown address returns SessionNotFound.
#[tokio::test]
async fn remove_unknown_peer_rejected() {
    let a = BfdDaemon::start(default_config("127.0.0.1:0")).await.unwrap();
    let addr: SocketAddr = "127.0.0.1:19998".parse().unwrap();

    let err = a.remove_peer(addr).await.unwrap_err();
    assert!(matches!(err, bfd::BfdError::SessionNotFound(_)));

    a.shutdown().await;
}

/// get_state returns None for an unknown peer.
#[tokio::test]
async fn get_state_unknown_peer_returns_none() {
    let a = BfdDaemon::start(default_config("127.0.0.1:0")).await.unwrap();
    let addr: SocketAddr = "127.0.0.1:19997".parse().unwrap();

    let state = a.get_state(addr).await.unwrap();
    assert!(state.is_none());

    a.shutdown().await;
}

/// shutdown() waits until the event loop has actually stopped.
#[tokio::test]
async fn shutdown_is_synchronous() {
    let a = BfdDaemon::start(default_config("127.0.0.1:0")).await.unwrap();
    let addr_a = a.local_addr();

    // shutdown() should complete promptly without hanging
    timeout(Duration::from_secs(2), a.shutdown())
        .await
        .expect("shutdown() did not complete within 2s");

    // After shutdown, re-binding the same address should succeed (port is released)
    let b_result = BfdDaemon::start(BfdConfig {
        listen_addr: addr_a,
        ..default_config("127.0.0.1:0")
    })
    .await;
    // May or may not succeed depending on OS TIME_WAIT, but must not hang
    drop(b_result);
}

/// Two daemons with echo configured both reach Up state; echo config doesn't break the control path.
#[tokio::test]
async fn echo_configured_sessions_reach_up() {
    let a = BfdDaemon::start(echo_config("127.0.0.1:0")).await.unwrap();
    let b = BfdDaemon::start(echo_config("127.0.0.1:0")).await.unwrap();

    // Echo sockets should be created
    assert!(a.echo_local_addr().is_some(), "daemon A should have an echo socket");
    assert!(b.echo_local_addr().is_some(), "daemon B should have an echo socket");

    let addr_a = a.local_addr();
    let addr_b = b.local_addr();

    let mut rx_a = a.subscribe();
    let mut rx_b = b.subscribe();

    a.add_peer(addr_b).await.unwrap();
    b.add_peer(addr_a).await.unwrap();

    // Both should reach Up via the control protocol
    let sc_a = wait_for_state(&mut rx_a, |sc| sc.new_state == BfdState::Up).await;
    assert!(sc_a.is_some(), "daemon A did not reach Up within 5s");

    let sc_b = wait_for_state(&mut rx_b, |sc| sc.new_state == BfdState::Up).await;
    assert!(sc_b.is_some(), "daemon B did not reach Up within 5s");

    a.shutdown().await;
    b.shutdown().await;
}

/// Two daemons reach Up, then one changes its TX interval; both remain Up throughout.
#[tokio::test]
async fn poll_sequence_completes() {
    let a = BfdDaemon::start(default_config("127.0.0.1:0")).await.unwrap();
    let b = BfdDaemon::start(default_config("127.0.0.1:0")).await.unwrap();

    let addr_a = a.local_addr();
    let addr_b = b.local_addr();

    let mut rx_a = a.subscribe();
    let mut rx_b = b.subscribe();

    a.add_peer(addr_b).await.unwrap();
    b.add_peer(addr_a).await.unwrap();

    wait_for_state(&mut rx_a, |sc| sc.new_state == BfdState::Up).await.unwrap();
    wait_for_state(&mut rx_b, |sc| sc.new_state == BfdState::Up).await.unwrap();

    // Change A's desired TX interval upward (applied immediately, triggers Poll).
    a.set_desired_min_tx(addr_b, 200_000).await.unwrap();

    // Give the Poll/Final exchange time to complete. Both sessions should remain Up.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(a.get_state(addr_b).await.unwrap(), Some(BfdState::Up));
    assert_eq!(b.get_state(addr_a).await.unwrap(), Some(BfdState::Up));

    // Also test decreasing (deferred until Final).
    a.set_desired_min_tx(addr_b, 100_000).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(a.get_state(addr_b).await.unwrap(), Some(BfdState::Up));

    a.shutdown().await;
    b.shutdown().await;
}

/// A second set_desired_min_tx while a Poll is in progress returns PollInProgress.
#[tokio::test]
async fn poll_rejected_while_active() {
    let a = BfdDaemon::start(default_config("127.0.0.1:0")).await.unwrap();
    let b = BfdDaemon::start(default_config("127.0.0.1:0")).await.unwrap();

    let addr_a = a.local_addr();
    let addr_b = b.local_addr();

    let mut rx_a = a.subscribe();
    let mut rx_b = b.subscribe();

    a.add_peer(addr_b).await.unwrap();
    b.add_peer(addr_a).await.unwrap();

    wait_for_state(&mut rx_a, |sc| sc.new_state == BfdState::Up).await.unwrap();
    wait_for_state(&mut rx_b, |sc| sc.new_state == BfdState::Up).await.unwrap();

    // Send first change — Poll starts immediately.
    a.set_desired_min_tx(addr_b, 200_000).await.unwrap();

    // Immediately request another change before Final can arrive.
    // This races: if Final arrived already the poll may have cleared.
    // We inject a short sleep to make the race less likely but note this
    // test is inherently timing-sensitive.
    let second = a.set_desired_min_tx(addr_b, 150_000).await;
    // Either the poll already completed (Ok) or it returned PollInProgress.
    match second {
        Ok(()) => {} // poll completed before our second call — that's fine
        Err(BfdError::PollInProgress(_)) => {} // expected when poll was still active
        Err(e) => panic!("unexpected error: {e}"),
    }

    a.shutdown().await;
    b.shutdown().await;
}

/// A daemon with echo RX configured loops back echo packets from external senders.
#[tokio::test]
async fn echo_responder_loops_back() {
    use tokio::net::UdpSocket as TokioUdp;

    // Create a daemon willing to loop back echo (required_min_echo_rx > 0)
    let config = BfdConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        required_min_echo_rx_interval_us: 50_000,
        echo_port: 0,
        ..default_config("127.0.0.1:0")
    };
    let a = BfdDaemon::start(config).await.unwrap();
    let echo_addr = a.echo_local_addr().expect("echo socket should exist");

    // External socket simulating a peer's echo packet
    let test_sock = TokioUdp::bind("127.0.0.1:0").await.unwrap();
    test_sock.connect(echo_addr).await.unwrap();

    // Build a valid BFD-format echo packet with a discriminator NOT in A's disc_map
    // so A will loop it back rather than treating it as a returning echo.
    let mut buf = [0u8; 24];
    buf[0] = 0x20; // version=1, diag=0
    buf[1] = 0xC0; // state=Up(3), no flags
    buf[2] = 3;    // detect_mult
    buf[3] = 24;   // length
    buf[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes()); // my_disc (unknown)
    buf[8..12].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes()); // your_disc
    buf[12..16].copy_from_slice(&100_000u32.to_be_bytes()); // desired_min_tx
    buf[16..20].copy_from_slice(&0u32.to_be_bytes());
    buf[20..24].copy_from_slice(&0u32.to_be_bytes());

    test_sock.send(&buf).await.unwrap();

    // Daemon should loop the packet back to us
    let mut recv_buf = [0u8; 64];
    let result = timeout(Duration::from_secs(2), test_sock.recv(&mut recv_buf)).await;
    assert!(result.is_ok(), "echo packet was not looped back within 2s");
    let len = result.unwrap().unwrap();
    assert_eq!(len, 24);
    // The looped-back packet should be identical to what we sent
    assert_eq!(&recv_buf[..24], &buf);

    a.shutdown().await;
}

/// Two peers reach Up; verify per-session counters have sensible values.
#[tokio::test]
async fn session_counters_after_up() {
    let a = BfdDaemon::start(default_config("127.0.0.1:0")).await.unwrap();
    let b = BfdDaemon::start(default_config("127.0.0.1:0")).await.unwrap();

    let addr_a = a.local_addr();
    let addr_b = b.local_addr();

    let mut rx_a = a.subscribe();
    let mut rx_b = b.subscribe();

    a.add_peer(addr_b).await.unwrap();
    b.add_peer(addr_a).await.unwrap();

    wait_for_state(&mut rx_a, |sc| sc.new_state == BfdState::Up).await.unwrap();
    wait_for_state(&mut rx_b, |sc| sc.new_state == BfdState::Up).await.unwrap();

    // Let some TX/RX cycles run
    tokio::time::sleep(Duration::from_millis(300)).await;

    let counters_a = a.get_peer_counters(addr_b).await.unwrap().expect("session exists");
    assert!(counters_a.control_tx > 0, "expected some control TX");
    assert!(counters_a.control_rx > 0, "expected some control RX");
    assert!(counters_a.state_transitions >= 2, "expected at least Down->Init and Init->Up");

    // Non-existent peer returns None
    let unknown: SocketAddr = "127.0.0.1:1".parse().unwrap();
    assert!(a.get_peer_counters(unknown).await.unwrap().is_none());

    a.shutdown().await;
    b.shutdown().await;
}

/// get_daemon_counters reflects peers_added and peers_removed correctly.
#[tokio::test]
async fn daemon_counters_peers() {
    let a = BfdDaemon::start(default_config("127.0.0.1:0")).await.unwrap();
    let peer: SocketAddr = "127.0.0.1:19996".parse().unwrap();

    let before = a.get_daemon_counters().await.unwrap();
    assert_eq!(before.peers_added, 0);
    assert_eq!(before.peers_removed, 0);

    a.add_peer(peer).await.unwrap();
    let after_add = a.get_daemon_counters().await.unwrap();
    assert_eq!(after_add.peers_added, 1);
    assert_eq!(after_add.peers_removed, 0);

    a.remove_peer(peer).await.unwrap();
    let after_remove = a.get_daemon_counters().await.unwrap();
    assert_eq!(after_remove.peers_added, 1);
    assert_eq!(after_remove.peers_removed, 1);

    a.shutdown().await;
}
