//! Demonstrates RFC 5880 §6.8.3 Poll/Final parameter negotiation.
//!
//! Two BFD daemons (A and B) come up on loopback, then their TX/RX intervals
//! are changed live via [`BfdDaemon::set_desired_min_tx`] and
//! [`BfdDaemon::set_required_min_rx`].  Watch the log for "poll" and "final"
//! packets and the detection-timer changes that follow each negotiation.
//!
//! Run with:
//!   RUST_LOG=bfd=debug cargo run --example poll_demo
use std::time::Duration;

use anyhow::Context;
use bfd::{BfdConfig, BfdDaemon, BfdState};
use tracing::{info, warn};

/// Wait until the named daemon reports its peer is in `Up` state, or timeout.
async fn wait_for_up(daemon: &BfdDaemon, peer_str: &str, label: &str) -> anyhow::Result<()> {
    let peer: std::net::SocketAddr = peer_str.parse().context("parse peer addr")?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("[{label}] timed out waiting for peer {peer} to reach Up");
        }
        if daemon.get_state(peer).await? == Some(BfdState::Up) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Try a `set_desired_min_tx` call, retrying on `PollInProgress` for up to 5 s.
async fn set_tx(daemon: &BfdDaemon, peer_str: &str, us: u32, label: &str) -> anyhow::Result<()> {
    let peer: std::net::SocketAddr = peer_str.parse().context("parse peer addr")?;
    let ms = us / 1_000;
    info!("[{label}] requesting desired_min_tx → {ms} ms");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match daemon.set_desired_min_tx(peer, us).await {
            Ok(()) => return Ok(()),
            Err(bfd::BfdError::PollInProgress(_)) => {
                if tokio::time::Instant::now() >= deadline {
                    anyhow::bail!("[{label}] set_desired_min_tx timed out waiting for poll to finish");
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => return Err(e.into()),
        }
    }
}

/// Try a `set_required_min_rx` call, retrying on `PollInProgress` for up to 5 s.
async fn set_rx(daemon: &BfdDaemon, peer_str: &str, us: u32, label: &str) -> anyhow::Result<()> {
    let peer: std::net::SocketAddr = peer_str.parse().context("parse peer addr")?;
    let ms = us / 1_000;
    info!("[{label}] requesting required_min_rx → {ms} ms");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match daemon.set_required_min_rx(peer, us).await {
            Ok(()) => return Ok(()),
            Err(bfd::BfdError::PollInProgress(_)) => {
                if tokio::time::Instant::now() >= deadline {
                    anyhow::bail!("[{label}] set_required_min_rx timed out waiting for poll to finish");
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => return Err(e.into()),
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("bfd=debug".parse().unwrap()),
        )
        .init();

    // ── Daemon A: 127.0.0.1:0 (ephemeral) ──────────────────────────────────
    let daemon_a = BfdDaemon::start(BfdConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        desired_min_tx_interval_us: 200_000, // 200 ms
        required_min_rx_interval_us: 200_000,
        detect_mult: 3,
        ..Default::default()
    })
    .await?;
    let addr_a = daemon_a.local_addr().to_string();
    info!("Daemon A listening on {addr_a}");

    // ── Daemon B: 127.0.0.1:0 (ephemeral) ──────────────────────────────────
    let daemon_b = BfdDaemon::start(BfdConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        desired_min_tx_interval_us: 200_000,
        required_min_rx_interval_us: 200_000,
        detect_mult: 3,
        ..Default::default()
    })
    .await?;
    let addr_b = daemon_b.local_addr().to_string();
    info!("Daemon B listening on {addr_b}");

    // ── Subscribe to state changes ──────────────────────────────────────────
    let mut sub_a = daemon_a.subscribe();
    let mut sub_b = daemon_b.subscribe();

    let label_a = addr_a.clone();
    let label_b = addr_b.clone();

    let h_a = tokio::spawn(async move {
        while let Ok(c) = sub_a.recv().await {
            println!(
                "[A @ {label_a}] peer={} {:?} → {:?} (diag: {:?})",
                c.peer, c.old_state, c.new_state, c.diagnostic
            );
        }
    });
    let h_b = tokio::spawn(async move {
        while let Ok(c) = sub_b.recv().await {
            println!(
                "[B @ {label_b}] peer={} {:?} → {:?} (diag: {:?})",
                c.peer, c.old_state, c.new_state, c.diagnostic
            );
        }
    });

    // ── Establish sessions ──────────────────────────────────────────────────
    daemon_a.add_peer(addr_b.parse().unwrap()).await?;
    daemon_b.add_peer(addr_a.parse().unwrap()).await?;

    println!("\n=== Waiting for both sessions to reach Up ===");
    wait_for_up(&daemon_a, &addr_b, "A").await?;
    wait_for_up(&daemon_b, &addr_a, "B").await?;
    println!("=== Both sessions Up ===\n");

    // Give things a moment to settle.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // ── Round 1: slow A's TX rate down (200 ms → 1 000 ms) ─────────────────
    // Increasing TX → applied immediately + poll started.  B will see slower
    // hellos; after Final, A's TX interval is confirmed at 1 000 ms.
    println!("=== Round 1: A slows TX to 1 000 ms ===");
    set_tx(&daemon_a, &addr_b, 1_000_000, "A").await?;

    // Wait long enough for poll to complete (≤ 3 × detection_time ≈ 3 s).
    tokio::time::sleep(Duration::from_secs(4)).await;
    println!();

    // ── Round 2: speed A's TX back up (1 000 ms → 100 ms) ─────────────────
    // Decreasing TX → deferred until Final is received, then applied.
    println!("=== Round 2: A speeds TX back to 100 ms ===");
    set_tx(&daemon_a, &addr_b, 100_000, "A").await?;

    tokio::time::sleep(Duration::from_secs(4)).await;
    println!();

    // ── Round 3: slow B's required RX (200 ms → 800 ms) ───────────────────
    // Decreasing RX → applied immediately + poll.  A's TX must not exceed 800 ms.
    println!("=== Round 3: B tightens required RX to 800 ms ===");
    set_rx(&daemon_b, &addr_a, 800_000, "B").await?;

    tokio::time::sleep(Duration::from_secs(4)).await;
    println!();

    // ── Round 4: loosen B's RX again (800 ms → 200 ms) ────────────────────
    // Increasing RX → deferred; A may keep its current TX until Final.
    println!("=== Round 4: B loosens required RX back to 200 ms ===");
    set_rx(&daemon_b, &addr_a, 200_000, "B").await?;

    tokio::time::sleep(Duration::from_secs(4)).await;
    println!();

    // ── Round 5: both sides simultaneously change parameters ───────────────
    println!("=== Round 5: simultaneous TX change on both sides ===");
    let (r1, r2) = tokio::join!(
        set_tx(&daemon_a, &addr_b, 500_000, "A"),
        set_tx(&daemon_b, &addr_a, 500_000, "B"),
    );
    if let Err(e) = r1 {
        warn!("A set_tx: {e}");
    }
    if let Err(e) = r2 {
        warn!("B set_tx: {e}");
    }

    tokio::time::sleep(Duration::from_secs(4)).await;
    println!();

    // ── Teardown ────────────────────────────────────────────────────────────
    println!("=== Shutting down ===");
    daemon_a.remove_peer(addr_b.parse().unwrap()).await?;
    daemon_b.remove_peer(addr_a.parse().unwrap()).await?;

    tokio::time::sleep(Duration::from_millis(300)).await;

    daemon_a.shutdown().await;
    daemon_b.shutdown().await;
    h_a.abort();
    h_b.abort();

    println!("Done.");
    Ok(())
}
