//! Two multi-hop BFD peers on 127.0.0.1:14784 and :14785 (max_hops=5).
//! Run with: `cargo run --example multihop`
use std::time::Duration;
use bfd::{BfdConfig, BfdDaemon, BfdMode};
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("bfd=info".parse().unwrap()),
        )
        .init();

    let config_a = BfdConfig {
        listen_addr: "127.0.0.1:14784".parse().unwrap(),
        desired_min_tx_interval_us: 250_000,
        required_min_rx_interval_us: 250_000,
        detect_mult: 3,
        mode: BfdMode::MultiHop { max_hops: 5 },
        ..Default::default()
    };

    let config_b = BfdConfig {
        listen_addr: "127.0.0.1:14785".parse().unwrap(),
        desired_min_tx_interval_us: 250_000,
        required_min_rx_interval_us: 250_000,
        detect_mult: 3,
        mode: BfdMode::MultiHop { max_hops: 5 },
        ..Default::default()
    };

    let daemon_a = BfdDaemon::start(config_a).await?;
    let daemon_b = BfdDaemon::start(config_b).await?;

    // Subscribe to state changes before adding peers
    let mut sub_a = daemon_a.subscribe();
    let mut sub_b = daemon_b.subscribe();

    // Spawn tasks to print state changes from each daemon
    let handle_a = tokio::spawn(async move {
        while let Ok(change) = sub_a.recv().await {
            println!(
                "[A] peer={} {:?} -> {:?} (diag: {:?})",
                change.peer, change.old_state, change.new_state, change.diagnostic
            );
        }
    });

    let handle_b = tokio::spawn(async move {
        while let Ok(change) = sub_b.recv().await {
            println!(
                "[B] peer={} {:?} -> {:?} (diag: {:?})",
                change.peer, change.old_state, change.new_state, change.diagnostic
            );
        }
    });

    // Each daemon adds the other as peer
    daemon_a.add_peer("127.0.0.1:14785".parse().unwrap()).await?;
    daemon_b.add_peer("127.0.0.1:14784".parse().unwrap()).await?;

    info!("Both peers added, running for 10 seconds...");
    println!("Waiting for BFD multihop sessions to come Up...");

    // Run for 10 seconds
    tokio::time::sleep(Duration::from_secs(10)).await;

    // Remove peers (will trigger Down transitions)
    println!("Removing peers...");
    daemon_a.remove_peer("127.0.0.1:14785".parse().unwrap()).await?;
    daemon_b.remove_peer("127.0.0.1:14784".parse().unwrap()).await?;

    // Brief pause to let the final state propagate
    tokio::time::sleep(Duration::from_millis(500)).await;

    daemon_a.shutdown().await;
    daemon_b.shutdown().await;

    handle_a.abort();
    handle_b.abort();

    println!("Done.");
    Ok(())
}
