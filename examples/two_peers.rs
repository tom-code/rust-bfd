//! Two single-hop BFD peers on 127.0.0.1:13784 and :13785, brought Up then torn down.
//! Run with: `cargo run --example two_peers`
use std::time::Duration;
use bfd::{BfdConfig, BfdDaemon};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("bfd=info".parse().unwrap()),
        )
        .init();

    let config_a = BfdConfig {
        listen_addr: "127.0.0.1:13784".parse().unwrap(),
        desired_min_tx_interval_us: 250_000,
        required_min_rx_interval_us: 250_000,
        detect_mult: 3,
        ..Default::default()
    };

    let config_b = BfdConfig {
        listen_addr: "127.0.0.1:13785".parse().unwrap(),
        desired_min_tx_interval_us: 250_000,
        required_min_rx_interval_us: 250_000,
        detect_mult: 3,
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
    daemon_a.add_peer("127.0.0.1:13785".parse().unwrap()).await?;
    daemon_b.add_peer("127.0.0.1:13784".parse().unwrap()).await?;

    println!("Waiting for BFD sessions to come Up...");

    let addr_a: std::net::SocketAddr = "127.0.0.1:13784".parse().unwrap();
    let addr_b: std::net::SocketAddr = "127.0.0.1:13785".parse().unwrap();

    // Let sessions run for 3 seconds while Up, then snapshot counters before teardown
    tokio::time::sleep(Duration::from_secs(3)).await;

    println!("\n--- Counters while Up ---");
    if let Ok(Some(c)) = daemon_a.get_peer_counters(addr_b).await {
        println!("[A] peer={addr_b} tx={} rx={} transitions={} send_errors={}",
            c.control_tx, c.control_rx, c.state_transitions, c.send_errors);
    }
    if let Ok(dc) = daemon_a.get_daemon_counters().await {
        println!("[A] daemon peers_added={} peers_removed={} discarded={}",
            dc.peers_added, dc.peers_removed, dc.control_rx_discarded);
    }
    if let Ok(Some(c)) = daemon_b.get_peer_counters(addr_a).await {
        println!("[B] peer={addr_a} tx={} rx={} transitions={} send_errors={}",
            c.control_tx, c.control_rx, c.state_transitions, c.send_errors);
    }
    if let Ok(dc) = daemon_b.get_daemon_counters().await {
        println!("[B] daemon peers_added={} peers_removed={} discarded={}",
            dc.peers_added, dc.peers_removed, dc.control_rx_discarded);
    }

    daemon_a.remove_peer(addr_b).await?;
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Remove peers (triggers AdminDown → Down transitions)
    println!("\nRemoving peers...");
    //daemon_a.remove_peer(addr_b).await?;
    daemon_b.remove_peer(addr_a).await?;

    // Brief pause to let the final state propagate
    tokio::time::sleep(Duration::from_millis(500)).await;

    daemon_a.shutdown().await;
    daemon_b.shutdown().await;

    handle_a.abort();
    handle_b.abort();

    println!("Done.");
    Ok(())
}
