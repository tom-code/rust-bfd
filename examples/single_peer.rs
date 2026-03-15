//! Single-peer BFD daemon with CLI arguments. Useful for testing against a real or external peer.
//! Run with: `cargo run --example single_peer -- --help`
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{bail, Context};
use bfd::{BfdConfig, BfdDaemon, BfdMode};
use clap::Parser;
use tracing::info;

/// BFD mode: "singlehop" or "multihop:<max_hops>"
#[derive(Clone, Debug)]
struct ModeArg(BfdMode);

impl FromStr for ModeArg {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.eq_ignore_ascii_case("singlehop") {
            return Ok(ModeArg(BfdMode::SingleHop));
        }
        if let Some(hops) = s.strip_prefix("multihop:") {
            let n: u8 = hops
                .parse()
                .map_err(|_| format!("invalid max_hops in '{s}': expected u8"))?;
            if n == 0 {
                return Err("max_hops must be >= 1".to_string());
            }
            return Ok(ModeArg(BfdMode::MultiHop { max_hops: n }));
        }
        Err(format!("unknown mode '{s}': use 'singlehop' or 'multihop:<max_hops>'"))
    }
}

#[derive(Parser, Debug)]
#[command(about = "Single-peer BFD daemon. Press Ctrl+C to stop.")]
struct Args {
    /// Local listen address
    #[arg(short, long, default_value = "0.0.0.0:3784")]
    listen: SocketAddr,

    /// Remote peer address (required)
    #[arg(short, long)]
    peer: SocketAddr,

    /// BFD mode: singlehop (default) or multihop:<max_hops>
    #[arg(short, long, default_value = "singlehop")]
    mode: ModeArg,

    /// Desired min TX interval in milliseconds
    #[arg(long, default_value_t = 250)]
    tx_interval: u32,

    /// Required min RX interval in milliseconds
    #[arg(long, default_value_t = 250)]
    rx_interval: u32,

    /// Detection multiplier
    #[arg(long, default_value_t = 3)]
    detect_mult: u8,

    /// Enable echo mode with this TX interval in milliseconds (omit to disable)
    #[arg(long)]
    echo_tx_interval: Option<u32>,

    /// Echo RX interval in milliseconds (willingness to loop back; 0 = won't loop back)
    #[arg(long, default_value_t = 0)]
    echo_rx_interval: u32,

    /// Control TX interval in milliseconds when echo is active
    #[arg(long, default_value_t = 1000)]
    echo_slow_timer: u32,

    /// UDP port for echo socket
    #[arg(long, default_value_t = 3785)]
    echo_port: u16,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("bfd=debug".parse().unwrap()),
        )
        .init();

    let args = Args::parse();

    let tx_us = args
        .tx_interval
        .checked_mul(1_000)
        .context("--tx-interval overflows u32")?;
    let rx_us = args
        .rx_interval
        .checked_mul(1_000)
        .context("--rx-interval overflows u32")?;

    if tx_us == 0 {
        bail!("--tx-interval must be > 0");
    }
    if rx_us == 0 {
        bail!("--rx-interval must be > 0");
    }
    if args.detect_mult == 0 {
        bail!("--detect-mult must be > 0");
    }

    let echo_tx_us = args
        .echo_tx_interval
        .map(|ms| ms.checked_mul(1_000).context("--echo-tx-interval overflows u32"))
        .transpose()?;
    if echo_tx_us == Some(0) {
        bail!("--echo-tx-interval must be > 0");
    }
    let echo_rx_us = args
        .echo_rx_interval
        .checked_mul(1_000)
        .context("--echo-rx-interval overflows u32")?;
    let echo_slow_us = args
        .echo_slow_timer
        .checked_mul(1_000)
        .context("--echo-slow-timer overflows u32")?;

    let config = BfdConfig {
        listen_addr: args.listen,
        desired_min_tx_interval_us: tx_us,
        required_min_rx_interval_us: rx_us,
        detect_mult: args.detect_mult,
        mode: args.mode.0,
        desired_min_echo_tx_interval_us: echo_tx_us,
        required_min_echo_rx_interval_us: echo_rx_us,
        echo_slow_timer_us: echo_slow_us,
        echo_port: args.echo_port,
    };

    let daemon = BfdDaemon::start(config).await?;
    let local = daemon.local_addr();
    info!("BFD daemon listening on {local}");
    if let Some(echo_addr) = daemon.echo_local_addr() {
        info!("BFD echo socket on {echo_addr}");
    }

    let mut sub = daemon.subscribe();
    let printer = tokio::spawn(async move {
        while let Ok(change) = sub.recv().await {
            println!(
                "peer={} {:?} -> {:?} (diag: {:?})",
                change.peer, change.old_state, change.new_state, change.diagnostic
            );
        }
    });

    daemon.add_peer(args.peer).await?;
    info!("Added peer {}", args.peer);

    tokio::signal::ctrl_c().await.context("ctrl_c failed")?;
    println!("\nShutting down...");

    // Print final counters
    println!("\n--- Final counters ---");
    if let Ok(Some(c)) = daemon.get_peer_counters(args.peer).await {
        println!(
            "peer={} tx={} rx={} rx_err={} echo_tx={} echo_rx={} transitions={} det_timeouts={} echo_det_timeouts={} polls={} send_errors={}",
            args.peer,
            c.control_tx, c.control_rx, c.control_rx_error,
            c.echo_tx, c.echo_rx,
            c.state_transitions, c.detection_timeouts, c.echo_detection_timeouts,
            c.poll_sequences, c.send_errors,
        );
    }
    if let Ok(dc) = daemon.get_daemon_counters().await {
        println!(
            "daemon peers_added={} peers_removed={} udp_rx_errors={} echo_rx_errors={} discarded={} echo_loopback={}",
            dc.peers_added, dc.peers_removed, dc.udp_rx_errors,
            dc.echo_rx_errors, dc.control_rx_discarded, dc.echo_loopback,
        );
    }

    daemon.shutdown().await;
    printer.abort();

    // Brief pause so final state-change prints flush before exit
    tokio::time::sleep(Duration::from_millis(100)).await;
    Ok(())
}
