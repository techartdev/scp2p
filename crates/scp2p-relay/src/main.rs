// Copyright (c) 2024-2026 Vanyo Vanev / Tech Art Ltd
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! `scp2p-relay` — standalone relay node for the SCP2P network.
//!
//! This binary starts a relay-only SCP2P node: it accepts tunnel
//! registrations from peers behind NAT, forwards data between them,
//! and announces itself to the DHT so clients can discover it.
//!
//! # Quick start
//!
//! ```text
//! # Minimal — listens on default ports, no bootstrap peers:
//! scp2p-relay
//!
//! # With bootstrap peers and a DNAT public address:
//! scp2p-relay \
//!     --bootstrap 1.2.3.4:7001 \
//!     --announce  tcp://5.6.7.8:7001 \
//!     --announce  quic://5.6.7.8:7000
//!
//! # Using a TOML config file:
//! scp2p-relay --config /etc/scp2p-relay/relay.toml
//! ```

use std::path::PathBuf;

use clap::Parser;

mod config;
mod persist;
mod runner;

use config::{build_config, load_file_config};
use persist::install_service;
use runner::run;

// ── CLI definition ─────────────────────────────────────────────────

/// SCP2P standalone relay node.
///
/// Relays bridge peers that cannot reach each other directly (NAT, firewall).
/// The node announces itself to the distributed hash table so clients can
/// discover it automatically.
///
/// All flags can also be set via environment variables (shown in help) or a
/// TOML config file passed with `--config`.
#[derive(Parser, Debug)]
#[command(
    name = "scp2p-relay",
    version,
    about = "SCP2P standalone relay node — bridges peers behind NAT",
    long_about = None,
)]
struct Cli {
    /// Path to a TOML config file.  CLI flags override file values.
    ///
    /// See the project README for the full field list.
    #[arg(long, short = 'c', env = "SCP2P_CONFIG", value_name = "FILE")]
    config: Option<PathBuf>,

    /// Directory for storing relay state (node identity, peer database).
    ///
    /// Defaults: Linux `~/.local/share/scp2p-relay`,
    ///           macOS `~/Library/Application Support/scp2p-relay`,
    ///           Windows `%APPDATA%\\scp2p-relay`.
    #[arg(long, env = "SCP2P_DATA_DIR", value_name = "DIR")]
    data_dir: Option<PathBuf>,

    /// TCP address for the TLS-over-TCP listener.
    ///
    /// Pass an empty string (`--bind-tcp ""`) to disable TLS entirely.
    /// Default: `0.0.0.0:7001`.
    #[arg(long, env = "SCP2P_BIND_TCP", value_name = "IP:PORT")]
    bind_tcp: Option<String>,

    /// UDP address for the QUIC listener.
    ///
    /// Pass an empty string (`--bind-quic ""`) to disable QUIC.
    /// Default: `0.0.0.0:7000`.
    #[arg(long, env = "SCP2P_BIND_QUIC", value_name = "IP:PORT")]
    bind_quic: Option<String>,

    /// Bootstrap peer address (repeatable).
    ///
    /// Format: `ip:port`, `tcp://ip:port`, or `quic://ip:port`.
    /// Can be comma-separated when using the env var.
    ///
    /// Example: `--bootstrap 1.2.3.4:7001 --bootstrap 5.6.7.8:7001`
    #[arg(
        long,
        short = 'b',
        env = "SCP2P_BOOTSTRAP",
        value_name = "ADDR",
        value_delimiter = ',',
        num_args = 0..
    )]
    bootstrap: Vec<String>,

    /// Public address to include in relay announcements (repeatable).
    ///
    /// Use this when the relay is behind DNAT / port-mapping and the bind
    /// address differs from the externally reachable address.
    ///
    /// Format: `tcp://ip:port` or `quic://ip:port`.
    /// Defaults to the bind addresses when omitted.
    #[arg(
        long,
        short = 'a',
        env = "SCP2P_ANNOUNCE_ADDRS",
        value_name = "ADDR",
        value_delimiter = ',',
        num_args = 0..
    )]
    announce: Vec<String>,

    /// Maximum simultaneous relay tunnels (advertised in DHT announcements).
    /// Default: 64.
    #[arg(long, env = "SCP2P_MAX_TUNNELS", value_name = "N")]
    max_tunnels: Option<u16>,

    /// Self-reported bandwidth class: `low`, `medium`, or `high`.
    /// Clients use this as a selection hint.  Default: `medium`.
    #[arg(long, env = "SCP2P_BANDWIDTH_CLASS", value_name = "CLASS")]
    bandwidth_class: Option<String>,

    /// How often to re-publish the relay announcement to the DHT, in seconds.
    /// Default: 1800 (30 minutes).  Minimum: 60.
    #[arg(long, env = "SCP2P_ANNOUNCE_INTERVAL_SECS", value_name = "SECS")]
    announce_interval_secs: Option<u64>,

    /// Logging level: `trace`, `debug`, `info`, `warn`, or `error`.
    /// Default: `info`.
    #[arg(long, env = "SCP2P_LOG_LEVEL", value_name = "LEVEL")]
    log_level: Option<String>,

    /// Log output format: `text` (human-readable) or `json` (for journald /
    /// log aggregators).  Default: `text`.
    #[arg(long, env = "SCP2P_LOG_FORMAT", value_name = "FORMAT")]
    log_format: Option<String>,

    /// Install scp2p-relay as a persistent background service and exit.
    ///
    /// On Linux this writes a systemd unit to
    /// `/etc/systemd/system/scp2p-relay.service`, runs
    /// `systemctl daemon-reload` and `systemctl enable --now scp2p-relay`.
    ///
    /// On macOS this writes a launchd plist to
    /// `/Library/LaunchDaemons/com.scp2p.relay.plist` and calls
    /// `launchctl bootstrap`.
    ///
    /// On Windows this registers the binary with the Windows Service Manager
    /// via `sc.exe` and starts it immediately.
    ///
    /// All other flags you pass alongside `--persist` are baked into the
    /// installed service command (e.g. `--bootstrap`, `--announce`).
    /// Run as root / Administrator.
    #[arg(long)]
    persist: bool,
}

// ── Entry point ────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Capture raw args *before* clap consumes them so --persist can
    // reconstruct the exact service command line.
    let raw_args: Vec<String> = std::env::args().skip(1).collect();

    let cli = Cli::parse();

    if cli.persist {
        return install_service(&raw_args);
    }

    // Load TOML config file (if given), then overlay CLI values.
    let file_cfg = load_file_config(cli.config.as_deref())?;
    let cfg = build_config(
        file_cfg,
        cli.data_dir,
        cli.bind_tcp,
        cli.bind_quic,
        cli.bootstrap,
        cli.announce,
        cli.max_tunnels,
        cli.bandwidth_class,
        cli.announce_interval_secs,
        cli.log_level.clone(),
        cli.log_format.clone(),
    )?;

    // Initialise logging using the resolved level and format.
    init_logging(&cfg.log_level, &cfg.log_format)?;

    // Delegate to the runner.
    run(cfg).await
}

// ── Logging setup ──────────────────────────────────────────────────

fn init_logging(level: &str, format: &str) -> anyhow::Result<()> {
    use tracing_subscriber::{EnvFilter, fmt, prelude::*};

    let filter = EnvFilter::try_new(level)
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();

    match format.to_lowercase().as_str() {
        "json" => {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer().json())
                .init();
        }
        _ => {
            tracing_subscriber::registry()
                .with(filter)
                .with(fmt::layer())
                .init();
        }
    }

    Ok(())
}
