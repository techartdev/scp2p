// Copyright (c) 2024-2026 Vanyo Vanev / Tech Art Ltd
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Configuration loading for the standalone relay node.
//!
//! Priority (highest wins):
//!   1. CLI flags
//!   2. TOML config file (`--config` / `SCP2P_CONFIG`)
//!   3. Compiled defaults

use std::{net::SocketAddr, path::PathBuf};

use anyhow::Context as _;
use scp2p_core::BandwidthClass;
use serde::Deserialize;

// ── Resolved config used by the runner ────────────────────────────

/// Fully resolved relay configuration — all fields have concrete values.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Directory for the SQLite state database and any future relay data.
    pub data_dir: PathBuf,

    /// TLS-over-TCP listener address. `None` disables TLS.
    pub bind_tcp: Option<SocketAddr>,

    /// QUIC/UDP listener address. `None` disables QUIC.
    pub bind_quic: Option<SocketAddr>,

    /// Bootstrap peer addresses (raw strings, parsed by runner).
    /// Format: `ip:port` or `tcp://ip:port` or `quic://ip:port`.
    pub bootstrap_peers: Vec<String>,

    /// Addresses included in signed relay announcements.
    /// Defaults to the bind addresses when empty.
    /// Use explicit values when behind DNAT / port-mapping.
    /// Format: `tcp://ip:port` or `quic://ip:port`.
    pub announce_addrs: Vec<String>,

    /// Maximum simultaneous relay tunnels advertised in announcements.
    pub max_tunnels: u16,

    /// Self-reported bandwidth class (Low / Medium / High).
    pub bandwidth_class: BandwidthClass,

    /// How often to re-publish the relay announcement to the DHT (seconds).
    pub announce_interval_secs: u64,

    /// Tracing log level string (e.g. "info", "debug", "warn").
    pub log_level: String,

    /// Log format: "text" (human) or "json" (machine / journald).
    pub log_format: String,
}

// ── On-disk TOML format ────────────────────────────────────────────

/// All fields optional — they overlay the defaults.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    pub data_dir: Option<String>,
    pub bind_tcp: Option<String>,
    pub bind_quic: Option<String>,
    pub bootstrap_peers: Option<Vec<String>>,
    pub announce_addrs: Option<Vec<String>>,
    pub max_tunnels: Option<u16>,
    /// "low" | "medium" | "high"
    pub bandwidth_class: Option<String>,
    pub announce_interval_secs: Option<u64>,
    pub log_level: Option<String>,
    pub log_format: Option<String>,
}

// ── Builder ────────────────────────────────────────────────────────

/// Merges a file config and CLI overrides into a `RelayConfig`.
///
/// All `cli_*` parameters are `Option` — `None` means "not supplied on CLI".
#[allow(clippy::too_many_arguments)]
pub fn build_config(
    file: FileConfig,
    cli_data_dir: Option<PathBuf>,
    cli_bind_tcp: Option<String>,
    cli_bind_quic: Option<String>,
    cli_bootstrap: Vec<String>,
    cli_announce_addrs: Vec<String>,
    cli_max_tunnels: Option<u16>,
    cli_bandwidth_class: Option<String>,
    cli_announce_interval_secs: Option<u64>,
    cli_log_level: Option<String>,
    cli_log_format: Option<String>,
) -> anyhow::Result<RelayConfig> {
    // data_dir
    let data_dir = cli_data_dir.unwrap_or_else(|| {
        file.data_dir
            .as_deref()
            .map(PathBuf::from)
            .unwrap_or_else(default_data_dir)
    });

    // bind_tcp ("" means disabled)
    let bind_tcp_str = cli_bind_tcp
        .or(file.bind_tcp)
        .unwrap_or_else(|| "0.0.0.0:7001".to_string());
    let bind_tcp = parse_optional_addr(&bind_tcp_str, "bind_tcp")?;

    // bind_quic ("" means disabled)
    let bind_quic_str = cli_bind_quic
        .or(file.bind_quic)
        .unwrap_or_else(|| "0.0.0.0:7000".to_string());
    let bind_quic = parse_optional_addr(&bind_quic_str, "bind_quic")?;

    // bootstrap peers — CLI overrides file completely when non-empty
    let bootstrap_peers = if !cli_bootstrap.is_empty() {
        cli_bootstrap
    } else {
        file.bootstrap_peers.unwrap_or_default()
    };

    // announce addrs — CLI overrides file when non-empty
    let announce_addrs = if !cli_announce_addrs.is_empty() {
        cli_announce_addrs
    } else {
        file.announce_addrs.unwrap_or_default()
    };

    // max_tunnels
    let max_tunnels = cli_max_tunnels.or(file.max_tunnels).unwrap_or(64);

    // bandwidth_class
    let bc_str = cli_bandwidth_class
        .or(file.bandwidth_class)
        .unwrap_or_else(|| "medium".to_string());
    let bandwidth_class = parse_bandwidth_class(&bc_str)?;

    // announce_interval_secs
    let announce_interval_secs = cli_announce_interval_secs
        .or(file.announce_interval_secs)
        .unwrap_or(1800);

    // log_level
    let log_level = cli_log_level
        .or(file.log_level)
        .unwrap_or_else(|| "info".to_string());

    // log_format
    let log_format = cli_log_format
        .or(file.log_format)
        .unwrap_or_else(|| "text".to_string());

    Ok(RelayConfig {
        data_dir,
        bind_tcp,
        bind_quic,
        bootstrap_peers,
        announce_addrs,
        max_tunnels,
        bandwidth_class,
        announce_interval_secs,
        log_level,
        log_format,
    })
}

// ── Helpers ────────────────────────────────────────────────────────

/// Returns `None` for an empty string (disables the listener), otherwise
/// parses it as a `SocketAddr`.
fn parse_optional_addr(s: &str, field: &str) -> anyhow::Result<Option<SocketAddr>> {
    if s.is_empty() {
        return Ok(None);
    }
    let addr: SocketAddr = s
        .parse()
        .with_context(|| format!("{field}: invalid socket address \"{s}\""))?;
    Ok(Some(addr))
}

/// Parses "low" | "medium" | "high" (case-insensitive) into a `BandwidthClass`.
pub fn parse_bandwidth_class(s: &str) -> anyhow::Result<BandwidthClass> {
    match s.to_lowercase().as_str() {
        "low" => Ok(BandwidthClass::Low),
        "medium" | "med" => Ok(BandwidthClass::Medium),
        "high" => Ok(BandwidthClass::High),
        _ => anyhow::bail!("unknown bandwidth-class \"{s}\"; expected low | medium | high"),
    }
}

/// Returns the platform-appropriate default data directory for the relay.
pub fn default_data_dir() -> PathBuf {
    // Windows: %APPDATA%\scp2p-relay
    #[cfg(target_os = "windows")]
    if let Some(appdata) = std::env::var_os("APPDATA") {
        return PathBuf::from(appdata).join("scp2p-relay");
    }
    // macOS: ~/Library/Application Support/scp2p-relay
    #[cfg(target_os = "macos")]
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("scp2p-relay");
    }
    // Linux / other Unix: ~/.local/share/scp2p-relay
    #[cfg(all(unix, not(target_os = "macos")))]
    if let Some(xdg_data) = std::env::var_os("XDG_DATA_HOME") {
        return PathBuf::from(xdg_data).join("scp2p-relay");
    }
    #[cfg(unix)]
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("scp2p-relay");
    }
    // Final fallback
    PathBuf::from("scp2p-relay-data")
}

/// Load and parse a TOML config file from disk.
///
/// Returns `FileConfig::default()` when the path is `None` so the rest of
/// the merge logic can be identical.
pub fn load_file_config(path: Option<&std::path::Path>) -> anyhow::Result<FileConfig> {
    let Some(p) = path else {
        return Ok(FileConfig::default());
    };
    let raw =
        std::fs::read_to_string(p).with_context(|| format!("read config file: {}", p.display()))?;
    let cfg: FileConfig =
        toml::from_str(&raw).with_context(|| format!("parse config file: {}", p.display()))?;
    Ok(cfg)
}
