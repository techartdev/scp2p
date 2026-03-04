// Copyright (c) 2024-2026 Vanyo Vanev / Tech Art Ltd
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Core relay runner.
//!
//! Call [`run`] to start the relay node.  The function blocks until a
//! graceful shutdown signal (Ctrl-C / SIGTERM) is received, then returns.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Context as _;
use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use scp2p_core::{
    BoxedStream, Capabilities, DirectRequestTransport, Node, NodeConfig, NodeHandle, PeerAddr,
    PeerConnector, RelayCapacity, SqliteStore, TransportProtocol, build_tls_server_handle,
    quic_connect_bi_session_insecure, start_quic_server, tls_connect_session_insecure,
};
use tracing::{info, warn};

use crate::config::RelayConfig;

// ── Session connector ──────────────────────────────────────────────

/// Minimal outbound-connection helper used for DHT and announcement publishing.
struct RelayConnector {
    signing_key: SigningKey,
    capabilities: Capabilities,
}

#[async_trait]
impl PeerConnector for RelayConnector {
    async fn connect(&self, peer: &PeerAddr) -> anyhow::Result<BoxedStream> {
        let remote = SocketAddr::new(peer.ip, peer.port);
        let expected = peer.pubkey_hint;
        match peer.transport {
            TransportProtocol::Tcp => {
                let (stream, _) = tls_connect_session_insecure(
                    remote,
                    &self.signing_key,
                    self.capabilities.clone(),
                    expected,
                )
                .await?;
                Ok(Box::new(stream) as BoxedStream)
            }
            TransportProtocol::Quic => {
                let session = quic_connect_bi_session_insecure(
                    remote,
                    &self.signing_key,
                    self.capabilities.clone(),
                    expected,
                )
                .await?;
                Ok(Box::new(session.stream) as BoxedStream)
            }
        }
    }
}

// ── Public entry-point ─────────────────────────────────────────────

/// Start the relay node and block until shutdown.
///
/// The function:
/// 1. Opens (or creates) the SQLite state database.
/// 2. Builds a node with `relay = true` capabilities.
/// 3. Starts TLS-over-TCP and/or QUIC listeners.
/// 4. Publishes a self-signed relay announcement to the DHT immediately,
///    then on a configurable interval.
/// 5. Runs the DHT republish loop to keep the relay visible in the DHT.
/// 6. Waits for Ctrl-C / SIGTERM, then returns cleanly.
pub async fn run(config: RelayConfig) -> anyhow::Result<()> {
    // ── 1. Storage ────────────────────────────────────────────────
    std::fs::create_dir_all(&config.data_dir)
        .with_context(|| format!("create data directory: {}", config.data_dir.display()))?;
    let db_path = config.data_dir.join("relay.db");
    let store = SqliteStore::open(&db_path)
        .with_context(|| format!("open state database: {}", db_path.display()))?;
    info!(db = %db_path.display(), "state database opened");

    // ── 2. Node ───────────────────────────────────────────────────
    let node_config = NodeConfig {
        bind_tcp: config.bind_tcp,
        bind_quic: config.bind_quic,
        capabilities: Capabilities {
            dht: true,
            relay: true,
            store: false,
            content_seed: false,
            mobile_light: false,
            ..Default::default()
        },
        bootstrap_peers: config.bootstrap_peers.clone(),
        ..NodeConfig::default()
    };

    // SqliteStore::open already returns Arc<SqliteStore>; coerce to Arc<dyn Store>.
    let store: Arc<dyn scp2p_core::Store> = store;
    let handle: NodeHandle = Node::start_with_store(node_config, store)
        .await
        .context("start node")?;

    // Stable node identity — persisted so the relay keeps the same pubkey
    // across restarts (essential for reputation and pinned-key clients).
    let signing_key = handle
        .ensure_node_identity()
        .await
        .context("ensure node identity")?;

    let relay_caps = Capabilities {
        dht: true,
        relay: true,
        store: false,
        content_seed: false,
        mobile_light: false,
        ..Default::default()
    };

    // ── 3. Listeners ──────────────────────────────────────────────
    let mut listener_count = 0u8;

    if let Some(tcp_addr) = config.bind_tcp {
        let tls_server = Arc::new(build_tls_server_handle().context("build TLS server handle")?);
        let _task = handle.clone().start_tls_dht_service(
            tcp_addr,
            signing_key.clone(),
            relay_caps.clone(),
            tls_server,
        );
        info!(addr = %tcp_addr, "TLS listener started");
        listener_count += 1;
    }

    if let Some(quic_addr) = config.bind_quic {
        let quic_server = start_quic_server(quic_addr).context("start QUIC server")?;
        let _task = handle.clone().start_quic_dht_service(
            quic_server,
            signing_key.clone(),
            relay_caps.clone(),
        );
        info!(addr = %quic_addr, "QUIC listener started");
        listener_count += 1;
    }

    if listener_count == 0 {
        warn!("no listeners configured — relay cannot accept inbound connections");
    }

    // ── 4. Announce addresses ─────────────────────────────────────
    // When no explicit announce addresses are given, fall back to the bind
    // addresses (suitable for a server with a public IP).
    let announce_addrs: Vec<PeerAddr> = if !config.announce_addrs.is_empty() {
        config
            .announce_addrs
            .iter()
            .map(|s| parse_peer_addr(s))
            .collect::<anyhow::Result<_>>()
            .context("parse announce addresses")?
    } else {
        build_default_announce_addrs(config.bind_tcp, config.bind_quic)
    };

    if announce_addrs.is_empty() {
        warn!("no announce addresses — relay will not be discoverable via DHT");
    } else {
        for addr in &announce_addrs {
            info!(announce = %format!("{:?}://{}:{}", addr.transport, addr.ip, addr.port),
                  "relay will announce");
        }
    }

    // ── 5. Bootstrap peers ────────────────────────────────────────
    let bootstrap_peers: Vec<PeerAddr> = config
        .bootstrap_peers
        .iter()
        .map(|s| parse_peer_addr(s))
        .collect::<anyhow::Result<_>>()
        .context("parse bootstrap peers")?;

    // ── 6. Transport (for outbound DHT + announcement publishing) ─
    let transport = Arc::new(DirectRequestTransport::new(RelayConnector {
        signing_key: signing_key.clone(),
        capabilities: relay_caps.clone(),
    }));

    // ── 7. Relay capacity advertised in announcements ─────────────
    let capacity = RelayCapacity {
        max_tunnels: config.max_tunnels,
        bandwidth_class: config.bandwidth_class,
        max_bytes_per_tunnel: None,
    };

    // Announce immediately on startup, then on every interval.
    if !announce_addrs.is_empty() && !bootstrap_peers.is_empty() {
        let h2 = handle.clone();
        let t2 = transport.clone();
        let bp2 = bootstrap_peers.clone();
        let cap2 = capacity.clone();
        let sk2 = signing_key.clone();
        let addrs2 = announce_addrs.clone();
        let interval = Duration::from_secs(config.announce_interval_secs.max(60));

        tokio::spawn(async move {
            loop {
                match publish_announcement(&h2, &sk2, addrs2.clone(), cap2.clone(), &t2, &bp2).await
                {
                    Ok(n) => info!(stores = n, "relay announcement published to DHT"),
                    Err(e) => warn!(err = %e, "relay announcement failed"),
                }
                tokio::time::sleep(interval).await;
            }
        });
    } else if announce_addrs.is_empty() {
        info!("skipping DHT announcements — no announce addresses");
    } else {
        info!("skipping DHT announcements — no bootstrap peers");
    }

    // ── 8. DHT republish loop (keeps relay in DHT routing tables) ─
    if !bootstrap_peers.is_empty() {
        let _task = handle.clone().start_dht_republish_loop(
            transport.clone(),
            bootstrap_peers.clone(),
            Duration::from_secs(300), // every 5 minutes
        );
        info!("DHT republish loop started");
    }

    // ── 9. Print identity info ────────────────────────────────────
    let pubkey = signing_key.verifying_key();
    info!(
        pubkey = hex::encode(pubkey.to_bytes()),
        version = scp2p_core::APP_VERSION,
        "relay node ready"
    );

    // ── 10. Wait for shutdown ─────────────────────────────────────
    shutdown_signal().await;
    info!("shutdown signal received — stopping relay");

    Ok(())
}

// ── Helpers ────────────────────────────────────────────────────────

/// Publish a signed relay announcement to the local cache and to the DHT.
async fn publish_announcement(
    handle: &NodeHandle,
    signing_key: &SigningKey,
    announce_addrs: Vec<PeerAddr>,
    capacity: RelayCapacity,
    transport: &DirectRequestTransport<RelayConnector>,
    bootstrap_peers: &[PeerAddr],
) -> anyhow::Result<usize> {
    let ann = handle
        .publish_relay_announcement(
            signing_key,
            announce_addrs,
            capacity,
            // TTL: use the maximum allowed (6h) so the announcement stays live
            // for the full rendezvous bucket even without a republish.
            scp2p_core::RELAY_ANNOUNCEMENT_MAX_TTL_SECS,
        )
        .await
        .context("build relay announcement")?;

    let n = handle
        .publish_relay_announcement_to_dht(transport, &ann, bootstrap_peers)
        .await
        .context("publish relay announcement to DHT")?;

    Ok(n)
}

/// Parse a peer address string into a `PeerAddr`.
///
/// Accepted formats:
/// - `ip:port` — defaults to TCP
/// - `tcp://ip:port`
/// - `quic://ip:port`
///
/// An optional `@<64-hex-pubkey>` suffix is accepted and parsed as a key hint.
fn parse_peer_addr(s: &str) -> anyhow::Result<PeerAddr> {
    // Strip scheme
    let (transport, rest) = if let Some(r) = s.strip_prefix("tcp://") {
        (TransportProtocol::Tcp, r)
    } else if let Some(r) = s.strip_prefix("quic://") {
        (TransportProtocol::Quic, r)
    } else {
        (TransportProtocol::Tcp, s)
    };

    // Optional @pubkey suffix
    let (addr_part, pubkey_hint) = if let Some((addr, key_hex)) = rest.split_once('@') {
        let key = hex::decode(key_hex)
            .ok()
            .and_then(|b| b.try_into().ok())
            .map(|arr: [u8; 32]| arr);
        (addr, key)
    } else {
        (rest, None)
    };

    let socket: SocketAddr = addr_part
        .parse()
        .with_context(|| format!("invalid peer address: \"{s}\""))?;

    Ok(PeerAddr {
        ip: socket.ip(),
        port: socket.port(),
        transport,
        pubkey_hint,
        relay_via: None,
    })
}

/// Build announce addresses from the bind addresses when the user did not
/// specify explicit announce addresses.
fn build_default_announce_addrs(
    bind_tcp: Option<SocketAddr>,
    bind_quic: Option<SocketAddr>,
) -> Vec<PeerAddr> {
    let mut out = Vec::new();
    if let Some(addr) = bind_tcp {
        out.push(PeerAddr {
            ip: addr.ip(),
            port: addr.port(),
            transport: TransportProtocol::Tcp,
            pubkey_hint: None,
            relay_via: None,
        });
    }
    if let Some(addr) = bind_quic {
        out.push(PeerAddr {
            ip: addr.ip(),
            port: addr.port(),
            transport: TransportProtocol::Quic,
            pubkey_hint: None,
            relay_via: None,
        });
    }
    out
}

/// Wait for Ctrl-C (all platforms) or SIGTERM (Unix only).
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                warn!(err = %e, "failed to register SIGTERM handler; Ctrl-C only");
                tokio::signal::ctrl_c()
                    .await
                    .expect("failed to listen for ctrl-c");
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to listen for ctrl-c");
    }
}
