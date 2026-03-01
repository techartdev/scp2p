// Copyright (c) 2024-2026 Vanyo Vanev / Tech Art Ltd
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
use super::*;
#[allow(deprecated)]
use crate::transport_net::tcp_connect_session;
use crate::{
    capabilities::Capabilities,
    ids::NodeId,
    manifest::ItemV1,
    net_fetch::{BoxedStream, FetchPolicy, PeerConnector, RequestTransport},
    peer::TransportProtocol,
    relay::RelayLimits,
    store::MemoryStore,
    wire::{
        CommunityStatus, Envelope, FLAG_ERROR, FLAG_RESPONSE, FindNode, FindNodeResult,
        FindValueResult, MsgType, Providers, PublicShareList, RelayConnect,
        RelayPayloadKind as WireRelayPayloadKind, RelayRegister, RelayRegistered, RelayStream,
        Store as WireStore, WirePayload,
    },
};
use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

type Handler = Arc<dyn Fn(Envelope) -> anyhow::Result<Envelope> + Send + Sync>;

#[derive(Default)]
struct MockDhtTransport {
    handlers: tokio::sync::RwLock<HashMap<String, Handler>>,
}

impl MockDhtTransport {
    async fn register<F>(&self, peer: &PeerAddr, handler: F)
    where
        F: Fn(Envelope) -> anyhow::Result<Envelope> + Send + Sync + 'static,
    {
        self.handlers
            .write()
            .await
            .insert(peer_key(peer), Arc::new(handler));
    }
}

#[async_trait]
impl RequestTransport for MockDhtTransport {
    async fn request(
        &self,
        peer: &PeerAddr,
        request: Envelope,
        _timeout_dur: Duration,
    ) -> anyhow::Result<Envelope> {
        let handlers = self.handlers.read().await;
        let Some(handler) = handlers.get(&peer_key(peer)) else {
            anyhow::bail!("no mock handler for peer");
        };
        handler(request)
    }
}

struct TcpSessionTransport {
    signing_key: SigningKey,
    capabilities: Capabilities,
}

#[async_trait]
impl PeerConnector for TcpSessionTransport {
    async fn connect(&self, peer: &PeerAddr) -> anyhow::Result<BoxedStream> {
        let remote = std::net::SocketAddr::new(peer.ip, peer.port);
        let expected = peer.pubkey_hint;
        #[allow(deprecated)]
        let (stream, _session) = tcp_connect_session(
            remote,
            &self.signing_key,
            self.capabilities.clone(),
            expected,
        )
        .await?;
        Ok(Box::new(stream) as BoxedStream)
    }
}

// RequestTransport is provided by blanket impl for all PeerConnector types.

/// Create a valid ShareHead DHT key + CBOR value pair for testing.
/// The returned key is `share_head_key(share_id)` and the value is
/// valid CBOR that passes `validate_dht_value_for_known_keyspaces`.
fn make_share_head_kv(share_id: [u8; 32]) -> ([u8; 32], Vec<u8>) {
    use crate::dht_keys::share_head_key;
    use crate::manifest::ShareHead;
    let key = share_head_key(&crate::ids::ShareId(share_id));
    let head = ShareHead {
        share_id,
        latest_seq: 1,
        latest_manifest_id: [0u8; 32],
        updated_at: 1_700_000_000,
        sig: vec![0u8; 64],
    };
    let value = crate::cbor::to_vec(&head).expect("encode share head");
    (key, value)
}

#[tokio::test]
async fn subscribe_roundtrip() {
    let handle = Node::start(NodeConfig::default()).await.expect("start");
    let mut rng = OsRng;
    let key = SigningKey::generate(&mut rng);
    let id = ShareId::from_pubkey(&key.verifying_key());

    handle.subscribe(id).await.expect("subscribe");
    handle.unsubscribe(id).await.expect("unsubscribe");
}

#[tokio::test]
async fn node_retains_runtime_config() {
    let config = NodeConfig {
        bind_quic: "127.0.0.1:7100".parse().ok(),
        bind_tcp: "127.0.0.1:7101".parse().ok(),
        bootstrap_peers: vec!["127.0.0.1:7201".to_string()],
        ..NodeConfig::default()
    };
    let handle = Node::start(config.clone()).await.expect("start");
    let actual = handle.runtime_config().await;
    assert_eq!(actual.bind_quic, config.bind_quic);
    assert_eq!(actual.bind_tcp, config.bind_tcp);
    assert_eq!(actual.bootstrap_peers, config.bootstrap_peers);
}

#[tokio::test]
async fn configured_bootstrap_peers_parse_from_runtime_config() {
    let handle = Node::start(NodeConfig {
        bootstrap_peers: vec!["127.0.0.1:7301".to_string()],
        ..NodeConfig::default()
    })
    .await
    .expect("start");
    let peers = handle
        .configured_bootstrap_peers()
        .await
        .expect("configured peers");
    assert_eq!(peers.len(), 1);
    assert_eq!(
        peers[0].ip,
        "127.0.0.1".parse::<std::net::IpAddr>().expect("ip")
    );
    assert_eq!(peers[0].port, 7301);
    assert_eq!(peers[0].transport, crate::peer::TransportProtocol::Tcp);
}

#[tokio::test]
async fn configured_bootstrap_peers_with_transport_prefix() {
    let handle = Node::start(NodeConfig {
        bootstrap_peers: vec![
            "quic://10.0.0.1:9000".to_string(),
            "tcp://10.0.0.2:9001".to_string(),
            "10.0.0.3:9002".to_string(),
        ],
        ..NodeConfig::default()
    })
    .await
    .expect("start");
    let peers = handle
        .configured_bootstrap_peers()
        .await
        .expect("configured peers");
    assert_eq!(peers.len(), 3);
    assert_eq!(peers[0].transport, crate::peer::TransportProtocol::Quic);
    assert_eq!(peers[0].port, 9000);
    assert_eq!(peers[1].transport, crate::peer::TransportProtocol::Tcp);
    assert_eq!(peers[1].port, 9001);
    // bare address defaults to TCP
    assert_eq!(peers[2].transport, crate::peer::TransportProtocol::Tcp);
    assert_eq!(peers[2].port, 9002);
}

#[tokio::test]
async fn peer_and_subscription_snapshots_are_exposed() {
    let handle = Node::start(NodeConfig::default()).await.expect("start");
    let peer = PeerAddr {
        ip: "10.0.0.99".parse().expect("ip"),
        port: 7001,
        transport: crate::peer::TransportProtocol::Tcp,
        pubkey_hint: None,
        relay_via: None,
    };
    let share_id = ShareId([9u8; 32]);

    handle.record_peer_seen(peer.clone()).await.expect("record");
    handle.subscribe(share_id).await.expect("subscribe");

    let peers = handle.peer_records().await;
    let subscriptions = handle.subscriptions().await;

    assert!(peers.iter().any(|record| record.addr == peer));
    assert!(subscriptions.iter().any(|sub| sub.share_id == share_id.0));
}

#[tokio::test]
async fn pex_offer_roundtrip_into_peer_db() {
    let handle = Node::start(NodeConfig::default()).await.expect("start");
    let offer = PexOffer {
        peers: vec![PeerAddr {
            ip: "10.0.0.2".parse().expect("valid ip"),
            port: 7000,
            transport: TransportProtocol::Quic,
            pubkey_hint: None,
            relay_via: None,
        }],
    };

    let known = handle.apply_pex_offer(offer).await.expect("apply offer");
    assert_eq!(known, 1);

    let response = handle
        .build_pex_offer(PexRequest { max_peers: 64 })
        .await
        .expect("build offer");
    assert_eq!(response.peers.len(), 1);
}

#[tokio::test]
async fn dht_store_find_value_roundtrip() {
    let handle = Node::start(NodeConfig::default()).await.expect("start");
    let (key, value) = make_share_head_kv([3u8; 32]);
    let req = WireStore {
        key,
        value: value.clone(),
        ttl_secs: 60,
    };
    handle.dht_store(req).await.expect("store value");

    let found = handle
        .dht_find_value(key)
        .await
        .expect("query value")
        .expect("value exists");
    assert_eq!(found.value, value);
}

#[tokio::test]
async fn dht_store_rejects_mismatched_share_head_key() {
    let handle = Node::start(NodeConfig::default()).await.expect("start");
    let mut rng = OsRng;
    let share = ShareKeypair::new(SigningKey::generate(&mut rng));
    let head = ShareHead::new_signed(share.share_id().0, 1, [5u8; 32], 1_700_000_000, &share)
        .expect("sign head");
    let err = handle
        .dht_store(WireStore {
            key: [9u8; 32],
            value: crate::cbor::to_vec(&head).expect("encode head"),
            ttl_secs: 60,
        })
        .await
        .expect_err("must reject key mismatch");
    assert!(
        err.to_string()
            .contains("share head value does not match share head key")
    );
}

#[tokio::test]
async fn dht_iterative_find_node_discovers_new_peers() {
    let handle = Node::start(NodeConfig::default()).await.expect("start");
    let transport = MockDhtTransport::default();
    let peer_a = PeerAddr {
        ip: "10.0.0.30".parse().expect("valid ip"),
        port: 7000,
        transport: TransportProtocol::Tcp,
        pubkey_hint: Some([1u8; 32]),
        relay_via: None,
    };
    let peer_b = PeerAddr {
        ip: "10.0.0.31".parse().expect("valid ip"),
        port: 7000,
        transport: TransportProtocol::Tcp,
        pubkey_hint: Some([2u8; 32]),
        relay_via: None,
    };
    let peer_c = PeerAddr {
        ip: "10.0.0.32".parse().expect("valid ip"),
        port: 7000,
        transport: TransportProtocol::Tcp,
        pubkey_hint: Some([3u8; 32]),
        relay_via: None,
    };

    transport
        .register(&peer_a, {
            let peer_b = peer_b.clone();
            move |request| {
                let target = request.decode_typed()?;
                let WirePayload::FindNode(_req) = target else {
                    anyhow::bail!("unexpected request payload");
                };
                Ok(Envelope {
                    r#type: MsgType::FindNode as u16,
                    req_id: request.req_id,
                    flags: FLAG_RESPONSE,
                    payload: crate::cbor::to_vec(&FindNodeResult {
                        peers: vec![peer_b.clone()],
                    })?,
                })
            }
        })
        .await;
    transport
        .register(&peer_b, {
            let peer_c = peer_c.clone();
            move |request| {
                let target = request.decode_typed()?;
                let WirePayload::FindNode(_req) = target else {
                    anyhow::bail!("unexpected request payload");
                };
                Ok(Envelope {
                    r#type: MsgType::FindNode as u16,
                    req_id: request.req_id,
                    flags: FLAG_RESPONSE,
                    payload: crate::cbor::to_vec(&FindNodeResult {
                        peers: vec![peer_c.clone()],
                    })?,
                })
            }
        })
        .await;
    transport
        .register(&peer_c, move |request| {
            let target = request.decode_typed()?;
            let WirePayload::FindNode(_req) = target else {
                anyhow::bail!("unexpected request payload");
            };
            Ok(Envelope {
                r#type: MsgType::FindNode as u16,
                req_id: request.req_id,
                flags: FLAG_RESPONSE,
                payload: crate::cbor::to_vec(&FindNodeResult { peers: vec![] })?,
            })
        })
        .await;

    let target = [9u8; 20];
    let found = handle
        .dht_find_node_iterative(&transport, target, std::slice::from_ref(&peer_a))
        .await
        .expect("iterative find node");
    assert!(found.contains(&peer_b));
    assert!(found.contains(&peer_c));
}

#[tokio::test]
async fn dht_iterative_find_value_returns_and_caches_remote_hit() {
    let handle = Node::start(NodeConfig::default()).await.expect("start");
    let transport = MockDhtTransport::default();
    let (key, expected) = make_share_head_kv([7u8; 32]);
    let peer_a = PeerAddr {
        ip: "10.0.0.40".parse().expect("valid ip"),
        port: 7000,
        transport: TransportProtocol::Tcp,
        pubkey_hint: Some([4u8; 32]),
        relay_via: None,
    };
    let peer_b = PeerAddr {
        ip: "10.0.0.41".parse().expect("valid ip"),
        port: 7000,
        transport: TransportProtocol::Tcp,
        pubkey_hint: Some([5u8; 32]),
        relay_via: None,
    };

    transport
        .register(&peer_a, {
            let peer_b = peer_b.clone();
            move |request| {
                let target = request.decode_typed()?;
                let WirePayload::FindValue(_req) = target else {
                    anyhow::bail!("unexpected request payload");
                };
                Ok(Envelope {
                    r#type: MsgType::FindValue as u16,
                    req_id: request.req_id,
                    flags: FLAG_RESPONSE,
                    payload: crate::cbor::to_vec(&FindValueResult {
                        value: None,
                        closer_peers: vec![peer_b.clone()],
                    })?,
                })
            }
        })
        .await;
    transport
        .register(&peer_b, {
            let value = expected.clone();
            move |request| {
                let target = request.decode_typed()?;
                let WirePayload::FindValue(_req) = target else {
                    anyhow::bail!("unexpected request payload");
                };
                Ok(Envelope {
                    r#type: MsgType::FindValue as u16,
                    req_id: request.req_id,
                    flags: FLAG_RESPONSE,
                    payload: crate::cbor::to_vec(&FindValueResult {
                        value: Some(WireStore {
                            key,
                            value: value.clone(),
                            ttl_secs: 120,
                        }),
                        closer_peers: vec![],
                    })?,
                })
            }
        })
        .await;

    let fetched = handle
        .dht_find_value_iterative(&transport, key, std::slice::from_ref(&peer_a))
        .await
        .expect("iterative find value")
        .expect("value exists");
    assert_eq!(fetched.value, expected);

    let cached = handle
        .dht_find_value(key)
        .await
        .expect("cached query")
        .expect("cached value");
    assert_eq!(cached.value, expected);
}

#[tokio::test]
async fn dht_iterative_find_value_ignores_mismatched_provider_key_value() {
    let handle = Node::start(NodeConfig::default()).await.expect("start");
    let transport = MockDhtTransport::default();
    let key = [31u8; 32];
    let peer = PeerAddr {
        ip: "10.0.0.45".parse().expect("valid ip"),
        port: 7000,
        transport: TransportProtocol::Tcp,
        pubkey_hint: Some([14u8; 32]),
        relay_via: None,
    };

    transport
        .register(&peer, move |request| {
            let target = request.decode_typed()?;
            let WirePayload::FindValue(_req) = target else {
                anyhow::bail!("unexpected request payload");
            };
            let mismatched = Providers {
                content_id: [99u8; 32],
                providers: vec![],
                updated_at: 1_700_000_000,
            };
            Ok(Envelope {
                r#type: MsgType::FindValue as u16,
                req_id: request.req_id,
                flags: FLAG_RESPONSE,
                payload: crate::cbor::to_vec(&FindValueResult {
                    value: Some(WireStore {
                        key,
                        value: crate::cbor::to_vec(&mismatched)?,
                        ttl_secs: 120,
                    }),
                    closer_peers: vec![],
                })?,
            })
        })
        .await;

    let found = handle
        .dht_find_value_iterative(&transport, key, std::slice::from_ref(&peer))
        .await
        .expect("iterative query");
    assert!(found.is_none());
    assert!(
        handle
            .dht_find_value(key)
            .await
            .expect("local query")
            .is_none()
    );
}

#[tokio::test]
async fn dht_iterative_find_share_head_verifies_signature_with_known_pubkey() {
    let handle = Node::start(NodeConfig::default()).await.expect("start");
    let transport = MockDhtTransport::default();
    let mut rng = OsRng;
    let share = ShareKeypair::new(SigningKey::generate(&mut rng));
    let share_id = share.share_id();
    let key = share_head_key(&share_id);
    let peer = PeerAddr {
        ip: "10.0.0.70".parse().expect("valid ip"),
        port: 7000,
        transport: TransportProtocol::Tcp,
        pubkey_hint: Some([15u8; 32]),
        relay_via: None,
    };

    let head =
        ShareHead::new_signed(share_id.0, 3, [42u8; 32], 1_700_000_000, &share).expect("sign head");
    transport
        .register(&peer, move |request| {
            let typed = request.decode_typed()?;
            let WirePayload::FindValue(_) = typed else {
                anyhow::bail!("unexpected payload");
            };
            Ok(Envelope {
                r#type: MsgType::FindValue as u16,
                req_id: request.req_id,
                flags: FLAG_RESPONSE,
                payload: crate::cbor::to_vec(&FindValueResult {
                    value: Some(WireStore {
                        key,
                        value: crate::cbor::to_vec(&head)?,
                        ttl_secs: 60,
                    }),
                    closer_peers: vec![],
                })?,
            })
        })
        .await;

    let found = handle
        .dht_find_share_head_iterative(
            &transport,
            share_id,
            Some(share.verifying_key().to_bytes()),
            std::slice::from_ref(&peer),
        )
        .await
        .expect("iterative share head")
        .expect("head exists");
    assert_eq!(found.latest_seq, 3);
}

#[tokio::test]
async fn dht_iterative_find_share_head_rejects_tampered_signature_with_known_pubkey() {
    let handle = Node::start(NodeConfig::default()).await.expect("start");
    let transport = MockDhtTransport::default();
    let mut rng = OsRng;
    let share = ShareKeypair::new(SigningKey::generate(&mut rng));
    let share_id = share.share_id();
    let key = share_head_key(&share_id);
    let peer = PeerAddr {
        ip: "10.0.0.71".parse().expect("valid ip"),
        port: 7000,
        transport: TransportProtocol::Tcp,
        pubkey_hint: Some([16u8; 32]),
        relay_via: None,
    };

    let mut head =
        ShareHead::new_signed(share_id.0, 4, [43u8; 32], 1_700_000_001, &share).expect("sign head");
    head.sig[0] ^= 0x01;
    transport
        .register(&peer, move |request| {
            let typed = request.decode_typed()?;
            let WirePayload::FindValue(_) = typed else {
                anyhow::bail!("unexpected payload");
            };
            Ok(Envelope {
                r#type: MsgType::FindValue as u16,
                req_id: request.req_id,
                flags: FLAG_RESPONSE,
                payload: crate::cbor::to_vec(&FindValueResult {
                    value: Some(WireStore {
                        key,
                        value: crate::cbor::to_vec(&head)?,
                        ttl_secs: 60,
                    }),
                    closer_peers: vec![],
                })?,
            })
        })
        .await;

    let err = handle
        .dht_find_share_head_iterative(
            &transport,
            share_id,
            Some(share.verifying_key().to_bytes()),
            std::slice::from_ref(&peer),
        )
        .await
        .expect_err("tampered head must fail verification");
    assert!(
        err.to_string().contains("signature")
            || err.to_string().contains("verify")
            || err.to_string().contains("mismatch")
    );
}

#[tokio::test]
async fn tcp_runtime_serves_dht_and_manifest_for_subscription_sync() {
    let server_handle = Node::start(NodeConfig::default())
        .await
        .expect("start server");
    let client_handle = Node::start(NodeConfig::default())
        .await
        .expect("start client");

    let mut rng = OsRng;
    let server_node_key = SigningKey::generate(&mut rng);
    let client_node_key = SigningKey::generate(&mut rng);

    let port_probe = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind probe");
    let bind_addr = port_probe.local_addr().expect("probe addr");
    drop(port_probe);

    let server_task = server_handle.clone().start_tcp_dht_service(
        bind_addr,
        server_node_key.clone(),
        Capabilities::default(),
    );
    tokio::time::sleep(Duration::from_millis(50)).await;

    let share = ShareKeypair::new(SigningKey::generate(&mut rng));
    let manifest = ManifestV1 {
        version: 1,
        share_pubkey: share.verifying_key().to_bytes(),
        share_id: share.share_id().0,
        seq: 1,
        created_at: 1_700_000_000,
        expires_at: None,
        title: Some("runtime".into()),
        description: Some("integration".into()),
        visibility: crate::manifest::ShareVisibility::Private,
        communities: vec![],
        items: vec![ItemV1 {
            content_id: [77u8; 32],
            size: 123,
            name: "runtime-test-item".into(),
            path: None,
            mime: None,
            tags: vec!["runtime".into()],
            chunk_count: 0,
            chunk_list_hash: [0u8; 32],
        }],
        recommended_shares: vec![],
        signature: None,
    };
    server_handle
        .publish_share(manifest, &share)
        .await
        .expect("publish on server");

    client_handle
        .subscribe_with_pubkey(share.share_id(), Some(share.verifying_key().to_bytes()))
        .await
        .expect("subscribe");

    let bootstrap_peer = PeerAddr {
        ip: "127.0.0.1".parse().expect("ip"),
        port: bind_addr.port(),
        transport: TransportProtocol::Tcp,
        pubkey_hint: Some(server_node_key.verifying_key().to_bytes()),
        relay_via: None,
    };
    let transport = TcpSessionTransport {
        signing_key: client_node_key,
        capabilities: Capabilities::default(),
    };
    client_handle
        .sync_subscriptions_over_dht(&transport, std::slice::from_ref(&bootstrap_peer))
        .await
        .expect("sync over dht");

    let hits = client_handle
        .search(SearchQuery {
            text: "runtime-test-item".into(),
        })
        .await
        .expect("search");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].share_id, share.share_id());

    server_task.abort();
}

#[tokio::test]
async fn tcp_runtime_serves_chunk_data_for_network_download() {
    let server_handle = Node::start(NodeConfig::default())
        .await
        .expect("start server");
    let client_handle = Node::start(NodeConfig::default())
        .await
        .expect("start client");

    let mut rng = OsRng;
    let server_node_key = SigningKey::generate(&mut rng);
    let client_node_key = SigningKey::generate(&mut rng);

    let port_probe = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind probe");
    let bind_addr = port_probe.local_addr().expect("probe addr");
    drop(port_probe);

    let server_task = server_handle.clone().start_tcp_dht_service(
        bind_addr,
        server_node_key.clone(),
        Capabilities::default(),
    );
    tokio::time::sleep(Duration::from_millis(50)).await;

    let content_dir = tempfile::tempdir().expect("content tmpdir");
    let payload = vec![7u8; crate::content::CHUNK_SIZE + 42];
    let desc = crate::content::describe_content(&payload);
    let provider_peer = PeerAddr {
        ip: "127.0.0.1".parse().expect("ip"),
        port: bind_addr.port(),
        transport: TransportProtocol::Tcp,
        pubkey_hint: Some(server_node_key.verifying_key().to_bytes()),
        relay_via: None,
    };
    server_handle
        .register_content_from_bytes(provider_peer.clone(), &payload, content_dir.path())
        .await
        .expect("register provider content");

    let share = ShareKeypair::new(SigningKey::generate(&mut rng));
    let manifest = ManifestV1 {
        version: 1,
        share_pubkey: share.verifying_key().to_bytes(),
        share_id: share.share_id().0,
        seq: 1,
        created_at: 1_700_000_100,
        expires_at: None,
        title: Some("runtime-content".into()),
        description: Some("integration".into()),
        visibility: crate::manifest::ShareVisibility::Private,
        communities: vec![],
        items: vec![ItemV1 {
            content_id: desc.content_id.0,
            size: payload.len() as u64,
            name: "runtime-content.bin".into(),
            path: None,
            mime: None,
            tags: vec!["runtime".into(), "content".into()],
            chunk_count: desc.chunk_count,
            chunk_list_hash: desc.chunk_list_hash,
        }],
        recommended_shares: vec![],
        signature: None,
    };
    server_handle
        .publish_share(manifest, &share)
        .await
        .expect("publish");

    client_handle
        .subscribe_with_pubkey(share.share_id(), Some(share.verifying_key().to_bytes()))
        .await
        .expect("subscribe");

    let transport = TcpSessionTransport {
        signing_key: client_node_key,
        capabilities: Capabilities::default(),
    };
    client_handle
        .sync_subscriptions_over_dht(&transport, std::slice::from_ref(&provider_peer))
        .await
        .expect("sync");

    let target = std::env::temp_dir().join(format!(
        "scp2p_net_download_{}.bin",
        now_unix_secs().expect("now")
    ));
    client_handle
        .download_from_peers(
            &transport,
            std::slice::from_ref(&provider_peer),
            desc.content_id.0,
            target.to_str().expect("utf8 path"),
            &FetchPolicy::default(),
            None,
            None,
        )
        .await
        .expect("download over network");

    let read_back = std::fs::read(&target).expect("read target");
    assert_eq!(read_back, payload);
    let _ = std::fs::remove_file(target);

    server_task.abort();
}

#[tokio::test]
async fn multi_node_churn_recovers_sync_search_and_download() {
    let bootstrap_handle = Node::start(NodeConfig::default())
        .await
        .expect("start bootstrap");
    let publisher_store = MemoryStore::new();
    let publisher_handle = Node::start_with_store(NodeConfig::default(), publisher_store)
        .await
        .expect("start publisher");
    let subscriber_handle = Node::start(NodeConfig::default())
        .await
        .expect("start subscriber");

    let mut rng = OsRng;
    let bootstrap_node_key = SigningKey::generate(&mut rng);
    let publisher_node_key = SigningKey::generate(&mut rng);
    let subscriber_node_key = SigningKey::generate(&mut rng);

    let bootstrap_probe = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind bootstrap probe");
    let bootstrap_addr = bootstrap_probe.local_addr().expect("bootstrap probe addr");
    drop(bootstrap_probe);

    let publisher_probe = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind publisher probe");
    let publisher_addr = publisher_probe.local_addr().expect("publisher probe addr");
    drop(publisher_probe);

    let bootstrap_task = bootstrap_handle.clone().start_tcp_dht_service(
        bootstrap_addr,
        bootstrap_node_key,
        Capabilities::default(),
    );
    let mut publisher_task = publisher_handle.clone().start_tcp_dht_service(
        publisher_addr,
        publisher_node_key.clone(),
        Capabilities::default(),
    );
    tokio::time::sleep(Duration::from_millis(50)).await;

    let bootstrap_peer = PeerAddr {
        ip: "127.0.0.1".parse().expect("ip"),
        port: bootstrap_addr.port(),
        transport: TransportProtocol::Tcp,
        pubkey_hint: None,
        relay_via: None,
    };
    let publisher_peer = PeerAddr {
        ip: "127.0.0.1".parse().expect("ip"),
        port: publisher_addr.port(),
        transport: TransportProtocol::Tcp,
        pubkey_hint: Some(publisher_node_key.verifying_key().to_bytes()),
        relay_via: None,
    };
    bootstrap_handle
        .dht_upsert_peer(
            NodeId([0u8; 20]),
            NodeId::from_pubkey_bytes(&publisher_node_key.verifying_key().to_bytes()),
            publisher_peer.clone(),
        )
        .await
        .expect("bootstrap learns publisher");

    let content_dir = tempfile::tempdir().expect("content tmpdir");
    let share = ShareKeypair::new(SigningKey::generate(&mut rng));
    let payload_v1 = vec![11u8; crate::content::CHUNK_SIZE + 33];
    let desc_v1 = crate::content::describe_content(&payload_v1);
    publisher_handle
        .register_content_from_bytes(publisher_peer.clone(), &payload_v1, content_dir.path())
        .await
        .expect("register v1 provider content");
    let manifest_v1 = ManifestV1 {
        version: 1,
        share_pubkey: share.verifying_key().to_bytes(),
        share_id: share.share_id().0,
        seq: 1,
        created_at: 1_700_000_200,
        expires_at: None,
        title: Some("churn-seq1".into()),
        description: Some("initial publish".into()),
        visibility: crate::manifest::ShareVisibility::Private,
        communities: vec![],
        items: vec![ItemV1 {
            content_id: desc_v1.content_id.0,
            size: payload_v1.len() as u64,
            name: "churn-v1.bin".into(),
            path: None,
            mime: None,
            tags: vec!["churn".into(), "v1".into()],
            chunk_count: desc_v1.chunk_count,
            chunk_list_hash: desc_v1.chunk_list_hash,
        }],
        recommended_shares: vec![],
        signature: None,
    };
    publisher_handle
        .publish_share(manifest_v1, &share)
        .await
        .expect("publish v1");

    subscriber_handle
        .subscribe_with_pubkey(share.share_id(), Some(share.verifying_key().to_bytes()))
        .await
        .expect("subscribe");
    let seed_peers = vec![bootstrap_peer.clone(), publisher_peer.clone()];
    let transport = TcpSessionTransport {
        signing_key: subscriber_node_key,
        capabilities: Capabilities::default(),
    };
    subscriber_handle
        .sync_subscriptions_over_dht(&transport, &seed_peers)
        .await
        .expect("sync v1");

    let seq_after_v1 = {
        let state = subscriber_handle.state.read().await;
        state
            .subscriptions
            .get(&share.share_id().0)
            .expect("subscription exists")
            .latest_seq
    };
    assert_eq!(seq_after_v1, 1);

    let hits_v1 = subscriber_handle
        .search(SearchQuery {
            text: "churn-v1".into(),
        })
        .await
        .expect("search v1");
    assert!(
        hits_v1
            .iter()
            .any(|hit| hit.content_id == desc_v1.content_id.0)
    );

    let target_v1 = std::env::temp_dir().join(format!(
        "scp2p_churn_v1_{}.bin",
        now_unix_secs().expect("now")
    ));
    subscriber_handle
        .download_from_peers(
            &transport,
            &seed_peers,
            desc_v1.content_id.0,
            target_v1.to_str().expect("utf8 path"),
            &FetchPolicy::default(),
            None,
            None,
        )
        .await
        .expect("download v1");
    let read_v1 = std::fs::read(&target_v1).expect("read v1");
    assert_eq!(read_v1, payload_v1);

    publisher_task.abort();
    let _ = publisher_task.await;

    let payload_v2 = vec![22u8; crate::content::CHUNK_SIZE * 2 + 17];
    let desc_v2 = crate::content::describe_content(&payload_v2);
    publisher_handle
        .register_content_from_bytes(publisher_peer.clone(), &payload_v2, content_dir.path())
        .await
        .expect("register v2 provider content");
    let manifest_v2 = ManifestV1 {
        version: 1,
        share_pubkey: share.verifying_key().to_bytes(),
        share_id: share.share_id().0,
        seq: 2,
        created_at: 1_700_000_201,
        expires_at: None,
        title: Some("churn-seq2".into()),
        description: Some("publisher restarted".into()),
        visibility: crate::manifest::ShareVisibility::Private,
        communities: vec![],
        items: vec![ItemV1 {
            content_id: desc_v2.content_id.0,
            size: payload_v2.len() as u64,
            name: "churn-v2.bin".into(),
            path: None,
            mime: None,
            tags: vec!["churn".into(), "v2".into()],
            chunk_count: desc_v2.chunk_count,
            chunk_list_hash: desc_v2.chunk_list_hash,
        }],
        recommended_shares: vec![],
        signature: None,
    };
    publisher_handle
        .publish_share(manifest_v2, &share)
        .await
        .expect("publish v2 while offline");

    subscriber_handle
        .sync_subscriptions_over_dht(&transport, &seed_peers)
        .await
        .expect("sync while publisher offline");
    let seq_while_offline = {
        let state = subscriber_handle.state.read().await;
        state
            .subscriptions
            .get(&share.share_id().0)
            .expect("subscription exists")
            .latest_seq
    };
    assert_eq!(seq_while_offline, 1);

    publisher_task = publisher_handle.clone().start_tcp_dht_service(
        publisher_addr,
        publisher_node_key,
        Capabilities::default(),
    );
    tokio::time::sleep(Duration::from_millis(50)).await;

    subscriber_handle
        .sync_subscriptions_over_dht(&transport, &seed_peers)
        .await
        .expect("sync v2 after restart");
    let seq_after_restart = {
        let state = subscriber_handle.state.read().await;
        state
            .subscriptions
            .get(&share.share_id().0)
            .expect("subscription exists")
            .latest_seq
    };
    assert_eq!(seq_after_restart, 2);

    let hits_v2 = subscriber_handle
        .search(SearchQuery {
            text: "churn-v2".into(),
        })
        .await
        .expect("search v2");
    assert!(
        hits_v2
            .iter()
            .any(|hit| hit.content_id == desc_v2.content_id.0)
    );

    let target_v2 = std::env::temp_dir().join(format!(
        "scp2p_churn_v2_{}.bin",
        now_unix_secs().expect("now")
    ));
    subscriber_handle
        .download_from_peers(
            &transport,
            &seed_peers,
            desc_v2.content_id.0,
            target_v2.to_str().expect("utf8 path"),
            &FetchPolicy::default(),
            None,
            None,
        )
        .await
        .expect("download v2");
    let read_v2 = std::fs::read(&target_v2).expect("read v2");
    assert_eq!(read_v2, payload_v2);

    let _ = std::fs::remove_file(target_v1);
    let _ = std::fs::remove_file(target_v2);
    bootstrap_task.abort();
    publisher_task.abort();
}

fn read_env_usize(name: &str, default: usize, min: usize, max: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .map(|value| value.clamp(min, max))
        .unwrap_or(default)
}

fn read_env_u64(name: &str, default: u64, min: u64, max: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(|value| value.clamp(min, max))
        .unwrap_or(default)
}

#[tokio::test]
async fn multi_node_churn_soak_is_configurable() {
    let node_count = read_env_usize("SCP2P_CHURN_NODE_COUNT", 5, 5, 50);
    let rounds = read_env_usize("SCP2P_CHURN_ROUNDS", 2, 1, 10);
    let max_sync_ms = read_env_u64("SCP2P_SOAK_MAX_SYNC_MS", 8_000, 500, 60_000);

    let bootstrap_handle = Node::start(NodeConfig::default())
        .await
        .expect("start bootstrap");
    let publisher_store = MemoryStore::new();
    let publisher_handle = Node::start_with_store(NodeConfig::default(), publisher_store)
        .await
        .expect("start publisher");

    let mut rng = OsRng;
    let bootstrap_node_key = SigningKey::generate(&mut rng);
    let publisher_node_key = SigningKey::generate(&mut rng);

    let bootstrap_probe = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind bootstrap probe");
    let bootstrap_addr = bootstrap_probe.local_addr().expect("bootstrap probe addr");
    drop(bootstrap_probe);

    let publisher_probe = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind publisher probe");
    let publisher_addr = publisher_probe.local_addr().expect("publisher probe addr");
    drop(publisher_probe);

    let bootstrap_task = bootstrap_handle.clone().start_tcp_dht_service(
        bootstrap_addr,
        bootstrap_node_key,
        Capabilities::default(),
    );
    let mut publisher_task = publisher_handle.clone().start_tcp_dht_service(
        publisher_addr,
        publisher_node_key.clone(),
        Capabilities::default(),
    );
    tokio::time::sleep(Duration::from_millis(75)).await;

    let bootstrap_peer = PeerAddr {
        ip: "127.0.0.1".parse().expect("ip"),
        port: bootstrap_addr.port(),
        transport: TransportProtocol::Tcp,
        pubkey_hint: None,
        relay_via: None,
    };
    let publisher_peer = PeerAddr {
        ip: "127.0.0.1".parse().expect("ip"),
        port: publisher_addr.port(),
        transport: TransportProtocol::Tcp,
        pubkey_hint: Some(publisher_node_key.verifying_key().to_bytes()),
        relay_via: None,
    };
    bootstrap_handle
        .dht_upsert_peer(
            NodeId([0u8; 20]),
            NodeId::from_pubkey_bytes(&publisher_node_key.verifying_key().to_bytes()),
            publisher_peer.clone(),
        )
        .await
        .expect("bootstrap learns publisher");
    let seed_peers = vec![bootstrap_peer.clone(), publisher_peer.clone()];

    struct SubscriberHarness {
        store: Arc<MemoryStore>,
        handle: NodeHandle,
    }

    let share = ShareKeypair::new(SigningKey::generate(&mut rng));
    let mut subscribers = Vec::with_capacity(node_count);
    let mut sync_ms_samples = Vec::new();
    let mut successful_downloads = 0usize;
    for _ in 0..node_count {
        let store = MemoryStore::new();
        let handle = Node::start_with_store(NodeConfig::default(), store.clone())
            .await
            .expect("start subscriber");
        handle
            .subscribe_with_pubkey(share.share_id(), Some(share.verifying_key().to_bytes()))
            .await
            .expect("subscribe");
        subscribers.push(SubscriberHarness { store, handle });
    }

    let content_dir = tempfile::tempdir().expect("content tmpdir");
    for seq in 1..=(rounds as u64 + 1) {
        publisher_task.abort();
        let _ = publisher_task.await;
        tokio::time::sleep(Duration::from_millis(40)).await;

        let payload = vec![seq as u8; crate::content::CHUNK_SIZE + 16 + seq as usize];
        let desc = crate::content::describe_content(&payload);
        publisher_handle
            .register_content_from_bytes(publisher_peer.clone(), &payload, content_dir.path())
            .await
            .expect("register provider content");
        let manifest = ManifestV1 {
            version: 1,
            share_pubkey: share.verifying_key().to_bytes(),
            share_id: share.share_id().0,
            seq,
            created_at: 1_700_000_500 + seq,
            expires_at: None,
            title: Some(format!("soak-seq-{seq}")),
            description: Some("multi-node churn soak".into()),
            visibility: crate::manifest::ShareVisibility::Private,
            communities: vec![],
            items: vec![ItemV1 {
                content_id: desc.content_id.0,
                size: payload.len() as u64,
                name: format!("soak-item-{seq}.bin"),
                path: None,
                mime: None,
                tags: vec!["soak".into(), format!("seq-{seq}")],
                chunk_count: desc.chunk_count,
                chunk_list_hash: desc.chunk_list_hash,
            }],
            recommended_shares: vec![],
            signature: None,
        };
        publisher_handle
            .publish_share(manifest, &share)
            .await
            .expect("publish");

        publisher_task = publisher_handle.clone().start_tcp_dht_service(
            publisher_addr,
            publisher_node_key.clone(),
            Capabilities::default(),
        );
        tokio::time::sleep(Duration::from_millis(75)).await;

        for (idx, subscriber) in subscribers.iter_mut().enumerate() {
            if seq > 1 && idx % 3 == (seq as usize % 3) {
                subscriber.handle =
                    Node::start_with_store(NodeConfig::default(), subscriber.store.clone())
                        .await
                        .expect("restart subscriber");
            }

            let requester_key = SigningKey::generate(&mut rng);
            let transport = TcpSessionTransport {
                signing_key: requester_key,
                capabilities: Capabilities::default(),
            };
            let sync_started = std::time::Instant::now();
            subscriber
                .handle
                .sync_subscriptions_over_dht(&transport, &seed_peers)
                .await
                .expect("sync");
            sync_ms_samples.push(sync_started.elapsed().as_millis() as u64);

            let latest_seq = {
                let state = subscriber.handle.state.read().await;
                state
                    .subscriptions
                    .get(&share.share_id().0)
                    .expect("subscription exists")
                    .latest_seq
            };
            assert_eq!(latest_seq, seq);

            let hits = subscriber
                .handle
                .search(SearchQuery {
                    text: format!("soak-item-{seq}"),
                })
                .await
                .expect("search");
            assert!(hits.iter().any(|hit| hit.content_id == desc.content_id.0));

            if idx == 0 {
                let target = std::env::temp_dir().join(format!(
                    "scp2p_soak_{}_{}_{}.bin",
                    node_count,
                    seq,
                    now_unix_secs().expect("now")
                ));
                subscriber
                    .handle
                    .download_from_peers(
                        &transport,
                        &seed_peers,
                        desc.content_id.0,
                        target.to_str().expect("utf8 path"),
                        &FetchPolicy::default(),
                        None,
                        None,
                    )
                    .await
                    .expect("download");
                let read_back = std::fs::read(&target).expect("read target");
                assert_eq!(read_back, payload);
                let _ = std::fs::remove_file(target);
                successful_downloads += 1;
            }
        }
    }

    let mut sorted = sync_ms_samples.clone();
    sorted.sort_unstable();
    let p95_index = ((sorted.len() as f64) * 0.95).floor() as usize;
    let p95_sync_ms = sorted[p95_index.min(sorted.len().saturating_sub(1))];
    assert!(
        p95_sync_ms <= max_sync_ms,
        "p95 sync latency {}ms exceeded configured threshold {}ms",
        p95_sync_ms,
        max_sync_ms
    );
    assert_eq!(successful_downloads, rounds + 1);

    bootstrap_task.abort();
    publisher_task.abort();
}

#[tokio::test]
async fn dht_store_replicated_stores_locally_and_on_closest_peers() {
    let handle = Node::start(NodeConfig::default()).await.expect("start");
    let transport = MockDhtTransport::default();
    let (key, value) = make_share_head_kv([13u8; 32]);
    let seed = PeerAddr {
        ip: "10.0.0.50".parse().expect("valid ip"),
        port: 7000,
        transport: TransportProtocol::Tcp,
        pubkey_hint: Some([6u8; 32]),
        relay_via: None,
    };
    let peer_a = PeerAddr {
        ip: "10.0.0.51".parse().expect("valid ip"),
        port: 7000,
        transport: TransportProtocol::Tcp,
        pubkey_hint: Some([7u8; 32]),
        relay_via: None,
    };
    let peer_b = PeerAddr {
        ip: "10.0.0.52".parse().expect("valid ip"),
        port: 7000,
        transport: TransportProtocol::Tcp,
        pubkey_hint: Some([8u8; 32]),
        relay_via: None,
    };
    let stored_count = Arc::new(AtomicUsize::new(0));

    transport
        .register(&seed, {
            let peer_a = peer_a.clone();
            let peer_b = peer_b.clone();
            let stored_count = stored_count.clone();
            move |request| match request.decode_typed()? {
                WirePayload::FindNode(_) => Ok(Envelope {
                    r#type: MsgType::FindNode as u16,
                    req_id: request.req_id,
                    flags: FLAG_RESPONSE,
                    payload: crate::cbor::to_vec(&FindNodeResult {
                        peers: vec![peer_a.clone(), peer_b.clone()],
                    })?,
                }),
                WirePayload::Store(_) => {
                    stored_count.fetch_add(1, Ordering::SeqCst);
                    Ok(Envelope {
                        r#type: MsgType::Store as u16,
                        req_id: request.req_id,
                        flags: FLAG_RESPONSE,
                        payload: vec![],
                    })
                }
                _ => anyhow::bail!("unexpected request payload"),
            }
        })
        .await;
    for peer in [peer_a.clone(), peer_b.clone()] {
        transport
            .register(&peer, {
                let stored_count = stored_count.clone();
                move |request| match request.decode_typed()? {
                    WirePayload::FindNode(_) => Ok(Envelope {
                        r#type: MsgType::FindNode as u16,
                        req_id: request.req_id,
                        flags: FLAG_RESPONSE,
                        payload: crate::cbor::to_vec(&FindNodeResult { peers: vec![] })?,
                    }),
                    WirePayload::Store(_) => {
                        stored_count.fetch_add(1, Ordering::SeqCst);
                        Ok(Envelope {
                            r#type: MsgType::Store as u16,
                            req_id: request.req_id,
                            flags: FLAG_RESPONSE,
                            payload: vec![],
                        })
                    }
                    _ => anyhow::bail!("unexpected request payload"),
                }
            })
            .await;
    }

    let stored = handle
        .dht_store_replicated(
            &transport,
            WireStore {
                key,
                value: value.clone(),
                ttl_secs: 120,
            },
            std::slice::from_ref(&seed),
        )
        .await
        .expect("replicated store");

    let local = handle
        .dht_find_value(key)
        .await
        .expect("local query")
        .expect("value must exist");
    assert_eq!(local.value, value);
    assert_eq!(stored, 3);
    assert_eq!(stored_count.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn dht_republish_once_repairs_remote_replication() {
    let handle = Node::start(NodeConfig::default()).await.expect("start");
    let transport = MockDhtTransport::default();
    let (key, value) = make_share_head_kv([21u8; 32]);
    let seed = PeerAddr {
        ip: "10.0.0.60".parse().expect("valid ip"),
        port: 7000,
        transport: TransportProtocol::Tcp,
        pubkey_hint: Some([9u8; 32]),
        relay_via: None,
    };
    let peer = PeerAddr {
        ip: "10.0.0.61".parse().expect("valid ip"),
        port: 7000,
        transport: TransportProtocol::Tcp,
        pubkey_hint: Some([10u8; 32]),
        relay_via: None,
    };
    let stored_count = Arc::new(AtomicUsize::new(0));

    transport
        .register(&seed, {
            let peer = peer.clone();
            move |request| match request.decode_typed()? {
                WirePayload::FindNode(_) => Ok(Envelope {
                    r#type: MsgType::FindNode as u16,
                    req_id: request.req_id,
                    flags: FLAG_RESPONSE,
                    payload: crate::cbor::to_vec(&FindNodeResult {
                        peers: vec![peer.clone()],
                    })?,
                }),
                _ => anyhow::bail!("unexpected request payload"),
            }
        })
        .await;
    transport
        .register(&peer, {
            let stored_count = stored_count.clone();
            move |request| match request.decode_typed()? {
                WirePayload::FindNode(_) => Ok(Envelope {
                    r#type: MsgType::FindNode as u16,
                    req_id: request.req_id,
                    flags: FLAG_RESPONSE,
                    payload: crate::cbor::to_vec(&FindNodeResult { peers: vec![] })?,
                }),
                WirePayload::Store(_) => {
                    stored_count.fetch_add(1, Ordering::SeqCst);
                    Ok(Envelope {
                        r#type: MsgType::Store as u16,
                        req_id: request.req_id,
                        flags: FLAG_RESPONSE,
                        payload: vec![],
                    })
                }
                _ => anyhow::bail!("unexpected request payload"),
            }
        })
        .await;

    handle
        .dht_store(WireStore {
            key,
            value,
            ttl_secs: 2,
        })
        .await
        .expect("local store");

    let republished = handle
        .dht_republish_once(&transport, std::slice::from_ref(&seed))
        .await
        .expect("republish once");
    assert_eq!(republished, 1);
    assert_eq!(stored_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn publish_and_sync_subscription_updates_seq() {
    let handle = Node::start(NodeConfig::default()).await.expect("start");
    let mut rng = OsRng;
    let share = ShareKeypair::new(SigningKey::generate(&mut rng));

    let manifest = ManifestV1 {
        version: 1,
        share_pubkey: share.verifying_key().to_bytes(),
        share_id: share.share_id().0,
        seq: 1,
        created_at: 1_700_000_000,
        expires_at: None,
        title: Some("t".into()),
        description: None,
        visibility: crate::manifest::ShareVisibility::Private,
        communities: vec![],
        items: vec![],
        recommended_shares: vec![],
        signature: None,
    };

    handle
        .subscribe_with_pubkey(share.share_id(), Some(share.verifying_key().to_bytes()))
        .await
        .expect("subscribe with pubkey");
    let manifest_id = handle
        .publish_share(manifest, &share)
        .await
        .expect("publish share");
    handle
        .sync_subscriptions()
        .await
        .expect("sync subscriptions");

    let state = handle.state.read().await;
    let sub = state
        .subscriptions
        .get(&share.share_id().0)
        .expect("subscription must exist");
    assert_eq!(sub.latest_seq, 1);
    assert_eq!(sub.latest_manifest_id, Some(manifest_id));
}

#[tokio::test]
async fn local_public_share_listing_filters_private_manifests() {
    let handle = Node::start(NodeConfig::default()).await.expect("start");
    let mut rng = OsRng;
    let public_share = ShareKeypair::new(SigningKey::generate(&mut rng));
    let private_share = ShareKeypair::new(SigningKey::generate(&mut rng));

    let public_manifest = ManifestV1 {
        version: 1,
        share_pubkey: public_share.verifying_key().to_bytes(),
        share_id: public_share.share_id().0,
        seq: 1,
        created_at: 1_700_000_010,
        expires_at: None,
        title: Some("public".into()),
        description: Some("visible".into()),
        visibility: crate::manifest::ShareVisibility::Public,
        communities: vec![],
        items: vec![],
        recommended_shares: vec![],
        signature: None,
    };
    let private_manifest = ManifestV1 {
        version: 1,
        share_pubkey: private_share.verifying_key().to_bytes(),
        share_id: private_share.share_id().0,
        seq: 1,
        created_at: 1_700_000_011,
        expires_at: None,
        title: Some("private".into()),
        description: Some("hidden".into()),
        visibility: crate::manifest::ShareVisibility::Private,
        communities: vec![],
        items: vec![],
        recommended_shares: vec![],
        signature: None,
    };

    handle
        .publish_share(public_manifest, &public_share)
        .await
        .expect("publish public");
    handle
        .publish_share(private_manifest, &private_share)
        .await
        .expect("publish private");

    let shares = handle
        .list_local_public_shares(10)
        .await
        .expect("list public shares");
    assert_eq!(shares.len(), 1);
    assert_eq!(shares[0].share_id, public_share.share_id().0);
    assert_eq!(
        shares[0].share_pubkey,
        public_share.verifying_key().to_bytes()
    );
    assert_eq!(shares[0].title.as_deref(), Some("public"));
}

#[tokio::test]
async fn fetch_public_shares_from_peer_roundtrip() {
    let handle = Node::start(NodeConfig::default()).await.expect("start");
    let transport = MockDhtTransport::default();
    let peer = PeerAddr {
        ip: "10.0.0.81".parse().expect("valid ip"),
        port: 7000,
        transport: TransportProtocol::Tcp,
        pubkey_hint: Some([17u8; 32]),
        relay_via: None,
    };

    transport
        .register(&peer, move |request| {
            let WirePayload::ListPublicShares(msg) = request.decode_typed()? else {
                anyhow::bail!("unexpected payload");
            };
            assert_eq!(msg.max_entries, 8);
            Ok(Envelope {
                r#type: MsgType::PublicShareList as u16,
                req_id: request.req_id,
                flags: FLAG_RESPONSE,
                payload: crate::cbor::to_vec(&PublicShareList {
                    shares: vec![PublicShareSummary {
                        share_id: [1u8; 32],
                        share_pubkey: [2u8; 32],
                        latest_seq: 3,
                        latest_manifest_id: [4u8; 32],
                        title: Some("public".into()),
                        description: Some("listed".into()),
                    }],
                })?,
            })
        })
        .await;

    let shares = handle
        .fetch_public_shares_from_peer(&transport, &peer, 8)
        .await
        .expect("fetch public shares");
    assert_eq!(shares.len(), 1);
    assert_eq!(shares[0].share_id, [1u8; 32]);
    assert_eq!(shares[0].title.as_deref(), Some("public"));
}

#[tokio::test]
async fn community_membership_persists_across_restart_with_memory_store() {
    let store = MemoryStore::new();
    let handle = Node::start_with_store(NodeConfig::default(), store.clone())
        .await
        .expect("start");
    let mut rng = OsRng;
    let community = ShareKeypair::new(SigningKey::generate(&mut rng));

    handle
        .join_community(community.share_id(), community.verifying_key().to_bytes())
        .await
        .expect("join community");

    let restarted = Node::start_with_store(NodeConfig::default(), store)
        .await
        .expect("restart");
    let communities = restarted.communities().await;
    assert_eq!(communities.len(), 1);
    assert_eq!(communities[0].share_id, community.share_id().0);
    assert_eq!(
        communities[0].share_pubkey,
        community.verifying_key().to_bytes()
    );
}

#[tokio::test]
async fn fetch_community_status_from_peer_roundtrip() {
    let handle = Node::start(NodeConfig::default()).await.expect("start");
    let transport = MockDhtTransport::default();
    let mut rng = OsRng;
    let community = ShareKeypair::new(SigningKey::generate(&mut rng));
    let peer = PeerAddr {
        ip: "10.0.0.82".parse().expect("valid ip"),
        port: 7000,
        transport: TransportProtocol::Tcp,
        pubkey_hint: Some([18u8; 32]),
        relay_via: None,
    };

    transport
        .register(&peer, {
            let share_id = community.share_id().0;
            let share_pubkey = community.verifying_key().to_bytes();
            move |request| {
                let WirePayload::GetCommunityStatus(msg) = request.decode_typed()? else {
                    anyhow::bail!("unexpected payload");
                };
                assert_eq!(msg.community_share_id, share_id);
                assert_eq!(msg.community_share_pubkey, share_pubkey);
                Ok(Envelope {
                    r#type: MsgType::CommunityStatus as u16,
                    req_id: request.req_id,
                    flags: FLAG_RESPONSE,
                    payload: crate::cbor::to_vec(&CommunityStatus {
                        community_share_id: share_id,
                        joined: true,
                        membership_proof: None,
                    })?,
                })
            }
        })
        .await;

    let joined = handle
        .fetch_community_status_from_peer(
            &transport,
            &peer,
            community.share_id(),
            community.verifying_key().to_bytes(),
        )
        .await
        .expect("fetch community status");
    assert!(joined);
}

#[tokio::test]
async fn search_is_subscription_scoped_and_weighted() {
    let handle = Node::start(NodeConfig::default()).await.expect("start");
    let mut rng = OsRng;

    let share_a = ShareKeypair::new(SigningKey::generate(&mut rng));
    let share_b = ShareKeypair::new(SigningKey::generate(&mut rng));

    for (share, title) in [(&share_a, "alpha"), (&share_b, "beta")] {
        handle
            .subscribe_with_pubkey(share.share_id(), Some(share.verifying_key().to_bytes()))
            .await
            .expect("subscribe");

        let manifest = ManifestV1 {
            version: 1,
            share_pubkey: share.verifying_key().to_bytes(),
            share_id: share.share_id().0,
            seq: 1,
            created_at: 1_700_000_001,
            expires_at: None,
            title: Some((*title).into()),
            description: Some("movie catalog".into()),
            visibility: crate::manifest::ShareVisibility::Private,
            communities: vec![],
            items: vec![ItemV1 {
                content_id: if title == "alpha" {
                    [5u8; 32]
                } else {
                    [6u8; 32]
                },
                size: 10,
                name: format!("movie {title}"),
                path: None,
                mime: None,
                tags: vec!["movie".into()],
                chunk_count: 0,
                chunk_list_hash: [0u8; 32],
            }],
            recommended_shares: vec![],
            signature: None,
        };
        handle
            .publish_share(manifest, share)
            .await
            .expect("publish");
    }

    handle.sync_subscriptions().await.expect("sync");
    handle
        .set_share_weight(share_b.share_id(), 2.0)
        .await
        .expect("weight");

    let hits = handle
        .search(SearchQuery {
            text: "movie".into(),
        })
        .await
        .expect("search");

    assert_eq!(hits.len(), 2);
    assert_eq!(hits[0].share_id, share_b.share_id());
}

#[tokio::test]
async fn search_default_excludes_untrusted_subscriptions() {
    let handle = Node::start(NodeConfig::default()).await.expect("start");
    let mut rng = OsRng;
    let trusted = ShareKeypair::new(SigningKey::generate(&mut rng));
    let untrusted = ShareKeypair::new(SigningKey::generate(&mut rng));

    for (share, trust, content_id) in [
        (&trusted, SubscriptionTrustLevel::Trusted, [11u8; 32]),
        (&untrusted, SubscriptionTrustLevel::Untrusted, [12u8; 32]),
    ] {
        handle
            .subscribe_with_trust(
                share.share_id(),
                Some(share.verifying_key().to_bytes()),
                trust,
            )
            .await
            .expect("subscribe");
        let manifest = ManifestV1 {
            version: 1,
            share_pubkey: share.verifying_key().to_bytes(),
            share_id: share.share_id().0,
            seq: 1,
            created_at: 1_700_000_010,
            expires_at: None,
            title: Some("tiered search".into()),
            description: None,
            visibility: crate::manifest::ShareVisibility::Private,
            communities: vec![],
            items: vec![ItemV1 {
                content_id,
                size: 1,
                name: "movie trust".into(),
                path: None,
                mime: None,
                tags: vec!["movie".into()],
                chunk_count: 0,
                chunk_list_hash: [0u8; 32],
            }],
            recommended_shares: vec![],
            signature: None,
        };
        handle
            .publish_share(manifest, share)
            .await
            .expect("publish");
    }

    handle.sync_subscriptions().await.expect("sync");

    let default_hits = handle
        .search(SearchQuery {
            text: "movie".into(),
        })
        .await
        .expect("search default");
    assert_eq!(default_hits.len(), 1);
    assert_eq!(default_hits[0].share_id, trusted.share_id());

    let all_hits = handle
        .search_with_trust_filter(
            SearchQuery {
                text: "movie".into(),
            },
            SearchTrustFilter::All,
        )
        .await
        .expect("search all tiers");
    assert_eq!(all_hits.len(), 2);
}

#[tokio::test]
async fn search_page_supports_offset_limit_and_snippets() {
    let handle = Node::start(NodeConfig::default()).await.expect("start");
    let mut rng = OsRng;
    for idx in 0..3u8 {
        let share = ShareKeypair::new(SigningKey::generate(&mut rng));
        handle
            .subscribe_with_trust(
                share.share_id(),
                Some(share.verifying_key().to_bytes()),
                SubscriptionTrustLevel::Trusted,
            )
            .await
            .expect("subscribe");
        let manifest = ManifestV1 {
            version: 1,
            share_pubkey: share.verifying_key().to_bytes(),
            share_id: share.share_id().0,
            seq: 1,
            created_at: 1_700_000_020 + idx as u64,
            expires_at: None,
            title: Some(format!("Trusted Movie Collection {}", idx + 1)),
            description: Some("Curated trusted movie archive".into()),
            visibility: crate::manifest::ShareVisibility::Private,
            communities: vec![],
            items: vec![ItemV1 {
                content_id: [20 + idx; 32],
                size: 1,
                name: format!("movie-{}.mkv", idx + 1),
                path: None,
                mime: None,
                tags: vec!["movie".into(), "trusted".into()],
                chunk_count: 0,
                chunk_list_hash: [0u8; 32],
            }],
            recommended_shares: vec![],
            signature: None,
        };
        handle
            .publish_share(manifest, &share)
            .await
            .expect("publish");
    }
    handle.sync_subscriptions().await.expect("sync");

    let page = handle
        .search_page(SearchPageQuery {
            text: "movie".into(),
            offset: 1,
            limit: 1,
            include_snippets: true,
        })
        .await
        .expect("search page");
    assert_eq!(page.total, 3);
    assert_eq!(page.results.len(), 1);

    let full_page = handle
        .search_page(SearchPageQuery {
            text: "movie".into(),
            offset: 0,
            limit: 2,
            include_snippets: true,
        })
        .await
        .expect("search full page");
    assert_eq!(full_page.total, 3);
    assert_eq!(full_page.results.len(), 2);
    assert!(
        full_page.results[0]
            .snippet
            .as_deref()
            .map(|s| s.to_lowercase().contains("movie"))
            .unwrap_or(false)
    );
}

#[tokio::test]
async fn can_update_subscription_trust_level() {
    let handle = Node::start(NodeConfig::default()).await.expect("start");
    let mut rng = OsRng;
    let share = ShareKeypair::new(SigningKey::generate(&mut rng));
    handle
        .subscribe_with_pubkey(share.share_id(), Some(share.verifying_key().to_bytes()))
        .await
        .expect("subscribe");
    handle
        .set_subscription_trust_level(share.share_id(), SubscriptionTrustLevel::Untrusted)
        .await
        .expect("set trust");

    let state = handle.state.read().await;
    let sub = state
        .subscriptions
        .get(&share.share_id().0)
        .expect("subscription must exist");
    assert_eq!(sub.trust_level, SubscriptionTrustLevel::Untrusted);
}

#[tokio::test]
async fn enabled_blocklist_share_filters_search_results() {
    let handle = Node::start(NodeConfig::default()).await.expect("start");
    let mut rng = OsRng;
    let share_a = ShareKeypair::new(SigningKey::generate(&mut rng));
    let share_b = ShareKeypair::new(SigningKey::generate(&mut rng));
    let blocklist_share = ShareKeypair::new(SigningKey::generate(&mut rng));
    let blocked_content = [42u8; 32];

    for (share, content_id, name) in [
        (&share_a, [41u8; 32], "movie-a"),
        (&share_b, blocked_content, "movie-b"),
    ] {
        handle
            .subscribe_with_trust(
                share.share_id(),
                Some(share.verifying_key().to_bytes()),
                SubscriptionTrustLevel::Trusted,
            )
            .await
            .expect("subscribe content share");
        let manifest = ManifestV1 {
            version: 1,
            share_pubkey: share.verifying_key().to_bytes(),
            share_id: share.share_id().0,
            seq: 1,
            created_at: 1_700_000_030,
            expires_at: None,
            title: Some("content share".into()),
            description: None,
            visibility: crate::manifest::ShareVisibility::Private,
            communities: vec![],
            items: vec![ItemV1 {
                content_id,
                size: 1,
                name: name.into(),
                path: None,
                mime: None,
                tags: vec!["movie".into()],
                chunk_count: 0,
                chunk_list_hash: [0u8; 32],
            }],
            recommended_shares: vec![],
            signature: None,
        };
        handle
            .publish_share(manifest, share)
            .await
            .expect("publish");
    }

    handle
        .subscribe_with_trust(
            blocklist_share.share_id(),
            Some(blocklist_share.verifying_key().to_bytes()),
            SubscriptionTrustLevel::Trusted,
        )
        .await
        .expect("subscribe blocklist share");
    handle
        .set_blocklist_rules(
            blocklist_share.share_id(),
            BlocklistRules {
                blocked_share_ids: vec![share_a.share_id().0],
                blocked_content_ids: vec![blocked_content],
            },
        )
        .await
        .expect("set blocklist rules");

    handle.sync_subscriptions().await.expect("sync");
    let baseline = handle
        .search(SearchQuery {
            text: "movie".into(),
        })
        .await
        .expect("baseline search");
    assert_eq!(baseline.len(), 2);

    handle
        .enable_blocklist_share(blocklist_share.share_id())
        .await
        .expect("enable blocklist");
    let filtered = handle
        .search(SearchQuery {
            text: "movie".into(),
        })
        .await
        .expect("filtered search");
    assert_eq!(filtered.len(), 0);

    handle
        .disable_blocklist_share(blocklist_share.share_id())
        .await
        .expect("disable blocklist");
    let restored = handle
        .search(SearchQuery {
            text: "movie".into(),
        })
        .await
        .expect("restored search");
    assert_eq!(restored.len(), 2);
}

#[tokio::test]
async fn relay_register_connect_and_stream_roundtrip() {
    let handle = Node::start(NodeConfig::default()).await.expect("start");
    let owner = PeerAddr {
        ip: "10.0.0.10".parse().expect("valid ip"),
        port: 7000,
        transport: TransportProtocol::Quic,
        pubkey_hint: None,
        relay_via: None,
    };
    let requester = PeerAddr {
        ip: "10.0.0.11".parse().expect("valid ip"),
        port: 7001,
        transport: TransportProtocol::Quic,
        pubkey_hint: None,
        relay_via: None,
    };

    let registered = handle
        .relay_register(owner.clone())
        .await
        .expect("register");
    handle
        .relay_connect(
            requester.clone(),
            RelayConnect {
                relay_slot_id: registered.relay_slot_id,
            },
        )
        .await
        .expect("connect");

    let stream = handle
        .relay_stream(
            requester,
            RelayStream {
                relay_slot_id: registered.relay_slot_id,
                stream_id: 1,
                kind: WireRelayPayloadKind::Control,
                payload: vec![1, 2, 3],
            },
        )
        .await
        .expect("stream");

    assert_eq!(stream.payload, vec![1, 2, 3]);
}

#[tokio::test]
async fn relay_selection_rotates_across_best_peers() {
    let handle = Node::start(NodeConfig::default()).await.expect("start");
    let peers = vec![
        PeerAddr {
            ip: "10.0.2.1".parse().expect("ip"),
            port: 7101,
            transport: TransportProtocol::Tcp,
            pubkey_hint: Some([1u8; 32]),
            relay_via: None,
        },
        PeerAddr {
            ip: "10.0.2.2".parse().expect("ip"),
            port: 7102,
            transport: TransportProtocol::Tcp,
            pubkey_hint: Some([2u8; 32]),
            relay_via: None,
        },
        PeerAddr {
            ip: "10.0.2.3".parse().expect("ip"),
            port: 7103,
            transport: TransportProtocol::Tcp,
            pubkey_hint: Some([3u8; 32]),
            relay_via: None,
        },
    ];
    for peer in &peers {
        handle.record_peer_seen(peer.clone()).await.expect("record");
    }

    let a = handle
        .select_relay_peer()
        .await
        .expect("select")
        .expect("peer");
    let b = handle
        .select_relay_peer()
        .await
        .expect("select")
        .expect("peer");
    let c = handle
        .select_relay_peer()
        .await
        .expect("select")
        .expect("peer");
    let mut seen = HashSet::new();
    seen.insert(relay_peer_key(&a));
    seen.insert(relay_peer_key(&b));
    seen.insert(relay_peer_key(&c));
    assert_eq!(seen.len(), 3);
}

#[tokio::test]
async fn relay_selection_prefers_healthier_peers() {
    let handle = Node::start(NodeConfig::default()).await.expect("start");
    let bad_peer = PeerAddr {
        ip: "10.0.3.1".parse().expect("ip"),
        port: 7201,
        transport: TransportProtocol::Tcp,
        pubkey_hint: Some([9u8; 32]),
        relay_via: None,
    };
    let good_peer = PeerAddr {
        ip: "10.0.3.2".parse().expect("ip"),
        port: 7202,
        transport: TransportProtocol::Tcp,
        pubkey_hint: Some([10u8; 32]),
        relay_via: None,
    };
    handle
        .record_peer_seen(bad_peer.clone())
        .await
        .expect("record bad");
    handle
        .record_peer_seen(good_peer.clone())
        .await
        .expect("record good");
    for _ in 0..3 {
        handle
            .note_relay_result(&bad_peer, false)
            .await
            .expect("penalize bad");
    }
    handle
        .note_relay_result(&good_peer, true)
        .await
        .expect("reward good");

    let selected = handle.select_relay_peers(2).await.expect("select list");
    assert!(!selected.is_empty());
    assert!(
        selected
            .iter()
            .all(|peer| relay_peer_key(peer) != relay_peer_key(&bad_peer))
    );
}

#[tokio::test]
async fn adaptive_relay_content_requires_positive_score() {
    let handle = Node::start(NodeConfig::default()).await.expect("start");
    handle
        .set_relay_limits(RelayLimits {
            content_relay_enabled: true,
            ..RelayLimits::default()
        })
        .await
        .expect("set limits");

    let owner = PeerAddr {
        ip: "10.0.4.1".parse().expect("ip"),
        port: 7301,
        transport: TransportProtocol::Tcp,
        pubkey_hint: Some([31u8; 32]),
        relay_via: None,
    };
    let requester = PeerAddr {
        ip: "10.0.4.2".parse().expect("ip"),
        port: 7302,
        transport: TransportProtocol::Tcp,
        pubkey_hint: Some([32u8; 32]),
        relay_via: None,
    };

    let registered = handle
        .relay_register(owner.clone())
        .await
        .expect("register");
    handle
        .relay_connect(
            requester.clone(),
            RelayConnect {
                relay_slot_id: registered.relay_slot_id,
            },
        )
        .await
        .expect("connect");

    let err = handle
        .relay_stream(
            requester.clone(),
            RelayStream {
                relay_slot_id: registered.relay_slot_id,
                stream_id: 1,
                kind: WireRelayPayloadKind::Content,
                payload: vec![7u8; 32],
            },
        )
        .await
        .expect_err("content should require trust score");
    assert!(err.to_string().contains("trust score"));

    handle
        .note_relay_result(&requester, true)
        .await
        .expect("raise score");
    handle
        .note_relay_result(&requester, true)
        .await
        .expect("raise score");
    handle
        .note_relay_result(&requester, true)
        .await
        .expect("raise score");

    let relayed = handle
        .relay_stream(
            requester,
            RelayStream {
                relay_slot_id: registered.relay_slot_id,
                stream_id: 2,
                kind: WireRelayPayloadKind::Content,
                payload: vec![9u8; 32],
            },
        )
        .await
        .expect("content should pass after score improves");
    assert_eq!(relayed.kind, WireRelayPayloadKind::Content);
}

#[tokio::test]
async fn incoming_request_rate_limits_are_enforced() {
    let handle = Node::start(NodeConfig::default()).await.expect("start");
    handle
        .set_abuse_limits(AbuseLimits {
            window_secs: 60,
            max_total_requests_per_window: 2,
            max_dht_requests_per_window: 10,
            max_fetch_requests_per_window: 10,
            max_relay_requests_per_window: 10,
        })
        .await
        .expect("set abuse limits");

    let remote = PeerAddr {
        ip: "10.0.9.9".parse().expect("ip"),
        port: 7999,
        transport: TransportProtocol::Tcp,
        pubkey_hint: Some([44u8; 32]),
        relay_via: None,
    };
    let req = Envelope::from_typed(
        next_req_id(),
        0,
        &WirePayload::FindNode(FindNode {
            target_node_id: [1u8; 20],
        }),
    )
    .expect("encode request");

    let first = handle
        .handle_incoming_envelope(req.clone(), Some(&remote))
        .await
        .expect("first response");
    assert_eq!(first.flags & FLAG_ERROR, 0);

    let second = handle
        .handle_incoming_envelope(req.clone(), Some(&remote))
        .await
        .expect("second response");
    assert_eq!(second.flags & FLAG_ERROR, 0);

    let third = handle
        .handle_incoming_envelope(req, Some(&remote))
        .await
        .expect("third response");
    assert_ne!(third.flags & FLAG_ERROR, 0);
    let message = String::from_utf8(third.payload).expect("utf8");
    assert!(message.contains("rate limit"));
}

#[tokio::test]
async fn tcp_runtime_supports_relay_for_simulated_nat_peers() {
    let relay_handle = Node::start(NodeConfig::default())
        .await
        .expect("start relay");
    let mut rng = OsRng;
    let relay_node_key = SigningKey::generate(&mut rng);
    let owner_key = SigningKey::generate(&mut rng);
    let requester_key = SigningKey::generate(&mut rng);

    let probe = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind probe");
    let bind_addr = probe.local_addr().expect("probe addr");
    drop(probe);

    let relay_task = relay_handle.clone().start_tcp_dht_service(
        bind_addr,
        relay_node_key.clone(),
        Capabilities::default(),
    );
    tokio::time::sleep(Duration::from_millis(50)).await;

    let relay_peer = PeerAddr {
        ip: "127.0.0.1".parse().expect("ip"),
        port: bind_addr.port(),
        transport: TransportProtocol::Tcp,
        pubkey_hint: Some(relay_node_key.verifying_key().to_bytes()),
        relay_via: None,
    };

    let owner_transport = TcpSessionTransport {
        signing_key: owner_key,
        capabilities: Capabilities::default(),
    };
    let requester_transport = TcpSessionTransport {
        signing_key: requester_key,
        capabilities: Capabilities::default(),
    };

    let register_req_id = next_req_id();
    let register_request = Envelope::from_typed(
        register_req_id,
        0,
        &WirePayload::RelayRegister(RelayRegister {
            relay_slot_id: None,
            tunnel: false,
        }),
    )
    .expect("encode register");
    let register_response = owner_transport
        .request(&relay_peer, register_request, Duration::from_secs(3))
        .await
        .expect("relay register");
    assert_eq!(register_response.r#type, MsgType::RelayRegistered as u16);
    assert_eq!(register_response.req_id, register_req_id);
    assert_ne!(register_response.flags & FLAG_RESPONSE, 0);
    let registered: RelayRegistered =
        crate::cbor::from_slice(&register_response.payload).expect("decode registered");
    tokio::time::sleep(Duration::from_millis(1100)).await;

    let renew_req_id = next_req_id();
    let renew_request = Envelope::from_typed(
        renew_req_id,
        0,
        &WirePayload::RelayRegister(RelayRegister {
            relay_slot_id: Some(registered.relay_slot_id),
            tunnel: false,
        }),
    )
    .expect("encode renew");
    let renew_response = owner_transport
        .request(&relay_peer, renew_request, Duration::from_secs(3))
        .await
        .expect("relay renew");
    assert_eq!(renew_response.r#type, MsgType::RelayRegistered as u16);
    assert_eq!(renew_response.req_id, renew_req_id);
    assert_ne!(renew_response.flags & FLAG_RESPONSE, 0);
    let renewed: RelayRegistered =
        crate::cbor::from_slice(&renew_response.payload).expect("decode renewed");
    assert_eq!(renewed.relay_slot_id, registered.relay_slot_id);
    assert!(renewed.expires_at > registered.expires_at);

    let connect_req_id = next_req_id();
    let connect_request = Envelope::from_typed(
        connect_req_id,
        0,
        &WirePayload::RelayConnect(RelayConnect {
            relay_slot_id: renewed.relay_slot_id,
        }),
    )
    .expect("encode connect");
    let connect_response = requester_transport
        .request(&relay_peer, connect_request, Duration::from_secs(3))
        .await
        .expect("relay connect");
    assert_eq!(connect_response.r#type, MsgType::RelayConnect as u16);
    assert_eq!(connect_response.req_id, connect_req_id);
    assert_ne!(connect_response.flags & FLAG_RESPONSE, 0);

    let stream_req_id = next_req_id();
    let stream_request = Envelope::from_typed(
        stream_req_id,
        0,
        &WirePayload::RelayStream(RelayStream {
            relay_slot_id: renewed.relay_slot_id,
            stream_id: 42,
            kind: WireRelayPayloadKind::Control,
            payload: b"nat-bridge".to_vec(),
        }),
    )
    .expect("encode stream");
    let stream_response = requester_transport
        .request(&relay_peer, stream_request, Duration::from_secs(3))
        .await
        .expect("relay stream");
    assert_eq!(stream_response.r#type, MsgType::RelayStream as u16);
    assert_eq!(stream_response.req_id, stream_req_id);
    assert_ne!(stream_response.flags & FLAG_RESPONSE, 0);
    let relayed: RelayStream =
        crate::cbor::from_slice(&stream_response.payload).expect("decode stream");
    assert_eq!(relayed.stream_id, 42);
    assert_eq!(relayed.kind, WireRelayPayloadKind::Control);
    assert_eq!(relayed.payload, b"nat-bridge".to_vec());

    relay_task.abort();
}

#[tokio::test]
async fn state_persists_across_restart_with_memory_store() {
    let store = MemoryStore::new();
    let mut rng = OsRng;
    let key = SigningKey::generate(&mut rng);
    let share_id = ShareId::from_pubkey(&key.verifying_key());
    let peer = PeerAddr {
        ip: "10.0.0.20".parse().expect("valid ip"),
        port: 7002,
        transport: TransportProtocol::Tcp,
        pubkey_hint: None,
        relay_via: None,
    };

    let first = Node::start_with_store(NodeConfig::default(), store.clone())
        .await
        .expect("start first");
    first
        .record_peer_seen(peer.clone())
        .await
        .expect("record peer");
    first.subscribe(share_id).await.expect("subscribe");
    first
        .set_share_weight(share_id, 1.7)
        .await
        .expect("set weight");
    first
        .begin_partial_download([9u8; 32], "partial.tmp".into(), 10)
        .await
        .expect("begin partial");
    first
        .mark_partial_chunk_complete([9u8; 32], 2)
        .await
        .expect("mark chunk");
    first
        .set_encrypted_node_key(b"node-private-key", "pw")
        .await
        .expect("set key");
    first
        .set_blocklist_rules(
            share_id,
            BlocklistRules {
                blocked_share_ids: vec![[7u8; 32]],
                blocked_content_ids: vec![[8u8; 32]],
            },
        )
        .await
        .expect("set blocklist");
    first
        .enable_blocklist_share(share_id)
        .await
        .expect("enable blocklist");

    let second = Node::start_with_store(NodeConfig::default(), store.clone())
        .await
        .expect("start second");
    let state = second.state.read().await;
    assert_eq!(state.peer_db.total_known_peers(), 1);
    assert!(state.subscriptions.contains_key(&share_id.0));
    assert_eq!(state.share_weights.get(&share_id.0), Some(&1.7));
    assert!(state.enabled_blocklist_shares.contains(&share_id.0));
    let rules = state
        .blocklist_rules_by_share
        .get(&share_id.0)
        .expect("blocklist should persist");
    assert_eq!(rules.blocked_share_ids, vec![[7u8; 32]]);
    assert_eq!(rules.blocked_content_ids, vec![[8u8; 32]]);
    let partial = state
        .partial_downloads
        .get(&[9u8; 32])
        .expect("partial should persist");
    assert_eq!(partial.completed_chunks, vec![2]);
    drop(state);
    let decrypted = second
        .decrypt_node_key("pw")
        .await
        .expect("decrypt")
        .expect("has key");
    assert_eq!(decrypted, b"node-private-key");
}

/// After downloading with a `self_addr`, the downloader should appear
/// as a seeder in the DHT and the content should be in its blob store.
#[tokio::test]
async fn download_from_peers_self_seeds_after_completion() {
    let mut rng = OsRng;
    let server_node_key = SigningKey::generate(&mut rng);
    let client_node_key = SigningKey::generate(&mut rng);

    let server_handle = Node::start(NodeConfig::default())
        .await
        .expect("start server");
    let client_handle = Node::start(NodeConfig::default())
        .await
        .expect("start client");

    let port_probe = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind probe");
    let bind_addr = port_probe.local_addr().expect("probe addr");
    drop(port_probe);

    let server_task = server_handle.clone().start_tcp_dht_service(
        bind_addr,
        server_node_key.clone(),
        Capabilities::default(),
    );
    tokio::time::sleep(Duration::from_millis(50)).await;

    let content_dir = tempfile::tempdir().expect("content tmpdir");
    let payload = vec![55u8; crate::content::CHUNK_SIZE + 7];
    let desc = crate::content::describe_content(&payload);
    let server_peer = PeerAddr {
        ip: "127.0.0.1".parse().expect("ip"),
        port: bind_addr.port(),
        transport: TransportProtocol::Tcp,
        pubkey_hint: Some(server_node_key.verifying_key().to_bytes()),
        relay_via: None,
    };
    server_handle
        .register_content_from_bytes(server_peer.clone(), &payload, content_dir.path())
        .await
        .expect("register");

    let share = ShareKeypair::new(SigningKey::generate(&mut rng));
    let manifest = ManifestV1 {
        version: 1,
        share_pubkey: share.verifying_key().to_bytes(),
        share_id: share.share_id().0,
        seq: 1,
        created_at: 1_700_000_200,
        expires_at: None,
        title: Some("self-seed-test".into()),
        description: None,
        visibility: crate::manifest::ShareVisibility::Private,
        communities: vec![],
        items: vec![ItemV1 {
            content_id: desc.content_id.0,
            size: payload.len() as u64,
            name: "data.bin".into(),
            path: None,
            mime: None,
            tags: vec![],
            chunk_count: desc.chunk_count,
            chunk_list_hash: desc.chunk_list_hash,
        }],
        recommended_shares: vec![],
        signature: None,
    };
    server_handle
        .publish_share(manifest, &share)
        .await
        .expect("publish");

    client_handle
        .subscribe_with_pubkey(share.share_id(), Some(share.verifying_key().to_bytes()))
        .await
        .expect("subscribe");

    let transport = TcpSessionTransport {
        signing_key: client_node_key,
        capabilities: Capabilities::default(),
    };
    client_handle
        .sync_subscriptions_over_dht(&transport, std::slice::from_ref(&server_peer))
        .await
        .expect("sync");

    let client_self_addr = PeerAddr {
        ip: "192.168.1.50".parse().expect("ip"),
        port: 7001,
        transport: TransportProtocol::Tcp,
        pubkey_hint: None,
        relay_via: None,
    };

    let target = std::env::temp_dir().join(format!(
        "scp2p_selfseed_{}.bin",
        now_unix_secs().expect("now")
    ));
    client_handle
        .download_from_peers(
            &transport,
            std::slice::from_ref(&server_peer),
            desc.content_id.0,
            target.to_str().expect("utf8 path"),
            &FetchPolicy::default(),
            Some(client_self_addr.clone()),
            None,
        )
        .await
        .expect("download with self-seed");

    let read_back = std::fs::read(&target).expect("read target");
    assert_eq!(read_back, payload);

    // Verify the client now has the content path registered (no blob copy).
    {
        let state = client_handle.state.read().await;
        assert!(
            state.content_paths.contains_key(&desc.content_id.0),
            "client should have content path registered after self-seeding"
        );
        let registered_path = state.content_paths.get(&desc.content_id.0).unwrap();
        assert_eq!(registered_path, &target);
    }

    // Verify the client registered itself as a provider in its local DHT.
    {
        let mut state = client_handle.state.write().await;
        let now = now_unix_secs().expect("now");
        let val = state
            .dht
            .find_value(
                crate::dht_keys::content_provider_key(&desc.content_id.0),
                now,
            )
            .expect("provider entry should exist");
        let providers: crate::wire::Providers =
            crate::cbor::from_slice(&val.value).expect("decode providers");
        assert!(
            providers.providers.contains(&client_self_addr),
            "client should be listed as a provider"
        );
    }

    let _ = std::fs::remove_file(target);
    server_task.abort();
}

/// `reannounce_seeded_content` refreshes DHT provider records for all
/// locally stored content.
#[tokio::test]
async fn reannounce_seeded_content_refreshes_dht_entries() {
    let handle = Node::start(NodeConfig::default())
        .await
        .expect("start node");

    let payload = vec![88u8; 1024];
    let desc = crate::content::describe_content(&payload);
    let self_addr = PeerAddr {
        ip: "10.0.0.1".parse().expect("ip"),
        port: 7000,
        transport: TransportProtocol::Tcp,
        pubkey_hint: None,
        relay_via: None,
    };

    let content_dir = tempfile::tempdir().expect("content tmpdir");
    handle
        .register_content_from_bytes(self_addr.clone(), &payload, content_dir.path())
        .await
        .expect("register");

    // Clear the DHT entry to simulate TTL expiry.
    {
        let mut state = handle.state.write().await;
        let now = now_unix_secs().expect("now");
        // Store an empty Providers to simulate expiry.
        let empty = crate::wire::Providers {
            content_id: desc.content_id.0,
            providers: vec![],
            updated_at: now,
        };
        state
            .dht
            .store(
                crate::dht_keys::content_provider_key(&desc.content_id.0),
                crate::cbor::to_vec(&empty).expect("encode"),
                crate::dht::DEFAULT_TTL_SECS,
                now,
            )
            .expect("store empty");
    }

    // Re-announce.
    let count = handle
        .reannounce_seeded_content(self_addr.clone())
        .await
        .expect("reannounce");
    assert_eq!(count, 1, "should announce 1 content item");

    // Verify the provider is back.
    {
        let mut state = handle.state.write().await;
        let now = now_unix_secs().expect("now");
        let val = state
            .dht
            .find_value(
                crate::dht_keys::content_provider_key(&desc.content_id.0),
                now,
            )
            .expect("provider entry must exist");
        let providers: crate::wire::Providers =
            crate::cbor::from_slice(&val.value).expect("decode");
        assert!(
            providers.providers.contains(&self_addr),
            "self_addr should be re-announced"
        );
    }
}

/// `reannounce_subscribed_share_heads` refreshes the DHT share-head entry
/// for public subscriptions but NOT for private ones.
#[tokio::test]
async fn reannounce_share_heads_only_refreshes_public_subscriptions() {
    let handle = Node::start(NodeConfig::default()).await.expect("start");
    let mut rng = OsRng;

    // ── Set up a public share and a private share ──
    let public_kp = ShareKeypair::new(SigningKey::generate(&mut rng));
    let private_kp = ShareKeypair::new(SigningKey::generate(&mut rng));

    let public_manifest = ManifestV1 {
        version: 1,
        share_pubkey: public_kp.verifying_key().to_bytes(),
        share_id: public_kp.share_id().0,
        seq: 1,
        created_at: 1_700_000_000,
        expires_at: None,
        title: Some("public share".into()),
        description: None,
        visibility: crate::manifest::ShareVisibility::Public,
        communities: vec![],
        items: vec![],
        recommended_shares: vec![],
        signature: None,
    };
    let private_manifest = ManifestV1 {
        version: 1,
        share_pubkey: private_kp.verifying_key().to_bytes(),
        share_id: private_kp.share_id().0,
        seq: 1,
        created_at: 1_700_000_001,
        expires_at: None,
        title: Some("private share".into()),
        description: None,
        visibility: crate::manifest::ShareVisibility::Private,
        communities: vec![],
        items: vec![],
        recommended_shares: vec![],
        signature: None,
    };

    // Publish both (which publishes the share head + manifest).
    handle
        .publish_share(public_manifest, &public_kp)
        .await
        .expect("publish public");
    handle
        .publish_share(private_manifest, &private_kp)
        .await
        .expect("publish private");

    // Subscribe to both.
    handle
        .subscribe(public_kp.share_id())
        .await
        .expect("subscribe public");
    handle
        .subscribe(private_kp.share_id())
        .await
        .expect("subscribe private");

    // Sync subscriptions to populate latest_seq / latest_manifest_id.
    handle
        .sync_subscriptions()
        .await
        .expect("sync subscriptions");

    // Now simulate the publisher going offline: remove the share head
    // DHT entries (as if TTL expired).
    {
        let mut state = handle.state.write().await;
        let now = now_unix_secs().expect("now");
        // Overwrite with a short TTL that's already expired.
        let pub_key = crate::dht_keys::share_head_key(&public_kp.share_id());
        let priv_key = crate::dht_keys::share_head_key(&private_kp.share_id());
        state
            .dht
            .store(pub_key, vec![0], 1, now.saturating_sub(100))
            .expect("store expired");
        state
            .dht
            .store(priv_key, vec![0], 1, now.saturating_sub(100))
            .expect("store expired");
    }

    // Verify both entries are expired.
    {
        let mut state = handle.state.write().await;
        let now = now_unix_secs().expect("now");
        assert!(
            state
                .dht
                .find_value(crate::dht_keys::share_head_key(&public_kp.share_id()), now)
                .is_none(),
            "public head should be expired"
        );
        assert!(
            state
                .dht
                .find_value(crate::dht_keys::share_head_key(&private_kp.share_id()), now)
                .is_none(),
            "private head should be expired"
        );
    }

    // Run re-announcement.
    let refreshed = handle
        .reannounce_subscribed_share_heads()
        .await
        .expect("reannounce");
    assert_eq!(refreshed, 1, "only the public share should be refreshed");

    // Verify: public share head is back in DHT, private is not.
    {
        let mut state = handle.state.write().await;
        let now = now_unix_secs().expect("now");
        let pub_val = state
            .dht
            .find_value(crate::dht_keys::share_head_key(&public_kp.share_id()), now);
        assert!(
            pub_val.is_some(),
            "public share head should be refreshed in DHT"
        );
        let priv_val = state
            .dht
            .find_value(crate::dht_keys::share_head_key(&private_kp.share_id()), now);
        assert!(
            priv_val.is_none(),
            "private share head must NOT be refreshed"
        );
    }
}

// ── Relay tunnel tests ──────────────────────────────────────────

/// `RelayTunnelRegistry` register → forward → remove roundtrip.
#[tokio::test]
async fn relay_tunnel_registry_register_forward_remove() {
    use crate::relay::RelayTunnelRegistry;

    let registry = RelayTunnelRegistry::default();
    let slot_id = 42u64;

    // Register a tunnel and get a receiver.
    let mut rx = registry.register(slot_id, 16).await;
    assert!(registry.has_tunnel(slot_id).await);
    assert!(!registry.has_tunnel(999).await);

    // Forward a request through the tunnel.
    let request = Envelope {
        r#type: MsgType::GetChunk as u16,
        req_id: 100,
        flags: 0,
        payload: b"hello".to_vec(),
    };
    let response = Envelope {
        r#type: MsgType::GetChunk as u16,
        req_id: 100,
        flags: FLAG_RESPONSE,
        payload: b"chunk-data".to_vec(),
    };

    let response_clone = response.clone();
    let forward_handle = tokio::spawn({
        let registry = registry.clone();
        async move {
            registry
                .forward(slot_id, request, std::time::Duration::from_secs(5))
                .await
        }
    });

    // Simulate the bridge side: receive the forwarded request and reply.
    let (forwarded_req, reply_tx) = rx.recv().await.expect("should receive forwarded request");
    assert_eq!(forwarded_req.req_id, 100);
    assert_eq!(forwarded_req.payload, b"hello");
    reply_tx.send(response_clone).expect("send response");

    let result = forward_handle.await.expect("join").expect("forward");
    assert_eq!(result.payload, b"chunk-data");

    // Remove the tunnel.
    registry.remove(slot_id).await;
    assert!(!registry.has_tunnel(slot_id).await);
}

/// `relayed_self_addr` wraps the address with relay routing when a
/// relay slot is active, and passes through unchanged otherwise.
#[tokio::test]
async fn relayed_self_addr_wraps_with_relay_route() {
    let handle = Node::start(NodeConfig::default()).await.expect("start");

    let direct_addr = PeerAddr {
        ip: "192.168.1.10".parse().expect("ip"),
        port: 7000,
        transport: TransportProtocol::Tcp,
        pubkey_hint: None,
        relay_via: None,
    };

    // Without active relay — should pass through unchanged.
    let result = handle.relayed_self_addr(direct_addr.clone()).await;
    assert_eq!(result.relay_via, None);
    assert_eq!(result, direct_addr);

    // Set an active relay slot.
    let relay_addr = PeerAddr {
        ip: "1.2.3.4".parse().expect("ip"),
        port: 9000,
        transport: TransportProtocol::Tcp,
        pubkey_hint: None,
        relay_via: None,
    };
    {
        let mut state = handle.state.write().await;
        state.active_relay_slots.push(ActiveRelaySlot {
            relay_addr: relay_addr.clone(),
            slot_id: 77,
            expires_at: 9999999999,
        });
    }

    // Now should wrap with relay routing.
    let relayed = handle.relayed_self_addr(direct_addr.clone()).await;
    let route = relayed.relay_via.expect("should have relay_via");
    assert_eq!(*route.relay_addr, relay_addr);
    assert_eq!(route.slot_id, 77);
    assert_eq!(relayed.ip, direct_addr.ip);
    assert_eq!(relayed.port, direct_addr.port);
}

/// End-to-end relay tunnel test: firewalled node registers a tunnel on
/// the relay, then a downloader sends a GetChunk request through the
/// relay and receives the chunk data from the firewalled node.
#[tokio::test]
async fn tcp_relay_tunnel_forwards_chunk_request_to_firewalled_node() {
    // ── Set up the relay node R ──
    let relay_handle = Node::start(NodeConfig::default())
        .await
        .expect("start relay");
    let mut rng = OsRng;
    let relay_node_key = SigningKey::generate(&mut rng);

    let relay_probe = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind relay probe");
    let relay_bind = relay_probe.local_addr().expect("relay bind addr");
    drop(relay_probe);

    let relay_task = relay_handle.clone().start_tcp_dht_service(
        relay_bind,
        relay_node_key.clone(),
        Capabilities::default(),
    );
    tokio::time::sleep(Duration::from_millis(50)).await;

    let relay_peer = PeerAddr {
        ip: "127.0.0.1".parse().expect("ip"),
        port: relay_bind.port(),
        transport: TransportProtocol::Tcp,
        pubkey_hint: Some(relay_node_key.verifying_key().to_bytes()),
        relay_via: None,
    };

    // ── Set up the firewalled node F ──
    let fw_handle = Node::start(NodeConfig::default())
        .await
        .expect("start firewalled");
    let fw_key = SigningKey::generate(&mut rng);

    // Register some content on the firewalled node.
    let content_dir = tempfile::tempdir().expect("content tmpdir");
    let payload = vec![42u8; crate::content::CHUNK_SIZE + 100];
    let desc = crate::content::describe_content(&payload);
    let fw_direct_addr = PeerAddr {
        ip: "127.0.0.1".parse().expect("ip"),
        port: 1, // doesn't matter — firewalled, not directly reachable
        transport: TransportProtocol::Tcp,
        pubkey_hint: None,
        relay_via: None,
    };
    fw_handle
        .register_content_from_bytes(fw_direct_addr.clone(), &payload, content_dir.path())
        .await
        .expect("register content on firewalled node");

    // Register relay tunnel (F → R).
    let fw_connector = TcpSessionTransport {
        signing_key: fw_key,
        capabilities: Capabilities::default(),
    };
    let slot = fw_handle
        .register_relay_tunnel(&fw_connector, &relay_peer)
        .await
        .expect("register relay tunnel");
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Build the relayed address for F.
    let fw_relayed_addr = PeerAddr {
        ip: fw_direct_addr.ip,
        port: fw_direct_addr.port,
        transport: fw_direct_addr.transport,
        pubkey_hint: None,
        relay_via: Some(crate::peer::RelayRoute {
            relay_addr: Box::new(relay_peer.clone()),
            slot_id: slot.slot_id,
        }),
    };

    // ── Downloader D sends a GetChunk request through the relay ──
    let dl_key = SigningKey::generate(&mut rng);
    let dl_connector = TcpSessionTransport {
        signing_key: dl_key,
        capabilities: Capabilities::default(),
    };

    // Use RelayAwareTransport to fetch chunk hashes.
    use crate::net_fetch::RelayAwareTransport;
    let transport = RelayAwareTransport::new(&dl_connector);

    // First request: GetChunkHashes.
    let get_hashes_req = Envelope::from_typed(
        next_req_id(),
        0,
        &WirePayload::GetChunkHashes(crate::wire::GetChunkHashes {
            content_id: desc.content_id.0,
        }),
    )
    .expect("encode GetChunkHashes");
    let hashes_resp = transport
        .request(&fw_relayed_addr, get_hashes_req, Duration::from_secs(5))
        .await
        .expect("GetChunkHashes through relay");
    assert_eq!(hashes_resp.r#type, MsgType::ChunkHashList as u16);
    assert_ne!(hashes_resp.flags & FLAG_RESPONSE, 0);
    let chunk_hashes: crate::wire::ChunkHashList =
        crate::cbor::from_slice(&hashes_resp.payload).expect("decode chunk hashes");
    assert_eq!(chunk_hashes.hashes.len(), desc.chunk_count as usize);

    // Second request: GetChunk for the first chunk.
    let get_chunk_req = Envelope::from_typed(
        next_req_id(),
        0,
        &WirePayload::GetChunk(crate::wire::GetChunk {
            content_id: desc.content_id.0,
            chunk_index: 0,
        }),
    )
    .expect("encode GetChunk");
    let chunk_resp = transport
        .request(&fw_relayed_addr, get_chunk_req, Duration::from_secs(5))
        .await
        .expect("GetChunk through relay");
    assert_eq!(chunk_resp.r#type, MsgType::ChunkData as u16);
    assert_ne!(chunk_resp.flags & FLAG_RESPONSE, 0);
    let chunk_data: crate::wire::ChunkData =
        crate::cbor::from_slice(&chunk_resp.payload).expect("decode chunk data");
    assert_eq!(chunk_data.bytes.len(), crate::content::CHUNK_SIZE);
    // Verify chunk hash matches.
    let computed_hash = blake3::hash(&chunk_data.bytes);
    assert_eq!(computed_hash.as_bytes(), &chunk_hashes.hashes[0]);

    relay_task.abort();
}

/// Full relay-tunneled download: firewalled node F seeds content, relay
/// node R bridges the tunnel, and downloader D downloads the full
/// content through the relay using `download_from_peers`.
#[tokio::test]
async fn tcp_relay_tunnel_full_content_download() {
    // ── Relay node R ──
    let relay_handle = Node::start(NodeConfig::default())
        .await
        .expect("start relay");
    let mut rng = OsRng;
    let relay_node_key = SigningKey::generate(&mut rng);

    let relay_probe = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind relay");
    let relay_bind = relay_probe.local_addr().expect("relay addr");
    drop(relay_probe);

    let relay_task = relay_handle.clone().start_tcp_dht_service(
        relay_bind,
        relay_node_key.clone(),
        Capabilities::default(),
    );
    tokio::time::sleep(Duration::from_millis(50)).await;

    let relay_peer = PeerAddr {
        ip: "127.0.0.1".parse().expect("ip"),
        port: relay_bind.port(),
        transport: TransportProtocol::Tcp,
        pubkey_hint: Some(relay_node_key.verifying_key().to_bytes()),
        relay_via: None,
    };

    // ── Firewalled node F ──
    let fw_handle = Node::start(NodeConfig::default())
        .await
        .expect("start firewalled");
    let fw_key = SigningKey::generate(&mut rng);

    let content_dir = tempfile::tempdir().expect("content tmpdir");
    // Use 2+ chunks to exercise parallel download.
    let payload = vec![0xAB_u8; crate::content::CHUNK_SIZE * 2 + 500];
    let desc = crate::content::describe_content(&payload);

    let fw_direct_addr = PeerAddr {
        ip: "127.0.0.1".parse().expect("ip"),
        port: 1,
        transport: TransportProtocol::Tcp,
        pubkey_hint: None,
        relay_via: None,
    };
    fw_handle
        .register_content_from_bytes(fw_direct_addr.clone(), &payload, content_dir.path())
        .await
        .expect("register content");

    // Tunnel F → R.
    let fw_connector = TcpSessionTransport {
        signing_key: fw_key,
        capabilities: Capabilities::default(),
    };
    let slot = fw_handle
        .register_relay_tunnel(&fw_connector, &relay_peer)
        .await
        .expect("tunnel registered");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let fw_relayed = PeerAddr {
        relay_via: Some(crate::peer::RelayRoute {
            relay_addr: Box::new(relay_peer.clone()),
            slot_id: slot.slot_id,
        }),
        ..fw_direct_addr
    };

    // ── Downloader D ──
    let dl_handle = Node::start(NodeConfig::default())
        .await
        .expect("start downloader");
    let dl_key = SigningKey::generate(&mut rng);
    let dl_connector = TcpSessionTransport {
        signing_key: dl_key,
        capabilities: Capabilities::default(),
    };

    // The downloader needs content metadata in its content_catalog
    // before it can call download_from_peers.
    {
        let mut state = dl_handle.state.write().await;
        state.content_catalog.insert(
            desc.content_id.0,
            crate::content::ChunkedContent {
                content_id: desc.content_id,
                chunk_count: desc.chunk_count,
                chunk_list_hash: desc.chunk_list_hash,
                chunks: desc.chunks.clone(),
            },
        );
    }

    let target_path = std::env::temp_dir().join(format!(
        "scp2p_relay_download_{}.bin",
        now_unix_secs().expect("now")
    ));

    dl_handle
        .download_from_peers(
            &dl_connector,
            &[fw_relayed],
            desc.content_id.0,
            target_path.to_str().expect("utf8"),
            &FetchPolicy::default(),
            None,
            None,
        )
        .await
        .expect("download through relay tunnel");

    let read_back = std::fs::read(&target_path).expect("read downloaded file");
    assert_eq!(read_back.len(), payload.len());
    assert_eq!(read_back, payload);
    let _ = std::fs::remove_file(target_path);

    relay_task.abort();
}

/// Helper: bind a TCP port and return the address.
async fn allocate_tcp_addr() -> std::net::SocketAddr {
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind probe");
    let addr = probe.local_addr().expect("addr");
    drop(probe);
    addr
}

/// 5-node integration test: publisher -> 3 intermediary DHT nodes -> subscriber.
///
/// Validates DHT routing / convergence across a chain of 5 nodes where
/// no single node has a direct peer entry for both publisher and subscriber.
///
/// Topology: `Pub <-> A <-> B <-> C <-> Sub`
#[tokio::test]
async fn five_node_dht_convergence_and_sync() {
    let mut rng = OsRng;

    // Create 5 nodes.
    let publisher = Node::start(NodeConfig::default()).await.expect("pub");
    let node_a = Node::start(NodeConfig::default()).await.expect("A");
    let node_b = Node::start(NodeConfig::default()).await.expect("B");
    let node_c = Node::start(NodeConfig::default()).await.expect("C");
    let subscriber = Node::start(NodeConfig::default()).await.expect("sub");

    // Generate signing keys and bind addresses.
    let pub_key = SigningKey::generate(&mut rng);
    let a_key = SigningKey::generate(&mut rng);
    let b_key = SigningKey::generate(&mut rng);
    let c_key = SigningKey::generate(&mut rng);
    let sub_key = SigningKey::generate(&mut rng);

    let pub_addr = allocate_tcp_addr().await;
    let a_addr = allocate_tcp_addr().await;
    let b_addr = allocate_tcp_addr().await;
    let c_addr = allocate_tcp_addr().await;

    // Start TCP services.
    let pub_task =
        publisher
            .clone()
            .start_tcp_dht_service(pub_addr, pub_key.clone(), Capabilities::default());
    let a_task =
        node_a
            .clone()
            .start_tcp_dht_service(a_addr, a_key.clone(), Capabilities::default());
    let b_task =
        node_b
            .clone()
            .start_tcp_dht_service(b_addr, b_key.clone(), Capabilities::default());
    let c_task =
        node_c
            .clone()
            .start_tcp_dht_service(c_addr, c_key.clone(), Capabilities::default());
    tokio::time::sleep(Duration::from_millis(80)).await;

    // Build PeerAddr structs.
    let pub_peer = PeerAddr {
        ip: "127.0.0.1".parse().expect("ip"),
        port: pub_addr.port(),
        transport: TransportProtocol::Tcp,
        pubkey_hint: Some(pub_key.verifying_key().to_bytes()),
        relay_via: None,
    };
    let a_peer = PeerAddr {
        ip: "127.0.0.1".parse().expect("ip"),
        port: a_addr.port(),
        transport: TransportProtocol::Tcp,
        pubkey_hint: Some(a_key.verifying_key().to_bytes()),
        relay_via: None,
    };
    let b_peer = PeerAddr {
        ip: "127.0.0.1".parse().expect("ip"),
        port: b_addr.port(),
        transport: TransportProtocol::Tcp,
        pubkey_hint: Some(b_key.verifying_key().to_bytes()),
        relay_via: None,
    };
    let c_peer = PeerAddr {
        ip: "127.0.0.1".parse().expect("ip"),
        port: c_addr.port(),
        transport: TransportProtocol::Tcp,
        pubkey_hint: Some(c_key.verifying_key().to_bytes()),
        relay_via: None,
    };

    // NodeId helpers.
    let pub_nid = NodeId::from_pubkey_bytes(&pub_key.verifying_key().to_bytes());
    let a_nid = NodeId::from_pubkey_bytes(&a_key.verifying_key().to_bytes());
    let b_nid = NodeId::from_pubkey_bytes(&b_key.verifying_key().to_bytes());
    let c_nid = NodeId::from_pubkey_bytes(&c_key.verifying_key().to_bytes());

    // Wire up chain: Pub <-> A <-> B <-> C
    // Each node knows its immediate neighbors.
    publisher
        .dht_upsert_peer(pub_nid, a_nid, a_peer.clone())
        .await
        .expect("pub->A");
    node_a
        .dht_upsert_peer(a_nid, pub_nid, pub_peer.clone())
        .await
        .expect("A->pub");
    node_a
        .dht_upsert_peer(a_nid, b_nid, b_peer.clone())
        .await
        .expect("A->B");
    node_b
        .dht_upsert_peer(b_nid, a_nid, a_peer.clone())
        .await
        .expect("B->A");
    node_b
        .dht_upsert_peer(b_nid, c_nid, c_peer.clone())
        .await
        .expect("B->C");
    node_c
        .dht_upsert_peer(c_nid, b_nid, b_peer.clone())
        .await
        .expect("C->B");

    // Publisher publishes a share.
    let share = ShareKeypair::new(SigningKey::generate(&mut rng));
    let manifest = ManifestV1 {
        version: 1,
        share_pubkey: share.verifying_key().to_bytes(),
        share_id: share.share_id().0,
        seq: 1,
        created_at: 1_700_000_500,
        expires_at: None,
        title: Some("five-node-test".into()),
        description: Some("dht convergence integration".into()),
        visibility: crate::manifest::ShareVisibility::Private,
        communities: vec![],
        items: vec![ItemV1 {
            content_id: [55u8; 32],
            size: 100,
            name: "convergence.txt".into(),
            path: None,
            mime: None,
            tags: vec!["dht".into()],
            chunk_count: 0,
            chunk_list_hash: [0u8; 32],
        }],
        recommended_shares: vec![],
        signature: None,
    };
    publisher
        .publish_share(manifest, &share)
        .await
        .expect("publish");

    // Subscriber subscribes and syncs via node C (which is 3 hops from publisher).
    subscriber
        .subscribe_with_pubkey(share.share_id(), Some(share.verifying_key().to_bytes()))
        .await
        .expect("subscribe");

    let sub_transport = TcpSessionTransport {
        signing_key: sub_key,
        capabilities: Capabilities::default(),
    };
    // Subscriber only knows about node_c directly — must route through C->B->A->Pub.
    subscriber
        .sync_subscriptions_over_dht(&sub_transport, &[c_peer])
        .await
        .expect("sync through 5-node chain");

    // Verify the subscriber received the manifest.
    let hits = subscriber
        .search(SearchQuery {
            text: "convergence".into(),
        })
        .await
        .expect("search");
    assert_eq!(
        hits.len(),
        1,
        "subscriber should find the item via DHT convergence"
    );
    assert_eq!(hits[0].content_id, [55u8; 32]);

    pub_task.abort();
    a_task.abort();
    b_task.abort();
    c_task.abort();
}

/// Two-provider concurrent download integration test.
///
/// Two nodes register the same content and the subscriber downloads from both
/// providers in the seed list, validating swarm-style multi-peer retrieval.
#[tokio::test]
async fn multi_provider_concurrent_download() {
    let mut rng = OsRng;

    let provider1 = Node::start(NodeConfig::default()).await.expect("p1");
    let provider2 = Node::start(NodeConfig::default()).await.expect("p2");
    let subscriber = Node::start(NodeConfig::default()).await.expect("sub");

    let p1_key = SigningKey::generate(&mut rng);
    let p2_key = SigningKey::generate(&mut rng);
    let sub_key = SigningKey::generate(&mut rng);

    let p1_addr = allocate_tcp_addr().await;
    let p2_addr = allocate_tcp_addr().await;

    let p1_task =
        provider1
            .clone()
            .start_tcp_dht_service(p1_addr, p1_key.clone(), Capabilities::default());
    let p2_task =
        provider2
            .clone()
            .start_tcp_dht_service(p2_addr, p2_key.clone(), Capabilities::default());
    tokio::time::sleep(Duration::from_millis(50)).await;

    let p1_peer = PeerAddr {
        ip: "127.0.0.1".parse().expect("ip"),
        port: p1_addr.port(),
        transport: TransportProtocol::Tcp,
        pubkey_hint: Some(p1_key.verifying_key().to_bytes()),
        relay_via: None,
    };
    let p2_peer = PeerAddr {
        ip: "127.0.0.1".parse().expect("ip"),
        port: p2_addr.port(),
        transport: TransportProtocol::Tcp,
        pubkey_hint: Some(p2_key.verifying_key().to_bytes()),
        relay_via: None,
    };

    // Both providers register the same content.
    let content_dir1 = tempfile::tempdir().expect("tmpdir1");
    let content_dir2 = tempfile::tempdir().expect("tmpdir2");
    let payload = vec![42u8; crate::content::CHUNK_SIZE * 3 + 99];
    let desc = crate::content::describe_content(&payload);

    provider1
        .register_content_from_bytes(p1_peer.clone(), &payload, content_dir1.path())
        .await
        .expect("register p1");
    provider2
        .register_content_from_bytes(p2_peer.clone(), &payload, content_dir2.path())
        .await
        .expect("register p2");

    // Provider 1 publishes the share manifest.
    let share = ShareKeypair::new(SigningKey::generate(&mut rng));
    let manifest = ManifestV1 {
        version: 1,
        share_pubkey: share.verifying_key().to_bytes(),
        share_id: share.share_id().0,
        seq: 1,
        created_at: 1_700_000_600,
        expires_at: None,
        title: Some("multi-provider".into()),
        description: Some("concurrent download test".into()),
        visibility: crate::manifest::ShareVisibility::Private,
        communities: vec![],
        items: vec![ItemV1 {
            content_id: desc.content_id.0,
            size: payload.len() as u64,
            name: "multi-provider.bin".into(),
            path: None,
            mime: None,
            tags: vec!["multi".into()],
            chunk_count: desc.chunk_count,
            chunk_list_hash: desc.chunk_list_hash,
        }],
        recommended_shares: vec![],
        signature: None,
    };
    provider1
        .publish_share(manifest, &share)
        .await
        .expect("publish");

    // Subscriber subscribes & syncs from provider1.
    subscriber
        .subscribe_with_pubkey(share.share_id(), Some(share.verifying_key().to_bytes()))
        .await
        .expect("subscribe");

    let transport = TcpSessionTransport {
        signing_key: sub_key,
        capabilities: Capabilities::default(),
    };
    subscriber
        .sync_subscriptions_over_dht(&transport, std::slice::from_ref(&p1_peer))
        .await
        .expect("sync");

    // Download with BOTH providers in the seed list.
    let target = std::env::temp_dir().join(format!(
        "scp2p_multi_provider_{}.bin",
        now_unix_secs().expect("now"),
    ));
    subscriber
        .download_from_peers(
            &transport,
            &[p1_peer, p2_peer],
            desc.content_id.0,
            target.to_str().expect("utf8"),
            &FetchPolicy::default(),
            None,
            None,
        )
        .await
        .expect("download from multiple providers");

    let read_back = std::fs::read(&target).expect("read target");
    assert_eq!(read_back.len(), payload.len());
    assert_eq!(read_back, payload);
    let _ = std::fs::remove_file(target);

    p1_task.abort();
    p2_task.abort();
}

// ── Community membership token tests (§4.2) ─────────────────────────

#[test]
fn community_membership_token_issue_and_verify() {
    use ed25519_dalek::SigningKey;
    use rand::SeedableRng;

    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    let community_key = SigningKey::generate(&mut rng);
    let member_key = SigningKey::generate(&mut rng);
    let member_pubkey = member_key.verifying_key().to_bytes();
    let community_pubkey = community_key.verifying_key().to_bytes();

    let token =
        CommunityMembershipToken::issue(&community_key, member_pubkey, 1_000_000, 2_000_000)
            .expect("issue token");

    // Verify should succeed.
    token
        .verify(&community_pubkey, Some(1_500_000))
        .expect("token should verify");

    // Verify with no timestamp check.
    token
        .verify(&community_pubkey, None)
        .expect("token should verify without timestamp");
}

#[test]
fn community_membership_token_rejects_expired() {
    use ed25519_dalek::SigningKey;
    use rand::SeedableRng;

    let mut rng = rand::rngs::StdRng::seed_from_u64(43);
    let community_key = SigningKey::generate(&mut rng);
    let member_key = SigningKey::generate(&mut rng);
    let member_pubkey = member_key.verifying_key().to_bytes();
    let community_pubkey = community_key.verifying_key().to_bytes();

    let token =
        CommunityMembershipToken::issue(&community_key, member_pubkey, 1_000_000, 1_500_000)
            .expect("issue token");

    let err = token
        .verify(&community_pubkey, Some(2_000_000))
        .expect_err("expired token should fail");
    assert!(err.to_string().contains("expired"));
}

#[test]
fn community_membership_token_rejects_wrong_pubkey() {
    use ed25519_dalek::SigningKey;
    use rand::SeedableRng;

    let mut rng = rand::rngs::StdRng::seed_from_u64(44);
    let community_key = SigningKey::generate(&mut rng);
    let wrong_key = SigningKey::generate(&mut rng);
    let member_key = SigningKey::generate(&mut rng);
    let member_pubkey = member_key.verifying_key().to_bytes();
    let wrong_pubkey = wrong_key.verifying_key().to_bytes();

    let token =
        CommunityMembershipToken::issue(&community_key, member_pubkey, 1_000_000, 2_000_000)
            .expect("issue token");

    let err = token
        .verify(&wrong_pubkey, None)
        .expect_err("wrong pubkey should fail");
    assert!(
        err.to_string().contains("does not match") || err.to_string().contains("signature"),
        "error should indicate mismatch or signature failure: {err}"
    );
}

#[test]
fn community_membership_token_roundtrip_cbor() {
    use ed25519_dalek::SigningKey;
    use rand::SeedableRng;

    let mut rng = rand::rngs::StdRng::seed_from_u64(45);
    let community_key = SigningKey::generate(&mut rng);
    let member_key = SigningKey::generate(&mut rng);
    let member_pubkey = member_key.verifying_key().to_bytes();
    let community_pubkey = community_key.verifying_key().to_bytes();

    let token = CommunityMembershipToken::issue(&community_key, member_pubkey, 100, 200)
        .expect("issue token");

    let bytes = crate::cbor::to_vec(&token).expect("encode token");
    let decoded: CommunityMembershipToken = crate::cbor::from_slice(&bytes).expect("decode token");
    assert_eq!(decoded, token);

    // Decoded copy should also verify
    decoded
        .verify(&community_pubkey, Some(150))
        .expect("decoded token should verify");
}

#[tokio::test]
async fn join_community_with_valid_token() {
    use ed25519_dalek::SigningKey;
    use rand::SeedableRng;

    let mut rng = rand::rngs::StdRng::seed_from_u64(46);
    let community_key = SigningKey::generate(&mut rng);
    let community_pubkey = community_key.verifying_key().to_bytes();
    let community_vk = VerifyingKey::from_bytes(&community_pubkey).unwrap();
    let community_share_id = ShareId::from_pubkey(&community_vk);

    let node_key = SigningKey::generate(&mut rng);
    let node_pubkey = node_key.verifying_key().to_bytes();

    let token = CommunityMembershipToken::issue(&community_key, node_pubkey, 100, 999_999_999)
        .expect("issue token");

    let handle = Node::start(NodeConfig::default()).await.expect("start");
    handle
        .join_community_with_token(community_share_id, community_pubkey, Some(token))
        .await
        .expect("join with valid token");

    let communities = handle.communities().await;
    assert_eq!(communities.len(), 1);
    assert!(
        communities[0].membership_token.is_some(),
        "persisted community should have token"
    );
}

#[tokio::test]
async fn join_community_with_invalid_token_rejected() {
    use ed25519_dalek::SigningKey;
    use rand::SeedableRng;

    let mut rng = rand::rngs::StdRng::seed_from_u64(47);
    let community_key = SigningKey::generate(&mut rng);
    let wrong_key = SigningKey::generate(&mut rng);
    let community_pubkey = community_key.verifying_key().to_bytes();
    let community_vk = VerifyingKey::from_bytes(&community_pubkey).unwrap();
    let community_share_id = ShareId::from_pubkey(&community_vk);

    let node_key = SigningKey::generate(&mut rng);
    let node_pubkey = node_key.verifying_key().to_bytes();

    // Token signed by wrong key
    let bad_token = CommunityMembershipToken::issue(&wrong_key, node_pubkey, 100, 999_999_999)
        .expect("issue wrong token");
    // Manually fix the community_share_id so the check reaches verification
    let mut patched = bad_token;
    patched.community_share_id = community_share_id.0;

    let handle = Node::start(NodeConfig::default()).await.expect("start");
    let err = handle
        .join_community_with_token(community_share_id, community_pubkey, Some(patched))
        .await
        .expect_err("invalid token should be rejected");
    assert!(
        err.to_string().contains("signature") || err.to_string().contains("does not match"),
        "error: {err}"
    );
}

// ── §4.13 Handler coverage for PEX / HaveContent / RelayList ──

#[tokio::test]
async fn handle_pex_request_returns_pex_offer() {
    let handle = Node::start(NodeConfig::default()).await.expect("start");
    // Seed a peer so there's something to return.
    let seed_peer = PeerAddr {
        ip: "10.0.0.5".parse().unwrap(),
        port: 7005,
        transport: TransportProtocol::Quic,
        pubkey_hint: None,
        relay_via: None,
    };
    handle
        .apply_pex_offer(PexOffer {
            peers: vec![seed_peer],
        })
        .await
        .expect("seed");

    let req = Envelope::from_typed(
        1,
        0x0001,
        &WirePayload::PexRequest(PexRequest { max_peers: 10 }),
    )
    .expect("encode");
    let resp = handle.handle_incoming_envelope(req, None).await.unwrap();
    assert_eq!(resp.r#type, MsgType::PexOffer as u16);
    let decoded: PexOffer = crate::cbor::from_slice(&resp.payload).expect("decode");
    assert_eq!(decoded.peers.len(), 1);
}

#[tokio::test]
async fn handle_pex_offer_ingests_peers() {
    let handle = Node::start(NodeConfig::default()).await.expect("start");
    let offer_peer = PeerAddr {
        ip: "10.0.0.6".parse().unwrap(),
        port: 7006,
        transport: TransportProtocol::Quic,
        pubkey_hint: None,
        relay_via: None,
    };
    let req = Envelope::from_typed(
        1,
        0x0001,
        &WirePayload::PexOffer(PexOffer {
            peers: vec![offer_peer],
        }),
    )
    .expect("encode");
    let resp = handle.handle_incoming_envelope(req, None).await.unwrap();
    assert_eq!(resp.r#type, MsgType::PexOffer as u16);
    // Verify the peer was ingested.
    let records = handle.peer_records().await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].addr.port, 7006);
}

#[tokio::test]
async fn handle_have_content_returns_ack() {
    let handle = Node::start(NodeConfig::default()).await.expect("start");
    let req = Envelope::from_typed(
        1,
        0x0001,
        &WirePayload::HaveContent(crate::wire::HaveContent {
            content_id: [42u8; 32],
        }),
    )
    .expect("encode");
    let resp = handle.handle_incoming_envelope(req, None).await.unwrap();
    assert_eq!(resp.r#type, MsgType::HaveContent as u16);
    assert!(resp.payload.is_empty());
}

#[tokio::test]
async fn handle_relay_list_request_returns_empty() {
    let handle = Node::start(NodeConfig::default()).await.expect("start");
    let req = Envelope::from_typed(
        1,
        0x0001,
        &WirePayload::RelayListRequest(crate::wire::RelayListRequest { max_count: 10 }),
    )
    .expect("encode");
    let resp = handle.handle_incoming_envelope(req, None).await.unwrap();
    assert_eq!(resp.r#type, MsgType::RelayListResponse as u16);
    let decoded: crate::wire::RelayListResponse =
        crate::cbor::from_slice(&resp.payload).expect("decode");
    assert!(decoded.announcements.is_empty());
}
