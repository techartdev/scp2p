use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::Mutex,
};

use crate::{
    content::{verify_chunk, verify_content},
    ids::ContentId,
    manifest::ManifestV1,
    peer::PeerAddr,
    transport::{read_envelope, write_envelope},
    wire::{
        ChunkData, Envelope, GetChunk, GetManifest, ManifestData, MsgType, WirePayload, FLAG_ERROR,
    },
};

pub trait AsyncIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> AsyncIo for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub type BoxedStream = Box<dyn AsyncIo>;

#[async_trait]
pub trait PeerConnector: Send + Sync {
    async fn connect(&self, peer: &PeerAddr) -> anyhow::Result<BoxedStream>;
}

#[async_trait]
pub trait RequestTransport: Send + Sync {
    async fn request(
        &self,
        peer: &PeerAddr,
        request: Envelope,
        timeout_dur: Duration,
    ) -> anyhow::Result<Envelope>;
}

#[async_trait]
impl<C: PeerConnector> RequestTransport for C {
    async fn request(
        &self,
        peer: &PeerAddr,
        request: Envelope,
        timeout_dur: Duration,
    ) -> anyhow::Result<Envelope> {
        let mut stream = self.connect(peer).await?;
        send_request_on_stream(&mut stream, request, timeout_dur).await
    }
}

pub struct DirectRequestTransport<C> {
    connector: C,
}

impl<C> DirectRequestTransport<C> {
    pub fn new(connector: C) -> Self {
        Self { connector }
    }
}

#[async_trait]
impl<C: PeerConnector> RequestTransport for DirectRequestTransport<C> {
    async fn request(
        &self,
        peer: &PeerAddr,
        request: Envelope,
        timeout_dur: Duration,
    ) -> anyhow::Result<Envelope> {
        let mut stream = self.connector.connect(peer).await?;
        send_request_on_stream(&mut stream, request, timeout_dur).await
    }
}

pub struct SessionPoolTransport<C> {
    connector: C,
    sessions: Mutex<HashMap<String, BoxedStream>>,
}

impl<C> SessionPoolTransport<C> {
    pub fn new(connector: C) -> Self {
        Self {
            connector,
            sessions: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl<C: PeerConnector> RequestTransport for SessionPoolTransport<C> {
    async fn request(
        &self,
        peer: &PeerAddr,
        request: Envelope,
        timeout_dur: Duration,
    ) -> anyhow::Result<Envelope> {
        let key = peer_key(peer);
        let mut stream = {
            let mut sessions = self.sessions.lock().await;
            sessions.remove(&key)
        };

        if stream.is_none() {
            stream = Some(self.connector.connect(peer).await?);
        }

        let mut stream = stream.expect("stream must be initialized");
        match send_request_on_stream(&mut stream, request.clone(), timeout_dur).await {
            Ok(response) => {
                let mut sessions = self.sessions.lock().await;
                sessions.insert(key, stream);
                Ok(response)
            }
            Err(first_err) => {
                // drop broken stream and redial once for retry.
                let mut fresh_stream = self.connector.connect(peer).await?;
                let response = send_request_on_stream(&mut fresh_stream, request, timeout_dur)
                    .await
                    .map_err(|_| first_err)?;
                let mut sessions = self.sessions.lock().await;
                sessions.insert(key, fresh_stream);
                Ok(response)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct FetchPolicy {
    pub attempts_per_peer: usize,
    pub request_timeout: Duration,
    pub max_chunks_per_peer: usize,
    pub failure_backoff_base: Duration,
    pub max_backoff: Duration,
}

impl Default for FetchPolicy {
    fn default() -> Self {
        Self {
            attempts_per_peer: 2,
            request_timeout: Duration::from_secs(3),
            max_chunks_per_peer: 128,
            failure_backoff_base: Duration::from_millis(300),
            max_backoff: Duration::from_secs(8),
        }
    }
}

pub async fn fetch_manifest_with_retry<T: RequestTransport + ?Sized>(
    transport: &T,
    peers: &[PeerAddr],
    manifest_id: [u8; 32],
    policy: &FetchPolicy,
) -> anyhow::Result<ManifestV1> {
    if peers.is_empty() {
        anyhow::bail!("no peers available for manifest fetch");
    }

    let mut req_id = 1u32;
    let mut last_err = None;
    for attempt in 0..policy.attempts_per_peer {
        for offset in 0..peers.len() {
            let idx = (attempt + offset) % peers.len();
            let target = &peers[idx];
            let result = fetch_manifest_once(transport, target, manifest_id, req_id, policy).await;
            req_id = req_id.wrapping_add(1);
            match result {
                Ok(manifest) => return Ok(manifest),
                Err(err) => last_err = Some(err),
            }
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("manifest fetch failed")))
}

pub async fn download_swarm_over_network<T: RequestTransport + ?Sized>(
    transport: &T,
    peers: &[PeerAddr],
    content_id: [u8; 32],
    chunk_hashes: &[[u8; 32]],
    policy: &FetchPolicy,
) -> anyhow::Result<Vec<u8>> {
    if peers.is_empty() {
        anyhow::bail!("no peers available for content download");
    }

    let mut req_id = 10_000u32;
    let mut output = Vec::new();
    let mut stats = peers
        .iter()
        .map(|peer| (peer_key(peer), PeerRuntimeStats::default()))
        .collect::<HashMap<_, _>>();

    for (chunk_idx, expected_hash) in chunk_hashes.iter().enumerate() {
        let mut chunk = None;
        let now = Instant::now();
        let mut ordered = peers.iter().collect::<Vec<_>>();
        ordered.sort_by(|a, b| {
            let a_key = peer_key(a);
            let b_key = peer_key(b);
            let a_stats = stats.get(&a_key).expect("exists");
            let b_stats = stats.get(&b_key).expect("exists");
            b_stats
                .score
                .cmp(&a_stats.score)
                .then(a_stats.requests.cmp(&b_stats.requests))
        });

        for peer in ordered {
            let key = peer_key(peer);
            let s = stats.get_mut(&key).expect("exists");
            if s.requests >= policy.max_chunks_per_peer {
                continue;
            }
            if let Some(until) = s.backoff_until {
                if until > now {
                    continue;
                }
            }

            s.requests += 1;
            let result = fetch_chunk_once(
                transport,
                peer,
                content_id,
                chunk_idx as u32,
                req_id,
                policy,
            )
            .await;
            req_id = req_id.wrapping_add(1);
            match result {
                Ok(bytes) => {
                    if verify_chunk(expected_hash, &bytes).is_ok() {
                        s.score += 2;
                        s.consecutive_failures = 0;
                        s.backoff_until = None;
                        chunk = Some(bytes);
                        break;
                    } else {
                        register_failure(s, policy, now);
                    }
                }
                Err(_) => register_failure(s, policy, now),
            }
        }

        let Some(bytes) = chunk else {
            anyhow::bail!("unable to retrieve verified chunk {}", chunk_idx);
        };
        output.extend_from_slice(&bytes);
    }

    verify_content(&ContentId(content_id), &output)?;
    Ok(output)
}

async fn fetch_manifest_once<T: RequestTransport + ?Sized>(
    transport: &T,
    peer: &PeerAddr,
    manifest_id: [u8; 32],
    req_id: u32,
    policy: &FetchPolicy,
) -> anyhow::Result<ManifestV1> {
    let request = Envelope::from_typed(
        req_id,
        0,
        &WirePayload::GetManifest(GetManifest { manifest_id }),
    )?;
    let response = transport
        .request(peer, request, policy.request_timeout)
        .await?;

    if response.req_id != req_id {
        anyhow::bail!("manifest response req_id mismatch");
    }
    if response.r#type != MsgType::ManifestData as u16 {
        anyhow::bail!("unexpected response type for manifest request");
    }
    let payload = response.decode_typed()?;
    let WirePayload::ManifestData(ManifestData {
        manifest_id: returned_id,
        bytes,
    }) = payload
    else {
        anyhow::bail!("invalid manifest response payload");
    };
    if returned_id != manifest_id {
        anyhow::bail!("manifest id mismatch");
    }

    let manifest: ManifestV1 = serde_cbor::from_slice(&bytes)?;
    if manifest.manifest_id()?.0 != manifest_id {
        anyhow::bail!("manifest bytes hash does not match manifest_id");
    }
    Ok(manifest)
}

async fn fetch_chunk_once<T: RequestTransport + ?Sized>(
    transport: &T,
    peer: &PeerAddr,
    content_id: [u8; 32],
    chunk_index: u32,
    req_id: u32,
    policy: &FetchPolicy,
) -> anyhow::Result<Vec<u8>> {
    let request = Envelope::from_typed(
        req_id,
        0,
        &WirePayload::GetChunk(GetChunk {
            content_id,
            chunk_index,
        }),
    )?;
    let response = transport
        .request(peer, request, policy.request_timeout)
        .await?;

    if response.req_id != req_id {
        anyhow::bail!("chunk response req_id mismatch");
    }
    if response.r#type != MsgType::ChunkData as u16 {
        anyhow::bail!("unexpected response type for chunk request");
    }
    let payload = response.decode_typed()?;
    let WirePayload::ChunkData(ChunkData {
        content_id: returned_content,
        chunk_index: returned_index,
        bytes,
    }) = payload
    else {
        anyhow::bail!("invalid chunk response payload");
    };
    if returned_content != content_id || returned_index != chunk_index {
        anyhow::bail!("chunk response mismatch");
    }
    Ok(bytes)
}

async fn send_request_on_stream(
    stream: &mut BoxedStream,
    request: Envelope,
    timeout_dur: Duration,
) -> anyhow::Result<Envelope> {
    tokio::time::timeout(timeout_dur, write_envelope(stream, &request))
        .await
        .map_err(|_| anyhow::anyhow!("request write timed out"))??;
    let response = tokio::time::timeout(timeout_dur, read_envelope(stream))
        .await
        .map_err(|_| anyhow::anyhow!("response read timed out"))??;
    if response.flags & FLAG_ERROR != 0 {
        let msg = if response.payload.is_empty() {
            "peer returned protocol error".to_string()
        } else if let Ok(text) = String::from_utf8(response.payload.clone()) {
            text
        } else {
            format!(
                "peer returned protocol error ({} bytes)",
                response.payload.len()
            )
        };
        anyhow::bail!("{msg}");
    }
    Ok(response)
}

#[derive(Debug, Default)]
struct PeerRuntimeStats {
    score: i32,
    requests: usize,
    consecutive_failures: u32,
    backoff_until: Option<Instant>,
}

fn register_failure(stats: &mut PeerRuntimeStats, policy: &FetchPolicy, now: Instant) {
    stats.score -= 1;
    stats.consecutive_failures = stats.consecutive_failures.saturating_add(1);
    let exp = stats.consecutive_failures.saturating_sub(1).min(8);
    let factor = 1u32 << exp;
    let mut backoff = policy.failure_backoff_base.saturating_mul(factor);
    if backoff > policy.max_backoff {
        backoff = policy.max_backoff;
    }
    stats.backoff_until = Some(now + backoff);
}

fn peer_key(peer: &PeerAddr) -> String {
    format!("{}:{}:{:?}", peer.ip, peer.port, peer.transport)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        future::Future,
        pin::Pin,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    };

    use tokio::{io::DuplexStream, sync::RwLock};

    use super::*;
    use crate::{
        content::{describe_content, CHUNK_SIZE},
        peer::TransportProtocol,
        wire::{GetChunk, GetManifest},
    };

    type ConnectFuture = Pin<Box<dyn Future<Output = anyhow::Result<BoxedStream>> + Send>>;
    type Handler = Box<dyn Fn() -> ConnectFuture + Send + Sync>;
    type HandlerMap = Arc<RwLock<HashMap<String, Handler>>>;

    struct MockConnector {
        handlers: HandlerMap,
    }

    impl MockConnector {
        fn new() -> Self {
            Self {
                handlers: Arc::new(RwLock::new(HashMap::new())),
            }
        }

        async fn register<F, Fut>(&self, peer: &PeerAddr, factory: F)
        where
            F: Fn() -> Fut + Send + Sync + 'static,
            Fut: Future<Output = anyhow::Result<BoxedStream>> + Send + 'static,
        {
            self.handlers
                .write()
                .await
                .insert(peer_key(peer), Box::new(move || Box::pin(factory())));
        }
    }

    #[async_trait]
    impl PeerConnector for MockConnector {
        async fn connect(&self, peer: &PeerAddr) -> anyhow::Result<BoxedStream> {
            let handlers = self.handlers.read().await;
            let Some(factory) = handlers.get(&peer_key(peer)) else {
                anyhow::bail!("no handler for peer");
            };
            (factory)().await
        }
    }

    fn make_peer(ip: &str, port: u16) -> PeerAddr {
        PeerAddr {
            ip: ip.parse().expect("valid ip"),
            port,
            transport: TransportProtocol::Tcp,
            pubkey_hint: None,
        }
    }

    async fn manifest_server(
        mut server: DuplexStream,
        manifest_bytes: Vec<u8>,
        manifest_id: [u8; 32],
    ) {
        let req = read_envelope(&mut server).await.expect("read request");
        let typed = req.decode_typed().expect("typed");
        let WirePayload::GetManifest(GetManifest {
            manifest_id: requested,
        }) = typed
        else {
            panic!("unexpected request type");
        };
        assert_eq!(requested, manifest_id);
        let resp = Envelope::from_typed(
            req.req_id,
            0x0001,
            &WirePayload::ManifestData(ManifestData {
                manifest_id,
                bytes: manifest_bytes,
            }),
        )
        .expect("resp");
        write_envelope(&mut server, &resp)
            .await
            .expect("write resp");
    }

    async fn chunk_server(
        mut server: DuplexStream,
        content_id: [u8; 32],
        chunk_index: u32,
        bytes: Vec<u8>,
    ) {
        let req = read_envelope(&mut server).await.expect("read request");
        let typed = req.decode_typed().expect("typed");
        let WirePayload::GetChunk(GetChunk {
            content_id: requested_id,
            chunk_index: requested_index,
        }) = typed
        else {
            panic!("unexpected request type");
        };
        assert_eq!(requested_id, content_id);
        assert_eq!(requested_index, chunk_index);
        let resp = Envelope::from_typed(
            req.req_id,
            0x0001,
            &WirePayload::ChunkData(ChunkData {
                content_id,
                chunk_index,
                bytes,
            }),
        )
        .expect("resp");
        write_envelope(&mut server, &resp)
            .await
            .expect("write resp");
    }

    #[tokio::test]
    async fn manifest_fetch_retries_and_rotates_peers() {
        let peer_a = make_peer("10.0.0.1", 7000);
        let peer_b = make_peer("10.0.0.2", 7000);
        let connector = MockConnector::new();
        let transport = DirectRequestTransport::new(connector);

        transport
            .connector
            .register(&peer_a, || async { anyhow::bail!("dial failed") })
            .await;

        let manifest = ManifestV1 {
            version: 1,
            share_pubkey: [1u8; 32],
            share_id: [2u8; 32],
            seq: 1,
            created_at: 1_700_000_000,
            expires_at: None,
            title: Some("m".into()),
            description: None,
            items: vec![],
            recommended_shares: vec![],
            signature: None,
        };
        let mut signed = manifest.clone();
        let kp =
            crate::manifest::ShareKeypair::new(ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]));
        signed.share_pubkey = kp.verifying_key().to_bytes();
        signed.share_id = kp.share_id().0;
        signed.sign(&kp).expect("sign");
        let manifest_id = signed.manifest_id().expect("id").0;
        let manifest_bytes = serde_cbor::to_vec(&signed).expect("bytes");

        transport
            .connector
            .register(&peer_b, {
                let manifest_bytes = manifest_bytes.clone();
                move || {
                    let manifest_bytes = manifest_bytes.clone();
                    async move {
                        let (client, server) = tokio::io::duplex(4096);
                        tokio::spawn(manifest_server(server, manifest_bytes, manifest_id));
                        Ok(Box::new(client) as BoxedStream)
                    }
                }
            })
            .await;

        let fetched = fetch_manifest_with_retry(
            &transport,
            &[peer_a, peer_b],
            manifest_id,
            &FetchPolicy::default(),
        )
        .await
        .expect("fetch manifest");
        assert_eq!(fetched.manifest_id().expect("id").0, manifest_id);
    }

    #[tokio::test]
    async fn chunk_fetch_downloads_and_verifies_content() {
        let peer_a = make_peer("10.0.0.3", 7000);
        let peer_b = make_peer("10.0.0.4", 7000);
        let connector = MockConnector::new();
        let transport = DirectRequestTransport::new(connector);

        let bytes = vec![5u8; CHUNK_SIZE + 5];
        let desc = describe_content(&bytes);
        let chunk0 = bytes[..CHUNK_SIZE].to_vec();
        let chunk1 = bytes[CHUNK_SIZE..].to_vec();
        let cid = desc.content_id.0;

        transport
            .connector
            .register(&peer_a, {
                let chunk0 = chunk0.clone();
                move || {
                    let value = chunk0.clone();
                    async move {
                        let (client, server) = tokio::io::duplex(4096);
                        tokio::spawn(chunk_server(server, cid, 0, value.clone()));
                        Ok(Box::new(client) as BoxedStream)
                    }
                }
            })
            .await;
        transport
            .connector
            .register(&peer_b, {
                let chunk1 = chunk1.clone();
                move || {
                    let value = chunk1.clone();
                    async move {
                        let (client, server) = tokio::io::duplex(4096);
                        tokio::spawn(chunk_server(server, cid, 1, value.clone()));
                        Ok(Box::new(client) as BoxedStream)
                    }
                }
            })
            .await;

        let policy = FetchPolicy {
            max_chunks_per_peer: 1,
            ..FetchPolicy::default()
        };
        let out =
            download_swarm_over_network(&transport, &[peer_a, peer_b], cid, &desc.chunks, &policy)
                .await
                .expect("download");
        assert_eq!(out, bytes);
    }

    #[tokio::test]
    async fn session_pool_reuses_connection_for_multiple_chunk_requests() {
        let peer = make_peer("10.0.0.5", 7000);
        let connector = MockConnector::new();
        let dial_count = Arc::new(AtomicUsize::new(0));
        let bytes = vec![8u8; CHUNK_SIZE - 17];
        let desc = describe_content(&bytes);
        let cid = desc.content_id.0;

        connector
            .register(&peer, {
                let dial_count = dial_count.clone();
                let first = bytes.clone();
                move || {
                    let dial_count = dial_count.clone();
                    let first = first.clone();
                    async move {
                        dial_count.fetch_add(1, Ordering::SeqCst);
                        let (client, mut server) = tokio::io::duplex(8192);
                        tokio::spawn(async move {
                            for _ in 0..2 {
                                let req = read_envelope(&mut server).await.expect("read request");
                                let typed = req.decode_typed().expect("typed");
                                let WirePayload::GetChunk(GetChunk {
                                    content_id: requested_id,
                                    chunk_index: requested_index,
                                }) = typed
                                else {
                                    panic!("unexpected request type");
                                };
                                assert_eq!(requested_id, cid);
                                assert_eq!(requested_index, 0);
                                let resp = Envelope::from_typed(
                                    req.req_id,
                                    0x0001,
                                    &WirePayload::ChunkData(ChunkData {
                                        content_id: cid,
                                        chunk_index: 0,
                                        bytes: first.clone(),
                                    }),
                                )
                                .expect("resp");
                                write_envelope(&mut server, &resp)
                                    .await
                                    .expect("write resp");
                            }
                        });
                        Ok(Box::new(client) as BoxedStream)
                    }
                }
            })
            .await;

        // For this test, use a single-chunk content so one request is enough and reuse is observable
        // by forcing two sequential downloads against same peer.
        let pool = SessionPoolTransport::new(connector);
        let single_chunk = vec![desc.chunks[0]];
        let p = FetchPolicy::default();
        let _ =
            download_swarm_over_network(&pool, std::slice::from_ref(&peer), cid, &single_chunk, &p)
                .await
                .expect("download1");
        let _ =
            download_swarm_over_network(&pool, std::slice::from_ref(&peer), cid, &single_chunk, &p)
                .await
                .expect("download2");

        assert_eq!(dial_count.load(Ordering::SeqCst), 1);
    }
}
