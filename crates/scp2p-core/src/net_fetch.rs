// Copyright (c) 2024-2026 Vanyo Vanev / Tech Art Ltd
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

use futures_util::stream::{FuturesUnordered, StreamExt};

use async_trait::async_trait;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::Mutex,
};

use crate::{
    content::{compute_chunk_list_hash, verify_chunk, verify_content},
    ids::ContentId,
    manifest::ManifestV1,
    peer::PeerAddr,
    transport::{read_envelope, write_envelope},
    wire::{
        ChunkData, ChunkHashList, Envelope, GetChunk, GetChunkHashes, GetManifest, ManifestData,
        MsgType, WirePayload, FLAG_ERROR,
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
    /// Maximum number of chunk requests in flight at once across all peers.
    /// Higher values improve throughput when multiple peers are available.
    pub parallel_chunks: usize,
}

impl Default for FetchPolicy {
    fn default() -> Self {
        Self {
            attempts_per_peer: 2,
            request_timeout: Duration::from_secs(3),
            max_chunks_per_peer: 128,
            failure_backoff_base: Duration::from_millis(300),
            max_backoff: Duration::from_secs(8),
            parallel_chunks: 8,
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

/// Fetch the chunk hash list for a content ID from a set of peers, verifying
/// the result against the expected `chunk_list_hash` commitment.
pub async fn fetch_chunk_hashes_with_retry<T: RequestTransport + ?Sized>(
    transport: &T,
    peers: &[PeerAddr],
    content_id: [u8; 32],
    expected_chunk_count: u32,
    expected_chunk_list_hash: [u8; 32],
    policy: &FetchPolicy,
) -> anyhow::Result<Vec<[u8; 32]>> {
    if peers.is_empty() {
        anyhow::bail!("no peers available for chunk hash fetch");
    }

    let mut req_id = 5_000u32;
    let mut last_err = None;
    for attempt in 0..policy.attempts_per_peer {
        for offset in 0..peers.len() {
            let idx = (attempt + offset) % peers.len();
            let target = &peers[idx];
            let result =
                fetch_chunk_hashes_once(transport, target, content_id, req_id, policy).await;
            req_id = req_id.wrapping_add(1);
            match result {
                Ok(hashes) => {
                    if hashes.len() != expected_chunk_count as usize {
                        last_err = Some(anyhow::anyhow!(
                            "chunk hash count mismatch: got {} expected {}",
                            hashes.len(),
                            expected_chunk_count
                        ));
                        continue;
                    }
                    let actual_hash = compute_chunk_list_hash(&hashes);
                    if actual_hash != expected_chunk_list_hash {
                        last_err = Some(anyhow::anyhow!("chunk_list_hash verification failed"));
                        continue;
                    }
                    return Ok(hashes);
                }
                Err(err) => last_err = Some(err),
            }
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("chunk hash fetch failed")))
}

async fn fetch_chunk_hashes_once<T: RequestTransport + ?Sized>(
    transport: &T,
    peer: &PeerAddr,
    content_id: [u8; 32],
    req_id: u32,
    policy: &FetchPolicy,
) -> anyhow::Result<Vec<[u8; 32]>> {
    let request = Envelope::from_typed(
        req_id,
        0,
        &WirePayload::GetChunkHashes(GetChunkHashes { content_id }),
    )?;
    let response = transport
        .request(peer, request, policy.request_timeout)
        .await?;

    if response.req_id != req_id {
        anyhow::bail!("chunk hash response req_id mismatch");
    }
    if response.r#type != MsgType::ChunkHashList as u16 {
        anyhow::bail!("unexpected response type for chunk hash request");
    }
    let payload = response.decode_typed()?;
    let WirePayload::ChunkHashList(ChunkHashList {
        content_id: returned_id,
        hashes,
    }) = payload
    else {
        anyhow::bail!("invalid chunk hash response payload");
    };
    if returned_id != content_id {
        anyhow::bail!("chunk hash content_id mismatch");
    }
    Ok(hashes)
}

/// Downloads content by fetching chunks from a set of peers **in parallel**.
///
/// Up to `policy.parallel_chunks` chunk requests are in flight at once.
/// Peers are ranked by a live score: fast, reliable peers accumulate score
/// and serve more chunks; failing peers get exponential back-off.  Chunks
/// that fail verification or time out are automatically retried on the next
/// best peer.
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

    let total_chunks = chunk_hashes.len();
    let max_parallel = policy.parallel_chunks.min(total_chunks).max(1);
    let max_retries_per_chunk = policy.attempts_per_peer * peers.len();
    let mut req_id = 10_000u32;

    let mut completed: Vec<Option<Vec<u8>>> = vec![None; total_chunks];
    let mut completed_count = 0usize;

    let mut stats: HashMap<String, PeerRuntimeStats> = peers
        .iter()
        .map(|peer| (peer_key(peer), PeerRuntimeStats::default()))
        .collect();

    // Work queues: fresh chunks + retries
    let mut next_chunk = 0usize;
    let mut retry_queue: VecDeque<(usize, usize)> = VecDeque::new();

    let mut in_flight = FuturesUnordered::new();
    let mut stall_count = 0usize;

    loop {
        // ── Schedule as many chunks as the parallelism window allows ──
        while in_flight.len() < max_parallel {
            let (chunk_idx, retries) = if let Some(retry) = retry_queue.pop_front() {
                retry
            } else if next_chunk < total_chunks {
                let idx = next_chunk;
                next_chunk += 1;
                (idx, 0)
            } else {
                break;
            };

            if retries >= max_retries_per_chunk {
                anyhow::bail!(
                    "unable to retrieve verified chunk {} after {} attempts",
                    chunk_idx,
                    retries
                );
            }

            if let Some(peer_idx) = pick_best_peer_index(peers, &stats, policy) {
                let peer = peers[peer_idx].clone();
                let pk = peer_key(&peer);
                let rid = req_id;
                req_id = req_id.wrapping_add(1);
                if let Some(s) = stats.get_mut(&pk) {
                    s.requests += 1;
                    s.in_flight += 1;
                }
                let expected = chunk_hashes[chunk_idx];
                in_flight.push(fetch_one_chunk(
                    transport, peer, content_id, chunk_idx, rid, expected, pk, policy, retries,
                ));
            } else {
                // No eligible peer right now — put chunk back
                retry_queue.push_front((chunk_idx, retries));
                break;
            }
        }

        // ── Done? ──
        if completed_count == total_chunks {
            break;
        }

        // ── If nothing is in flight, peers may be in back-off; wait briefly ──
        if in_flight.is_empty() {
            stall_count += 1;
            if stall_count > 60 {
                anyhow::bail!(
                    "download stalled: no peers can serve remaining {}/{} chunks",
                    total_chunks - completed_count,
                    total_chunks
                );
            }
            tokio::time::sleep(policy.failure_backoff_base).await;
            continue;
        }
        stall_count = 0;

        // ── Wait for the next chunk to arrive ──
        let res = in_flight
            .next()
            .await
            .expect("non-empty FuturesUnordered");

        // Decrement in-flight counter
        if let Some(s) = stats.get_mut(&res.peer_key) {
            s.in_flight = s.in_flight.saturating_sub(1);
        }

        let now = Instant::now();
        match res.data {
            Ok(bytes) if verify_chunk(&res.expected_hash, &bytes).is_ok() => {
                if let Some(s) = stats.get_mut(&res.peer_key) {
                    s.score += 2;
                    s.consecutive_failures = 0;
                    s.backoff_until = None;
                }
                completed[res.chunk_idx] = Some(bytes);
                completed_count += 1;
            }
            Ok(_) => {
                // Hash mismatch — penalise peer, retry chunk
                if let Some(s) = stats.get_mut(&res.peer_key) {
                    register_failure(s, policy, now);
                }
                retry_queue.push_back((res.chunk_idx, res.retries + 1));
            }
            Err(_) => {
                if let Some(s) = stats.get_mut(&res.peer_key) {
                    register_failure(s, policy, now);
                }
                retry_queue.push_back((res.chunk_idx, res.retries + 1));
            }
        }
    }

    // Assemble output in chunk order
    let mut output = Vec::new();
    for chunk_data in completed {
        output.extend_from_slice(&chunk_data.expect("all chunks completed"));
    }

    verify_content(&ContentId(content_id), &output)?;
    Ok(output)
}

/// Outcome of a single chunk fetch attempt, returned from the in-flight
/// future back to the download loop.
struct ChunkFetchOutcome {
    chunk_idx: usize,
    peer_key: String,
    expected_hash: [u8; 32],
    data: anyhow::Result<Vec<u8>>,
    retries: usize,
}

/// Async helper that fetches one chunk from one peer and wraps the result.
///
/// Because every call site uses the same concrete `async fn`, all returned
/// futures share the same type — allowing `FuturesUnordered` to hold them
/// without boxing.
#[allow(clippy::too_many_arguments)]
async fn fetch_one_chunk<T: RequestTransport + ?Sized>(
    transport: &T,
    peer: PeerAddr,
    content_id: [u8; 32],
    chunk_idx: usize,
    req_id: u32,
    expected_hash: [u8; 32],
    peer_key: String,
    policy: &FetchPolicy,
    retries: usize,
) -> ChunkFetchOutcome {
    let data =
        fetch_chunk_once(transport, &peer, content_id, chunk_idx as u32, req_id, policy).await;
    ChunkFetchOutcome {
        chunk_idx,
        peer_key,
        expected_hash,
        data,
        retries,
    }
}

/// Pick the best eligible peer for a chunk request.  Selection criteria
/// (in order): highest score, fewest in-flight requests, fewest total
/// requests.  Peers that have exceeded `max_chunks_per_peer` or are in
/// back-off are skipped.
fn pick_best_peer_index(
    peers: &[PeerAddr],
    stats: &HashMap<String, PeerRuntimeStats>,
    policy: &FetchPolicy,
) -> Option<usize> {
    let now = Instant::now();
    let mut best: Option<(usize, i32, usize, usize)> = None;
    for (i, peer) in peers.iter().enumerate() {
        let key = peer_key(peer);
        let s = match stats.get(&key) {
            Some(s) => s,
            None => continue,
        };
        if s.requests >= policy.max_chunks_per_peer {
            continue;
        }
        if let Some(until) = s.backoff_until {
            if until > now {
                continue;
            }
        }
        let candidate = (i, s.score, s.in_flight, s.requests);
        match best {
            None => best = Some(candidate),
            Some((_, bs, bif, br)) => {
                if s.score > bs
                    || (s.score == bs && s.in_flight < bif)
                    || (s.score == bs && s.in_flight == bif && s.requests < br)
                {
                    best = Some(candidate);
                }
            }
        }
    }
    best.map(|(idx, _, _, _)| idx)
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
    /// Number of chunk requests currently in flight to this peer.
    in_flight: usize,
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
            visibility: crate::manifest::ShareVisibility::Private,
            communities: vec![],
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

    /// Helper: spawns a server that can serve ANY chunk from the given bytes,
    /// routing by the `chunk_index` in the incoming request.
    async fn any_chunk_server(
        mut server: DuplexStream,
        content_id: [u8; 32],
        chunks: Vec<Vec<u8>>,
    ) {
        let req = read_envelope(&mut server).await.expect("read request");
        let typed = req.decode_typed().expect("typed");
        let WirePayload::GetChunk(GetChunk {
            content_id: requested_id,
            chunk_index,
        }) = typed
        else {
            panic!("unexpected request type in any_chunk_server");
        };
        assert_eq!(requested_id, content_id);
        let bytes = chunks[chunk_index as usize].clone();
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
    async fn parallel_download_distributes_chunks_across_peers() {
        // Create content that spans 4 chunks.
        let bytes = vec![42u8; CHUNK_SIZE * 3 + 100];
        let desc = describe_content(&bytes);
        let cid = desc.content_id.0;

        // Split into individual chunk payloads.
        let raw_chunks: Vec<Vec<u8>> = desc
            .chunks
            .iter()
            .enumerate()
            .map(|(i, _)| {
                let start = i * CHUNK_SIZE;
                let end = ((i + 1) * CHUNK_SIZE).min(bytes.len());
                bytes[start..end].to_vec()
            })
            .collect();
        assert_eq!(raw_chunks.len(), 4);

        // Two peers; each can serve any chunk but limited to 2 each.
        let peer_a = make_peer("10.0.0.20", 7000);
        let peer_b = make_peer("10.0.0.21", 7000);
        let connector = MockConnector::new();
        let transport = DirectRequestTransport::new(connector);

        let peer_a_count = Arc::new(AtomicUsize::new(0));
        let peer_b_count = Arc::new(AtomicUsize::new(0));

        transport
            .connector
            .register(&peer_a, {
                let chunks = raw_chunks.clone();
                let counter = peer_a_count.clone();
                move || {
                    let chunks = chunks.clone();
                    let counter = counter.clone();
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        let (client, server) = tokio::io::duplex(65536);
                        tokio::spawn(any_chunk_server(server, cid, chunks));
                        Ok(Box::new(client) as BoxedStream)
                    }
                }
            })
            .await;

        transport
            .connector
            .register(&peer_b, {
                let chunks = raw_chunks.clone();
                let counter = peer_b_count.clone();
                move || {
                    let chunks = chunks.clone();
                    let counter = counter.clone();
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        let (client, server) = tokio::io::duplex(65536);
                        tokio::spawn(any_chunk_server(server, cid, chunks));
                        Ok(Box::new(client) as BoxedStream)
                    }
                }
            })
            .await;

        let policy = FetchPolicy {
            max_chunks_per_peer: 2,
            parallel_chunks: 4,
            ..FetchPolicy::default()
        };

        let out = download_swarm_over_network(
            &transport,
            &[peer_a, peer_b],
            cid,
            &desc.chunks,
            &policy,
        )
        .await
        .expect("parallel download");

        assert_eq!(out, bytes);

        // Both peers should have been used (2 chunks each).
        let a = peer_a_count.load(Ordering::SeqCst);
        let b = peer_b_count.load(Ordering::SeqCst);
        assert!(a > 0, "peer_a should have served at least 1 chunk");
        assert!(b > 0, "peer_b should have served at least 1 chunk");
        assert_eq!(a + b, 4, "total chunks served should be 4");
    }

    #[tokio::test]
    async fn parallel_download_retries_failed_chunk_on_other_peer() {
        // 2 chunks; peer_a always fails, peer_b serves both.
        let bytes = vec![99u8; CHUNK_SIZE + 10];
        let desc = describe_content(&bytes);
        let cid = desc.content_id.0;

        let raw_chunks: Vec<Vec<u8>> = desc
            .chunks
            .iter()
            .enumerate()
            .map(|(i, _)| {
                let start = i * CHUNK_SIZE;
                let end = ((i + 1) * CHUNK_SIZE).min(bytes.len());
                bytes[start..end].to_vec()
            })
            .collect();

        let peer_a = make_peer("10.0.0.30", 7000);
        let peer_b = make_peer("10.0.0.31", 7000);
        let connector = MockConnector::new();
        let transport = DirectRequestTransport::new(connector);

        // peer_a always fails
        transport
            .connector
            .register(&peer_a, || async { anyhow::bail!("peer_a unavailable") })
            .await;

        // peer_b serves any chunk
        transport
            .connector
            .register(&peer_b, {
                let chunks = raw_chunks.clone();
                move || {
                    let chunks = chunks.clone();
                    async move {
                        let (client, server) = tokio::io::duplex(65536);
                        tokio::spawn(any_chunk_server(server, cid, chunks));
                        Ok(Box::new(client) as BoxedStream)
                    }
                }
            })
            .await;

        let policy = FetchPolicy {
            parallel_chunks: 2,
            ..FetchPolicy::default()
        };

        let out = download_swarm_over_network(
            &transport,
            &[peer_a, peer_b],
            cid,
            &desc.chunks,
            &policy,
        )
        .await
        .expect("download with retries");

        assert_eq!(out, bytes);
    }
}
