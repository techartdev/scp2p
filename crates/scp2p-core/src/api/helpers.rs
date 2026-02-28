// Copyright (c) 2024-2026 Vanyo Vanev / Tech Art Ltd
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//! Free helper functions used across the `api` module.

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU32, Ordering},
    time::{Duration, SystemTime},
};

use crate::{
    dht::K,
    dht_keys::{content_provider_key, share_head_key},
    ids::{NodeId, ShareId},
    manifest::{ManifestV1, PublicShareSummary, ShareHead},
    net_fetch::RequestTransport,
    peer::PeerAddr,
    relay::RelayPayloadKind as RelayInternalPayloadKind,
    search::IndexedItem,
    wire::{
        CommunityPublicShareList, CommunityStatus, Envelope, FindNode, FindNodeResult, FindValue,
        FindValueResult, GetCommunityStatus, ListCommunityPublicShares, ListPublicShares, MsgType,
        Providers, PublicShareList, RelayPayloadKind as WireRelayPayloadKind, Store as WireStore,
        WirePayload, FLAG_RESPONSE,
    },
};

use super::{NodeHandle, RequestClass};

pub(super) fn now_unix_secs() -> anyhow::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs())
}

pub(super) fn peer_key(peer: &PeerAddr) -> String {
    format!("{}:{}:{:?}", peer.ip, peer.port, peer.transport)
}

pub(super) fn relay_peer_key(peer: &PeerAddr) -> String {
    peer.pubkey_hint
        .map(|pubkey| format!("pubkey:{}", hex::encode(pubkey)))
        .unwrap_or_else(|| peer_key(peer))
}

pub(super) fn relay_payload_kind_to_internal(
    kind: WireRelayPayloadKind,
) -> RelayInternalPayloadKind {
    match kind {
        WireRelayPayloadKind::Control => RelayInternalPayloadKind::Control,
        WireRelayPayloadKind::Content => RelayInternalPayloadKind::Content,
    }
}

pub(super) fn relay_payload_kind_to_wire(kind: RelayInternalPayloadKind) -> WireRelayPayloadKind {
    match kind {
        RelayInternalPayloadKind::Control => WireRelayPayloadKind::Control,
        RelayInternalPayloadKind::Content => WireRelayPayloadKind::Content,
    }
}

pub(super) fn request_class(payload: &WirePayload) -> RequestClass {
    match payload {
        WirePayload::FindNode(_) | WirePayload::FindValue(_) | WirePayload::Store(_) => {
            RequestClass::Dht
        }
        WirePayload::GetManifest(_)
        | WirePayload::ListPublicShares(_)
        | WirePayload::GetCommunityStatus(_)
        | WirePayload::ListCommunityPublicShares(_)
        | WirePayload::GetChunkHashes(_) => RequestClass::Fetch,
        // Chunk data is not rate-limited by request count — TCP bandwidth is the
        // natural throttle.  Applying a fixed-count limit here would cap large
        // file transfers at max_fetch_requests_per_window * CHUNK_SIZE bytes
        // (e.g. 240 * 256 KiB ≈ 60 MiB) regardless of available bandwidth.
        WirePayload::GetChunk(_) => RequestClass::Other,
        WirePayload::RelayRegister(_)
        | WirePayload::RelayConnect(_)
        | WirePayload::RelayStream(_) => RequestClass::Relay,
        _ => RequestClass::Other,
    }
}

pub(super) fn peer_distance_key(peer: &PeerAddr, target_node_id: [u8; 20]) -> [u8; 20] {
    peer.pubkey_hint
        .map(|hint| NodeId::from_pubkey_bytes(&hint).xor_distance(&NodeId(target_node_id)))
        .unwrap_or([0xffu8; 20])
}

pub(super) fn sort_peers_for_target(peers: &mut [PeerAddr], target_node_id: [u8; 20]) {
    peers.sort_by(|a, b| {
        peer_distance_key(a, target_node_id)
            .cmp(&peer_distance_key(b, target_node_id))
            .then(peer_key(a).cmp(&peer_key(b)))
    });
}

pub(super) fn merge_peer_list(into: &mut Vec<PeerAddr>, incoming: Vec<PeerAddr>) -> bool {
    let mut changed = false;
    let mut known = into.iter().map(peer_key).collect::<HashSet<_>>();
    for peer in incoming {
        let key = peer_key(&peer);
        if known.insert(key) {
            into.push(peer);
            changed = true;
        }
    }
    changed
}

pub(super) fn next_req_id() -> u32 {
    static NEXT_REQ_ID: AtomicU32 = AtomicU32::new(1_000_000);
    NEXT_REQ_ID.fetch_add(1, Ordering::Relaxed)
}

pub(super) fn validate_dht_value_for_known_keyspaces(
    key: [u8; 32],
    value: &[u8],
) -> anyhow::Result<()> {
    if let Ok(head) = serde_cbor::from_slice::<ShareHead>(value) {
        let expected = share_head_key(&ShareId(head.share_id));
        if expected != key {
            anyhow::bail!("share head value does not match share head key");
        }
        return Ok(());
    }
    if let Ok(providers) = serde_cbor::from_slice::<Providers>(value) {
        let expected = content_provider_key(&providers.content_id);
        if expected != key {
            anyhow::bail!("providers value does not match content provider key");
        }
        return Ok(());
    }
    Ok(())
}

pub(super) async fn query_find_node<T: RequestTransport + ?Sized>(
    transport: &T,
    peer: &PeerAddr,
    target_node_id: [u8; 20],
) -> anyhow::Result<FindNodeResult> {
    let req_id = next_req_id();
    let request = Envelope::from_typed(
        req_id,
        0,
        &WirePayload::FindNode(FindNode { target_node_id }),
    )?;
    let response = transport
        .request(peer, request, Duration::from_secs(3))
        .await?;
    if response.r#type != MsgType::FindNode as u16 {
        anyhow::bail!("unexpected find_node response type");
    }
    if response.req_id != req_id {
        anyhow::bail!("find_node response req_id mismatch");
    }
    if response.flags & FLAG_RESPONSE == 0 {
        anyhow::bail!("find_node response missing response flag");
    }
    Ok(serde_cbor::from_slice(&response.payload)?)
}

pub(super) async fn query_find_value<T: RequestTransport + ?Sized>(
    transport: &T,
    peer: &PeerAddr,
    key: [u8; 32],
) -> anyhow::Result<FindValueResult> {
    let req_id = next_req_id();
    let request = Envelope::from_typed(req_id, 0, &WirePayload::FindValue(FindValue { key }))?;
    let response = transport
        .request(peer, request, Duration::from_secs(3))
        .await?;
    if response.r#type != MsgType::FindValue as u16 {
        anyhow::bail!("unexpected find_value response type");
    }
    if response.req_id != req_id {
        anyhow::bail!("find_value response req_id mismatch");
    }
    if response.flags & FLAG_RESPONSE == 0 {
        anyhow::bail!("find_value response missing response flag");
    }
    Ok(serde_cbor::from_slice(&response.payload)?)
}

pub(super) async fn query_public_shares<T: RequestTransport + ?Sized>(
    transport: &T,
    peer: &PeerAddr,
    max_entries: u16,
) -> anyhow::Result<Vec<PublicShareSummary>> {
    let req_id = next_req_id();
    let request = Envelope::from_typed(
        req_id,
        0,
        &WirePayload::ListPublicShares(ListPublicShares { max_entries }),
    )?;
    let response = transport
        .request(peer, request, Duration::from_secs(3))
        .await?;
    if response.r#type != MsgType::PublicShareList as u16 {
        anyhow::bail!("unexpected public share list response type");
    }
    if response.req_id != req_id {
        anyhow::bail!("public share list response req_id mismatch");
    }
    if response.flags & FLAG_RESPONSE == 0 {
        anyhow::bail!("public share list response missing response flag");
    }
    Ok(serde_cbor::from_slice::<PublicShareList>(&response.payload)?.shares)
}

pub(super) async fn query_community_status<T: RequestTransport + ?Sized>(
    transport: &T,
    peer: &PeerAddr,
    share_id: ShareId,
    share_pubkey: [u8; 32],
) -> anyhow::Result<bool> {
    let req_id = next_req_id();
    let request = Envelope::from_typed(
        req_id,
        0,
        &WirePayload::GetCommunityStatus(GetCommunityStatus {
            community_share_id: share_id.0,
            community_share_pubkey: share_pubkey,
        }),
    )?;
    let response = transport
        .request(peer, request, Duration::from_secs(3))
        .await?;
    if response.r#type != MsgType::CommunityStatus as u16 {
        anyhow::bail!("unexpected community status response type");
    }
    if response.req_id != req_id {
        anyhow::bail!("community status response req_id mismatch");
    }
    if response.flags & FLAG_RESPONSE == 0 {
        anyhow::bail!("community status response missing response flag");
    }
    let status: CommunityStatus = serde_cbor::from_slice(&response.payload)?;
    if status.community_share_id != share_id.0 {
        anyhow::bail!("community status response share_id mismatch");
    }
    Ok(status.joined)
}

pub(super) async fn query_community_public_shares<T: RequestTransport + ?Sized>(
    transport: &T,
    peer: &PeerAddr,
    community_share_id: ShareId,
    community_share_pubkey: [u8; 32],
    max_entries: u16,
) -> anyhow::Result<Vec<PublicShareSummary>> {
    let req_id = next_req_id();
    let request = Envelope::from_typed(
        req_id,
        0,
        &WirePayload::ListCommunityPublicShares(ListCommunityPublicShares {
            community_share_id: community_share_id.0,
            community_share_pubkey,
            max_entries,
        }),
    )?;
    let response = transport
        .request(peer, request, Duration::from_secs(3))
        .await?;
    if response.r#type != MsgType::CommunityPublicShareList as u16 {
        anyhow::bail!("unexpected community public share list response type");
    }
    if response.req_id != req_id {
        anyhow::bail!("community public share list response req_id mismatch");
    }
    if response.flags & FLAG_RESPONSE == 0 {
        anyhow::bail!("community public share list response missing response flag");
    }
    let payload: CommunityPublicShareList = serde_cbor::from_slice(&response.payload)?;
    if payload.community_share_id != community_share_id.0 {
        anyhow::bail!("community public share list response share_id mismatch");
    }
    Ok(payload.shares)
}

pub(super) async fn query_store<T: RequestTransport + ?Sized>(
    transport: &T,
    peer: &PeerAddr,
    key: [u8; 32],
    value: Vec<u8>,
    ttl_secs: u64,
) -> anyhow::Result<()> {
    let req_id = next_req_id();
    let request = Envelope::from_typed(
        req_id,
        0,
        &WirePayload::Store(WireStore {
            key,
            value,
            ttl_secs,
        }),
    )?;
    let response = transport
        .request(peer, request, Duration::from_secs(3))
        .await?;
    if response.r#type != MsgType::Store as u16 {
        anyhow::bail!("unexpected store response type");
    }
    if response.req_id != req_id {
        anyhow::bail!("store response req_id mismatch");
    }
    if response.flags & FLAG_RESPONSE == 0 {
        anyhow::bail!("store response missing response flag");
    }
    Ok(())
}

pub(super) async fn replicate_store_to_closest<T: RequestTransport + ?Sized>(
    transport: &T,
    handle: &NodeHandle,
    key: [u8; 32],
    value: Vec<u8>,
    ttl_secs: u64,
    seed_peers: &[PeerAddr],
) -> anyhow::Result<usize> {
    let mut target = [0u8; 20];
    target.copy_from_slice(&key[..20]);
    let peers = handle
        .dht_find_node_iterative(transport, target, seed_peers)
        .await?;

    let mut stored = 0usize;
    for peer in peers.into_iter().take(K) {
        if query_store(transport, &peer, key, value.clone(), ttl_secs)
            .await
            .is_ok()
        {
            stored += 1;
        }
    }
    Ok(stored)
}

/// Persist current state: snapshot under read-lock, drop lock, then write.
/// This avoids holding the `RwLock` across async I/O.
pub(super) async fn persist_state(handle: &NodeHandle) -> anyhow::Result<()> {
    let (snapshot, store) = {
        let state = handle.state.read().await;
        (state.to_persisted(), state.store.clone())
    };
    store.save_state(&snapshot).await
}

pub(super) fn error_envelope(message_type: u16, req_id: u32, message: &str) -> Envelope {
    Envelope {
        r#type: message_type,
        req_id,
        flags: FLAG_RESPONSE | crate::wire::FLAG_ERROR,
        payload: message.as_bytes().to_vec(),
    }
}

// Path-safety helpers
// ---------------------------------------------------------------------------

/// Maximum number of items allowed in a single manifest.
pub(super) const MAX_MANIFEST_ITEMS: usize = 10_000;

/// Maximum total number of chunk hashes across all items in a manifest.
pub(super) const MAX_MANIFEST_CHUNK_HASHES: usize = 100_000;

/// Maximum byte length of a normalised path.
const MAX_PATH_BYTES: usize = 1024;

/// Normalise a relative path for inclusion in a manifest item.
pub(super) fn normalize_item_path(raw: &str) -> anyhow::Result<String> {
    let unified = raw.replace('\\', "/");
    let mut parts: Vec<&str> = Vec::new();

    for seg in unified.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            anyhow::bail!("path contains disallowed '..' segment: {raw}");
        }
        if parts.is_empty() && seg.len() == 2 && seg.as_bytes()[1] == b':' {
            let letter = seg.as_bytes()[0];
            if letter.is_ascii_alphabetic() {
                anyhow::bail!("path contains drive letter prefix: {raw}");
            }
        }
        parts.push(seg);
    }

    if parts.is_empty() {
        anyhow::bail!("path is empty after normalisation: {raw}");
    }

    let result = parts.join("/");
    if result.len() > MAX_PATH_BYTES {
        anyhow::bail!(
            "normalised path exceeds {MAX_PATH_BYTES} bytes ({} bytes): {result}",
            result.len()
        );
    }
    Ok(result)
}

/// Validate manifest item counts against protocol limits.
pub(super) fn check_manifest_limits(manifest: &ManifestV1) -> anyhow::Result<()> {
    if manifest.items.len() > MAX_MANIFEST_ITEMS {
        anyhow::bail!(
            "manifest has {} items, exceeding limit of {MAX_MANIFEST_ITEMS}",
            manifest.items.len()
        );
    }
    let total_chunks: u32 = manifest.items.iter().map(|i| i.chunk_count).sum();
    if total_chunks > MAX_MANIFEST_CHUNK_HASHES as u32 {
        anyhow::bail!(
            "manifest has {total_chunks} total chunk hashes, exceeding limit of {MAX_MANIFEST_CHUNK_HASHES}"
        );
    }
    Ok(())
}

/// Recursively collect all file paths under `dir`, skipping directories.
pub(super) async fn collect_files_recursive(dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut result = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let mut entries = tokio::fs::read_dir(&current).await?;
        while let Some(entry) = entries.next_entry().await? {
            let ft = entry.file_type().await?;
            if ft.is_dir() {
                stack.push(entry.path());
            } else if ft.is_file() {
                result.push(entry.path());
            }
        }
    }
    result.sort();
    Ok(result)
}

/// Best-effort MIME type from file extension.
pub(super) fn mime_from_extension(filename: &str) -> Option<String> {
    let ext = filename.rsplit('.').next()?.to_ascii_lowercase();
    let mime = match ext.as_str() {
        "txt" | "text" => "text/plain",
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" | "mjs" => "application/javascript",
        "json" => "application/json",
        "xml" => "application/xml",
        "csv" => "text/csv",
        "md" | "markdown" => "text/markdown",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "gz" | "gzip" => "application/gzip",
        "tar" => "application/x-tar",
        "7z" => "application/x-7z-compressed",
        "rar" => "application/vnd.rar",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "mp3" => "audio/mpeg",
        "ogg" => "audio/ogg",
        "wav" => "audio/wav",
        "flac" => "audio/flac",
        "mp4" => "video/mp4",
        "mkv" => "video/x-matroska",
        "webm" => "video/webm",
        "avi" => "video/x-msvideo",
        "mov" => "video/quicktime",
        "wasm" => "application/wasm",
        "toml" => "application/toml",
        "yaml" | "yml" => "application/x-yaml",
        "rs" => "text/x-rust",
        "py" => "text/x-python",
        "ts" | "tsx" => "text/typescript",
        "exe" => "application/vnd.microsoft.portable-executable",
        "bin" | "dat" => "application/octet-stream",
        _ => return None,
    };
    Some(mime.to_owned())
}

pub(super) fn build_search_snippet(
    item: &IndexedItem,
    query: &str,
    include_snippet: bool,
) -> Option<String> {
    if !include_snippet {
        return None;
    }
    let terms = query
        .split(|c: char| !c.is_alphanumeric())
        .filter(|term| !term.is_empty())
        .map(|term| term.to_lowercase())
        .collect::<Vec<_>>();
    if terms.is_empty() {
        return None;
    }

    let candidates = [
        item.title.as_deref(),
        item.description.as_deref(),
        Some(item.name.as_str()),
    ];
    for candidate in candidates.into_iter().flatten() {
        let lower = candidate.to_lowercase();
        let mut first_match = None;
        for term in &terms {
            if let Some(idx) = lower.find(term) {
                first_match = Some(idx);
                break;
            }
        }
        let Some(match_index) = first_match else {
            continue;
        };

        let snippet_radius = 48usize;
        let start = match_index.saturating_sub(snippet_radius);
        let end = (match_index + snippet_radius).min(candidate.len());
        let Some(window) = candidate.get(start..end) else {
            continue;
        };
        let mut snippet = window.trim().to_string();
        if start > 0 {
            snippet.insert_str(0, "...");
        }
        if end < candidate.len() {
            snippet.push_str("...");
        }
        if !snippet.is_empty() {
            return Some(snippet);
        }
    }
    None
}
