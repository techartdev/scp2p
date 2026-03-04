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
    dht_keys::{
        community_info_key, community_member_key, community_share_key, content_provider_key,
        manifest_loc_key, share_head_key,
    },
    ids::{NodeId, ShareId},
    manifest::{ManifestV1, PublicShareSummary, ShareHead},
    net_fetch::RequestTransport,
    peer::{PeerAddr, TransportProtocol},
    relay::{
        RelayAnnouncement, RelayPayloadKind as RelayInternalPayloadKind, current_rendezvous_bucket,
        relay_rendezvous_index, relay_rendezvous_key,
    },
    search::IndexedItem,
    wire::{
        CommunityEventsResp, CommunityMembers, CommunityMembersPageResponse,
        CommunityPublicShareList, CommunitySearchResultsResp, CommunitySharesPageResponse,
        CommunityStatus, Envelope, FLAG_RESPONSE, FindNode, FindNodeResult, FindValue,
        FindValueResult, GetCommunityStatus, ListCommunityEventsReq, ListCommunityMembersPage,
        ListCommunityPublicShares, ListCommunitySharesPage, ListPublicShares, MsgType, Providers,
        PublicShareList, RelayListRequest, RelayListResponse,
        RelayPayloadKind as WireRelayPayloadKind, SearchCommunitySharesReq, Store as WireStore,
        WirePayload,
    },
};

use tracing::{debug, warn};

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

/// Convert an ASCII hex digit to its value (0–15), or `None`.
pub(super) fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
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
        // Community index queries have their own rate-limit bucket so
        // that community browse/search cannot starve manifest/chunk
        // fetches sharing the generic Fetch counter.
        WirePayload::ListCommunityMembersPage(_)
        | WirePayload::ListCommunitySharesPage(_)
        | WirePayload::SearchCommunityShares(_)
        | WirePayload::ListCommunityEvents(_) => RequestClass::Community,
        // Chunk data requests are rate-limited by per-peer chunk request
        // count.  Each chunk is up to CHUNK_SIZE (256 KiB), so the
        // `max_chunk_requests_per_window` field in `AbuseLimits`
        // effectively caps bandwidth per peer.
        WirePayload::GetChunk(_) => RequestClass::Chunk,
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
            // Prefer TCP over QUIC as a tiebreaker — if QUIC is blocked
            // by the network this avoids 5-second timeout penalties.
            .then(transport_order(a).cmp(&transport_order(b)))
            .then(peer_key(a).cmp(&peer_key(b)))
    });
}

fn transport_order(p: &PeerAddr) -> u8 {
    match p.transport {
        TransportProtocol::Tcp => 0,
        TransportProtocol::Quic => 1,
    }
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
    // ── Prefix-first dispatch ──────────────────────────────────────
    // Check well-known tag bytes before any trial CBOR deserialization.
    // Community records (§15) use explicit tag prefixes; all other
    // types are plain CBOR and start with map/array markers (0x80+).
    if let Some(&tag) = value.first() {
        match tag {
            crate::wire::community_tags::MEMBER_RECORD => {
                return validate_community_member_record(key, value);
            }
            crate::wire::community_tags::SHARE_RECORD => {
                return validate_community_share_record(key, value);
            }
            crate::wire::community_tags::BOOTSTRAP_HINT => {
                return validate_community_bootstrap_hint(key, value);
            }
            _ => {}
        }
    }

    // ── Trial CBOR deserialization for untagged keyspaces ───────────
    if let Ok(head) = crate::cbor::from_slice::<ShareHead>(value) {
        let expected = share_head_key(&ShareId(head.share_id));
        if expected != key {
            anyhow::bail!("share head value does not match share head key");
        }
        return Ok(());
    }
    if let Ok(providers) = crate::cbor::from_slice::<Providers>(value) {
        let expected = content_provider_key(&providers.content_id);
        if expected != key {
            anyhow::bail!("providers value does not match content provider key");
        }
        return Ok(());
    }
    // Manifests are stored at manifest_loc_key so peers behind NAT can
    // fetch them from the DHT without a direct publisher connection.
    if let Ok(manifest) = crate::cbor::from_slice::<ManifestV1>(value) {
        if let Ok(mid) = manifest.manifest_id() {
            let expected = manifest_loc_key(&mid);
            if expected == key {
                return Ok(());
            }
        }
        anyhow::bail!("manifest value does not match manifest loc key");
    }
    // Relay announcements are stored at DHT rendezvous keys (§4.9).
    if let Ok(ann) = crate::cbor::from_slice::<RelayAnnouncement>(value) {
        // Full structural + cryptographic validation.
        ann.verify_signature()?;
        // Accept if the key matches any valid rendezvous slot for this relay.
        if is_valid_relay_rendezvous_key(key, &ann) {
            return Ok(());
        }
        anyhow::bail!("relay announcement key does not match any valid rendezvous slot");
    }

    // Legacy community member lists stored at community_info_key(share_id).
    if let Ok(cm) = crate::cbor::from_slice::<CommunityMembers>(value) {
        let expected = community_info_key(&ShareId(cm.community_share_id));
        if expected != key {
            anyhow::bail!("community members value does not match community info key");
        }
        return Ok(());
    }
    // Reject values that do not match any recognized keyspace to prevent
    // arbitrary data storage and potential abuse (§4.5).
    anyhow::bail!("DHT value does not match any recognized keyspace")
}

/// Validate a tagged `CommunityMemberRecord` (§15.4.1).
fn validate_community_member_record(key: [u8; 32], value: &[u8]) -> anyhow::Result<()> {
    use crate::wire::CommunityMemberRecord;
    let record = CommunityMemberRecord::decode_tagged(value)?;
    // Key must match (community_id, member_node_pubkey).
    let expected = community_member_key(&record.community_id, &record.member_node_pubkey);
    if expected != key {
        anyhow::bail!("community member record key mismatch");
    }
    // Cryptographic signature verification.
    record.verify_signature()?;
    Ok(())
}

/// Validate a tagged `CommunityShareRecord` (§15.4.2).
fn validate_community_share_record(key: [u8; 32], value: &[u8]) -> anyhow::Result<()> {
    use crate::wire::CommunityShareRecord;
    let record = CommunityShareRecord::decode_tagged(value)?;
    // Key must match (community_id, share_id).
    let expected = community_share_key(&record.community_id, &record.share_id);
    if expected != key {
        anyhow::bail!("community share record key mismatch");
    }
    // Signature + share_id derivation verification.
    record.verify()?;
    Ok(())
}

/// Validate a tagged `CommunityBootstrapHint` (§15.4.1b).
fn validate_community_bootstrap_hint(key: [u8; 32], value: &[u8]) -> anyhow::Result<()> {
    use crate::wire::CommunityBootstrapHint;
    let hint = CommunityBootstrapHint::decode_tagged(value)?;
    // Key must match community_info_key(community_id).
    let expected = community_info_key(&ShareId(hint.community_id));
    if expected != key {
        anyhow::bail!("community bootstrap hint key mismatch");
    }
    // Bounds enforcement.
    if hint.sample_members.len() > CommunityBootstrapHint::MAX_SAMPLE_MEMBERS {
        anyhow::bail!("bootstrap hint sample_members exceeds max");
    }
    if hint.index_peers.len() > CommunityBootstrapHint::MAX_INDEX_PEERS {
        anyhow::bail!("bootstrap hint index_peers exceeds max");
    }
    Ok(())
}

/// Check whether `key` is a valid relay rendezvous key for the relay pubkey
/// embedded in `ann`.  Checks the bucket derived from `ann.issued_at` plus
/// the adjacent bucket to tolerate boundary timing.
pub(super) fn is_valid_relay_rendezvous_key(key: [u8; 32], ann: &RelayAnnouncement) -> bool {
    let issued_bucket = current_rendezvous_bucket(ann.issued_at);
    let buckets = [
        issued_bucket,
        issued_bucket.saturating_sub(1),
        issued_bucket.saturating_add(1),
    ];
    for bucket_id in buckets {
        for which in 0u8..2 {
            let slot = relay_rendezvous_index(&ann.relay_pubkey, bucket_id, which);
            if relay_rendezvous_key(bucket_id, slot) == key {
                return true;
            }
        }
    }
    false
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
    Ok(crate::cbor::from_slice(&response.payload)?)
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
    Ok(crate::cbor::from_slice(&response.payload)?)
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
    Ok(crate::cbor::from_slice::<PublicShareList>(&response.payload)?.shares)
}

pub(super) async fn query_community_status<T: RequestTransport + ?Sized>(
    transport: &T,
    peer: &PeerAddr,
    share_id: ShareId,
    share_pubkey: [u8; 32],
) -> anyhow::Result<CommunityStatusResult> {
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
    let status: CommunityStatus = crate::cbor::from_slice(&response.payload)?;
    if status.community_share_id != share_id.0 {
        anyhow::bail!("community status response share_id mismatch");
    }
    Ok(CommunityStatusResult {
        joined: status.joined,
        name: status.name,
    })
}

/// Result of a community status query.
pub(super) struct CommunityStatusResult {
    pub joined: bool,
    /// Community name reported by the remote peer (if known).
    pub name: Option<String>,
}

pub(super) async fn query_community_public_shares<T: RequestTransport + ?Sized>(
    transport: &T,
    peer: &PeerAddr,
    community_share_id: ShareId,
    community_share_pubkey: [u8; 32],
    max_entries: u16,
    requester_node_pubkey: Option<[u8; 32]>,
    requester_membership_proof: Option<Vec<u8>>,
) -> anyhow::Result<Vec<PublicShareSummary>> {
    let req_id = next_req_id();
    let request = Envelope::from_typed(
        req_id,
        0,
        &WirePayload::ListCommunityPublicShares(ListCommunityPublicShares {
            community_share_id: community_share_id.0,
            community_share_pubkey,
            max_entries,
            requester_node_pubkey,
            requester_membership_proof,
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
    let payload: CommunityPublicShareList = crate::cbor::from_slice(&response.payload)?;
    if payload.community_share_id != community_share_id.0 {
        anyhow::bail!("community public share list response share_id mismatch");
    }
    Ok(payload.shares)
}

/// Ask a peer for a paged member list for a community (§15.6.1).
pub(super) async fn query_community_members_page<T: RequestTransport + ?Sized>(
    transport: &T,
    peer: &PeerAddr,
    community_id: [u8; 32],
    cursor: Option<String>,
    limit: u16,
) -> anyhow::Result<CommunityMembersPageResponse> {
    let req_id = next_req_id();
    let request = Envelope::from_typed(
        req_id,
        0,
        &WirePayload::ListCommunityMembersPage(ListCommunityMembersPage {
            community_id,
            cursor,
            limit,
        }),
    )?;
    let response = transport
        .request(peer, request, Duration::from_secs(5))
        .await?;
    if response.r#type != MsgType::CommunityMembersPage as u16 {
        anyhow::bail!("unexpected community members page response type");
    }
    if response.req_id != req_id {
        anyhow::bail!("community members page response req_id mismatch");
    }
    if response.flags & FLAG_RESPONSE == 0 {
        anyhow::bail!("community members page response missing response flag");
    }
    let payload: CommunityMembersPageResponse = crate::cbor::from_slice(&response.payload)?;
    if payload.community_id != community_id {
        anyhow::bail!("community members page response community_id mismatch");
    }
    Ok(payload)
}

/// Ask a peer for a paged share list for a community (§15.6.1).
pub(super) async fn query_community_shares_page<T: RequestTransport + ?Sized>(
    transport: &T,
    peer: &PeerAddr,
    community_id: [u8; 32],
    cursor: Option<String>,
    limit: u16,
    since_unix: Option<u64>,
) -> anyhow::Result<CommunitySharesPageResponse> {
    let req_id = next_req_id();
    let request = Envelope::from_typed(
        req_id,
        0,
        &WirePayload::ListCommunitySharesPage(ListCommunitySharesPage {
            community_id,
            cursor,
            limit,
            since_unix,
        }),
    )?;
    let response = transport
        .request(peer, request, Duration::from_secs(5))
        .await?;
    if response.r#type != MsgType::CommunitySharesPage as u16 {
        anyhow::bail!("unexpected community shares page response type");
    }
    if response.req_id != req_id {
        anyhow::bail!("community shares page response req_id mismatch");
    }
    if response.flags & FLAG_RESPONSE == 0 {
        anyhow::bail!("community shares page response missing response flag");
    }
    let payload: CommunitySharesPageResponse = crate::cbor::from_slice(&response.payload)?;
    if payload.community_id != community_id {
        anyhow::bail!("community shares page response community_id mismatch");
    }
    Ok(payload)
}

/// Ask a peer for community search results (§15.6.2).
pub(super) async fn query_community_search_shares<T: RequestTransport + ?Sized>(
    transport: &T,
    peer: &PeerAddr,
    community_id: [u8; 32],
    query: String,
    cursor: Option<String>,
    limit: u16,
) -> anyhow::Result<CommunitySearchResultsResp> {
    let req_id = next_req_id();
    let request = Envelope::from_typed(
        req_id,
        0,
        &WirePayload::SearchCommunityShares(SearchCommunitySharesReq {
            community_id,
            query,
            cursor,
            limit,
        }),
    )?;
    let response = transport
        .request(peer, request, Duration::from_secs(5))
        .await?;
    if response.r#type != MsgType::CommunitySearchResults as u16 {
        anyhow::bail!("unexpected community search results response type");
    }
    if response.req_id != req_id {
        anyhow::bail!("community search results response req_id mismatch");
    }
    if response.flags & FLAG_RESPONSE == 0 {
        anyhow::bail!("community search results response missing response flag");
    }
    let payload: CommunitySearchResultsResp = crate::cbor::from_slice(&response.payload)?;
    if payload.community_id != community_id {
        anyhow::bail!("community search results response community_id mismatch");
    }
    Ok(payload)
}

/// Ask a peer for community delta events (§15.6.3).
pub(super) async fn query_community_events<T: RequestTransport + ?Sized>(
    transport: &T,
    peer: &PeerAddr,
    community_id: [u8; 32],
    since_cursor: Option<String>,
    limit: u16,
) -> anyhow::Result<CommunityEventsResp> {
    let req_id = next_req_id();
    let request = Envelope::from_typed(
        req_id,
        0,
        &WirePayload::ListCommunityEvents(ListCommunityEventsReq {
            community_id,
            since_cursor,
            limit,
        }),
    )?;
    let response = transport
        .request(peer, request, Duration::from_secs(5))
        .await?;
    if response.r#type != MsgType::CommunityEvents as u16 {
        anyhow::bail!("unexpected community events response type");
    }
    if response.req_id != req_id {
        anyhow::bail!("community events response req_id mismatch");
    }
    if response.flags & FLAG_RESPONSE == 0 {
        anyhow::bail!("community events response missing response flag");
    }
    let payload: CommunityEventsResp = crate::cbor::from_slice(&response.payload)?;
    if payload.community_id != community_id {
        anyhow::bail!("community events response community_id mismatch");
    }
    Ok(payload)
}

/// Ask a single peer for its known relay announcements (Relay-PEX, §4.9).
pub(super) async fn query_relay_list<T: RequestTransport + ?Sized>(
    transport: &T,
    peer: &PeerAddr,
    max_count: u16,
) -> anyhow::Result<Vec<RelayAnnouncement>> {
    let req_id = next_req_id();
    let request = Envelope::from_typed(
        req_id,
        0,
        &WirePayload::RelayListRequest(RelayListRequest { max_count }),
    )?;
    let response = transport
        .request(peer, request, Duration::from_secs(5))
        .await?;
    if response.r#type != MsgType::RelayListResponse as u16 {
        anyhow::bail!("unexpected relay list response type");
    }
    if response.req_id != req_id {
        anyhow::bail!("relay list response req_id mismatch");
    }
    if response.flags & FLAG_RESPONSE == 0 {
        anyhow::bail!("relay list response missing response flag");
    }
    let resp: RelayListResponse = crate::cbor::from_slice(&response.payload)?;
    Ok(resp.announcements)
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
    replication_factor: usize,
) -> anyhow::Result<usize> {
    let key_hex = hex::encode(&key[..8]);
    let mut target = [0u8; 20];
    target.copy_from_slice(&key[..20]);
    let peers = handle
        .dht_find_node_iterative(transport, target, seed_peers)
        .await?;

    debug!(
        key = %key_hex,
        closest_peers = peers.len(),
        replication_factor,
        "replicate_store_to_closest: found closest peers"
    );

    let deduped = dedup_peers_by_pubkey(peers);

    let mut stored = 0usize;
    for peer in deduped.into_iter().take(replication_factor) {
        match query_store(transport, &peer, key, value.clone(), ttl_secs).await {
            Ok(()) => {
                debug!(key = %key_hex, peer = ?peer, "replicate_store: stored on peer");
                stored += 1;
            }
            Err(e) => {
                warn!(key = %key_hex, peer = ?peer, error = %e, "replicate_store: failed to store on peer");
            }
        }
    }
    debug!(key = %key_hex, stored, "replicate_store_to_closest: done");
    Ok(stored)
}

/// Store a DHT value on a pre-resolved peer list (skips iterative lookup).
///
/// Returns `(stored_count, rate_limited)` so callers can back off when the
/// remote peer is throttling.
pub(super) async fn replicate_store_to_peers<T: RequestTransport + ?Sized>(
    transport: &T,
    key: [u8; 32],
    value: Vec<u8>,
    ttl_secs: u64,
    peers: &[PeerAddr],
    replication_factor: usize,
) -> (usize, bool) {
    let key_hex = hex::encode(&key[..8]);
    let mut stored = 0usize;
    let mut rate_limited = false;
    for peer in peers.iter().take(replication_factor) {
        match query_store(transport, peer, key, value.clone(), ttl_secs).await {
            Ok(()) => {
                debug!(key = %key_hex, peer = ?peer, "replicate_store_to_peers: stored");
                stored += 1;
            }
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("rate limit") {
                    debug!(key = %key_hex, peer = ?peer, "replicate_store_to_peers: rate limited");
                    rate_limited = true;
                    break;
                }
                debug!(key = %key_hex, peer = ?peer, error = %msg, "replicate_store_to_peers: failed");
            }
        }
    }
    (stored, rate_limited)
}

/// Deduplicate peers so that each unique pubkey (or IP:port:transport for
/// peers without a pubkey hint) appears only once.  Keeps the first
/// occurrence.
fn dedup_peers_by_pubkey(peers: Vec<PeerAddr>) -> Vec<PeerAddr> {
    let mut seen = HashSet::new();
    peers
        .into_iter()
        .filter(|p| seen.insert(relay_peer_key(p)))
        .collect()
}

/// Persist current state: snapshot under write-lock (to read and clear
/// dirty flags), drop lock, then write only dirty sections.
/// Short-circuits when nothing has changed.
pub(super) async fn persist_state(handle: &NodeHandle) -> anyhow::Result<()> {
    let (snapshot, store, dirty) = {
        let mut state = handle.state.write().await;
        let dirty = state.dirty;
        if !dirty.any() {
            return Ok(());
        }
        let snapshot = state.to_persisted();
        state.dirty = crate::store::DirtyFlags::default();
        (snapshot, state.store.clone(), dirty)
    };
    store.save_incremental(&snapshot, &dirty).await
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
