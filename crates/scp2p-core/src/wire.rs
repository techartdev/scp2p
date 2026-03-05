// Copyright (c) 2024-2026 Vanyo Vanev / Tech Art Ltd
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
use ed25519_dalek::{Signer, Verifier};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

use crate::{manifest::PublicShareSummary, peer::PeerAddr};

// ── Integer-keyed CBOR helpers ──────────────────────────────────────────
//
// High-frequency wire payloads are encoded as CBOR maps with integer keys
// (rather than string field names) to reduce bandwidth.

mod int_cbor {
    use ciborium::Value;

    /// Extract a `Vec<(Value, Value)>` map from a ciborium `Value`.
    pub fn into_map(val: Value) -> Result<Vec<(Value, Value)>, String> {
        match val {
            Value::Map(m) => Ok(m),
            other => Err(format!("expected CBOR map, got {:?}", other)),
        }
    }

    /// Find a field in a CBOR map by integer key.
    ///
    /// The `str_key` parameter is unused for matching but kept as a
    /// label for error messages in callers.
    pub fn find_field<'a>(
        map: &'a [(Value, Value)],
        int_key: i64,
        _str_key: &str,
    ) -> Option<&'a Value> {
        map.iter()
            .find(|(k, _)| {
                k.as_integer()
                    .map(|i| i128::from(i) == int_key as i128)
                    .unwrap_or(false)
            })
            .map(|(_, v)| v)
    }

    /// Extract a required byte-array field of exactly `N` bytes.
    pub fn extract_byte_array<const N: usize>(
        map: &[(Value, Value)],
        int_key: i64,
        str_key: &str,
    ) -> Result<[u8; N], String> {
        let val =
            find_field(map, int_key, str_key).ok_or_else(|| format!("missing field {str_key}"))?;
        let bytes = val
            .as_bytes()
            .ok_or_else(|| format!("field {str_key}: expected bytes"))?;
        if bytes.len() != N {
            return Err(format!(
                "field {str_key}: expected {N} bytes, got {}",
                bytes.len()
            ));
        }
        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    /// Extract a required byte buffer field.
    pub fn extract_bytes(
        map: &[(Value, Value)],
        int_key: i64,
        str_key: &str,
    ) -> Result<Vec<u8>, String> {
        let val =
            find_field(map, int_key, str_key).ok_or_else(|| format!("missing field {str_key}"))?;
        val.as_bytes()
            .cloned()
            .ok_or_else(|| format!("field {str_key}: expected bytes"))
    }

    /// Extract a required unsigned integer field.
    pub fn extract_u64(map: &[(Value, Value)], int_key: i64, str_key: &str) -> Result<u64, String> {
        let val =
            find_field(map, int_key, str_key).ok_or_else(|| format!("missing field {str_key}"))?;
        match val.as_integer() {
            Some(i) => {
                let n: i128 = i.into();
                u64::try_from(n).map_err(|_| format!("field {str_key}: integer out of u64 range"))
            }
            None => Err(format!("field {str_key}: expected integer")),
        }
    }

    /// Extract a required u32 field.
    pub fn extract_u32(map: &[(Value, Value)], int_key: i64, str_key: &str) -> Result<u32, String> {
        extract_u64(map, int_key, str_key)?
            .try_into()
            .map_err(|_| format!("field {str_key}: integer out of u32 range"))
    }

    /// Encode a byte array as `(integer_key, Value::Bytes)` pair.
    pub fn kv_bytes(key: i64, bytes: &[u8]) -> (Value, Value) {
        (Value::Integer(key.into()), Value::Bytes(bytes.to_vec()))
    }

    /// Encode a u64 as `(integer_key, Value::Integer)` pair.
    pub fn kv_u64(key: i64, n: u64) -> (Value, Value) {
        (
            Value::Integer(key.into()),
            Value::Integer((n as i64).into()),
        )
    }

    /// Encode a u32 as `(integer_key, Value::Integer)` pair.
    pub fn kv_u32(key: i64, n: u32) -> (Value, Value) {
        kv_u64(key, n as u64)
    }

    /// Encode a serde-serializable value as `(integer_key, Value)` pair.
    pub fn kv_serde<T: serde::Serialize>(key: i64, val: &T) -> Result<(Value, Value), String> {
        // Serialize to CBOR bytes, then parse back as Value.
        let cbor_bytes = crate::cbor::to_vec(val).map_err(|e| format!("serialize nested: {e}"))?;
        let v: Value =
            crate::cbor::from_slice(&cbor_bytes).map_err(|e| format!("parse nested value: {e}"))?;
        Ok((Value::Integer(key.into()), v))
    }

    /// Deserialize a nested serde type from a CBOR Value.
    pub fn deser_value<T: serde::de::DeserializeOwned>(
        map: &[(Value, Value)],
        int_key: i64,
        str_key: &str,
    ) -> Result<T, String> {
        let val =
            find_field(map, int_key, str_key).ok_or_else(|| format!("missing field {str_key}"))?;
        // Round-trip through CBOR bytes.
        let cbor_bytes = crate::cbor::to_vec(val)
            .map_err(|e| format!("field {str_key}: serialize for deser: {e}"))?;
        crate::cbor::from_slice(&cbor_bytes)
            .map_err(|e| format!("field {str_key}: deserialize: {e}"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub r#type: u16,
    pub req_id: u32,
    pub flags: u16,
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
}

pub const FLAG_RESPONSE: u16 = 0x0001;
pub const FLAG_ERROR: u16 = 0x0002;

/// Default upper bound for serialized envelope size accepted from the wire.
pub const MAX_ENVELOPE_BYTES: usize = 2 * 1024 * 1024;
/// Default upper bound for decoded payload bytes accepted from the wire.
pub const MAX_ENVELOPE_PAYLOAD_BYTES: usize = 1024 * 1024;

impl Envelope {
    pub fn encode(&self) -> anyhow::Result<Vec<u8>> {
        Ok(crate::cbor::to_vec(self)?)
    }

    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        Self::decode_with_limits(bytes, MAX_ENVELOPE_BYTES, MAX_ENVELOPE_PAYLOAD_BYTES)
    }

    pub fn decode_with_limits(
        bytes: &[u8],
        max_envelope_bytes: usize,
        max_payload_bytes: usize,
    ) -> anyhow::Result<Self> {
        if bytes.len() > max_envelope_bytes {
            anyhow::bail!(
                "envelope exceeds max size: {} > {}",
                bytes.len(),
                max_envelope_bytes
            );
        }

        let envelope: Self = crate::cbor::from_slice(bytes)?;
        if envelope.payload.len() > max_payload_bytes {
            anyhow::bail!(
                "envelope payload exceeds max size: {} > {}",
                envelope.payload.len(),
                max_payload_bytes
            );
        }
        Ok(envelope)
    }

    /// Decode the envelope payload into a typed protocol message.
    pub fn decode_typed(&self) -> anyhow::Result<WirePayload> {
        WirePayload::decode(self.r#type, &self.payload)
    }

    /// Build an envelope from a typed protocol payload.
    pub fn from_typed(req_id: u32, flags: u16, payload: &WirePayload) -> anyhow::Result<Self> {
        Ok(Self {
            r#type: u16::from(payload.msg_type()),
            req_id,
            flags,
            payload: payload.encode()?,
        })
    }
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MsgType {
    /// Peer exchange with known-good peer addresses.
    PexOffer = 100,
    /// Request peer exchange records from a remote peer.
    PexRequest = 101,
    /// Kademlia FIND_NODE query.
    FindNode = 200,
    /// Kademlia FIND_VALUE query.
    FindValue = 201,
    /// Kademlia STORE request.
    Store = 202,
    /// Subscription manifest request.
    GetManifest = 400,
    /// Serialized manifest response.
    ManifestData = 401,
    /// Request public-share summaries from a reachable peer.
    ListPublicShares = 402,
    /// Public-share listing response.
    PublicShareList = 403,
    /// Ask a reachable peer whether it is joined to a specific community.
    GetCommunityStatus = 404,
    /// Response for a specific community membership probe.
    CommunityStatus = 405,
    /// Request public-share summaries for a specific joined community.
    ListCommunityPublicShares = 406,
    /// Community-scoped public-share listing response.
    CommunityPublicShareList = 407,
    // §15.6 — Large-scale community browse, search, and delta sync
    /// Paginated community member list request (§15.6.1).
    ListCommunityMembersPage = 410,
    /// Paginated community member list response (§15.6.1).
    CommunityMembersPage = 411,
    /// Paginated community shares list request (§15.6.1).
    ListCommunitySharesPage = 412,
    /// Paginated community shares list response (§15.6.1).
    CommunitySharesPage = 413,
    /// Community metadata search request (§15.6.2).
    SearchCommunityShares = 414,
    /// Community metadata search response (§15.6.2).
    CommunitySearchResults = 415,
    /// Community delta/event sync request (§15.6.3).
    ListCommunityEvents = 416,
    /// Community delta/event sync response (§15.6.3).
    CommunityEvents = 417,
    /// Relay registration request.
    RelayRegister = 450,
    /// Relay registration acknowledgement.
    RelayRegistered = 451,
    /// Relay connection request.
    RelayConnect = 452,
    /// Relay stream frame.
    RelayStream = 453,
    /// Provider hint response for a content object.
    Providers = 498,
    /// Provider hint advertisement for a content object.
    HaveContent = 499,
    /// Chunk request.
    GetChunk = 500,
    /// Chunk payload response.
    ChunkData = 501,
    /// Request chunk hash list for a content object.
    GetChunkHashes = 502,
    /// Chunk hash list response.
    ChunkHashList = 503,
    /// Relay-PEX: request known relays.
    RelayListRequest = 460,
    /// Relay-PEX: response with known relay announcements.
    RelayListResponse = 461,
}

impl MsgType {
    /// Stable `u16` registry for protocol envelope types.
    pub const ALL: [Self; 33] = [
        Self::PexOffer,
        Self::PexRequest,
        Self::FindNode,
        Self::FindValue,
        Self::Store,
        Self::GetManifest,
        Self::ManifestData,
        Self::ListPublicShares,
        Self::PublicShareList,
        Self::GetCommunityStatus,
        Self::CommunityStatus,
        Self::ListCommunityPublicShares,
        Self::CommunityPublicShareList,
        Self::ListCommunityMembersPage,
        Self::CommunityMembersPage,
        Self::ListCommunitySharesPage,
        Self::CommunitySharesPage,
        Self::SearchCommunityShares,
        Self::CommunitySearchResults,
        Self::ListCommunityEvents,
        Self::CommunityEvents,
        Self::RelayRegister,
        Self::RelayRegistered,
        Self::RelayConnect,
        Self::RelayStream,
        Self::RelayListRequest,
        Self::RelayListResponse,
        Self::Providers,
        Self::HaveContent,
        Self::GetChunk,
        Self::ChunkData,
        Self::GetChunkHashes,
        Self::ChunkHashList,
    ];
}

impl From<MsgType> for u16 {
    fn from(value: MsgType) -> Self {
        value as u16
    }
}

impl TryFrom<u16> for MsgType {
    type Error = anyhow::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            100 => Ok(Self::PexOffer),
            101 => Ok(Self::PexRequest),
            200 => Ok(Self::FindNode),
            201 => Ok(Self::FindValue),
            202 => Ok(Self::Store),
            400 => Ok(Self::GetManifest),
            401 => Ok(Self::ManifestData),
            402 => Ok(Self::ListPublicShares),
            403 => Ok(Self::PublicShareList),
            404 => Ok(Self::GetCommunityStatus),
            405 => Ok(Self::CommunityStatus),
            406 => Ok(Self::ListCommunityPublicShares),
            407 => Ok(Self::CommunityPublicShareList),
            410 => Ok(Self::ListCommunityMembersPage),
            411 => Ok(Self::CommunityMembersPage),
            412 => Ok(Self::ListCommunitySharesPage),
            413 => Ok(Self::CommunitySharesPage),
            414 => Ok(Self::SearchCommunityShares),
            415 => Ok(Self::CommunitySearchResults),
            416 => Ok(Self::ListCommunityEvents),
            417 => Ok(Self::CommunityEvents),
            450 => Ok(Self::RelayRegister),
            451 => Ok(Self::RelayRegistered),
            452 => Ok(Self::RelayConnect),
            453 => Ok(Self::RelayStream),
            460 => Ok(Self::RelayListRequest),
            461 => Ok(Self::RelayListResponse),
            498 => Ok(Self::Providers),
            499 => Ok(Self::HaveContent),
            500 => Ok(Self::GetChunk),
            501 => Ok(Self::ChunkData),
            502 => Ok(Self::GetChunkHashes),
            503 => Ok(Self::ChunkHashList),
            _ => anyhow::bail!("unknown message type {value}"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PexOffer {
    pub peers: Vec<PeerAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PexRequest {
    pub max_peers: u8,
}

/// Kademlia FIND_NODE query.  Wire format: integer-keyed CBOR map `{0: bytes}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindNode {
    pub target_node_id: [u8; 20],
}

impl Serialize for FindNode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        ciborium::Value::Map(vec![int_cbor::kv_bytes(0, &self.target_node_id)])
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for FindNode {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let val = ciborium::Value::deserialize(deserializer)?;
        let map = int_cbor::into_map(val).map_err(serde::de::Error::custom)?;
        Ok(FindNode {
            target_node_id: int_cbor::extract_byte_array(&map, 0, "target_node_id")
                .map_err(serde::de::Error::custom)?,
        })
    }
}

/// Kademlia FIND_NODE result.  Wire format: integer-keyed CBOR map `{0: array}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindNodeResult {
    pub peers: Vec<PeerAddr>,
}

impl Serialize for FindNodeResult {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        ciborium::Value::Map(vec![
            int_cbor::kv_serde(0, &self.peers).map_err(serde::ser::Error::custom)?,
        ])
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for FindNodeResult {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let val = ciborium::Value::deserialize(deserializer)?;
        let map = int_cbor::into_map(val).map_err(serde::de::Error::custom)?;
        Ok(FindNodeResult {
            peers: int_cbor::deser_value(&map, 0, "peers").map_err(serde::de::Error::custom)?,
        })
    }
}

/// Kademlia FIND_VALUE query.  Wire format: integer-keyed CBOR map `{0: bytes}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindValue {
    pub key: [u8; 32],
}

impl Serialize for FindValue {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        ciborium::Value::Map(vec![int_cbor::kv_bytes(0, &self.key)]).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for FindValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let val = ciborium::Value::deserialize(deserializer)?;
        let map = int_cbor::into_map(val).map_err(serde::de::Error::custom)?;
        Ok(FindValue {
            key: int_cbor::extract_byte_array(&map, 0, "key").map_err(serde::de::Error::custom)?,
        })
    }
}

/// Kademlia STORE request.  Wire format: `{0: key, 1: value, 2: ttl_secs}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Store {
    pub key: [u8; 32],
    pub value: Vec<u8>,
    pub ttl_secs: u64,
}

impl Serialize for Store {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        ciborium::Value::Map(vec![
            int_cbor::kv_bytes(0, &self.key),
            int_cbor::kv_bytes(1, &self.value),
            int_cbor::kv_u64(2, self.ttl_secs),
        ])
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Store {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let val = ciborium::Value::deserialize(deserializer)?;
        let map = int_cbor::into_map(val).map_err(serde::de::Error::custom)?;
        Ok(Store {
            key: int_cbor::extract_byte_array(&map, 0, "key").map_err(serde::de::Error::custom)?,
            value: int_cbor::extract_bytes(&map, 1, "value").map_err(serde::de::Error::custom)?,
            ttl_secs: int_cbor::extract_u64(&map, 2, "ttl_secs")
                .map_err(serde::de::Error::custom)?,
        })
    }
}

/// FIND_VALUE result.  Wire format: `{0: value_or_null, 1: closer_peers}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindValueResult {
    pub value: Option<Store>,
    pub closer_peers: Vec<PeerAddr>,
}

impl Serialize for FindValueResult {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let val_entry = match &self.value {
            Some(s) => int_cbor::kv_serde(0, s).map_err(serde::ser::Error::custom)?,
            None => (ciborium::Value::Integer(0.into()), ciborium::Value::Null),
        };
        ciborium::Value::Map(vec![
            val_entry,
            int_cbor::kv_serde(1, &self.closer_peers).map_err(serde::ser::Error::custom)?,
        ])
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for FindValueResult {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let val = ciborium::Value::deserialize(deserializer)?;
        let map = int_cbor::into_map(val).map_err(serde::de::Error::custom)?;
        let value_field = int_cbor::find_field(&map, 0, "value");
        let value = match value_field {
            Some(ciborium::Value::Null) | None => None,
            Some(_) => {
                Some(int_cbor::deser_value(&map, 0, "value").map_err(serde::de::Error::custom)?)
            }
        };
        Ok(FindValueResult {
            value,
            closer_peers: int_cbor::deser_value(&map, 1, "closer_peers")
                .map_err(serde::de::Error::custom)?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GetManifest {
    pub manifest_id: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestData {
    pub manifest_id: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListPublicShares {
    pub max_entries: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicShareList {
    pub shares: Vec<PublicShareSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GetCommunityStatus {
    pub community_share_id: [u8; 32],
    pub community_share_pubkey: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommunityStatus {
    pub community_share_id: [u8; 32],
    pub joined: bool,
    /// Serialized `CommunityMembershipToken` (CBOR bytes), if the node
    /// holds a cryptographic proof of membership.  Absent means
    /// membership is self-asserted (v0.1 default).
    #[serde(default, with = "serde_bytes")]
    pub membership_proof: Option<Vec<u8>>,
    /// Human-readable community name, if the responding node knows it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListCommunityPublicShares {
    pub community_share_id: [u8; 32],
    pub community_share_pubkey: [u8; 32],
    pub max_entries: u16,
    /// Ed25519 public key of the requesting node's stable identity.
    ///
    /// Required when the serving node has `community_strict_mode` enabled.
    /// May be omitted for permissive-mode servers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester_node_pubkey: Option<[u8; 32]>,
    /// Serialized `CommunityMembershipToken` (CBOR bytes) proving the
    /// requester is a member of the requested community.
    ///
    /// Required when the serving node has `community_strict_mode` enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester_membership_proof: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommunityPublicShareList {
    pub community_share_id: [u8; 32],
    pub shares: Vec<PublicShareSummary>,
}

// ── §15.6 Paginated community browse / search / delta messages ──────

/// Paginated member list request (§15.6.1).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListCommunityMembersPage {
    pub community_id: [u8; 32],
    /// Opaque cursor from a previous response.  Absent for the first page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    pub limit: u16,
}

/// Summary of a community member for paginated responses.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommunityMemberSummary {
    pub member_node_pubkey: [u8; 32],
    pub status: CommunityMemberStatus,
    pub announce_seq: u64,
    pub addr: Option<PeerAddr>,
}

/// Paginated member list response (§15.6.1).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommunityMembersPageResponse {
    pub community_id: [u8; 32],
    pub entries: Vec<CommunityMemberSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Paginated share list request (§15.6.1).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListCommunitySharesPage {
    pub community_id: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    pub limit: u16,
    /// Optional: only return entries updated after this UNIX timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since_unix: Option<u64>,
}

/// Summary of a community share for paginated responses.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommunityShareSummary {
    pub share_id: [u8; 32],
    pub share_pubkey: [u8; 32],
    pub latest_seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub updated_at: u64,
}

/// Paginated share list response (§15.6.1).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommunitySharesPageResponse {
    pub community_id: [u8; 32],
    pub entries: Vec<CommunityShareSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Community metadata search request (§15.6.2).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SearchCommunitySharesReq {
    pub community_id: [u8; 32],
    pub query: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    pub limit: u16,
}

/// Community metadata search hit.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommunityShareHit {
    pub share_id: [u8; 32],
    pub share_pubkey: [u8; 32],
    pub latest_seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub score: u32,
}

/// Community metadata search response (§15.6.2).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommunitySearchResultsResp {
    pub community_id: [u8; 32],
    pub hits: Vec<CommunityShareHit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Community delta/event sync request (§15.6.3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListCommunityEventsReq {
    pub community_id: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since_cursor: Option<String>,
    pub limit: u16,
}

/// Community event types (§15.6.3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CommunityEvent {
    MemberJoined {
        member_node_pubkey: [u8; 32],
        announce_seq: u64,
    },
    MemberLeft {
        member_node_pubkey: [u8; 32],
        announce_seq: u64,
    },
    ShareUpserted {
        share_id: [u8; 32],
        latest_seq: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        title: Option<String>,
    },
}

/// Community delta/event sync response (§15.6.3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommunityEventsResp {
    pub community_id: [u8; 32],
    pub events: Vec<CommunityEvent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayRegister {
    #[serde(default)]
    pub relay_slot_id: Option<u64>,
    /// When `true` the sender is a firewalled node that wants the relay
    /// to keep this connection open and forward incoming requests from
    /// other peers through it.  The relay transitions the connection to
    /// relay-bridge mode after replying with `RelayRegistered`.
    #[serde(default)]
    pub tunnel: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayRegistered {
    pub relay_slot_id: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayConnect {
    pub relay_slot_id: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum RelayPayloadKind {
    #[default]
    Control,
    Content,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayStream {
    pub relay_slot_id: u64,
    pub stream_id: u32,
    #[serde(default)]
    pub kind: RelayPayloadKind,
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HaveContent {
    pub content_id: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Providers {
    pub content_id: [u8; 32],
    pub providers: Vec<PeerAddr>,
    pub updated_at: u64,
}

/// DHT value listing peer addresses of nodes that have joined a community.
///
/// Stored under `community_info_key(share_id)`.  When a remote peer
/// receives a STORE for this key, it merges the incoming member list
/// with the existing one so the relay accumulates all members.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommunityMembers {
    pub community_share_id: [u8; 32],
    pub members: Vec<PeerAddr>,
    pub updated_at: u64,
}

// ── §15 Large-Scale Community Records ───────────────────────────────

/// Typed value tag bytes for community keyspace dispatch (§15.4.0).
///
/// The first byte of the DHT value payload identifies the record type,
/// allowing the validator to route to the correct deserializer without
/// trial-parsing every known struct.
pub mod community_tags {
    /// Per-member community record (§15.4.1).
    pub const MEMBER_RECORD: u8 = 0x31;
    /// Per-share community announcement (§15.4.2).
    pub const SHARE_RECORD: u8 = 0x32;
    /// Lightweight community bootstrap hint (§15.4.1b).
    pub const BOOTSTRAP_HINT: u8 = 0x33;
    /// Materialized members page (§15.5, relay-derived).
    pub const MEMBERS_PAGE: u8 = 0x34;
    /// Materialized shares page (§15.5, relay-derived).
    pub const SHARES_PAGE: u8 = 0x35;
}

/// Per-member community record stored in the DHT (§15.4.1).
///
/// Signed by the member's own Ed25519 node key.  Replaces the
/// monolithic `CommunityMembers` blob for scalable membership tracking.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommunityMemberRecord {
    pub community_id: [u8; 32],
    pub member_node_pubkey: [u8; 32],
    pub announce_seq: u64,
    pub status: CommunityMemberStatus,
    pub issued_at: u64,
    pub expires_at: u64,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    /// Optional publisher-issued authorization token (§4.2).
    ///
    /// When the community enforces publisher authorization, the community
    /// publisher signs a [`CommunityMembershipToken`] for this member and
    /// the member includes its CBOR-encoded bytes here.  Relaying peers
    /// for which this community is token-gated will reject records without
    /// a valid token.
    ///
    /// `None` for open (self-join) communities.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_token_bytes: Option<serde_bytes::ByteBuf>,
}

/// Member status for per-member community records.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CommunityMemberStatus {
    Joined,
    Left,
}

/// Signable portion of a `CommunityMemberRecord` (all fields except `signature`).
#[derive(Serialize)]
struct CommunityMemberRecordSignable(
    [u8; 32], // community_id
    [u8; 32], // member_node_pubkey
    u64,      // announce_seq
    bool,     // true = joined, false = left
    u64,      // issued_at
    u64,      // expires_at
);

impl CommunityMemberRecord {
    /// Maximum TTL for leave tombstones (7 days per §15.4.1).
    pub const LEAVE_TOMBSTONE_MAX_TTL_SECS: u64 = 7 * 24 * 3600;

    /// Create and sign a new member record.
    pub fn new_signed(
        signing_key: &ed25519_dalek::SigningKey,
        community_id: [u8; 32],
        announce_seq: u64,
        status: CommunityMemberStatus,
        issued_at: u64,
        expires_at: u64,
    ) -> anyhow::Result<Self> {
        let member_node_pubkey = signing_key.verifying_key().to_bytes();
        let is_joined = matches!(status, CommunityMemberStatus::Joined);
        let signable = CommunityMemberRecordSignable(
            community_id,
            member_node_pubkey,
            announce_seq,
            is_joined,
            issued_at,
            expires_at,
        );
        let sig = signing_key.sign(&crate::cbor::to_vec(&signable)?);
        Ok(Self {
            community_id,
            member_node_pubkey,
            announce_seq,
            status,
            issued_at,
            expires_at,
            signature: sig.to_bytes().to_vec(),
            auth_token_bytes: None,
        })
    }

    /// Verify the Ed25519 signature against `member_node_pubkey`.
    pub fn verify_signature(&self) -> anyhow::Result<()> {
        use ed25519_dalek::{Signature, VerifyingKey};
        if self.signature.len() != 64 {
            anyhow::bail!("CommunityMemberRecord signature must be 64 bytes");
        }
        let vk = VerifyingKey::from_bytes(&self.member_node_pubkey)?;
        let is_joined = matches!(self.status, CommunityMemberStatus::Joined);
        let signable = CommunityMemberRecordSignable(
            self.community_id,
            self.member_node_pubkey,
            self.announce_seq,
            is_joined,
            self.issued_at,
            self.expires_at,
        );
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&self.signature);
        vk.verify(
            &crate::cbor::to_vec(&signable)?,
            &Signature::from_bytes(&sig_arr),
        )?;
        Ok(())
    }

    /// Encode with typed tag prefix for DHT storage (§15.4.0).
    pub fn encode_tagged(&self) -> anyhow::Result<Vec<u8>> {
        let cbor = crate::cbor::to_vec(self)?;
        let mut out = Vec::with_capacity(1 + cbor.len());
        out.push(community_tags::MEMBER_RECORD);
        out.extend_from_slice(&cbor);
        Ok(out)
    }

    /// Decode from a tagged value payload.
    ///
    /// Caller must have already verified the first byte is
    /// `community_tags::MEMBER_RECORD`.
    pub fn decode_tagged(data: &[u8]) -> anyhow::Result<Self> {
        if data.is_empty() {
            anyhow::bail!("empty tagged community member record");
        }
        if data[0] != community_tags::MEMBER_RECORD {
            anyhow::bail!("wrong tag for community member record: 0x{:02x}", data[0]);
        }
        Ok(crate::cbor::from_slice(&data[1..])?)
    }
}

/// Per-share community announcement stored in the DHT (§15.4.2).
///
/// Signed by the share's Ed25519 key.  Allows browsing community
/// shares without querying every participant.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommunityShareRecord {
    pub community_id: [u8; 32],
    pub share_id: [u8; 32],
    pub share_pubkey: [u8; 32],
    pub latest_manifest_id: [u8; 32],
    pub latest_seq: u64,
    pub visibility: ShareVisibilityTag,
    pub updated_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

/// Visibility tag for community share records.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ShareVisibilityTag {
    Public,
}

/// Signable portion of a `CommunityShareRecord`.
#[derive(Serialize)]
struct CommunityShareRecordSignable(
    [u8; 32], // community_id
    [u8; 32], // share_id
    [u8; 32], // share_pubkey
    [u8; 32], // latest_manifest_id
    u64,      // latest_seq
    u64,      // updated_at
);

impl CommunityShareRecord {
    /// Create and sign a new share announcement.
    ///
    /// `share_signing_key` is the Ed25519 key for the share.
    pub fn new_signed(
        share_signing_key: &ed25519_dalek::SigningKey,
        community_id: [u8; 32],
        latest_manifest_id: [u8; 32],
        latest_seq: u64,
        updated_at: u64,
        title: Option<String>,
        description: Option<String>,
    ) -> anyhow::Result<Self> {
        let share_pubkey = share_signing_key.verifying_key().to_bytes();
        let share_id = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(share_pubkey);
            let d = h.finalize();
            let mut out = [0u8; 32];
            out.copy_from_slice(&d);
            out
        };
        let signable = CommunityShareRecordSignable(
            community_id,
            share_id,
            share_pubkey,
            latest_manifest_id,
            latest_seq,
            updated_at,
        );
        let sig = share_signing_key.sign(&crate::cbor::to_vec(&signable)?);
        Ok(Self {
            community_id,
            share_id,
            share_pubkey,
            latest_manifest_id,
            latest_seq,
            visibility: ShareVisibilityTag::Public,
            updated_at,
            title,
            description,
            signature: sig.to_bytes().to_vec(),
        })
    }

    /// Verify the signature and that `share_id == SHA-256(share_pubkey)`.
    pub fn verify(&self) -> anyhow::Result<()> {
        use ed25519_dalek::{Signature, VerifyingKey};
        // Check share_id derivation rule.
        let expected_id = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(self.share_pubkey);
            let d = h.finalize();
            let mut out = [0u8; 32];
            out.copy_from_slice(&d);
            out
        };
        if expected_id != self.share_id {
            anyhow::bail!("share_id does not match SHA-256(share_pubkey)");
        }
        // Verify signature.
        if self.signature.len() != 64 {
            anyhow::bail!("CommunityShareRecord signature must be 64 bytes");
        }
        let vk = VerifyingKey::from_bytes(&self.share_pubkey)?;
        let signable = CommunityShareRecordSignable(
            self.community_id,
            self.share_id,
            self.share_pubkey,
            self.latest_manifest_id,
            self.latest_seq,
            self.updated_at,
        );
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&self.signature);
        vk.verify(
            &crate::cbor::to_vec(&signable)?,
            &Signature::from_bytes(&sig_arr),
        )?;
        Ok(())
    }

    /// Encode with typed tag prefix for DHT storage (§15.4.0).
    pub fn encode_tagged(&self) -> anyhow::Result<Vec<u8>> {
        let cbor = crate::cbor::to_vec(self)?;
        let mut out = Vec::with_capacity(1 + cbor.len());
        out.push(community_tags::SHARE_RECORD);
        out.extend_from_slice(&cbor);
        Ok(out)
    }

    /// Decode from a tagged value payload.
    pub fn decode_tagged(data: &[u8]) -> anyhow::Result<Self> {
        if data.is_empty() {
            anyhow::bail!("empty tagged community share record");
        }
        if data[0] != community_tags::SHARE_RECORD {
            anyhow::bail!("wrong tag for community share record: 0x{:02x}", data[0]);
        }
        Ok(crate::cbor::from_slice(&data[1..])?)
    }
}

/// Lightweight community bootstrap hint for first-contact discovery (§15.4.1b).
///
/// Advisory only — not authoritative for membership.  Clients MUST
/// verify discovered membership/share state using signed per-member/
/// per-share records before trusting anything from the hint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommunityBootstrapHint {
    pub community_id: [u8; 32],
    pub member_count_estimate: u64,
    /// Bounded sample of known member addresses (max 16).
    pub sample_members: Vec<PeerAddr>,
    /// Peers/relays known to serve paginated community indexes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub index_peers: Vec<PeerAddr>,
    pub updated_at: u64,
}

impl CommunityBootstrapHint {
    /// Max entries in `sample_members` to keep the hint bounded.
    pub const MAX_SAMPLE_MEMBERS: usize = 16;
    /// Max entries in `index_peers`.
    pub const MAX_INDEX_PEERS: usize = 8;

    /// Encode with typed tag prefix for DHT storage (§15.4.0).
    pub fn encode_tagged(&self) -> anyhow::Result<Vec<u8>> {
        let cbor = crate::cbor::to_vec(self)?;
        let mut out = Vec::with_capacity(1 + cbor.len());
        out.push(community_tags::BOOTSTRAP_HINT);
        out.extend_from_slice(&cbor);
        Ok(out)
    }

    /// Decode from a tagged value payload.
    pub fn decode_tagged(data: &[u8]) -> anyhow::Result<Self> {
        if data.is_empty() {
            anyhow::bail!("empty tagged community bootstrap hint");
        }
        if data[0] != community_tags::BOOTSTRAP_HINT {
            anyhow::bail!("wrong tag for community bootstrap hint: 0x{:02x}", data[0]);
        }
        Ok(crate::cbor::from_slice(&data[1..])?)
    }
}

/// Materialized community members page stored in the DHT (§15.5).
///
/// Relay-derived snapshot of a page of community members.  These are
/// advisory cache entries — the source of truth remains the individual
/// signed `CommunityMemberRecord` values.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MaterializedMembersPage {
    pub community_id: [u8; 32],
    /// Time bucket (unix secs / `MATERIALIZED_BUCKET_SECS`).
    pub bucket: u64,
    /// Zero-based page number within this bucket snapshot.
    pub page_no: u16,
    /// Total pages in the snapshot (so the client knows when to stop).
    pub total_pages: u16,
    /// Member summaries for this page.
    pub entries: Vec<CommunityMemberSummary>,
    /// UNIX timestamp when this page was built.
    pub built_at: u64,
}

impl MaterializedMembersPage {
    /// Encode with typed tag prefix for DHT storage.
    pub fn encode_tagged(&self) -> anyhow::Result<Vec<u8>> {
        let cbor = crate::cbor::to_vec(self)?;
        let mut out = Vec::with_capacity(1 + cbor.len());
        out.push(community_tags::MEMBERS_PAGE);
        out.extend_from_slice(&cbor);
        Ok(out)
    }

    /// Decode from a tagged value payload.
    pub fn decode_tagged(data: &[u8]) -> anyhow::Result<Self> {
        if data.is_empty() {
            anyhow::bail!("empty tagged materialized members page");
        }
        if data[0] != community_tags::MEMBERS_PAGE {
            anyhow::bail!("wrong tag for materialized members page: 0x{:02x}", data[0]);
        }
        Ok(crate::cbor::from_slice(&data[1..])?)
    }
}

/// Materialized community shares page stored in the DHT (§15.5).
///
/// Relay-derived snapshot of a page of community shares.  These are
/// advisory cache entries — the source of truth remains the individual
/// signed `CommunityShareRecord` values.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MaterializedSharesPage {
    pub community_id: [u8; 32],
    /// Time bucket (unix secs / `MATERIALIZED_BUCKET_SECS`).
    pub bucket: u64,
    /// Zero-based page number within this bucket snapshot.
    pub page_no: u16,
    /// Total pages in the snapshot.
    pub total_pages: u16,
    /// Share summaries for this page.
    pub entries: Vec<CommunityShareSummary>,
    /// UNIX timestamp when this page was built.
    pub built_at: u64,
}

impl MaterializedSharesPage {
    /// Encode with typed tag prefix for DHT storage.
    pub fn encode_tagged(&self) -> anyhow::Result<Vec<u8>> {
        let cbor = crate::cbor::to_vec(self)?;
        let mut out = Vec::with_capacity(1 + cbor.len());
        out.push(community_tags::SHARES_PAGE);
        out.extend_from_slice(&cbor);
        Ok(out)
    }

    /// Decode from a tagged value payload.
    pub fn decode_tagged(data: &[u8]) -> anyhow::Result<Self> {
        if data.is_empty() {
            anyhow::bail!("empty tagged materialized shares page");
        }
        if data[0] != community_tags::SHARES_PAGE {
            anyhow::bail!("wrong tag for materialized shares page: 0x{:02x}", data[0]);
        }
        Ok(crate::cbor::from_slice(&data[1..])?)
    }
}

/// Chunk request.  Wire format: `{0: content_id, 1: chunk_index}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetChunk {
    pub content_id: [u8; 32],
    pub chunk_index: u32,
}

impl Serialize for GetChunk {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        ciborium::Value::Map(vec![
            int_cbor::kv_bytes(0, &self.content_id),
            int_cbor::kv_u32(1, self.chunk_index),
        ])
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for GetChunk {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let val = ciborium::Value::deserialize(deserializer)?;
        let map = int_cbor::into_map(val).map_err(serde::de::Error::custom)?;
        Ok(GetChunk {
            content_id: int_cbor::extract_byte_array(&map, 0, "content_id")
                .map_err(serde::de::Error::custom)?,
            chunk_index: int_cbor::extract_u32(&map, 1, "chunk_index")
                .map_err(serde::de::Error::custom)?,
        })
    }
}

/// Chunk payload response.  Wire format: `{0: content_id, 1: chunk_index, 2: bytes}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkData {
    pub content_id: [u8; 32],
    pub chunk_index: u32,
    pub bytes: Vec<u8>,
}

impl Serialize for ChunkData {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        ciborium::Value::Map(vec![
            int_cbor::kv_bytes(0, &self.content_id),
            int_cbor::kv_u32(1, self.chunk_index),
            int_cbor::kv_bytes(2, &self.bytes),
        ])
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ChunkData {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let val = ciborium::Value::deserialize(deserializer)?;
        let map = int_cbor::into_map(val).map_err(serde::de::Error::custom)?;
        Ok(ChunkData {
            content_id: int_cbor::extract_byte_array(&map, 0, "content_id")
                .map_err(serde::de::Error::custom)?,
            chunk_index: int_cbor::extract_u32(&map, 1, "chunk_index")
                .map_err(serde::de::Error::custom)?,
            bytes: int_cbor::extract_bytes(&map, 2, "bytes").map_err(serde::de::Error::custom)?,
        })
    }
}

/// Request the chunk hash list for a content object.  Wire format: `{0: content_id}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetChunkHashes {
    pub content_id: [u8; 32],
}

impl Serialize for GetChunkHashes {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        ciborium::Value::Map(vec![int_cbor::kv_bytes(0, &self.content_id)]).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for GetChunkHashes {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let val = ciborium::Value::deserialize(deserializer)?;
        let map = int_cbor::into_map(val).map_err(serde::de::Error::custom)?;
        Ok(GetChunkHashes {
            content_id: int_cbor::extract_byte_array(&map, 0, "content_id")
                .map_err(serde::de::Error::custom)?,
        })
    }
}

/// Chunk hash list response.  Wire format: `{0: content_id, 1: hashes}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkHashList {
    pub content_id: [u8; 32],
    pub hashes: Vec<[u8; 32]>,
}

impl Serialize for ChunkHashList {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        ciborium::Value::Map(vec![
            int_cbor::kv_bytes(0, &self.content_id),
            int_cbor::kv_serde(1, &self.hashes).map_err(serde::ser::Error::custom)?,
        ])
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ChunkHashList {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let val = ciborium::Value::deserialize(deserializer)?;
        let map = int_cbor::into_map(val).map_err(serde::de::Error::custom)?;
        Ok(ChunkHashList {
            content_id: int_cbor::extract_byte_array(&map, 0, "content_id")
                .map_err(serde::de::Error::custom)?,
            hashes: int_cbor::deser_value(&map, 1, "hashes").map_err(serde::de::Error::custom)?,
        })
    }
}

/// Relay-PEX: request known relay announcements from a peer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayListRequest {
    /// Maximum number of relay announcements to return.
    pub max_count: u16,
}

/// Relay-PEX: response with known relay announcements.
///
/// Each entry is a full signed `RelayAnnouncement` so recipients
/// can validate independently.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayListResponse {
    pub announcements: Vec<crate::relay::RelayAnnouncement>,
}

/// Typed envelope payloads used by dispatcher-style message handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WirePayload {
    PexOffer(PexOffer),
    PexRequest(PexRequest),
    FindNode(FindNode),
    FindValue(FindValue),
    Store(Store),
    GetManifest(GetManifest),
    ManifestData(ManifestData),
    ListPublicShares(ListPublicShares),
    PublicShareList(PublicShareList),
    GetCommunityStatus(GetCommunityStatus),
    CommunityStatus(CommunityStatus),
    ListCommunityPublicShares(ListCommunityPublicShares),
    CommunityPublicShareList(CommunityPublicShareList),
    ListCommunityMembersPage(ListCommunityMembersPage),
    CommunityMembersPage(CommunityMembersPageResponse),
    ListCommunitySharesPage(ListCommunitySharesPage),
    CommunitySharesPage(CommunitySharesPageResponse),
    SearchCommunityShares(SearchCommunitySharesReq),
    CommunitySearchResults(CommunitySearchResultsResp),
    ListCommunityEvents(ListCommunityEventsReq),
    CommunityEvents(CommunityEventsResp),
    RelayRegister(RelayRegister),
    RelayRegistered(RelayRegistered),
    RelayConnect(RelayConnect),
    RelayStream(RelayStream),
    RelayListRequest(RelayListRequest),
    RelayListResponse(RelayListResponse),
    Providers(Providers),
    HaveContent(HaveContent),
    GetChunk(GetChunk),
    ChunkData(ChunkData),
    GetChunkHashes(GetChunkHashes),
    ChunkHashList(ChunkHashList),
}

impl WirePayload {
    pub fn msg_type(&self) -> MsgType {
        match self {
            Self::PexOffer(_) => MsgType::PexOffer,
            Self::PexRequest(_) => MsgType::PexRequest,
            Self::FindNode(_) => MsgType::FindNode,
            Self::FindValue(_) => MsgType::FindValue,
            Self::Store(_) => MsgType::Store,
            Self::GetManifest(_) => MsgType::GetManifest,
            Self::ManifestData(_) => MsgType::ManifestData,
            Self::ListPublicShares(_) => MsgType::ListPublicShares,
            Self::PublicShareList(_) => MsgType::PublicShareList,
            Self::GetCommunityStatus(_) => MsgType::GetCommunityStatus,
            Self::CommunityStatus(_) => MsgType::CommunityStatus,
            Self::ListCommunityPublicShares(_) => MsgType::ListCommunityPublicShares,
            Self::CommunityPublicShareList(_) => MsgType::CommunityPublicShareList,
            Self::ListCommunityMembersPage(_) => MsgType::ListCommunityMembersPage,
            Self::CommunityMembersPage(_) => MsgType::CommunityMembersPage,
            Self::ListCommunitySharesPage(_) => MsgType::ListCommunitySharesPage,
            Self::CommunitySharesPage(_) => MsgType::CommunitySharesPage,
            Self::SearchCommunityShares(_) => MsgType::SearchCommunityShares,
            Self::CommunitySearchResults(_) => MsgType::CommunitySearchResults,
            Self::ListCommunityEvents(_) => MsgType::ListCommunityEvents,
            Self::CommunityEvents(_) => MsgType::CommunityEvents,
            Self::RelayRegister(_) => MsgType::RelayRegister,
            Self::RelayRegistered(_) => MsgType::RelayRegistered,
            Self::RelayConnect(_) => MsgType::RelayConnect,
            Self::RelayStream(_) => MsgType::RelayStream,
            Self::RelayListRequest(_) => MsgType::RelayListRequest,
            Self::RelayListResponse(_) => MsgType::RelayListResponse,
            Self::Providers(_) => MsgType::Providers,
            Self::HaveContent(_) => MsgType::HaveContent,
            Self::GetChunk(_) => MsgType::GetChunk,
            Self::ChunkData(_) => MsgType::ChunkData,
            Self::GetChunkHashes(_) => MsgType::GetChunkHashes,
            Self::ChunkHashList(_) => MsgType::ChunkHashList,
        }
    }

    pub fn encode(&self) -> anyhow::Result<Vec<u8>> {
        Ok(match self {
            Self::PexOffer(msg) => crate::cbor::to_vec(msg)?,
            Self::PexRequest(msg) => crate::cbor::to_vec(msg)?,
            Self::FindNode(msg) => crate::cbor::to_vec(msg)?,
            Self::FindValue(msg) => crate::cbor::to_vec(msg)?,
            Self::Store(msg) => crate::cbor::to_vec(msg)?,
            Self::GetManifest(msg) => crate::cbor::to_vec(msg)?,
            Self::ManifestData(msg) => crate::cbor::to_vec(msg)?,
            Self::ListPublicShares(msg) => crate::cbor::to_vec(msg)?,
            Self::PublicShareList(msg) => crate::cbor::to_vec(msg)?,
            Self::GetCommunityStatus(msg) => crate::cbor::to_vec(msg)?,
            Self::CommunityStatus(msg) => crate::cbor::to_vec(msg)?,
            Self::ListCommunityPublicShares(msg) => crate::cbor::to_vec(msg)?,
            Self::CommunityPublicShareList(msg) => crate::cbor::to_vec(msg)?,
            Self::ListCommunityMembersPage(msg) => crate::cbor::to_vec(msg)?,
            Self::CommunityMembersPage(msg) => crate::cbor::to_vec(msg)?,
            Self::ListCommunitySharesPage(msg) => crate::cbor::to_vec(msg)?,
            Self::CommunitySharesPage(msg) => crate::cbor::to_vec(msg)?,
            Self::SearchCommunityShares(msg) => crate::cbor::to_vec(msg)?,
            Self::CommunitySearchResults(msg) => crate::cbor::to_vec(msg)?,
            Self::ListCommunityEvents(msg) => crate::cbor::to_vec(msg)?,
            Self::CommunityEvents(msg) => crate::cbor::to_vec(msg)?,
            Self::RelayRegister(msg) => crate::cbor::to_vec(msg)?,
            Self::RelayRegistered(msg) => crate::cbor::to_vec(msg)?,
            Self::RelayConnect(msg) => crate::cbor::to_vec(msg)?,
            Self::RelayStream(msg) => crate::cbor::to_vec(msg)?,
            Self::RelayListRequest(msg) => crate::cbor::to_vec(msg)?,
            Self::RelayListResponse(msg) => crate::cbor::to_vec(msg)?,
            Self::Providers(msg) => crate::cbor::to_vec(msg)?,
            Self::HaveContent(msg) => crate::cbor::to_vec(msg)?,
            Self::GetChunk(msg) => crate::cbor::to_vec(msg)?,
            Self::ChunkData(msg) => crate::cbor::to_vec(msg)?,
            Self::GetChunkHashes(msg) => crate::cbor::to_vec(msg)?,
            Self::ChunkHashList(msg) => crate::cbor::to_vec(msg)?,
        })
    }

    pub fn decode(message_type: u16, payload: &[u8]) -> anyhow::Result<Self> {
        let msg_type = MsgType::try_from(message_type)?;
        Ok(match msg_type {
            MsgType::PexOffer => Self::PexOffer(crate::cbor::from_slice(payload)?),
            MsgType::PexRequest => Self::PexRequest(crate::cbor::from_slice(payload)?),
            MsgType::FindNode => Self::FindNode(crate::cbor::from_slice(payload)?),
            MsgType::FindValue => Self::FindValue(crate::cbor::from_slice(payload)?),
            MsgType::Store => Self::Store(crate::cbor::from_slice(payload)?),
            MsgType::GetManifest => Self::GetManifest(crate::cbor::from_slice(payload)?),
            MsgType::ManifestData => Self::ManifestData(crate::cbor::from_slice(payload)?),
            MsgType::ListPublicShares => Self::ListPublicShares(crate::cbor::from_slice(payload)?),
            MsgType::PublicShareList => Self::PublicShareList(crate::cbor::from_slice(payload)?),
            MsgType::GetCommunityStatus => {
                Self::GetCommunityStatus(crate::cbor::from_slice(payload)?)
            }
            MsgType::CommunityStatus => Self::CommunityStatus(crate::cbor::from_slice(payload)?),
            MsgType::ListCommunityPublicShares => {
                Self::ListCommunityPublicShares(crate::cbor::from_slice(payload)?)
            }
            MsgType::CommunityPublicShareList => {
                Self::CommunityPublicShareList(crate::cbor::from_slice(payload)?)
            }
            MsgType::ListCommunityMembersPage => {
                Self::ListCommunityMembersPage(crate::cbor::from_slice(payload)?)
            }
            MsgType::CommunityMembersPage => {
                Self::CommunityMembersPage(crate::cbor::from_slice(payload)?)
            }
            MsgType::ListCommunitySharesPage => {
                Self::ListCommunitySharesPage(crate::cbor::from_slice(payload)?)
            }
            MsgType::CommunitySharesPage => {
                Self::CommunitySharesPage(crate::cbor::from_slice(payload)?)
            }
            MsgType::SearchCommunityShares => {
                Self::SearchCommunityShares(crate::cbor::from_slice(payload)?)
            }
            MsgType::CommunitySearchResults => {
                Self::CommunitySearchResults(crate::cbor::from_slice(payload)?)
            }
            MsgType::ListCommunityEvents => {
                Self::ListCommunityEvents(crate::cbor::from_slice(payload)?)
            }
            MsgType::CommunityEvents => Self::CommunityEvents(crate::cbor::from_slice(payload)?),
            MsgType::RelayRegister => Self::RelayRegister(crate::cbor::from_slice(payload)?),
            MsgType::RelayRegistered => Self::RelayRegistered(crate::cbor::from_slice(payload)?),
            MsgType::RelayConnect => Self::RelayConnect(crate::cbor::from_slice(payload)?),
            MsgType::RelayStream => Self::RelayStream(crate::cbor::from_slice(payload)?),
            MsgType::RelayListRequest => Self::RelayListRequest(crate::cbor::from_slice(payload)?),
            MsgType::RelayListResponse => {
                Self::RelayListResponse(crate::cbor::from_slice(payload)?)
            }
            MsgType::Providers => Self::Providers(crate::cbor::from_slice(payload)?),
            MsgType::HaveContent => Self::HaveContent(crate::cbor::from_slice(payload)?),
            MsgType::GetChunk => Self::GetChunk(crate::cbor::from_slice(payload)?),
            MsgType::ChunkData => Self::ChunkData(crate::cbor::from_slice(payload)?),
            MsgType::GetChunkHashes => Self::GetChunkHashes(crate::cbor::from_slice(payload)?),
            MsgType::ChunkHashList => Self::ChunkHashList(crate::cbor::from_slice(payload)?),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ids::NodeId, peer::TransportProtocol};

    // ── Integer-keyed CBOR encoding verification tests ──────────────

    /// Verify that FindNode serializes with integer key 0 (not string "target_node_id").
    #[test]
    fn int_cbor_find_node_uses_integer_keys() {
        let msg = FindNode {
            target_node_id: [0xAA; 20],
        };
        let bytes = crate::cbor::to_vec(&msg).expect("encode");
        let val: ciborium::Value = crate::cbor::from_slice(&bytes).expect("parse value");
        let map = val.as_map().expect("should be map");
        // Key should be integer 0, not string
        assert!(
            map[0].0.as_integer().is_some(),
            "FindNode key should be integer, got {:?}",
            map[0].0
        );
        assert_eq!(i128::from(map[0].0.as_integer().unwrap()), 0);
    }

    /// Verify that Store serializes with integer keys 0, 1, 2.
    #[test]
    fn int_cbor_store_uses_integer_keys() {
        let msg = Store {
            key: [0xBB; 32],
            value: vec![1, 2, 3],
            ttl_secs: 300,
        };
        let bytes = crate::cbor::to_vec(&msg).expect("encode");
        let val: ciborium::Value = crate::cbor::from_slice(&bytes).expect("parse value");
        let map = val.as_map().expect("should be map");
        assert_eq!(map.len(), 3);
        for (i, (k, _)) in map.iter().enumerate() {
            let int_key = k.as_integer().expect("key should be integer");
            assert_eq!(i128::from(int_key), i as i128);
        }
    }

    /// Verify GetChunk and ChunkData use integer keys and roundtrip correctly.
    #[test]
    fn int_cbor_chunk_messages_integer_keys_and_roundtrip() {
        let get = GetChunk {
            content_id: [0xEE; 32],
            chunk_index: 42,
        };
        let bytes = crate::cbor::to_vec(&get).expect("encode");
        let val: ciborium::Value = crate::cbor::from_slice(&bytes).expect("parse");
        let map = val.as_map().expect("should be map");
        assert!(map[0].0.as_integer().is_some());
        assert!(map[1].0.as_integer().is_some());
        let rt: GetChunk = crate::cbor::from_slice(&bytes).expect("roundtrip");
        assert_eq!(rt, get);

        let data = ChunkData {
            content_id: [0xFF; 32],
            chunk_index: 7,
            bytes: vec![10, 20, 30],
        };
        let data_bytes = crate::cbor::to_vec(&data).expect("encode");
        let data_val: ciborium::Value = crate::cbor::from_slice(&data_bytes).expect("parse");
        let data_map = data_val.as_map().expect("should be map");
        assert_eq!(data_map.len(), 3);
        for (k, _) in data_map {
            assert!(k.as_integer().is_some(), "all keys should be integers");
        }
        let data_rt: ChunkData = crate::cbor::from_slice(&data_bytes).expect("roundtrip");
        assert_eq!(data_rt, data);
    }

    #[test]
    fn envelope_roundtrip() {
        let payload = PexRequest { max_peers: 32 };
        let envelope = Envelope {
            r#type: MsgType::PexRequest as u16,
            req_id: 7,
            flags: 0,
            payload: crate::cbor::to_vec(&payload).expect("encode payload"),
        };

        let encoded = envelope.encode().expect("encode envelope");
        let decoded = Envelope::decode(&encoded).expect("decode envelope");
        let decoded_payload: PexRequest =
            crate::cbor::from_slice(&decoded.payload).expect("decode payload");

        assert_eq!(decoded.r#type, MsgType::PexRequest as u16);
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn pex_offer_roundtrip() {
        let offer = PexOffer {
            peers: vec![PeerAddr {
                ip: "10.0.0.5".parse().expect("valid ip"),
                port: 7001,
                transport: TransportProtocol::Tcp,
                pubkey_hint: Some([1u8; 32]),
                relay_via: None,
            }],
        };

        let encoded = crate::cbor::to_vec(&offer).expect("encode pex offer");
        let decoded: PexOffer = crate::cbor::from_slice(&encoded).expect("decode pex offer");
        assert_eq!(decoded, offer);
    }

    #[test]
    fn dht_messages_roundtrip() {
        let find_node = FindNode {
            target_node_id: NodeId([1u8; 20]).0,
        };
        let find_node_roundtrip: FindNode =
            crate::cbor::from_slice(&crate::cbor::to_vec(&find_node).expect("encode find node"))
                .expect("decode find node");
        assert_eq!(find_node_roundtrip, find_node);

        let store = Store {
            key: [9u8; 32],
            value: vec![1, 2, 3],
            ttl_secs: 60,
        };
        let find_value_result = FindValueResult {
            value: Some(store),
            closer_peers: vec![PeerAddr {
                ip: "192.168.1.2".parse().expect("valid ip"),
                port: 7000,
                transport: TransportProtocol::Quic,
                pubkey_hint: None,
                relay_via: None,
            }],
        };

        let encoded = crate::cbor::to_vec(&find_value_result).expect("encode find value result");
        let decoded: FindValueResult =
            crate::cbor::from_slice(&encoded).expect("decode find value result");
        assert_eq!(decoded, find_value_result);
    }

    #[test]
    fn relay_messages_roundtrip() {
        let reg = RelayRegister {
            relay_slot_id: Some(42),
            tunnel: false,
        };
        let reg_rt: RelayRegister =
            crate::cbor::from_slice(&crate::cbor::to_vec(&reg).expect("encode relay register"))
                .expect("decode relay register");
        assert_eq!(reg_rt, reg);

        let reg_empty: RelayRegister = crate::cbor::from_slice(
            &crate::cbor::to_vec(&crate::cbor::Value::Map(Vec::new()))
                .expect("encode legacy empty register map"),
        )
        .expect("decode legacy empty register map");
        assert_eq!(reg_empty.relay_slot_id, None);

        let registered = RelayRegistered {
            relay_slot_id: 7,
            expires_at: 99,
        };
        let registered_rt: RelayRegistered = crate::cbor::from_slice(
            &crate::cbor::to_vec(&registered).expect("encode relay registered"),
        )
        .expect("decode relay registered");
        assert_eq!(registered_rt, registered);

        let stream = RelayStream {
            relay_slot_id: 7,
            stream_id: 1,
            kind: RelayPayloadKind::Control,
            payload: vec![1, 2, 3],
        };
        let stream_rt: RelayStream =
            crate::cbor::from_slice(&crate::cbor::to_vec(&stream).expect("encode relay stream"))
                .expect("decode relay stream");
        assert_eq!(stream_rt, stream);

        assert!(
            crate::cbor::from_slice::<RelayStream>(
                &crate::cbor::to_vec(&(7u64, 9u32, serde_bytes::ByteBuf::from(vec![8u8, 7])))
                    .expect("encode legacy stream tuple"),
            )
            .is_err(),
            "legacy tuple encoding should not decode as struct"
        );
    }

    #[test]
    fn provider_messages_roundtrip() {
        let have = HaveContent {
            content_id: [4u8; 32],
        };
        let have_rt: HaveContent =
            crate::cbor::from_slice(&crate::cbor::to_vec(&have).expect("encode have"))
                .expect("decode have");
        assert_eq!(have_rt, have);

        let prov = Providers {
            content_id: [4u8; 32],
            providers: vec![PeerAddr {
                ip: "10.1.0.2".parse().expect("valid ip"),
                port: 7777,
                transport: TransportProtocol::Quic,
                pubkey_hint: None,
                relay_via: None,
            }],
            updated_at: 123,
        };
        let prov_rt: Providers =
            crate::cbor::from_slice(&crate::cbor::to_vec(&prov).expect("encode providers"))
                .expect("decode providers");
        assert_eq!(prov_rt, prov);
    }

    #[test]
    fn public_share_messages_roundtrip() {
        let request = ListPublicShares { max_entries: 25 };
        let request_rt: ListPublicShares = crate::cbor::from_slice(
            &crate::cbor::to_vec(&request).expect("encode public list req"),
        )
        .expect("decode public list req");
        assert_eq!(request_rt, request);

        let response = PublicShareList {
            shares: vec![PublicShareSummary {
                share_id: [1u8; 32],
                share_pubkey: [2u8; 32],
                latest_seq: 7,
                latest_manifest_id: [3u8; 32],
                title: Some("Public Catalog".into()),
                description: Some("shared".into()),
            }],
        };
        let response_rt: PublicShareList = crate::cbor::from_slice(
            &crate::cbor::to_vec(&response).expect("encode public list response"),
        )
        .expect("decode public list response");
        assert_eq!(response_rt, response);
    }

    #[test]
    fn community_status_messages_roundtrip() {
        let request = GetCommunityStatus {
            community_share_id: [4u8; 32],
            community_share_pubkey: [5u8; 32],
        };
        let request_rt: GetCommunityStatus =
            crate::cbor::from_slice(&crate::cbor::to_vec(&request).expect("encode"))
                .expect("decode");
        assert_eq!(request_rt, request);

        let response = CommunityStatus {
            community_share_id: [4u8; 32],
            joined: true,
            membership_proof: None,
            name: None,
        };
        let response_rt: CommunityStatus =
            crate::cbor::from_slice(&crate::cbor::to_vec(&response).expect("encode"))
                .expect("decode");
        assert_eq!(response_rt, response);

        // Verify name field survives roundtrip.
        let response_with_name = CommunityStatus {
            community_share_id: [4u8; 32],
            joined: true,
            membership_proof: None,
            name: Some("Pavlikeni".to_string()),
        };
        let rt2: CommunityStatus =
            crate::cbor::from_slice(&crate::cbor::to_vec(&response_with_name).expect("encode"))
                .expect("decode");
        assert_eq!(rt2.name, Some("Pavlikeni".to_string()));
    }

    #[test]
    fn community_public_share_messages_roundtrip() {
        let request = ListCommunityPublicShares {
            community_share_id: [6u8; 32],
            community_share_pubkey: [7u8; 32],
            max_entries: 12,
            requester_node_pubkey: None,
            requester_membership_proof: None,
        };
        let request_rt: ListCommunityPublicShares =
            crate::cbor::from_slice(&crate::cbor::to_vec(&request).expect("encode"))
                .expect("decode");
        assert_eq!(request_rt, request);

        let response = CommunityPublicShareList {
            community_share_id: [6u8; 32],
            shares: vec![PublicShareSummary {
                share_id: [8u8; 32],
                share_pubkey: [9u8; 32],
                latest_seq: 2,
                latest_manifest_id: [10u8; 32],
                title: Some("Community Public".into()),
                description: None,
            }],
        };
        let response_rt: CommunityPublicShareList =
            crate::cbor::from_slice(&crate::cbor::to_vec(&response).expect("encode"))
                .expect("decode");
        assert_eq!(response_rt, response);
    }

    #[test]
    fn chunk_messages_roundtrip() {
        let get = GetChunk {
            content_id: [9u8; 32],
            chunk_index: 3,
        };
        let get_encoded = crate::cbor::to_vec(&get).expect("encode get chunk");
        let get_decoded: GetChunk =
            crate::cbor::from_slice(&get_encoded).expect("decode get chunk");
        assert_eq!(get_decoded, get);

        let data = ChunkData {
            content_id: [9u8; 32],
            chunk_index: 3,
            bytes: vec![1, 2, 3],
        };
        let data_encoded = crate::cbor::to_vec(&data).expect("encode chunk data");
        let data_decoded: ChunkData =
            crate::cbor::from_slice(&data_encoded).expect("decode chunk data");
        assert_eq!(data_decoded, data);
    }

    #[test]
    fn chunk_hash_messages_roundtrip() {
        let get = GetChunkHashes {
            content_id: [11u8; 32],
        };
        let get_rt: GetChunkHashes =
            crate::cbor::from_slice(&crate::cbor::to_vec(&get).expect("encode")).expect("decode");
        assert_eq!(get_rt, get);

        let list = ChunkHashList {
            content_id: [11u8; 32],
            hashes: vec![[1u8; 32], [2u8; 32]],
        };
        let list_rt: ChunkHashList =
            crate::cbor::from_slice(&crate::cbor::to_vec(&list).expect("encode")).expect("decode");
        assert_eq!(list_rt, list);
    }

    #[test]
    fn msg_type_registry_roundtrip_and_unique_values() {
        let mut sorted_values = MsgType::ALL
            .iter()
            .copied()
            .map(u16::from)
            .collect::<Vec<u16>>();

        for msg_type in MsgType::ALL {
            let wire_value = u16::from(msg_type);
            let roundtrip = MsgType::try_from(wire_value).expect("registry roundtrip");
            assert_eq!(roundtrip, msg_type);
        }

        let expected_len = sorted_values.len();
        sorted_values.sort_unstable();
        sorted_values.dedup();
        assert_eq!(sorted_values.len(), expected_len);
    }

    #[test]
    fn envelope_decode_rejects_large_payload_limit() {
        let envelope = Envelope {
            r#type: MsgType::ChunkData as u16,
            req_id: 9,
            flags: 0,
            payload: vec![7u8; 32],
        };
        let encoded = envelope.encode().expect("encode envelope");

        let err = Envelope::decode_with_limits(&encoded, 1024, 16)
            .expect_err("payload limit should reject envelope");
        assert!(err.to_string().contains("payload exceeds max size"));
    }

    #[test]
    fn envelope_decode_rejects_large_serialized_limit() {
        let envelope = Envelope {
            r#type: MsgType::PexOffer as u16,
            req_id: 10,
            flags: 0,
            payload: vec![1u8; 8],
        };
        let encoded = envelope.encode().expect("encode envelope");

        let err = Envelope::decode_with_limits(&encoded, 2, 1024)
            .expect_err("envelope bytes limit should reject envelope");
        assert!(err.to_string().contains("envelope exceeds max size"));
    }

    #[test]
    fn typed_payload_dispatch_roundtrip_for_all_registered_types() {
        let cases = vec![
            WirePayload::PexOffer(PexOffer {
                peers: vec![PeerAddr {
                    ip: "10.0.0.2".parse().expect("valid ip"),
                    port: 1234,
                    transport: TransportProtocol::Tcp,
                    pubkey_hint: None,
                    relay_via: None,
                }],
            }),
            WirePayload::PexRequest(PexRequest { max_peers: 8 }),
            WirePayload::FindNode(FindNode {
                target_node_id: NodeId([1u8; 20]).0,
            }),
            WirePayload::FindValue(FindValue { key: [2u8; 32] }),
            WirePayload::Store(Store {
                key: [3u8; 32],
                value: vec![1, 2, 3],
                ttl_secs: 15,
            }),
            WirePayload::GetManifest(GetManifest {
                manifest_id: [4u8; 32],
            }),
            WirePayload::ManifestData(ManifestData {
                manifest_id: [5u8; 32],
                bytes: vec![9, 8, 7],
            }),
            WirePayload::ListPublicShares(ListPublicShares { max_entries: 5 }),
            WirePayload::PublicShareList(PublicShareList {
                shares: vec![PublicShareSummary {
                    share_id: [6u8; 32],
                    share_pubkey: [7u8; 32],
                    latest_seq: 8,
                    latest_manifest_id: [9u8; 32],
                    title: Some("pub".into()),
                    description: None,
                }],
            }),
            WirePayload::GetCommunityStatus(GetCommunityStatus {
                community_share_id: [14u8; 32],
                community_share_pubkey: [15u8; 32],
            }),
            WirePayload::CommunityStatus(CommunityStatus {
                community_share_id: [14u8; 32],
                joined: true,
                membership_proof: None,
                name: None,
            }),
            WirePayload::ListCommunityPublicShares(ListCommunityPublicShares {
                community_share_id: [16u8; 32],
                community_share_pubkey: [17u8; 32],
                max_entries: 4,
                requester_node_pubkey: None,
                requester_membership_proof: None,
            }),
            WirePayload::CommunityPublicShareList(CommunityPublicShareList {
                community_share_id: [16u8; 32],
                shares: vec![PublicShareSummary {
                    share_id: [18u8; 32],
                    share_pubkey: [19u8; 32],
                    latest_seq: 5,
                    latest_manifest_id: [20u8; 32],
                    title: Some("community".into()),
                    description: Some("public".into()),
                }],
            }),
            WirePayload::RelayRegister(RelayRegister {
                relay_slot_id: Some(77),
                tunnel: false,
            }),
            WirePayload::RelayRegistered(RelayRegistered {
                relay_slot_id: 77,
                expires_at: 88,
            }),
            WirePayload::RelayConnect(RelayConnect { relay_slot_id: 11 }),
            WirePayload::RelayStream(RelayStream {
                relay_slot_id: 11,
                stream_id: 3,
                kind: RelayPayloadKind::Control,
                payload: vec![5, 4, 3],
            }),
            WirePayload::Providers(Providers {
                content_id: [10u8; 32],
                providers: vec![PeerAddr {
                    ip: "10.0.0.3".parse().expect("valid ip"),
                    port: 9999,
                    transport: TransportProtocol::Quic,
                    pubkey_hint: Some([1u8; 32]),
                    relay_via: None,
                }],
                updated_at: 321,
            }),
            WirePayload::HaveContent(HaveContent {
                content_id: [11u8; 32],
            }),
            WirePayload::GetChunk(GetChunk {
                content_id: [12u8; 32],
                chunk_index: 2,
            }),
            WirePayload::ChunkData(ChunkData {
                content_id: [13u8; 32],
                chunk_index: 2,
                bytes: vec![6, 6, 6],
            }),
            WirePayload::GetChunkHashes(GetChunkHashes {
                content_id: [14u8; 32],
            }),
            WirePayload::ChunkHashList(ChunkHashList {
                content_id: [14u8; 32],
                hashes: vec![[1u8; 32], [2u8; 32]],
            }),
            // §15 community browse/search/delta messages
            WirePayload::ListCommunityMembersPage(ListCommunityMembersPage {
                community_id: [30u8; 32],
                cursor: None,
                limit: 50,
            }),
            WirePayload::CommunityMembersPage(CommunityMembersPageResponse {
                community_id: [30u8; 32],
                entries: vec![CommunityMemberSummary {
                    member_node_pubkey: [31u8; 32],
                    status: CommunityMemberStatus::Joined,
                    announce_seq: 1,
                    addr: None,
                }],
                next_cursor: Some("abc".into()),
            }),
            WirePayload::ListCommunitySharesPage(ListCommunitySharesPage {
                community_id: [32u8; 32],
                cursor: None,
                limit: 20,
                since_unix: Some(1000),
            }),
            WirePayload::CommunitySharesPage(CommunitySharesPageResponse {
                community_id: [32u8; 32],
                entries: vec![CommunityShareSummary {
                    share_id: [33u8; 32],
                    share_pubkey: [34u8; 32],
                    latest_seq: 7,
                    title: Some("test share".into()),
                    description: None,
                    updated_at: 2000,
                }],
                next_cursor: None,
            }),
            WirePayload::SearchCommunityShares(SearchCommunitySharesReq {
                community_id: [35u8; 32],
                query: "hello".into(),
                cursor: None,
                limit: 10,
            }),
            WirePayload::CommunitySearchResults(CommunitySearchResultsResp {
                community_id: [35u8; 32],
                hits: vec![CommunityShareHit {
                    share_id: [36u8; 32],
                    share_pubkey: [37u8; 32],
                    latest_seq: 2,
                    title: Some("found".into()),
                    description: None,
                    score: 100,
                }],
                next_cursor: None,
            }),
            WirePayload::ListCommunityEvents(ListCommunityEventsReq {
                community_id: [38u8; 32],
                since_cursor: None,
                limit: 25,
            }),
            WirePayload::CommunityEvents(CommunityEventsResp {
                community_id: [38u8; 32],
                events: vec![
                    CommunityEvent::MemberJoined {
                        member_node_pubkey: [39u8; 32],
                        announce_seq: 1,
                    },
                    CommunityEvent::ShareUpserted {
                        share_id: [40u8; 32],
                        latest_seq: 3,
                        title: Some("new share".into()),
                    },
                ],
                next_cursor: Some("xyz".into()),
            }),
        ];

        for (idx, message) in cases.iter().enumerate() {
            let envelope = Envelope::from_typed(idx as u32, 0, message).expect("build envelope");
            let decoded = envelope.decode_typed().expect("decode typed payload");
            assert_eq!(&decoded, message);
        }
    }

    // ── §15 Signed record tests ──────────────────────────────────────

    #[test]
    fn community_member_record_sign_verify_roundtrip() {
        use ed25519_dalek::SigningKey;
        use rand::{SeedableRng, rngs::StdRng};

        let mut rng = StdRng::seed_from_u64(42);
        let key = SigningKey::generate(&mut rng);
        let community_id = [0xAA; 32];
        let now = 1_700_000_000u64;
        let expires = now + 3600;

        let rec = CommunityMemberRecord::new_signed(
            &key,
            community_id,
            1,
            CommunityMemberStatus::Joined,
            now,
            expires,
        )
        .expect("create member record");

        assert_eq!(rec.community_id, community_id);
        assert_eq!(rec.member_node_pubkey, key.verifying_key().to_bytes());
        assert_eq!(rec.announce_seq, 1);
        rec.verify_signature().expect("signature should verify");

        // Encode/decode tagged roundtrip.
        let tagged = rec.encode_tagged().expect("encode tagged");
        assert_eq!(tagged[0], community_tags::MEMBER_RECORD);
        let decoded = CommunityMemberRecord::decode_tagged(&tagged).expect("decode tagged");
        assert_eq!(decoded, rec);
        decoded.verify_signature().expect("decoded sig ok");
    }

    #[test]
    fn community_member_record_rejects_bad_signature() {
        use ed25519_dalek::SigningKey;
        use rand::{SeedableRng, rngs::StdRng};

        let mut rng = StdRng::seed_from_u64(99);
        let key = SigningKey::generate(&mut rng);
        let mut rec = CommunityMemberRecord::new_signed(
            &key,
            [0xBB; 32],
            1,
            CommunityMemberStatus::Joined,
            1_700_000_000,
            1_700_003_600,
        )
        .expect("create");
        // Corrupt the signature.
        rec.signature[0] ^= 0xFF;
        assert!(rec.verify_signature().is_err());
    }

    #[test]
    fn community_member_record_leave_tombstone() {
        use ed25519_dalek::SigningKey;
        use rand::{SeedableRng, rngs::StdRng};

        let mut rng = StdRng::seed_from_u64(77);
        let key = SigningKey::generate(&mut rng);
        let now = 1_700_000_000u64;
        let rec = CommunityMemberRecord::new_signed(
            &key,
            [0xCC; 32],
            2,
            CommunityMemberStatus::Left,
            now,
            now + CommunityMemberRecord::LEAVE_TOMBSTONE_MAX_TTL_SECS,
        )
        .expect("create leave tombstone");

        assert_eq!(rec.status, CommunityMemberStatus::Left);
        rec.verify_signature().expect("leave sig verifies");
    }

    #[test]
    fn community_share_record_sign_verify_roundtrip() {
        use ed25519_dalek::SigningKey;
        use rand::{SeedableRng, rngs::StdRng};

        let mut rng = StdRng::seed_from_u64(55);
        let share_key = SigningKey::generate(&mut rng);
        let community_id = [0xDD; 32];
        let manifest_id = [0xEE; 32];
        let now = 1_700_000_000u64;

        let rec = CommunityShareRecord::new_signed(
            &share_key,
            community_id,
            manifest_id,
            1,
            now,
            Some("My Share".into()),
            Some("A test share".into()),
        )
        .expect("create share record");

        assert_eq!(rec.community_id, community_id);
        assert_eq!(rec.latest_manifest_id, manifest_id);
        assert_eq!(rec.share_pubkey, share_key.verifying_key().to_bytes());
        assert_eq!(rec.visibility, ShareVisibilityTag::Public);
        rec.verify().expect("share sig verifies");

        // Tagged roundtrip.
        let tagged = rec.encode_tagged().expect("encode tagged");
        assert_eq!(tagged[0], community_tags::SHARE_RECORD);
        let decoded = CommunityShareRecord::decode_tagged(&tagged).expect("decode tagged");
        assert_eq!(decoded, rec);
        decoded.verify().expect("decoded share sig ok");
    }

    #[test]
    fn community_share_record_rejects_bad_signature() {
        use ed25519_dalek::SigningKey;
        use rand::{SeedableRng, rngs::StdRng};

        let mut rng = StdRng::seed_from_u64(66);
        let key = SigningKey::generate(&mut rng);
        let mut rec = CommunityShareRecord::new_signed(
            &key,
            [0xAA; 32],
            [0xBB; 32],
            1,
            1_700_000_000,
            None,
            None,
        )
        .expect("create");
        rec.signature[0] ^= 0xFF;
        assert!(rec.verify().is_err());
    }

    #[test]
    fn community_bootstrap_hint_encode_decode_roundtrip() {
        use crate::peer::TransportProtocol;

        let hint = CommunityBootstrapHint {
            community_id: [0xFF; 32],
            member_count_estimate: 42,
            sample_members: vec![PeerAddr {
                ip: "10.0.0.1".parse().expect("valid ip"),
                port: 7000,
                transport: TransportProtocol::Quic,
                pubkey_hint: Some([1u8; 32]),
                relay_via: None,
            }],
            index_peers: vec![],
            updated_at: 1_700_000_000,
        };

        let tagged = hint.encode_tagged().expect("encode");
        assert_eq!(tagged[0], community_tags::BOOTSTRAP_HINT);
        let decoded = CommunityBootstrapHint::decode_tagged(&tagged).expect("decode");
        assert_eq!(decoded, hint);
    }

    #[test]
    fn community_bootstrap_hint_wrong_tag_rejected() {
        // Construct data with wrong tag byte.
        let hint = CommunityBootstrapHint {
            community_id: [0x11; 32],
            member_count_estimate: 5,
            sample_members: vec![],
            index_peers: vec![],
            updated_at: 100,
        };
        let mut tagged = hint.encode_tagged().expect("encode");
        tagged[0] = 0x99; // wrong tag
        assert!(CommunityBootstrapHint::decode_tagged(&tagged).is_err());
    }

    #[test]
    fn community_member_record_wrong_tag_rejected() {
        use ed25519_dalek::SigningKey;
        use rand::{SeedableRng, rngs::StdRng};

        let mut rng = StdRng::seed_from_u64(11);
        let key = SigningKey::generate(&mut rng);
        let rec = CommunityMemberRecord::new_signed(
            &key,
            [0xAA; 32],
            1,
            CommunityMemberStatus::Joined,
            100,
            200,
        )
        .expect("create");
        let mut tagged = rec.encode_tagged().expect("encode");
        tagged[0] = community_tags::SHARE_RECORD; // wrong tag
        assert!(CommunityMemberRecord::decode_tagged(&tagged).is_err());
    }

    #[test]
    fn materialized_members_page_roundtrip() {
        let page = MaterializedMembersPage {
            community_id: [0xAA; 32],
            bucket: 12345,
            page_no: 0,
            total_pages: 2,
            entries: vec![CommunityMemberSummary {
                member_node_pubkey: [0xBB; 32],
                status: CommunityMemberStatus::Joined,
                announce_seq: 1,
                addr: None,
            }],
            built_at: 1_700_000_000,
        };
        let tagged = page.encode_tagged().expect("encode");
        assert_eq!(tagged[0], community_tags::MEMBERS_PAGE);
        let decoded = MaterializedMembersPage::decode_tagged(&tagged).expect("decode");
        assert_eq!(decoded, page);
    }

    #[test]
    fn materialized_shares_page_roundtrip() {
        let page = MaterializedSharesPage {
            community_id: [0xCC; 32],
            bucket: 99999,
            page_no: 1,
            total_pages: 3,
            entries: vec![CommunityShareSummary {
                share_id: [0xDD; 32],
                share_pubkey: [0xEE; 32],
                latest_seq: 5,
                title: Some("test".into()),
                description: None,
                updated_at: 1_700_000_000,
            }],
            built_at: 1_700_000_000,
        };
        let tagged = page.encode_tagged().expect("encode");
        assert_eq!(tagged[0], community_tags::SHARES_PAGE);
        let decoded = MaterializedSharesPage::decode_tagged(&tagged).expect("decode");
        assert_eq!(decoded, page);
    }

    #[test]
    fn materialized_members_page_wrong_tag_rejected() {
        let page = MaterializedMembersPage {
            community_id: [0x11; 32],
            bucket: 1,
            page_no: 0,
            total_pages: 1,
            entries: vec![],
            built_at: 100,
        };
        let mut tagged = page.encode_tagged().expect("encode");
        tagged[0] = community_tags::SHARES_PAGE; // wrong tag
        assert!(MaterializedMembersPage::decode_tagged(&tagged).is_err());
    }

    #[test]
    fn materialized_shares_page_wrong_tag_rejected() {
        let page = MaterializedSharesPage {
            community_id: [0x22; 32],
            bucket: 1,
            page_no: 0,
            total_pages: 1,
            entries: vec![],
            built_at: 100,
        };
        let mut tagged = page.encode_tagged().expect("encode");
        tagged[0] = community_tags::MEMBERS_PAGE; // wrong tag
        assert!(MaterializedSharesPage::decode_tagged(&tagged).is_err());
    }
}
