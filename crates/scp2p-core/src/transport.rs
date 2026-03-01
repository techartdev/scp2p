// Copyright (c) 2024-2026 Vanyo Vanev / Tech Art Ltd
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use async_trait::async_trait;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

use crate::{
    capabilities::Capabilities,
    wire::{
        ChunkData, CommunityPublicShareList, CommunityStatus, Envelope, FindNode, FindValue,
        GetChunk, GetCommunityStatus, GetManifest, HaveContent, ListCommunityPublicShares,
        ListPublicShares, MAX_ENVELOPE_BYTES, MAX_ENVELOPE_PAYLOAD_BYTES, ManifestData, PexOffer,
        PexRequest, Providers, PublicShareList, RelayConnect, RelayRegister, RelayRegistered,
        RelayStream, Store, WirePayload,
    },
};

pub const HANDSHAKE_MAX_BYTES: usize = 64 * 1024;
pub const HANDSHAKE_MAX_CLOCK_SKEW_SECS: u64 = 5 * 60;

/// Current wire-protocol version.  Bump when breaking changes land.
pub const PROTOCOL_VERSION: u16 = 1;

/// Generate a 32-byte handshake nonce from a CSPRNG.
///
/// Always use this helper (or `OsRng` directly) to generate nonces —
/// never use deterministic or hardcoded values outside of tests.
pub fn generate_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Tracks recently seen handshake nonces to prevent replay attacks.
///
/// Nonces are stored with their associated timestamp and pruned once
/// they fall outside the `HANDSHAKE_MAX_CLOCK_SKEW_SECS` window.
/// Call [`NonceTracker::check_and_record`] after `verify_hello` to
/// reject any nonce that was already observed.
#[derive(Debug, Default)]
pub struct NonceTracker {
    seen: HashMap<[u8; 32], u64>,
}

impl NonceTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a nonce seen at `now_unix`. Returns an error if the nonce
    /// was already observed within the allowed clock-skew window.
    pub fn check_and_record(&mut self, nonce: [u8; 32], now_unix: u64) -> anyhow::Result<()> {
        self.prune(now_unix);
        if self.seen.contains_key(&nonce) {
            anyhow::bail!("handshake nonce replay detected");
        }
        self.seen.insert(nonce, now_unix);
        Ok(())
    }

    fn prune(&mut self, now_unix: u64) {
        let cutoff = now_unix.saturating_sub(HANDSHAKE_MAX_CLOCK_SKEW_SECS * 2);
        self.seen.retain(|_, ts| *ts > cutoff);
    }
}

#[derive(Debug, Clone)]
pub struct AuthenticatedSession {
    pub remote_node_pubkey: [u8; 32],
    pub remote_capabilities: Capabilities,
    pub remote_nonce: [u8; 32],
    pub remote_protocol_version: u16,
    /// Shared session secret derived from ephemeral X25519 key exchange.
    /// Provides forward secrecy: even if long-term Ed25519 keys are
    /// compromised later, previously recorded sessions cannot be replayed.
    pub session_secret: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HandshakeHello {
    pub node_pubkey: [u8; 32],
    pub capabilities: Capabilities,
    pub nonce: [u8; 32],
    pub echoed_nonce: Option<[u8; 32]>,
    pub timestamp_unix_secs: u64,
    /// Wire-protocol version advertised by the sender.
    #[serde(default = "default_protocol_version")]
    pub protocol_version: u16,
    /// Ephemeral X25519 public key for forward-secret key exchange.
    /// `None` only when talking to a legacy peer that predates this field.
    #[serde(default)]
    pub ephemeral_pubkey: Option<[u8; 32]>,
    pub signature: Vec<u8>,
}

fn default_protocol_version() -> u16 {
    1
}

/// Fields signed during handshake. The ephemeral X25519 public key (field 6)
/// is included so that a MITM cannot substitute a different ephemeral key.
#[derive(Serialize)]
struct HandshakeSigningTuple(
    [u8; 32],         // 0: node_pubkey
    Capabilities,     // 1: capabilities
    [u8; 32],         // 2: nonce
    Option<[u8; 32]>, // 3: echoed_nonce
    u64,              // 4: timestamp_unix_secs
    u16,              // 5: protocol_version
    Option<[u8; 32]>, // 6: ephemeral_pubkey (X25519)
);

/// Generate an ephemeral X25519 keypair for forward-secret key exchange.
fn generate_ephemeral_x25519() -> (EphemeralSecret, [u8; 32]) {
    let secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let public = X25519PublicKey::from(&secret);
    (secret, public.to_bytes())
}

/// Derive a 32-byte session secret from the raw X25519 shared secret,
/// contextualised with both nonces so each session produces a unique key.
fn derive_session_secret(
    dh_shared: &[u8; 32],
    initiator_nonce: &[u8; 32],
    responder_nonce: &[u8; 32],
) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(96);
    ikm.extend_from_slice(dh_shared);
    ikm.extend_from_slice(initiator_nonce);
    ikm.extend_from_slice(responder_nonce);
    blake3::derive_key("scp2p-handshake-session-secret-v1", &ikm)
}

/// Perform the initiator (client) side of the 3-message handshake:
///
/// 1. **ClientHello** → send our pubkey, capabilities, nonce (no echoed nonce).
/// 2. **ServerHello** ← receive server's pubkey, capabilities, nonce, and
///    verify it echoes our nonce.
/// 3. **ClientAck**   → send acknowledgement echoing the server's nonce,
///    proving we observed message 2.
///
/// Both sides exchange ephemeral X25519 public keys and derive a shared
/// session secret providing forward secrecy.
pub async fn handshake_initiator<S>(
    io: &mut S,
    local_signing_key: &SigningKey,
    capabilities: Capabilities,
    local_nonce: [u8; 32],
    expected_remote_pubkey: Option<[u8; 32]>,
) -> anyhow::Result<AuthenticatedSession>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Generate ephemeral X25519 keypair for forward secrecy
    let (eph_secret, eph_pubkey) = generate_ephemeral_x25519();

    // Step 1 – ClientHello
    let client_hello = signed_hello(
        local_signing_key,
        capabilities.clone(),
        local_nonce,
        None,
        Some(eph_pubkey),
    )?;
    write_handshake_hello(io, &client_hello).await?;

    // Step 2 – ServerHello
    let server_hello = read_handshake_hello(io).await?;
    verify_hello(&server_hello)?;
    if server_hello.echoed_nonce != Some(local_nonce) {
        anyhow::bail!("server handshake does not bind initiator nonce");
    }
    if let Some(expected) = expected_remote_pubkey
        && server_hello.node_pubkey != expected
    {
        anyhow::bail!("remote pubkey mismatch");
    }

    // Step 3 – ClientAck (echo server nonce)
    let ack = signed_hello(
        local_signing_key,
        capabilities,
        local_nonce,
        Some(server_hello.nonce),
        Some(eph_pubkey),
    )?;
    write_handshake_hello(io, &ack).await?;

    // Derive session secret from X25519 DH
    let session_secret = match server_hello.ephemeral_pubkey {
        Some(remote_eph) => {
            let remote_pub = X25519PublicKey::from(remote_eph);
            let dh_shared = eph_secret.diffie_hellman(&remote_pub);
            Some(derive_session_secret(
                dh_shared.as_bytes(),
                &local_nonce,
                &server_hello.nonce,
            ))
        }
        None => None, // legacy peer without ephemeral key support
    };

    let session = AuthenticatedSession {
        remote_node_pubkey: server_hello.node_pubkey,
        remote_capabilities: server_hello.capabilities,
        remote_nonce: server_hello.nonce,
        remote_protocol_version: server_hello.protocol_version,
        session_secret,
    };
    check_protocol_version(&session)?;
    Ok(session)
}

/// Perform the responder (server) side of the 3-message handshake:
///
/// 1. **ClientHello** ← read initiator's pubkey, capabilities, nonce.
/// 2. **ServerHello** → send our pubkey, capabilities, nonce, echoing the
///    client's nonce.
/// 3. **ClientAck**   ← read the initiator's acknowledgement and verify it
///    echoes our nonce, proving the initiator observed message 2.
///
/// Both sides exchange ephemeral X25519 public keys and derive a shared
/// session secret providing forward secrecy.
pub async fn handshake_responder<S>(
    io: &mut S,
    local_signing_key: &SigningKey,
    capabilities: Capabilities,
    local_nonce: [u8; 32],
    expected_remote_pubkey: Option<[u8; 32]>,
    nonce_tracker: Option<&mut NonceTracker>,
) -> anyhow::Result<AuthenticatedSession>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Generate ephemeral X25519 keypair for forward secrecy
    let (eph_secret, eph_pubkey) = generate_ephemeral_x25519();

    // Step 1 – ClientHello
    let client_hello = read_handshake_hello(io).await?;
    verify_hello(&client_hello)?;

    // Replay detection: reject if we've seen this nonce recently.
    if let Some(tracker) = nonce_tracker {
        let now = now_unix_secs()?;
        tracker.check_and_record(client_hello.nonce, now)?;
    }

    if let Some(expected) = expected_remote_pubkey
        && client_hello.node_pubkey != expected
    {
        anyhow::bail!("remote pubkey mismatch");
    }

    // Step 2 – ServerHello (echo client nonce)
    let server_hello = signed_hello(
        local_signing_key,
        capabilities,
        local_nonce,
        Some(client_hello.nonce),
        Some(eph_pubkey),
    )?;
    write_handshake_hello(io, &server_hello).await?;

    // Step 3 – ClientAck (verify it echoes our nonce)
    let ack = read_handshake_hello(io).await?;
    verify_hello(&ack)?;
    if ack.node_pubkey != client_hello.node_pubkey {
        anyhow::bail!("client ack pubkey does not match initial hello");
    }
    if ack.echoed_nonce != Some(local_nonce) {
        anyhow::bail!("client ack does not bind responder nonce");
    }

    // Derive session secret from X25519 DH
    let session_secret = match client_hello.ephemeral_pubkey {
        Some(remote_eph) => {
            let remote_pub = X25519PublicKey::from(remote_eph);
            let dh_shared = eph_secret.diffie_hellman(&remote_pub);
            Some(derive_session_secret(
                dh_shared.as_bytes(),
                &client_hello.nonce,
                &local_nonce,
            ))
        }
        None => None, // legacy peer without ephemeral key support
    };

    let session = AuthenticatedSession {
        remote_node_pubkey: client_hello.node_pubkey,
        remote_capabilities: client_hello.capabilities,
        remote_nonce: client_hello.nonce,
        remote_protocol_version: client_hello.protocol_version,
        session_secret,
    };
    check_protocol_version(&session)?;
    Ok(session)
}

/// Check that the remote peer uses a compatible protocol version.
///
/// For pre-1.0 versions (`v0.x`), an exact match is required.
/// For 1.0+ a future range-negotiation strategy can be applied.
fn check_protocol_version(session: &AuthenticatedSession) -> anyhow::Result<()> {
    let remote = session.remote_protocol_version;
    if remote != PROTOCOL_VERSION {
        anyhow::bail!(
            "incompatible protocol version: local={}, remote={}",
            PROTOCOL_VERSION,
            remote
        );
    }
    Ok(())
}

fn signed_hello(
    signing_key: &SigningKey,
    capabilities: Capabilities,
    nonce: [u8; 32],
    echoed_nonce: Option<[u8; 32]>,
    ephemeral_pubkey: Option<[u8; 32]>,
) -> anyhow::Result<HandshakeHello> {
    signed_hello_at(
        signing_key,
        capabilities,
        nonce,
        echoed_nonce,
        now_unix_secs()?,
        ephemeral_pubkey,
    )
}

fn signed_hello_at(
    signing_key: &SigningKey,
    capabilities: Capabilities,
    nonce: [u8; 32],
    echoed_nonce: Option<[u8; 32]>,
    timestamp_unix_secs: u64,
    ephemeral_pubkey: Option<[u8; 32]>,
) -> anyhow::Result<HandshakeHello> {
    let pubkey = signing_key.verifying_key().to_bytes();
    let signable = HandshakeSigningTuple(
        pubkey,
        capabilities.clone(),
        nonce,
        echoed_nonce,
        timestamp_unix_secs,
        PROTOCOL_VERSION,
        ephemeral_pubkey,
    );
    let signature = signing_key.sign(&crate::cbor::to_vec(&signable)?);
    Ok(HandshakeHello {
        node_pubkey: pubkey,
        capabilities,
        nonce,
        echoed_nonce,
        timestamp_unix_secs,
        protocol_version: PROTOCOL_VERSION,
        ephemeral_pubkey,
        signature: signature.to_bytes().to_vec(),
    })
}

fn verify_hello(hello: &HandshakeHello) -> anyhow::Result<()> {
    if hello.signature.len() != 64 {
        anyhow::bail!("handshake signature must be 64 bytes");
    }
    let now = now_unix_secs()?;
    let skew = now.abs_diff(hello.timestamp_unix_secs);
    if skew > HANDSHAKE_MAX_CLOCK_SKEW_SECS {
        anyhow::bail!("handshake timestamp outside allowed clock skew");
    }
    let pubkey = VerifyingKey::from_bytes(&hello.node_pubkey)?;
    let signable = HandshakeSigningTuple(
        hello.node_pubkey,
        hello.capabilities.clone(),
        hello.nonce,
        hello.echoed_nonce,
        hello.timestamp_unix_secs,
        hello.protocol_version,
        hello.ephemeral_pubkey,
    );
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&hello.signature);
    pubkey.verify(
        &crate::cbor::to_vec(&signable)?,
        &Signature::from_bytes(&sig_arr),
    )?;
    Ok(())
}

async fn write_handshake_hello<S>(io: &mut S, hello: &HandshakeHello) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let bytes = crate::cbor::to_vec(hello)?;
    if bytes.len() > HANDSHAKE_MAX_BYTES {
        anyhow::bail!("handshake exceeds max size");
    }
    write_frame(io, &bytes).await
}

async fn read_handshake_hello<S>(io: &mut S) -> anyhow::Result<HandshakeHello>
where
    S: AsyncRead + Unpin,
{
    let bytes = read_frame(io, HANDSHAKE_MAX_BYTES).await?;
    Ok(crate::cbor::from_slice(&bytes)?)
}

pub async fn write_envelope<S>(io: &mut S, envelope: &Envelope) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let encoded = envelope.encode()?;
    if encoded.len() > MAX_ENVELOPE_BYTES {
        anyhow::bail!("envelope exceeds max size");
    }
    write_frame(io, &encoded).await
}

pub async fn read_envelope<S>(io: &mut S) -> anyhow::Result<Envelope>
where
    S: AsyncRead + Unpin,
{
    let encoded = read_frame(io, MAX_ENVELOPE_BYTES).await?;
    Envelope::decode_with_limits(&encoded, MAX_ENVELOPE_BYTES, MAX_ENVELOPE_PAYLOAD_BYTES)
}

/// Write a length-prefixed frame.  The 4-byte length prefix is big-endian
/// (network byte order), followed by the raw payload bytes.
async fn write_frame<S>(io: &mut S, data: &[u8]) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let len = u32::try_from(data.len()).context("frame too large for u32 length prefix")?;
    io.write_u32(len).await?; // big-endian by tokio default
    io.write_all(data).await?;
    io.flush().await?;
    Ok(())
}

/// Read a length-prefixed frame.  Expects a 4-byte big-endian length
/// followed by that many payload bytes.  Rejects frames larger than
/// `max_len`.
async fn read_frame<S>(io: &mut S, max_len: usize) -> anyhow::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let len = io.read_u32().await? as usize; // big-endian by tokio default
    if len > max_len {
        anyhow::bail!("frame exceeds max size");
    }
    let mut data = vec![0u8; len];
    io.read_exact(&mut data).await?;
    Ok(data)
}

#[derive(Debug, Clone)]
pub struct DispatchResult {
    pub response: Option<Envelope>,
}

impl DispatchResult {
    pub fn none() -> Self {
        Self { response: None }
    }

    pub fn response(response: Envelope) -> Self {
        Self {
            response: Some(response),
        }
    }
}

#[async_trait]
pub trait WireDispatcher {
    async fn on_pex_offer(&mut self, msg: PexOffer) -> anyhow::Result<DispatchResult>;
    async fn on_pex_request(&mut self, msg: PexRequest) -> anyhow::Result<DispatchResult>;
    async fn on_find_node(&mut self, msg: FindNode) -> anyhow::Result<DispatchResult>;
    async fn on_find_value(&mut self, msg: FindValue) -> anyhow::Result<DispatchResult>;
    async fn on_store(&mut self, msg: Store) -> anyhow::Result<DispatchResult>;
    async fn on_get_manifest(&mut self, msg: GetManifest) -> anyhow::Result<DispatchResult>;
    async fn on_manifest_data(&mut self, msg: ManifestData) -> anyhow::Result<DispatchResult>;
    async fn on_list_public_shares(
        &mut self,
        msg: ListPublicShares,
    ) -> anyhow::Result<DispatchResult>;
    async fn on_public_share_list(
        &mut self,
        msg: PublicShareList,
    ) -> anyhow::Result<DispatchResult>;
    async fn on_get_community_status(
        &mut self,
        msg: GetCommunityStatus,
    ) -> anyhow::Result<DispatchResult>;
    async fn on_community_status(&mut self, msg: CommunityStatus)
    -> anyhow::Result<DispatchResult>;
    async fn on_list_community_public_shares(
        &mut self,
        msg: ListCommunityPublicShares,
    ) -> anyhow::Result<DispatchResult>;
    async fn on_community_public_share_list(
        &mut self,
        msg: CommunityPublicShareList,
    ) -> anyhow::Result<DispatchResult>;
    async fn on_relay_register(&mut self, msg: RelayRegister) -> anyhow::Result<DispatchResult>;
    async fn on_relay_registered(&mut self, msg: RelayRegistered)
    -> anyhow::Result<DispatchResult>;
    async fn on_relay_connect(&mut self, msg: RelayConnect) -> anyhow::Result<DispatchResult>;
    async fn on_relay_stream(&mut self, msg: RelayStream) -> anyhow::Result<DispatchResult>;
    async fn on_relay_list_request(
        &mut self,
        msg: crate::wire::RelayListRequest,
    ) -> anyhow::Result<DispatchResult>;
    async fn on_relay_list_response(
        &mut self,
        msg: crate::wire::RelayListResponse,
    ) -> anyhow::Result<DispatchResult>;
    async fn on_providers(&mut self, msg: Providers) -> anyhow::Result<DispatchResult>;
    async fn on_have_content(&mut self, msg: HaveContent) -> anyhow::Result<DispatchResult>;
    async fn on_get_chunk(&mut self, msg: GetChunk) -> anyhow::Result<DispatchResult>;
    async fn on_chunk_data(&mut self, msg: ChunkData) -> anyhow::Result<DispatchResult>;
    async fn on_get_chunk_hashes(
        &mut self,
        msg: crate::wire::GetChunkHashes,
    ) -> anyhow::Result<DispatchResult>;
    async fn on_chunk_hash_list(
        &mut self,
        msg: crate::wire::ChunkHashList,
    ) -> anyhow::Result<DispatchResult>;
}

pub async fn dispatch_envelope<D: WireDispatcher + Send>(
    dispatcher: &mut D,
    envelope: Envelope,
) -> anyhow::Result<Option<Envelope>> {
    let typed = envelope.decode_typed()?;
    let result = match typed {
        WirePayload::PexOffer(msg) => dispatcher.on_pex_offer(msg).await?,
        WirePayload::PexRequest(msg) => dispatcher.on_pex_request(msg).await?,
        WirePayload::FindNode(msg) => dispatcher.on_find_node(msg).await?,
        WirePayload::FindValue(msg) => dispatcher.on_find_value(msg).await?,
        WirePayload::Store(msg) => dispatcher.on_store(msg).await?,
        WirePayload::GetManifest(msg) => dispatcher.on_get_manifest(msg).await?,
        WirePayload::ManifestData(msg) => dispatcher.on_manifest_data(msg).await?,
        WirePayload::ListPublicShares(msg) => dispatcher.on_list_public_shares(msg).await?,
        WirePayload::PublicShareList(msg) => dispatcher.on_public_share_list(msg).await?,
        WirePayload::GetCommunityStatus(msg) => dispatcher.on_get_community_status(msg).await?,
        WirePayload::CommunityStatus(msg) => dispatcher.on_community_status(msg).await?,
        WirePayload::ListCommunityPublicShares(msg) => {
            dispatcher.on_list_community_public_shares(msg).await?
        }
        WirePayload::CommunityPublicShareList(msg) => {
            dispatcher.on_community_public_share_list(msg).await?
        }
        WirePayload::RelayRegister(msg) => dispatcher.on_relay_register(msg).await?,
        WirePayload::RelayRegistered(msg) => dispatcher.on_relay_registered(msg).await?,
        WirePayload::RelayConnect(msg) => dispatcher.on_relay_connect(msg).await?,
        WirePayload::RelayStream(msg) => dispatcher.on_relay_stream(msg).await?,
        WirePayload::RelayListRequest(msg) => dispatcher.on_relay_list_request(msg).await?,
        WirePayload::RelayListResponse(msg) => dispatcher.on_relay_list_response(msg).await?,
        WirePayload::Providers(msg) => dispatcher.on_providers(msg).await?,
        WirePayload::HaveContent(msg) => dispatcher.on_have_content(msg).await?,
        WirePayload::GetChunk(msg) => dispatcher.on_get_chunk(msg).await?,
        WirePayload::ChunkData(msg) => dispatcher.on_chunk_data(msg).await?,
        WirePayload::GetChunkHashes(msg) => dispatcher.on_get_chunk_hashes(msg).await?,
        WirePayload::ChunkHashList(msg) => dispatcher.on_chunk_hash_list(msg).await?,
    };
    Ok(result.response)
}

pub async fn run_message_loop<S, D>(io: &mut S, dispatcher: &mut D) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    D: WireDispatcher + Send,
{
    loop {
        let incoming = read_envelope(io).await?;
        if let Some(response) = dispatch_envelope(dispatcher, incoming).await? {
            write_envelope(io, &response).await?;
        }
    }
}

pub struct NoopDispatcher;

#[async_trait]
impl WireDispatcher for NoopDispatcher {
    async fn on_pex_offer(&mut self, _msg: PexOffer) -> anyhow::Result<DispatchResult> {
        Ok(DispatchResult::none())
    }

    async fn on_pex_request(&mut self, _msg: PexRequest) -> anyhow::Result<DispatchResult> {
        Ok(DispatchResult::none())
    }

    async fn on_find_node(&mut self, _msg: FindNode) -> anyhow::Result<DispatchResult> {
        Ok(DispatchResult::none())
    }

    async fn on_find_value(&mut self, _msg: FindValue) -> anyhow::Result<DispatchResult> {
        Ok(DispatchResult::none())
    }

    async fn on_store(&mut self, _msg: Store) -> anyhow::Result<DispatchResult> {
        Ok(DispatchResult::none())
    }

    async fn on_get_manifest(&mut self, _msg: GetManifest) -> anyhow::Result<DispatchResult> {
        Ok(DispatchResult::none())
    }

    async fn on_manifest_data(&mut self, _msg: ManifestData) -> anyhow::Result<DispatchResult> {
        Ok(DispatchResult::none())
    }

    async fn on_list_public_shares(
        &mut self,
        _msg: ListPublicShares,
    ) -> anyhow::Result<DispatchResult> {
        Ok(DispatchResult::none())
    }

    async fn on_public_share_list(
        &mut self,
        _msg: PublicShareList,
    ) -> anyhow::Result<DispatchResult> {
        Ok(DispatchResult::none())
    }

    async fn on_get_community_status(
        &mut self,
        _msg: GetCommunityStatus,
    ) -> anyhow::Result<DispatchResult> {
        Ok(DispatchResult::none())
    }

    async fn on_community_status(
        &mut self,
        _msg: CommunityStatus,
    ) -> anyhow::Result<DispatchResult> {
        Ok(DispatchResult::none())
    }

    async fn on_list_community_public_shares(
        &mut self,
        _msg: ListCommunityPublicShares,
    ) -> anyhow::Result<DispatchResult> {
        Ok(DispatchResult::none())
    }

    async fn on_community_public_share_list(
        &mut self,
        _msg: CommunityPublicShareList,
    ) -> anyhow::Result<DispatchResult> {
        Ok(DispatchResult::none())
    }

    async fn on_relay_register(&mut self, _msg: RelayRegister) -> anyhow::Result<DispatchResult> {
        Ok(DispatchResult::none())
    }

    async fn on_relay_registered(
        &mut self,
        _msg: RelayRegistered,
    ) -> anyhow::Result<DispatchResult> {
        Ok(DispatchResult::none())
    }

    async fn on_relay_connect(&mut self, _msg: RelayConnect) -> anyhow::Result<DispatchResult> {
        Ok(DispatchResult::none())
    }

    async fn on_relay_stream(&mut self, _msg: RelayStream) -> anyhow::Result<DispatchResult> {
        Ok(DispatchResult::none())
    }

    async fn on_relay_list_request(
        &mut self,
        _msg: crate::wire::RelayListRequest,
    ) -> anyhow::Result<DispatchResult> {
        Ok(DispatchResult::none())
    }

    async fn on_relay_list_response(
        &mut self,
        _msg: crate::wire::RelayListResponse,
    ) -> anyhow::Result<DispatchResult> {
        Ok(DispatchResult::none())
    }

    async fn on_providers(&mut self, _msg: Providers) -> anyhow::Result<DispatchResult> {
        Ok(DispatchResult::none())
    }

    async fn on_have_content(&mut self, _msg: HaveContent) -> anyhow::Result<DispatchResult> {
        Ok(DispatchResult::none())
    }

    async fn on_get_chunk(&mut self, _msg: GetChunk) -> anyhow::Result<DispatchResult> {
        Ok(DispatchResult::none())
    }

    async fn on_chunk_data(&mut self, _msg: ChunkData) -> anyhow::Result<DispatchResult> {
        Ok(DispatchResult::none())
    }

    async fn on_get_chunk_hashes(
        &mut self,
        _msg: crate::wire::GetChunkHashes,
    ) -> anyhow::Result<DispatchResult> {
        Ok(DispatchResult::none())
    }

    async fn on_chunk_hash_list(
        &mut self,
        _msg: crate::wire::ChunkHashList,
    ) -> anyhow::Result<DispatchResult> {
        Ok(DispatchResult::none())
    }
}

pub fn now_unix_secs() -> anyhow::Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use rand::{SeedableRng, rngs::StdRng};

    use super::*;
    use crate::wire::{ChunkHashList, GetChunkHashes, MsgType};

    struct TestDispatcher;

    #[async_trait]
    impl WireDispatcher for TestDispatcher {
        async fn on_pex_offer(&mut self, _msg: PexOffer) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::none())
        }
        async fn on_pex_request(&mut self, _msg: PexRequest) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::response(Envelope::from_typed(
                91,
                0x0001,
                &WirePayload::PexOffer(PexOffer { peers: vec![] }),
            )?))
        }
        async fn on_find_node(&mut self, _msg: FindNode) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::none())
        }
        async fn on_find_value(&mut self, _msg: FindValue) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::none())
        }
        async fn on_store(&mut self, _msg: Store) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::none())
        }
        async fn on_get_manifest(&mut self, _msg: GetManifest) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::none())
        }
        async fn on_manifest_data(&mut self, _msg: ManifestData) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::none())
        }
        async fn on_list_public_shares(
            &mut self,
            _msg: ListPublicShares,
        ) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::none())
        }
        async fn on_public_share_list(
            &mut self,
            _msg: PublicShareList,
        ) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::none())
        }
        async fn on_get_community_status(
            &mut self,
            _msg: GetCommunityStatus,
        ) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::none())
        }
        async fn on_community_status(
            &mut self,
            _msg: CommunityStatus,
        ) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::none())
        }
        async fn on_list_community_public_shares(
            &mut self,
            _msg: ListCommunityPublicShares,
        ) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::none())
        }
        async fn on_community_public_share_list(
            &mut self,
            _msg: CommunityPublicShareList,
        ) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::none())
        }
        async fn on_relay_register(
            &mut self,
            _msg: RelayRegister,
        ) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::none())
        }
        async fn on_relay_registered(
            &mut self,
            _msg: RelayRegistered,
        ) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::none())
        }
        async fn on_relay_connect(&mut self, _msg: RelayConnect) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::none())
        }
        async fn on_relay_stream(&mut self, _msg: RelayStream) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::none())
        }
        async fn on_relay_list_request(
            &mut self,
            _msg: crate::wire::RelayListRequest,
        ) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::none())
        }
        async fn on_relay_list_response(
            &mut self,
            _msg: crate::wire::RelayListResponse,
        ) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::none())
        }
        async fn on_providers(&mut self, _msg: Providers) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::none())
        }
        async fn on_have_content(&mut self, _msg: HaveContent) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::none())
        }
        async fn on_get_chunk(&mut self, _msg: GetChunk) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::none())
        }
        async fn on_chunk_data(&mut self, _msg: ChunkData) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::none())
        }
        async fn on_get_chunk_hashes(
            &mut self,
            _msg: GetChunkHashes,
        ) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::none())
        }
        async fn on_chunk_hash_list(
            &mut self,
            _msg: ChunkHashList,
        ) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::none())
        }
    }

    #[tokio::test]
    async fn handshake_roundtrip_binds_remote_pubkey() {
        let mut rng = StdRng::seed_from_u64(7);
        let client_key = SigningKey::generate(&mut rng);
        let server_key = SigningKey::generate(&mut rng);
        let client_pubkey = client_key.verifying_key().to_bytes();
        let server_pubkey = server_key.verifying_key().to_bytes();
        let client_caps = Capabilities {
            dht: true,
            store: false,
            relay: false,
            content_seed: true,
            mobile_light: false,
        };
        let server_caps = Capabilities {
            dht: true,
            store: true,
            relay: true,
            content_seed: true,
            mobile_light: false,
        };
        let client_nonce = [1u8; 32];
        let server_nonce = [2u8; 32];

        let (mut client_io, mut server_io) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            handshake_responder(
                &mut server_io,
                &server_key,
                server_caps,
                server_nonce,
                Some(client_pubkey),
                None,
            )
            .await
        });

        let client_session = handshake_initiator(
            &mut client_io,
            &client_key,
            client_caps,
            client_nonce,
            Some(server_pubkey),
        )
        .await
        .expect("client handshake");
        let server_session = server_task.await.expect("join").expect("server handshake");

        assert_eq!(client_session.remote_node_pubkey, server_pubkey);
        assert_eq!(server_session.remote_node_pubkey, client_pubkey);
        assert_eq!(client_session.remote_nonce, server_nonce);
        assert_eq!(server_session.remote_nonce, client_nonce);
    }

    #[tokio::test]
    async fn handshake_rejects_unexpected_remote_pubkey() {
        let mut rng = StdRng::seed_from_u64(99);
        let client_key = SigningKey::generate(&mut rng);
        let server_key = SigningKey::generate(&mut rng);
        let wrong_expected = SigningKey::generate(&mut rng).verifying_key().to_bytes();

        let (mut client_io, mut server_io) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            handshake_responder(
                &mut server_io,
                &server_key,
                Capabilities::default(),
                [2u8; 32],
                None,
                None,
            )
            .await
        });

        let err = handshake_initiator(
            &mut client_io,
            &client_key,
            Capabilities::default(),
            [1u8; 32],
            Some(wrong_expected),
        )
        .await
        .expect_err("should reject wrong expected pubkey");
        assert!(err.to_string().contains("remote pubkey mismatch"));
        // Drop the client half so the server's read_frame gets an EOF
        // instead of blocking forever waiting for the ClientAck.
        drop(client_io);
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn envelope_framing_roundtrip() {
        let payload = WirePayload::PexRequest(PexRequest { max_peers: 16 });
        let env = Envelope::from_typed(44, 0, &payload).expect("build envelope");

        let (mut a, mut b) = tokio::io::duplex(2048);
        let send = tokio::spawn(async move { write_envelope(&mut a, &env).await });
        let recv = tokio::spawn(async move { read_envelope(&mut b).await });

        send.await.expect("send task").expect("send envelope");
        let decoded = recv.await.expect("recv task").expect("receive envelope");
        assert_eq!(decoded.r#type, MsgType::PexRequest as u16);
        assert_eq!(decoded.req_id, 44);
    }

    #[tokio::test]
    async fn dispatch_returns_response_with_same_req_id() {
        let req =
            Envelope::from_typed(91, 0, &WirePayload::PexRequest(PexRequest { max_peers: 1 }))
                .expect("request envelope");
        let mut dispatcher = TestDispatcher;
        let response = dispatch_envelope(&mut dispatcher, req)
            .await
            .expect("dispatch")
            .expect("response envelope");
        assert_eq!(response.req_id, 91);
        assert_eq!(response.flags & 0x0001, 0x0001);
        assert_eq!(response.r#type, MsgType::PexOffer as u16);
    }

    #[tokio::test]
    async fn handshake_nonce_binding_is_enforced() {
        let mut rng = StdRng::seed_from_u64(42);
        let client_key = SigningKey::generate(&mut rng);
        let server_key = SigningKey::generate(&mut rng);
        let (mut client_io, mut server_io) = tokio::io::duplex(4096);

        let server = tokio::spawn(async move {
            let client = read_handshake_hello(&mut server_io)
                .await
                .expect("read client hello");
            let wrong = signed_hello(
                &server_key,
                Capabilities::default(),
                [9u8; 32],
                Some([7u8; 32]),
                None,
            )
            .expect("sign wrong hello");
            let _ = client;
            write_handshake_hello(&mut server_io, &wrong)
                .await
                .expect("write wrong");
        });

        let err = handshake_initiator(
            &mut client_io,
            &client_key,
            Capabilities::default(),
            [1u8; 32],
            None,
        )
        .await
        .expect_err("must reject mismatched echoed nonce");
        assert!(
            err.to_string()
                .contains("server handshake does not bind initiator nonce")
        );

        server.await.expect("server task");
    }

    #[test]
    fn handshake_rejects_stale_timestamp() {
        let mut rng = StdRng::seed_from_u64(1234);
        let key = SigningKey::generate(&mut rng);
        let now = now_unix_secs().expect("now");
        let hello = signed_hello_at(
            &key,
            Capabilities::default(),
            [3u8; 32],
            None,
            now.saturating_sub(HANDSHAKE_MAX_CLOCK_SKEW_SECS + 1),
            None,
        )
        .expect("hello");
        let err = verify_hello(&hello).expect_err("stale timestamp must fail");
        assert!(
            err.to_string()
                .contains("handshake timestamp outside allowed clock skew")
        );
    }

    #[test]
    fn handshake_rejects_future_timestamp() {
        let mut rng = StdRng::seed_from_u64(5678);
        let key = SigningKey::generate(&mut rng);
        let now = now_unix_secs().expect("now");
        let hello = signed_hello_at(
            &key,
            Capabilities::default(),
            [4u8; 32],
            None,
            now + HANDSHAKE_MAX_CLOCK_SKEW_SECS + 1,
            None,
        )
        .expect("hello");
        let err = verify_hello(&hello).expect_err("future timestamp must fail");
        assert!(
            err.to_string()
                .contains("handshake timestamp outside allowed clock skew")
        );
    }

    #[tokio::test]
    async fn read_frame_rejects_oversized_payload() {
        let (mut writer, mut reader) = tokio::io::duplex(128);
        let send = tokio::spawn(async move {
            writer.write_u32(65).await.expect("len prefix");
            writer.flush().await.expect("flush");
        });

        let err = read_frame(&mut reader, 64)
            .await
            .expect_err("should reject oversized frame");
        assert!(err.to_string().contains("frame exceeds max size"));
        send.await.expect("join");
    }

    /// Verify that the responder rejects a ClientAck whose echoed_nonce does
    /// not match the server's local nonce (3-message binding).
    #[tokio::test]
    async fn responder_rejects_wrong_ack_nonce() {
        let mut rng = StdRng::seed_from_u64(77);
        let client_key = SigningKey::generate(&mut rng);
        let server_key = SigningKey::generate(&mut rng);
        let client_nonce = [10u8; 32];
        let server_nonce = [20u8; 32];

        let (mut client_io, mut server_io) = tokio::io::duplex(8192);

        // Drive the client side manually: send hello, read server hello, send
        // an ack with the *wrong* echoed nonce.
        let client_task = tokio::spawn(async move {
            // Step 1 – send valid ClientHello
            let hello = signed_hello(
                &client_key,
                Capabilities::default(),
                client_nonce,
                None,
                None,
            )
            .expect("client hello");
            write_handshake_hello(&mut client_io, &hello)
                .await
                .expect("send hello");

            // Step 2 – read ServerHello (don't bother verifying fully here)
            let _server = read_handshake_hello(&mut client_io)
                .await
                .expect("read server hello");

            // Step 3 – send ack with WRONG echoed nonce
            let bad_ack = signed_hello(
                &client_key,
                Capabilities::default(),
                client_nonce,
                Some([0xFFu8; 32]), // wrong nonce
                None,
            )
            .expect("bad ack");
            write_handshake_hello(&mut client_io, &bad_ack)
                .await
                .expect("send bad ack");
        });

        let err = handshake_responder(
            &mut server_io,
            &server_key,
            Capabilities::default(),
            server_nonce,
            None,
            None,
        )
        .await
        .expect_err("responder must reject wrong ack nonce");
        assert!(
            err.to_string()
                .contains("client ack does not bind responder nonce")
        );

        client_task.await.expect("client task");
    }

    /// Verify the responder rejects a ClientAck from a different pubkey than
    /// the original ClientHello.
    #[tokio::test]
    async fn responder_rejects_ack_pubkey_mismatch() {
        let mut rng = StdRng::seed_from_u64(88);
        let client_key = SigningKey::generate(&mut rng);
        let imposter_key = SigningKey::generate(&mut rng);
        let server_key = SigningKey::generate(&mut rng);
        let client_nonce = [11u8; 32];
        let server_nonce = [22u8; 32];

        let (mut client_io, mut server_io) = tokio::io::duplex(8192);

        let client_task = tokio::spawn(async move {
            // Step 1 – valid ClientHello
            let hello = signed_hello(
                &client_key,
                Capabilities::default(),
                client_nonce,
                None,
                None,
            )
            .expect("client hello");
            write_handshake_hello(&mut client_io, &hello)
                .await
                .expect("send hello");

            // Step 2 – read ServerHello
            let server = read_handshake_hello(&mut client_io)
                .await
                .expect("read server hello");

            // Step 3 – send ack signed by a *different* key
            let bad_ack = signed_hello(
                &imposter_key,
                Capabilities::default(),
                client_nonce,
                Some(server.nonce),
                None,
            )
            .expect("imposter ack");
            write_handshake_hello(&mut client_io, &bad_ack)
                .await
                .expect("send imposter ack");
        });

        let err = handshake_responder(
            &mut server_io,
            &server_key,
            Capabilities::default(),
            server_nonce,
            None,
            None,
        )
        .await
        .expect_err("responder must reject ack from different pubkey");
        assert!(
            err.to_string()
                .contains("client ack pubkey does not match initial hello")
        );

        client_task.await.expect("client task");
    }

    /// Verify that a full handshake derives identical session secrets on
    /// both sides (X25519 forward secrecy).
    #[tokio::test]
    async fn handshake_derives_matching_session_secrets() {
        let mut rng = StdRng::seed_from_u64(42);
        let client_key = SigningKey::generate(&mut rng);
        let server_key = SigningKey::generate(&mut rng);
        let client_nonce = generate_nonce();
        let server_nonce = generate_nonce();

        let (mut client_io, mut server_io) = tokio::io::duplex(16384);

        let server = tokio::spawn(async move {
            handshake_responder(
                &mut server_io,
                &server_key,
                Capabilities::default(),
                server_nonce,
                None,
                None,
            )
            .await
        });

        let client_session = handshake_initiator(
            &mut client_io,
            &client_key,
            Capabilities::default(),
            client_nonce,
            None,
        )
        .await
        .expect("client handshake");

        let server_session = server.await.expect("join").expect("server handshake");

        // Both sides should have derived a session secret
        assert!(
            client_session.session_secret.is_some(),
            "client should have session secret"
        );
        assert!(
            server_session.session_secret.is_some(),
            "server should have session secret"
        );

        // The secrets must match
        assert_eq!(
            client_session.session_secret.unwrap(),
            server_session.session_secret.unwrap(),
            "session secrets must match"
        );

        // Each handshake should produce a different secret (ephemeral) —
        // verify by running a second handshake with fresh nonces
        let client_key2 = SigningKey::generate(&mut rng);
        let server_key2 = SigningKey::generate(&mut rng);
        let (mut c2, mut s2) = tokio::io::duplex(16384);

        let server2 = tokio::spawn(async move {
            handshake_responder(
                &mut s2,
                &server_key2,
                Capabilities::default(),
                generate_nonce(),
                None,
                None,
            )
            .await
        });
        let session2 = handshake_initiator(
            &mut c2,
            &client_key2,
            Capabilities::default(),
            generate_nonce(),
            None,
        )
        .await
        .expect("handshake 2");
        let server_session2 = server2.await.expect("join").expect("server handshake 2");

        assert_ne!(
            client_session.session_secret.unwrap(),
            session2.session_secret.unwrap(),
            "different handshakes must produce different session secrets"
        );
        assert_eq!(
            session2.session_secret.unwrap(),
            server_session2.session_secret.unwrap(),
            "second handshake secrets must match"
        );
    }
}
