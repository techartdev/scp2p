use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context;
use async_trait::async_trait;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    capabilities::Capabilities,
    wire::{
        ChunkData, CommunityPublicShareList, CommunityStatus, Envelope, FindNode, FindValue,
        GetChunk, GetCommunityStatus, GetManifest, HaveContent, ListCommunityPublicShares,
        ListPublicShares, ManifestData, PexOffer, PexRequest, Providers, PublicShareList,
        RelayConnect, RelayRegister, RelayRegistered, RelayStream, Store, WirePayload,
        MAX_ENVELOPE_BYTES, MAX_ENVELOPE_PAYLOAD_BYTES,
    },
};

pub const HANDSHAKE_MAX_BYTES: usize = 64 * 1024;
pub const HANDSHAKE_MAX_CLOCK_SKEW_SECS: u64 = 5 * 60;

#[derive(Debug, Clone)]
pub struct AuthenticatedSession {
    pub remote_node_pubkey: [u8; 32],
    pub remote_capabilities: Capabilities,
    pub remote_nonce: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HandshakeHello {
    pub node_pubkey: [u8; 32],
    pub capabilities: Capabilities,
    pub nonce: [u8; 32],
    pub echoed_nonce: Option<[u8; 32]>,
    pub timestamp_unix_secs: u64,
    pub signature: Vec<u8>,
}

#[derive(Serialize)]
struct HandshakeSigningTuple([u8; 32], Capabilities, [u8; 32], Option<[u8; 32]>, u64);

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
    let client = signed_hello(local_signing_key, capabilities, local_nonce, None)?;
    write_handshake_hello(io, &client).await?;

    let server = read_handshake_hello(io).await?;
    verify_hello(&server)?;
    if server.echoed_nonce != Some(local_nonce) {
        anyhow::bail!("server handshake does not bind initiator nonce");
    }
    if let Some(expected) = expected_remote_pubkey {
        if server.node_pubkey != expected {
            anyhow::bail!("remote pubkey mismatch");
        }
    }

    Ok(AuthenticatedSession {
        remote_node_pubkey: server.node_pubkey,
        remote_capabilities: server.capabilities,
        remote_nonce: server.nonce,
    })
}

pub async fn handshake_responder<S>(
    io: &mut S,
    local_signing_key: &SigningKey,
    capabilities: Capabilities,
    local_nonce: [u8; 32],
    expected_remote_pubkey: Option<[u8; 32]>,
) -> anyhow::Result<AuthenticatedSession>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let client = read_handshake_hello(io).await?;
    verify_hello(&client)?;
    if let Some(expected) = expected_remote_pubkey {
        if client.node_pubkey != expected {
            anyhow::bail!("remote pubkey mismatch");
        }
    }

    let server = signed_hello(
        local_signing_key,
        capabilities,
        local_nonce,
        Some(client.nonce),
    )?;
    write_handshake_hello(io, &server).await?;

    Ok(AuthenticatedSession {
        remote_node_pubkey: client.node_pubkey,
        remote_capabilities: client.capabilities,
        remote_nonce: client.nonce,
    })
}

fn signed_hello(
    signing_key: &SigningKey,
    capabilities: Capabilities,
    nonce: [u8; 32],
    echoed_nonce: Option<[u8; 32]>,
) -> anyhow::Result<HandshakeHello> {
    signed_hello_at(
        signing_key,
        capabilities,
        nonce,
        echoed_nonce,
        now_unix_secs()?,
    )
}

fn signed_hello_at(
    signing_key: &SigningKey,
    capabilities: Capabilities,
    nonce: [u8; 32],
    echoed_nonce: Option<[u8; 32]>,
    timestamp_unix_secs: u64,
) -> anyhow::Result<HandshakeHello> {
    let pubkey = signing_key.verifying_key().to_bytes();
    let signable = HandshakeSigningTuple(
        pubkey,
        capabilities.clone(),
        nonce,
        echoed_nonce,
        timestamp_unix_secs,
    );
    let signature = signing_key.sign(&serde_cbor::to_vec(&signable)?);
    Ok(HandshakeHello {
        node_pubkey: pubkey,
        capabilities,
        nonce,
        echoed_nonce,
        timestamp_unix_secs,
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
    );
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&hello.signature);
    pubkey.verify(
        &serde_cbor::to_vec(&signable)?,
        &Signature::from_bytes(&sig_arr),
    )?;
    Ok(())
}

async fn write_handshake_hello<S>(io: &mut S, hello: &HandshakeHello) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let bytes = serde_cbor::to_vec(hello)?;
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
    Ok(serde_cbor::from_slice(&bytes)?)
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

async fn write_frame<S>(io: &mut S, data: &[u8]) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let len = u32::try_from(data.len()).context("frame too large for u32 length prefix")?;
    io.write_u32(len).await?;
    io.write_all(data).await?;
    io.flush().await?;
    Ok(())
}

async fn read_frame<S>(io: &mut S, max_len: usize) -> anyhow::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let len = io.read_u32().await? as usize;
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
    async fn on_providers(&mut self, msg: Providers) -> anyhow::Result<DispatchResult>;
    async fn on_have_content(&mut self, msg: HaveContent) -> anyhow::Result<DispatchResult>;
    async fn on_get_chunk(&mut self, msg: GetChunk) -> anyhow::Result<DispatchResult>;
    async fn on_chunk_data(&mut self, msg: ChunkData) -> anyhow::Result<DispatchResult>;
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
        WirePayload::Providers(msg) => dispatcher.on_providers(msg).await?,
        WirePayload::HaveContent(msg) => dispatcher.on_have_content(msg).await?,
        WirePayload::GetChunk(msg) => dispatcher.on_get_chunk(msg).await?,
        WirePayload::ChunkData(msg) => dispatcher.on_chunk_data(msg).await?,
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
}

fn now_unix_secs() -> anyhow::Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;
    use crate::wire::MsgType;

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
        assert!(err
            .to_string()
            .contains("server handshake does not bind initiator nonce"));

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
        )
        .expect("hello");
        let err = verify_hello(&hello).expect_err("stale timestamp must fail");
        assert!(err
            .to_string()
            .contains("handshake timestamp outside allowed clock skew"));
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
        )
        .expect("hello");
        let err = verify_hello(&hello).expect_err("future timestamp must fail");
        assert!(err
            .to_string()
            .contains("handshake timestamp outside allowed clock skew"));
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
}
