// Copyright (c) 2024-2026 Vanyo Vanev / Tech Art Ltd
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
use std::{
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    sync::Once,
    task::{Context, Poll},
};

use anyhow::Context as _;
use ed25519_dalek::SigningKey;
use quinn::{ClientConfig, Endpoint, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::{
    capabilities::Capabilities,
    transport::{handshake_initiator, handshake_responder, AuthenticatedSession},
};

pub async fn tcp_accept_session(
    listener: &TcpListener,
    local_signing_key: &SigningKey,
    capabilities: Capabilities,
    local_nonce: [u8; 32],
    expected_remote_pubkey: Option<[u8; 32]>,
) -> anyhow::Result<(TcpStream, AuthenticatedSession, SocketAddr)> {
    let (mut stream, remote_addr) = listener.accept().await?;
    let session = handshake_responder(
        &mut stream,
        local_signing_key,
        capabilities,
        local_nonce,
        expected_remote_pubkey,
    )
    .await?;
    Ok((stream, session, remote_addr))
}

pub async fn tcp_connect_session(
    remote_addr: SocketAddr,
    local_signing_key: &SigningKey,
    capabilities: Capabilities,
    local_nonce: [u8; 32],
    expected_remote_pubkey: Option<[u8; 32]>,
) -> anyhow::Result<(TcpStream, AuthenticatedSession)> {
    let mut stream = TcpStream::connect(remote_addr).await?;
    let session = handshake_initiator(
        &mut stream,
        local_signing_key,
        capabilities,
        local_nonce,
        expected_remote_pubkey,
    )
    .await?;
    Ok((stream, session))
}

pub struct TlsServerHandle {
    acceptor: TlsAcceptor,
    pub server_certificate_der: Vec<u8>,
}

pub fn build_tls_server_handle() -> anyhow::Result<TlsServerHandle> {
    ensure_rustls_crypto_provider();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_der = cert.cert.der().to_vec();
    let key_der = cert.key_pair.serialize_der();

    let cert_chain = vec![CertificateDer::from(cert_der.clone())];
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der).clone_key());
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .context("build tls server config")?;

    Ok(TlsServerHandle {
        acceptor: TlsAcceptor::from(Arc::new(server_config)),
        server_certificate_der: cert_der,
    })
}

pub async fn tls_accept_session(
    listener: &TcpListener,
    server: &TlsServerHandle,
    local_signing_key: &SigningKey,
    capabilities: Capabilities,
    local_nonce: [u8; 32],
    expected_remote_pubkey: Option<[u8; 32]>,
) -> anyhow::Result<(
    tokio_rustls::server::TlsStream<TcpStream>,
    AuthenticatedSession,
    SocketAddr,
)> {
    let (tcp_stream, remote_addr) = listener.accept().await?;
    let mut tls_stream = server.acceptor.accept(tcp_stream).await?;
    let session = handshake_responder(
        &mut tls_stream,
        local_signing_key,
        capabilities,
        local_nonce,
        expected_remote_pubkey,
    )
    .await?;
    Ok((tls_stream, session, remote_addr))
}

pub async fn tls_connect_session(
    remote_addr: SocketAddr,
    server_name: &str,
    trusted_server_certificate_der: &[u8],
    local_signing_key: &SigningKey,
    capabilities: Capabilities,
    local_nonce: [u8; 32],
    expected_remote_pubkey: Option<[u8; 32]>,
) -> anyhow::Result<(
    tokio_rustls::client::TlsStream<TcpStream>,
    AuthenticatedSession,
)> {
    ensure_rustls_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(
        trusted_server_certificate_der.to_vec(),
    ))?;

    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));
    let server_name = rustls::pki_types::ServerName::try_from(server_name.to_string())
        .context("invalid tls server name")?;

    let tcp_stream = TcpStream::connect(remote_addr).await?;
    let mut tls_stream = connector.connect(server_name, tcp_stream).await?;
    let session = handshake_initiator(
        &mut tls_stream,
        local_signing_key,
        capabilities,
        local_nonce,
        expected_remote_pubkey,
    )
    .await?;
    Ok((tls_stream, session))
}

pub struct QuicServerHandle {
    endpoint: Endpoint,
    pub server_certificate_der: Vec<u8>,
}

impl QuicServerHandle {
    pub fn local_addr(&self) -> anyhow::Result<SocketAddr> {
        Ok(self.endpoint.local_addr()?)
    }
}

pub fn start_quic_server(bind_addr: SocketAddr) -> anyhow::Result<QuicServerHandle> {
    let (server_config, server_certificate_der) = build_quic_server_config()?;
    let endpoint = Endpoint::server(server_config, bind_addr)?;
    Ok(QuicServerHandle {
        endpoint,
        server_certificate_der,
    })
}

pub async fn quic_accept_bi_session(
    server: &QuicServerHandle,
    local_signing_key: &SigningKey,
    capabilities: Capabilities,
    local_nonce: [u8; 32],
    expected_remote_pubkey: Option<[u8; 32]>,
) -> anyhow::Result<(QuicBiStream, AuthenticatedSession)> {
    let incoming = server
        .endpoint
        .accept()
        .await
        .ok_or_else(|| anyhow::anyhow!("quic endpoint closed before accept"))?;
    let connection = incoming.await?;
    let (send, recv) = connection.accept_bi().await?;
    let mut stream = QuicBiStream { send, recv };
    let session = handshake_responder(
        &mut stream,
        local_signing_key,
        capabilities,
        local_nonce,
        expected_remote_pubkey,
    )
    .await?;
    Ok((stream, session))
}

pub struct QuicClientSession {
    _endpoint: Endpoint,
    pub stream: QuicBiStream,
    pub session: AuthenticatedSession,
}

pub async fn quic_connect_bi_session(
    remote_addr: SocketAddr,
    server_name: &str,
    trusted_server_certificate_der: &[u8],
    local_signing_key: &SigningKey,
    capabilities: Capabilities,
    local_nonce: [u8; 32],
    expected_remote_pubkey: Option<[u8; 32]>,
) -> anyhow::Result<QuicClientSession> {
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse().expect("valid socket"))?;
    endpoint.set_default_client_config(build_quic_client_config(trusted_server_certificate_der)?);

    let connecting = endpoint.connect(remote_addr, server_name)?;
    let connection = connecting.await?;
    let (send, recv) = connection.open_bi().await?;
    let mut stream = QuicBiStream { send, recv };
    let session = handshake_initiator(
        &mut stream,
        local_signing_key,
        capabilities,
        local_nonce,
        expected_remote_pubkey,
    )
    .await?;

    Ok(QuicClientSession {
        _endpoint: endpoint,
        stream,
        session,
    })
}

fn build_quic_server_config() -> anyhow::Result<(ServerConfig, Vec<u8>)> {
    ensure_rustls_crypto_provider();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])?;
    let cert_der = cert.cert.der().to_vec();
    let key_der = cert.key_pair.serialize_der();

    let cert_chain = vec![CertificateDer::from(cert_der.clone())];
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der.clone()).clone_key());
    let server_config = ServerConfig::with_single_cert(cert_chain, private_key)
        .context("build quic server config with certificate")?;
    Ok((server_config, cert_der))
}

fn build_quic_client_config(trusted_server_certificate_der: &[u8]) -> anyhow::Result<ClientConfig> {
    ensure_rustls_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(
        trusted_server_certificate_der.to_vec(),
    ))?;
    let rustls_client = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(rustls_client)?,
    )))
}

fn ensure_rustls_crypto_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

pub struct QuicBiStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl AsyncRead for QuicBiStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicBiStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match Pin::new(&mut self.send).poll_write(cx, buf) {
            Poll::Ready(Ok(written)) => Poll::Ready(Ok(written)),
            Poll::Ready(Err(err)) => Poll::Ready(Err(std::io::Error::other(err))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match Pin::new(&mut self.send).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(err)) => Poll::Ready(Err(std::io::Error::other(err))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match Pin::new(&mut self.send).poll_shutdown(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(err)) => Poll::Ready(Err(std::io::Error::other(err))),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use rand::{rngs::StdRng, SeedableRng};

    use super::*;
    use crate::{
        transport::{
            dispatch_envelope, read_envelope, write_envelope, DispatchResult, WireDispatcher,
        },
        wire::{Envelope, MsgType, PexOffer, PexRequest, WirePayload},
    };

    struct PexResponder;

    #[async_trait]
    impl WireDispatcher for PexResponder {
        async fn on_pex_offer(&mut self, _msg: PexOffer) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::none())
        }
        async fn on_pex_request(&mut self, msg: PexRequest) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::response(Envelope::from_typed(
                1,
                0x0001,
                &WirePayload::PexOffer(PexOffer {
                    peers: Vec::with_capacity(usize::from(msg.max_peers.min(1))),
                }),
            )?))
        }
        async fn on_find_node(
            &mut self,
            _msg: crate::wire::FindNode,
        ) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::none())
        }
        async fn on_find_value(
            &mut self,
            _msg: crate::wire::FindValue,
        ) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::none())
        }
        async fn on_store(&mut self, _msg: crate::wire::Store) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::none())
        }
        async fn on_get_manifest(
            &mut self,
            _msg: crate::wire::GetManifest,
        ) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::none())
        }
        async fn on_manifest_data(
            &mut self,
            _msg: crate::wire::ManifestData,
        ) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::none())
        }
        async fn on_list_public_shares(
            &mut self,
            _msg: crate::wire::ListPublicShares,
        ) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::none())
        }
        async fn on_public_share_list(
            &mut self,
            _msg: crate::wire::PublicShareList,
        ) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::none())
        }
        async fn on_get_community_status(
            &mut self,
            _msg: crate::wire::GetCommunityStatus,
        ) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::none())
        }
        async fn on_community_status(
            &mut self,
            _msg: crate::wire::CommunityStatus,
        ) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::none())
        }
        async fn on_list_community_public_shares(
            &mut self,
            _msg: crate::wire::ListCommunityPublicShares,
        ) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::none())
        }
        async fn on_community_public_share_list(
            &mut self,
            _msg: crate::wire::CommunityPublicShareList,
        ) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::none())
        }
        async fn on_relay_register(
            &mut self,
            _msg: crate::wire::RelayRegister,
        ) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::none())
        }
        async fn on_relay_registered(
            &mut self,
            _msg: crate::wire::RelayRegistered,
        ) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::none())
        }
        async fn on_relay_connect(
            &mut self,
            _msg: crate::wire::RelayConnect,
        ) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::none())
        }
        async fn on_relay_stream(
            &mut self,
            _msg: crate::wire::RelayStream,
        ) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::none())
        }
        async fn on_providers(
            &mut self,
            _msg: crate::wire::Providers,
        ) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::none())
        }
        async fn on_have_content(
            &mut self,
            _msg: crate::wire::HaveContent,
        ) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::none())
        }
        async fn on_get_chunk(
            &mut self,
            _msg: crate::wire::GetChunk,
        ) -> anyhow::Result<DispatchResult> {
            Ok(DispatchResult::none())
        }
        async fn on_chunk_data(
            &mut self,
            _msg: crate::wire::ChunkData,
        ) -> anyhow::Result<DispatchResult> {
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

    #[tokio::test]
    async fn tcp_runtime_session_and_dispatch_roundtrip() {
        let mut rng = StdRng::seed_from_u64(123);
        let client_key = SigningKey::generate(&mut rng);
        let server_key = SigningKey::generate(&mut rng);
        let client_pub = client_key.verifying_key().to_bytes();
        let server_pub = server_key.verifying_key().to_bytes();
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let server_addr = listener.local_addr().expect("local addr");

        let server = tokio::spawn(async move {
            let (mut stream, _session, _addr) = tcp_accept_session(
                &listener,
                &server_key,
                Capabilities::default(),
                [8u8; 32],
                Some(client_pub),
            )
            .await
            .expect("accept session");
            let request = read_envelope(&mut stream).await.expect("read request");
            let mut responder = PexResponder;
            let response = dispatch_envelope(&mut responder, request)
                .await
                .expect("dispatch")
                .expect("response");
            write_envelope(&mut stream, &response)
                .await
                .expect("write response");
        });

        let (mut stream, session) = tcp_connect_session(
            server_addr,
            &client_key,
            Capabilities::default(),
            [7u8; 32],
            Some(server_pub),
        )
        .await
        .expect("connect session");
        assert_eq!(session.remote_node_pubkey, server_pub);

        let req = Envelope::from_typed(1, 0, &WirePayload::PexRequest(PexRequest { max_peers: 2 }))
            .expect("request");
        write_envelope(&mut stream, &req).await.expect("write req");
        let resp = read_envelope(&mut stream).await.expect("read resp");
        assert_eq!(resp.r#type, MsgType::PexOffer as u16);

        server.await.expect("join");
    }

    #[tokio::test]
    async fn quic_runtime_session_and_dispatch_roundtrip() {
        let mut rng = StdRng::seed_from_u64(777);
        let client_key = SigningKey::generate(&mut rng);
        let server_key = SigningKey::generate(&mut rng);
        let client_pub = client_key.verifying_key().to_bytes();
        let server_pub = server_key.verifying_key().to_bytes();

        let server = start_quic_server("127.0.0.1:0".parse().expect("addr")).expect("server");
        let server_addr = server.local_addr().expect("local addr");
        let trusted_cert = server.server_certificate_der.clone();

        let server_task = tokio::spawn(async move {
            let (mut stream, _session) = quic_accept_bi_session(
                &server,
                &server_key,
                Capabilities::default(),
                [4u8; 32],
                Some(client_pub),
            )
            .await
            .expect("accept quic session");
            let request = read_envelope(&mut stream).await.expect("read request");
            assert_eq!(request.r#type, MsgType::PexRequest as u16);
        });

        let mut client = quic_connect_bi_session(
            server_addr,
            "localhost",
            &trusted_cert,
            &client_key,
            Capabilities::default(),
            [3u8; 32],
            Some(server_pub),
        )
        .await
        .expect("connect quic");
        assert_eq!(client.session.remote_node_pubkey, server_pub);

        let req = Envelope::from_typed(1, 0, &WirePayload::PexRequest(PexRequest { max_peers: 2 }))
            .expect("request");
        write_envelope(&mut client.stream, &req)
            .await
            .expect("write req");

        server_task.await.expect("join");
    }

    #[tokio::test]
    async fn tls_runtime_session_and_dispatch_roundtrip() {
        let mut rng = StdRng::seed_from_u64(991);
        let client_key = SigningKey::generate(&mut rng);
        let server_key = SigningKey::generate(&mut rng);
        let client_pub = client_key.verifying_key().to_bytes();
        let server_pub = server_key.verifying_key().to_bytes();

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let server_addr = listener.local_addr().expect("local addr");
        let tls_server = build_tls_server_handle().expect("tls server");
        let trusted_server_cert = tls_server.server_certificate_der.clone();

        let server = tokio::spawn(async move {
            let (mut stream, _session, _addr) = tls_accept_session(
                &listener,
                &tls_server,
                &server_key,
                Capabilities::default(),
                [6u8; 32],
                Some(client_pub),
            )
            .await
            .expect("accept tls session");
            let request = read_envelope(&mut stream).await.expect("read request");
            let mut responder = PexResponder;
            let response = dispatch_envelope(&mut responder, request)
                .await
                .expect("dispatch")
                .expect("response");
            write_envelope(&mut stream, &response)
                .await
                .expect("write response");
        });

        let (mut stream, session) = tls_connect_session(
            server_addr,
            "localhost",
            &trusted_server_cert,
            &client_key,
            Capabilities::default(),
            [5u8; 32],
            Some(server_pub),
        )
        .await
        .expect("connect tls session");
        assert_eq!(session.remote_node_pubkey, server_pub);

        let req = Envelope::from_typed(1, 0, &WirePayload::PexRequest(PexRequest { max_peers: 2 }))
            .expect("request");
        write_envelope(&mut stream, &req).await.expect("write req");
        let resp = read_envelope(&mut stream).await.expect("read resp");
        assert_eq!(resp.r#type, MsgType::PexOffer as u16);

        server.await.expect("join");
    }
}
