//! Quick QUIC & TCP connectivity diagnostic.
//! Usage: cargo run --example quic_probe -- 178.104.13.182:7000
use std::net::SocketAddr;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use scp2p_core::capabilities::Capabilities;
use scp2p_core::transport_net::{quic_connect_bi_session_insecure, tls_connect_session_insecure};

#[tokio::main]
async fn main() {
    let addr_str = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: quic_probe <ip:port>");
        std::process::exit(1);
    });
    let addr: SocketAddr = addr_str.parse().expect("parse socket addr");
    let key = SigningKey::generate(&mut OsRng);

    // Test QUIC
    println!("QUIC probe -> {addr} ...");
    match quic_connect_bi_session_insecure(addr, &key, Capabilities::default(), None).await {
        Ok(session) => {
            println!("QUIC SUCCESS — connected");
            println!(
                "  remote pubkey: {}",
                hex::encode(session.session.remote_node_pubkey)
            );
        }
        Err(e) => {
            println!("QUIC FAILED — {e:#}");
        }
    }

    // Test TCP (port + 1)
    let tcp_addr = SocketAddr::new(addr.ip(), addr.port() + 1);
    println!("\nTCP/TLS probe -> {tcp_addr} ...");
    let key2 = SigningKey::generate(&mut OsRng);
    match tls_connect_session_insecure(tcp_addr, &key2, Capabilities::default(), None).await {
        Ok((_stream, session)) => {
            println!("TCP SUCCESS — connected");
            println!(
                "  remote pubkey: {}",
                hex::encode(session.remote_node_pubkey)
            );
        }
        Err(e) => {
            println!("TCP FAILED — {e:#}");
        }
    }
}
