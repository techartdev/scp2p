// Copyright (c) 2024-2026 Vanyo Vanev / Tech Art Ltd
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TransportProtocol {
    Quic,
    Tcp,
}

/// Routing information for reaching a peer via a relay node.
///
/// When a firewalled node registers a relay slot on a public relay,
/// it advertises itself with a `PeerAddr` containing `relay_via`.
/// Connectors that encounter this field connect to the relay address
/// and tunnel requests through the relay slot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayRoute {
    /// Address of the relay node that holds the tunnel.
    pub relay_addr: Box<PeerAddr>,
    /// The relay slot ID assigned during `RelayRegister`.
    pub slot_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerAddr {
    pub ip: IpAddr,
    pub port: u16,
    pub transport: TransportProtocol,
    pub pubkey_hint: Option<[u8; 32]>,
    /// If present, this peer is behind a firewall and can only be reached
    /// by tunneling through the relay described here.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_via: Option<RelayRoute>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_addr_cbor_roundtrip() {
        let addr = PeerAddr {
            ip: "127.0.0.1".parse().expect("valid ip"),
            port: 7000,
            transport: TransportProtocol::Quic,
            pubkey_hint: Some([7u8; 32]),
            relay_via: None,
        };

        let encoded = crate::cbor::to_vec(&addr).expect("encode peer addr");
        let decoded: PeerAddr = crate::cbor::from_slice(&encoded).expect("decode peer addr");
        assert_eq!(decoded, addr);
    }

    #[test]
    fn peer_addr_with_relay_via_roundtrip() {
        let relay = PeerAddr {
            ip: "10.0.0.1".parse().expect("valid ip"),
            port: 8000,
            transport: TransportProtocol::Tcp,
            pubkey_hint: Some([1u8; 32]),
            relay_via: None,
        };
        let addr = PeerAddr {
            ip: "192.168.1.5".parse().expect("valid ip"),
            port: 7000,
            transport: TransportProtocol::Tcp,
            pubkey_hint: Some([7u8; 32]),
            relay_via: Some(RelayRoute {
                relay_addr: Box::new(relay.clone()),
                slot_id: 42,
            }),
        };

        let encoded = crate::cbor::to_vec(&addr).expect("encode peer addr with relay");
        let decoded: PeerAddr =
            crate::cbor::from_slice(&encoded).expect("decode peer addr with relay");
        assert_eq!(decoded, addr);
        let route = decoded.relay_via.unwrap();
        assert_eq!(*route.relay_addr, relay);
        assert_eq!(route.slot_id, 42);
    }

    #[test]
    fn peer_addr_without_relay_via_is_backward_compatible() {
        // Encode a PeerAddr _without_ the relay_via field by building
        // the struct normally and then stripping `relay_via` from the
        // resulting CBOR map.  This simulates old peers that were
        // encoded before the field was added.
        let original = PeerAddr {
            ip: "10.0.0.5".parse().unwrap(),
            port: 9000,
            transport: TransportProtocol::Tcp,
            pubkey_hint: None,
            relay_via: None,
        };
        let full_bytes = crate::cbor::to_vec(&original).expect("encode");
        let mut val: crate::cbor::Value =
            crate::cbor::from_slice(&full_bytes).expect("decode value");
        // Strip relay_via from the map to simulate legacy encoding.
        if let crate::cbor::Value::Map(ref mut m) = val {
            m.retain(|(k, _)| *k != crate::cbor::Value::Text("relay_via".into()));
        }
        let legacy = crate::cbor::to_vec(&val).expect("re-encode without relay_via");
        let decoded: PeerAddr = crate::cbor::from_slice(&legacy).expect("decode legacy peer addr");
        assert_eq!(decoded.relay_via, None);
        assert_eq!(decoded.ip, original.ip);
        assert_eq!(decoded.port, 9000);
    }
}
