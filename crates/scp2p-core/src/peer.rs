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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerAddr {
    pub ip: IpAddr,
    pub port: u16,
    pub transport: TransportProtocol,
    pub pubkey_hint: Option<[u8; 32]>,
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
        };

        let encoded = serde_cbor::to_vec(&addr).expect("encode peer addr");
        let decoded: PeerAddr = serde_cbor::from_slice(&encoded).expect("decode peer addr");
        assert_eq!(decoded, addr);
    }
}
