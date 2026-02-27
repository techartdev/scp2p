// Copyright (c) 2024-2026 Vanyo Vanev / Tech Art Ltd
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId(pub [u8; 20]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ShareId(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContentId(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ManifestId(pub [u8; 32]);

impl NodeId {
    pub fn from_pubkey(pubkey: &VerifyingKey) -> Self {
        Self::from_pubkey_bytes(pubkey.as_bytes())
    }

    pub fn from_pubkey_bytes(pubkey: &[u8; 32]) -> Self {
        let digest = Sha256::digest(pubkey);
        let mut id = [0u8; 20];
        id.copy_from_slice(&digest[..20]);
        Self(id)
    }

    pub fn xor_distance(&self, other: &Self) -> [u8; 20] {
        let mut out = [0u8; 20];
        for (idx, byte) in out.iter_mut().enumerate() {
            *byte = self.0[idx] ^ other.0[idx];
        }
        out
    }

    pub fn distance_cmp(&self, target: &Self, other: &Self) -> std::cmp::Ordering {
        let a = self.xor_distance(target);
        let b = other.xor_distance(target);
        a.cmp(&b)
    }
}

impl ShareId {
    pub fn from_pubkey(pubkey: &VerifyingKey) -> Self {
        Self::from_pubkey_bytes(pubkey.as_bytes())
    }

    pub fn from_pubkey_bytes(pubkey: &[u8; 32]) -> Self {
        let digest = Sha256::digest(pubkey);
        let mut id = [0u8; 32];
        id.copy_from_slice(&digest[..]);
        Self(id)
    }

    pub fn xor_distance(&self, other: &Self) -> [u8; 20] {
        let mut out = [0u8; 20];
        for (idx, byte) in out.iter_mut().enumerate() {
            *byte = self.0[idx] ^ other.0[idx];
        }
        out
    }

    pub fn distance_cmp(&self, target: &Self, other: &Self) -> std::cmp::Ordering {
        let a = self.xor_distance(target);
        let b = other.xor_distance(target);
        a.cmp(&b)
    }
}

impl ContentId {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(*blake3::hash(bytes).as_bytes())
    }
}

impl ManifestId {
    pub fn from_manifest_bytes(bytes: &[u8]) -> Self {
        Self(*blake3::hash(bytes).as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    #[test]
    fn node_id_len_matches_spec() {
        let mut rng = OsRng;
        let key = SigningKey::generate(&mut rng);
        let node_id = NodeId::from_pubkey(&key.verifying_key());
        assert_eq!(node_id.0.len(), 20);
    }

    #[test]
    fn content_id_is_stable() {
        let a = ContentId::from_bytes(b"scp2p");
        let b = ContentId::from_bytes(b"scp2p");
        assert_eq!(a, b);
    }

    #[test]
    fn node_distance_compare_orders_closest() {
        let target = NodeId([0u8; 20]);
        let a = NodeId([1u8; 20]);
        let b = NodeId([2u8; 20]);
        assert!(a.distance_cmp(&target, &b).is_lt());
    }
}
