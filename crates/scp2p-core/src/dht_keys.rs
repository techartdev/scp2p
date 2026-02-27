// Copyright (c) 2024-2026 Vanyo Vanev / Tech Art Ltd
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
use sha2::{Digest, Sha256};

use crate::{ids::ManifestId, ids::ShareId};

pub fn share_head_key(share_id: &ShareId) -> [u8; 32] {
    prefixed_hash(b"share:head:", &share_id.0)
}

pub fn manifest_loc_key(manifest_id: &ManifestId) -> [u8; 32] {
    prefixed_hash(b"manifest:loc:", &manifest_id.0)
}

pub fn content_provider_key(content_id: &[u8; 32]) -> [u8; 32] {
    prefixed_hash(b"content:prov:", content_id)
}

fn prefixed_hash(prefix: &[u8], id: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(prefix);
    hasher.update(id);
    let digest = hasher.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_head_key_is_deterministic() {
        let sid = ShareId([7u8; 32]);
        assert_eq!(share_head_key(&sid), share_head_key(&sid));
    }

    #[test]
    fn prefixed_keys_do_not_collide_for_same_id() {
        let mid = ManifestId([9u8; 32]);
        let sid = ShareId(mid.0);
        assert_ne!(share_head_key(&sid), manifest_loc_key(&mid));
    }

    #[test]
    fn content_provider_key_is_distinct() {
        let cid = [3u8; 32];
        let sid = ShareId(cid);
        assert_ne!(content_provider_key(&cid), share_head_key(&sid));
    }
}
