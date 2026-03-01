// Copyright (c) 2024-2026 Vanyo Vanev / Tech Art Ltd
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
#[cfg(test)]
mod tests {
    use ed25519_dalek::{SigningKey, VerifyingKey};

    use crate::{
        content::{chunk_hashes, describe_content, CHUNK_SIZE},
        dht_keys::share_head_key,
        ids::{NodeId, ShareId},
        manifest::{ManifestV1, ShareHead, ShareKeypair},
    };

    const PUBKEY_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const SHARE_ID_HEX: &str = "21fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b9";
    const NODE_ID_HEX: &str = "21fe31dfa154a261626bf854046fd2271b7bed4b";
    const SHARE_HEAD_KEY_HEX: &str =
        "edcfbb3a4c7e3da470fec41e8eac723d143ac3a69537a81a43200c4fa9df50ed";
    const MANIFEST_UNSIGNED_HEX: &str = "8c0198200318a10718bf18f318ce1018be181d187018dd181818e7184b18c01899186718e418d61830189b18a50d185f181d18dc18861864121855183118b8982018561847185a18a7185418631847184c02188518df185d18bf182b18ca18b7183d18a6185118351888183918e918b71874188118b218ea18b1071870188c071a6553f1001a6555428073436f6e666f726d616e636520436174616c6f676d666978656420766563746f72736770726976617465808188982007070707070707070707070707070707070707070707070707070707070707071904d26a73616d706c652e62696ef678186170706c69636174696f6e2f6f637465742d73747265616d826673616d706c6566766563746f720298201825181a18810a181d185e189618eb189a181a18ea183616187218a6181b182418de18c81835181f187718b2186a131821187c18e5182b183b18e5185d8198200303030303030303030303030303030303030303030303030303030303030303";
    const MANIFEST_SIGNATURE_HEX: &str =
        "c9659453aaa719dc6ddb9064c7a822d4ff848e525a7b3983f32b3d139683b05913e19e1ecdea09d067e7637190218babd701ad3715433b5632091a8f6f46c609";
    const SHARE_HEAD_SIGNABLE_HEX: &str = "84982018561847185a18a7185418631847184c02188518df185d18bf182b18ca18b7183d18a6185118351888183918e918b71874188118b218ea18b1071870188c07982018a90a1861183c186d18dd021844189a18d71854188d18c0182e182a184218f31858101825181c18f518bc18a4188218aa18d418f318ed18a6186f182b1a6553f10a";
    const SHARE_HEAD_SIGNATURE_HEX: &str =
        "6874d73dce29cc079e80d9d2ee817c3e3ecaef5cd5bd86fae1ef837578dd90772a539b3974598979d03fcd4b52d9c5b8b4e7ca166a5476ee454b5d2c5e56ca03";
    const CONTENT_ID_HEX: &str = "543ffc51ceb43ab2cbb9d294d87e0a07627d758918e3ef37167aebf6f8635542";
    const CHUNK0_HASH_HEX: &str =
        "d57dc906e20d3fd326ffaa85535500486f46a0979f5a323f028dcabfd381fd4a";
    const CHUNK1_HASH_HEX: &str =
        "16c73b1fdd38762790888bfc3a0d47db8fe7ef558df79d91d6b22b63ed289542";

    #[test]
    fn id_derivation_vectors_match_sha256() {
        let pubkey_bytes = hex::decode(PUBKEY_HEX).expect("pubkey hex");
        let pubkey =
            VerifyingKey::from_bytes(pubkey_bytes.as_slice().try_into().expect("pubkey bytes"))
                .expect("valid verifying key");

        let share_id = ShareId::from_pubkey(&pubkey);
        let node_id = NodeId::from_pubkey(&pubkey);

        assert_eq!(hex::encode(share_id.0), SHARE_ID_HEX);
        assert_eq!(hex::encode(node_id.0), NODE_ID_HEX);
    }

    #[test]
    fn share_head_key_vector_matches_sha256() {
        let share_id_bytes: [u8; 32] = hex::decode(SHARE_ID_HEX)
            .expect("share id hex")
            .try_into()
            .expect("share id bytes");
        let share_id = ShareId(share_id_bytes);

        let key = share_head_key(&share_id);
        assert_eq!(hex::encode(key), SHARE_HEAD_KEY_HEX);
    }

    #[test]
    fn signature_vectors_manifest_and_share_head() {
        let signing_key = SigningKey::from_bytes(
            &hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
                .expect("seed hex")
                .try_into()
                .expect("seed bytes"),
        );
        let share = ShareKeypair::new(signing_key);

        let mut manifest = ManifestV1 {
            version: 1,
            share_pubkey: share.verifying_key().to_bytes(),
            share_id: share.share_id().0,
            seq: 7,
            created_at: 1_700_000_000,
            expires_at: Some(1_700_086_400),
            title: Some("Conformance Catalog".to_string()),
            description: Some("fixed vectors".to_string()),
            visibility: crate::manifest::ShareVisibility::Private,
            communities: vec![],
            items: vec![crate::manifest::ItemV1 {
                content_id: [7u8; 32],
                size: 1234,
                name: "sample.bin".to_string(),
                path: None,
                mime: Some("application/octet-stream".to_string()),
                tags: vec!["sample".to_string(), "vector".to_string()],
                chunk_count: 2,
                chunk_list_hash: crate::content::compute_chunk_list_hash(&[[8u8; 32], [9u8; 32]]),
            }],
            recommended_shares: vec![[3u8; 32]],
            signature: None,
        };

        let unsigned = manifest.unsigned_bytes().expect("manifest unsigned");
        manifest.sign(&share).expect("manifest sign");
        // Use verify_at with a timestamp inside the manifest's validity window
        // (created_at=1_700_000_000, expires_at=1_700_086_400).
        manifest.verify_at(1_700_000_001).expect("manifest verify");

        let signature = manifest.signature.expect("manifest signature");
        assert_eq!(hex::encode(unsigned), MANIFEST_UNSIGNED_HEX);
        assert_eq!(hex::encode(signature), MANIFEST_SIGNATURE_HEX);

        let head = ShareHead::new_signed(
            share.share_id().0,
            manifest.seq,
            manifest.manifest_id().expect("manifest id").0,
            1_700_000_010,
            &share,
        )
        .expect("share head sign");
        head.verify_with_pubkey(share.verifying_key().to_bytes())
            .expect("share head verify");

        let signable = head.signable_bytes().expect("share head signable");
        assert_eq!(hex::encode(&signable), SHARE_HEAD_SIGNABLE_HEX);
        assert_eq!(hex::encode(&head.sig), SHARE_HEAD_SIGNATURE_HEX);
    }

    #[test]
    fn chunk_hashing_vectors() {
        let mut bytes = vec![0u8; CHUNK_SIZE + 16];
        for (idx, b) in bytes.iter_mut().enumerate() {
            *b = (idx % 251) as u8;
        }

        let desc = describe_content(&bytes);
        let chunks = chunk_hashes(&bytes);

        assert_eq!(chunks.len(), 2);
        assert_eq!(hex::encode(desc.content_id.0), CONTENT_ID_HEX);
        assert_eq!(hex::encode(chunks[0]), CHUNK0_HASH_HEX);
        assert_eq!(hex::encode(chunks[1]), CHUNK1_HASH_HEX);
    }
}
