// Copyright (c) 2024-2026 Vanyo Vanev / Tech Art Ltd
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::ids::{ManifestId, ShareId};

#[derive(Debug, Clone)]
pub struct ShareKeypair {
    pub signing_key: SigningKey,
}

impl ShareKeypair {
    pub fn new(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn share_id(&self) -> ShareId {
        ShareId::from_pubkey(&self.verifying_key())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemV1 {
    pub content_id: [u8; 32],
    pub size: u64,
    pub name: String,
    /// Relative path inside a folder share (e.g. `"sub/dir/file.txt"`).
    /// `None` for single-file shares.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub mime: Option<String>,
    pub tags: Vec<String>,
    /// Number of 256 KiB chunks that constitute this item.
    #[serde(default)]
    pub chunk_count: u32,
    /// BLAKE3 hash over the concatenation of all chunk hashes.
    ///
    /// Chunk hashes are fetched on demand via `GetChunkHashes`;
    /// the receiver verifies `BLAKE3(chunk_hashes) == chunk_list_hash`
    /// to authenticate them against the signed manifest.
    #[serde(default)]
    pub chunk_list_hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ShareVisibility {
    #[default]
    Private,
    Public,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestV1 {
    pub version: u8,
    pub share_pubkey: [u8; 32],
    pub share_id: [u8; 32],
    pub seq: u64,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub title: Option<String>,
    pub description: Option<String>,
    #[serde(default)]
    pub visibility: ShareVisibility,
    #[serde(default)]
    pub communities: Vec<[u8; 32]>,
    pub items: Vec<ItemV1>,
    pub recommended_shares: Vec<[u8; 32]>,
    /// Ed25519 signature — always exactly 64 bytes when present.
    #[serde(default, with = "sig_serde")]
    pub signature: Option<[u8; 64]>,
}

/// Custom serde for `Option<[u8; 64]>` — serializes as CBOR byte string
/// (wire-compatible with the previous `Option<Vec<u8>>`).
mod sig_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(sig: &Option<[u8; 64]>, s: S) -> Result<S::Ok, S::Error> {
        match sig {
            Some(bytes) => s.serialize_bytes(bytes),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 64]>, D::Error> {
        let opt: Option<serde_bytes::ByteBuf> = Deserialize::deserialize(d)?;
        match opt {
            Some(buf) => {
                if buf.len() != 64 {
                    return Err(serde::de::Error::custom(format!(
                        "signature must be 64 bytes, got {}",
                        buf.len()
                    )));
                }
                let mut arr = [0u8; 64];
                arr.copy_from_slice(&buf);
                Ok(Some(arr))
            }
            None => Ok(None),
        }
    }
}

#[derive(Debug, Clone)]
struct ManifestUnsigned<'a> {
    version: u8,
    share_pubkey: [u8; 32],
    share_id: [u8; 32],
    seq: u64,
    created_at: u64,
    expires_at: Option<u64>,
    title: &'a Option<String>,
    description: &'a Option<String>,
    visibility: ShareVisibility,
    communities: &'a [[u8; 32]],
    items: &'a [ItemSigningTuple<'a>],
    recommended_shares: &'a [[u8; 32]],
}

#[derive(Serialize)]
struct ManifestSigningTuple<'a>(
    u8,
    [u8; 32],
    [u8; 32],
    u64,
    u64,
    Option<u64>,
    &'a Option<String>,
    &'a Option<String>,
    ShareVisibility,
    &'a [[u8; 32]],
    &'a [ItemSigningTuple<'a>],
    &'a [[u8; 32]],
);

#[derive(Debug, Clone, Serialize)]
struct ItemSigningTuple<'a>(
    [u8; 32],
    u64,
    &'a str,
    Option<&'a str>,
    Option<&'a str>,
    &'a [String],
    u32,
    [u8; 32],
);

impl ManifestV1 {
    pub fn unsigned_bytes(&self) -> anyhow::Result<Vec<u8>> {
        // Signature payloads use positional CBOR arrays to avoid map key ordering variance.
        let items = self
            .items
            .iter()
            .map(|item| {
                ItemSigningTuple(
                    item.content_id,
                    item.size,
                    item.name.as_str(),
                    item.path.as_deref(),
                    item.mime.as_deref(),
                    &item.tags,
                    item.chunk_count,
                    item.chunk_list_hash,
                )
            })
            .collect::<Vec<_>>();
        let unsigned = ManifestUnsigned {
            version: self.version,
            share_pubkey: self.share_pubkey,
            share_id: self.share_id,
            seq: self.seq,
            created_at: self.created_at,
            expires_at: self.expires_at,
            title: &self.title,
            description: &self.description,
            visibility: self.visibility,
            communities: &self.communities,
            items: &items,
            recommended_shares: &self.recommended_shares,
        };
        let signing_tuple = ManifestSigningTuple(
            unsigned.version,
            unsigned.share_pubkey,
            unsigned.share_id,
            unsigned.seq,
            unsigned.created_at,
            unsigned.expires_at,
            unsigned.title,
            unsigned.description,
            unsigned.visibility,
            unsigned.communities,
            unsigned.items,
            unsigned.recommended_shares,
        );
        Ok(crate::cbor::to_vec(&signing_tuple)?)
    }

    pub fn sign(&mut self, key: &ShareKeypair) -> anyhow::Result<()> {
        let bytes = self.unsigned_bytes()?;
        let signature: Signature = key.signing_key.sign(&bytes);
        self.signature = Some(signature.to_bytes());
        Ok(())
    }

    pub fn verify(&self) -> anyhow::Result<()> {
        self.verify_at(crate::transport::now_unix_secs()?)
    }

    /// Verify the manifest signature and expiry at a given timestamp.
    pub fn verify_at(&self, now_unix: u64) -> anyhow::Result<()> {
        // Check expiry first — an expired manifest should never be accepted.
        if let Some(exp) = self.expires_at {
            if now_unix > exp {
                anyhow::bail!("manifest has expired");
            }
            if exp <= self.created_at {
                anyhow::bail!("manifest expires_at must be after created_at");
            }
        }

        let sig = self
            .signature
            .ok_or_else(|| anyhow::anyhow!("manifest missing signature"))?;

        let pubkey = VerifyingKey::from_bytes(&self.share_pubkey)?;
        if ShareId::from_pubkey(&pubkey).0 != self.share_id {
            anyhow::bail!("manifest share_id does not match share_pubkey");
        }

        let bytes = self.unsigned_bytes()?;
        pubkey.verify(&bytes, &Signature::from_bytes(&sig))?;
        Ok(())
    }

    pub fn manifest_id(&self) -> anyhow::Result<ManifestId> {
        let content = ManifestContentTuple(
            self.version,
            self.share_pubkey,
            self.share_id,
            self.seq,
            self.created_at,
            self.expires_at,
            &self.title,
            &self.description,
            self.visibility,
            &self.communities,
            &self.items,
            &self.recommended_shares,
            self.signature.as_ref().map(|s| &s[..]),
        );
        Ok(ManifestId::from_manifest_bytes(&crate::cbor::to_vec(
            &content,
        )?))
    }
}

#[derive(Serialize)]
struct ManifestContentTuple<'a>(
    u8,
    [u8; 32],
    [u8; 32],
    u64,
    u64,
    Option<u64>,
    &'a Option<String>,
    &'a Option<String>,
    ShareVisibility,
    &'a [[u8; 32]],
    &'a [ItemV1],
    &'a [[u8; 32]],
    Option<&'a [u8]>,
);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareHead {
    pub share_id: [u8; 32],
    pub latest_seq: u64,
    pub latest_manifest_id: [u8; 32],
    pub updated_at: u64,
    pub sig: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PublicShareSummary {
    pub share_id: [u8; 32],
    pub share_pubkey: [u8; 32],
    pub latest_seq: u64,
    pub latest_manifest_id: [u8; 32],
    pub title: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone)]
struct ShareHeadUnsigned {
    share_id: [u8; 32],
    latest_seq: u64,
    latest_manifest_id: [u8; 32],
    updated_at: u64,
}

#[derive(Serialize)]
struct ShareHeadSigningTuple([u8; 32], u64, [u8; 32], u64);

impl ShareHead {
    pub fn signable_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let unsigned = ShareHeadUnsigned {
            share_id: self.share_id,
            latest_seq: self.latest_seq,
            latest_manifest_id: self.latest_manifest_id,
            updated_at: self.updated_at,
        };
        let signing_tuple = ShareHeadSigningTuple(
            unsigned.share_id,
            unsigned.latest_seq,
            unsigned.latest_manifest_id,
            unsigned.updated_at,
        );
        Ok(crate::cbor::to_vec(&signing_tuple)?)
    }

    pub fn new_signed(
        share_id: [u8; 32],
        latest_seq: u64,
        latest_manifest_id: [u8; 32],
        updated_at: u64,
        keypair: &ShareKeypair,
    ) -> anyhow::Result<Self> {
        let mut head = Self {
            share_id,
            latest_seq,
            latest_manifest_id,
            updated_at,
            sig: vec![],
        };
        let sig = keypair.signing_key.sign(&head.signable_bytes()?);
        head.sig = sig.to_bytes().to_vec();
        Ok(head)
    }

    pub fn verify_with_pubkey(&self, share_pubkey: [u8; 32]) -> anyhow::Result<()> {
        if self.sig.len() != 64 {
            anyhow::bail!("share head signature must be 64 bytes");
        }

        let pubkey = VerifyingKey::from_bytes(&share_pubkey)?;
        if ShareId::from_pubkey(&pubkey).0 != self.share_id {
            anyhow::bail!("share head share_id does not match share_pubkey");
        }

        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&self.sig);
        pubkey.verify(&self.signable_bytes()?, &Signature::from_bytes(&sig_arr))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn manifest_sign_verify_roundtrip() {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let share = ShareKeypair::new(signing_key);

        let mut manifest = ManifestV1 {
            version: 1,
            share_pubkey: share.verifying_key().to_bytes(),
            share_id: share.share_id().0,
            seq: 1,
            created_at: 1_700_000_000,
            expires_at: None,
            title: Some("sample".to_owned()),
            description: None,
            visibility: ShareVisibility::Private,
            communities: vec![],
            items: vec![],
            recommended_shares: vec![],
            signature: None,
        };

        manifest.sign(&share).expect("sign manifest");
        manifest.verify().expect("verify manifest");
    }

    #[test]
    fn share_head_sign_verify_roundtrip() {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let share = ShareKeypair::new(signing_key);

        let head = ShareHead::new_signed(share.share_id().0, 3, [4u8; 32], 1_700_000_000, &share)
            .expect("sign head");
        head.verify_with_pubkey(share.verifying_key().to_bytes())
            .expect("verify head");
    }

    #[test]
    fn signature_payloads_use_positional_arrays() {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let share = ShareKeypair::new(signing_key);

        let manifest = ManifestV1 {
            version: 1,
            share_pubkey: share.verifying_key().to_bytes(),
            share_id: share.share_id().0,
            seq: 2,
            created_at: 1_700_000_001,
            expires_at: Some(1_700_000_100),
            title: Some("sample".to_owned()),
            description: Some("desc".to_owned()),
            visibility: ShareVisibility::Private,
            communities: vec![],
            items: vec![],
            recommended_shares: vec![],
            signature: None,
        };

        let unsigned_manifest: crate::cbor::Value =
            crate::cbor::from_slice(&manifest.unsigned_bytes().expect("manifest unsigned bytes"))
                .expect("decode manifest unsigned");
        let items = match unsigned_manifest {
            crate::cbor::Value::Array(values) => {
                assert_eq!(values.len(), 12);
                assert_eq!(values[8], crate::cbor::Value::Text("private".to_string()));
                match &values[9] {
                    crate::cbor::Value::Array(communities) => assert!(communities.is_empty()),
                    _ => panic!("manifest communities should be cbor array"),
                }
                values[10].clone()
            }
            _ => panic!("manifest unsigned form should be cbor array"),
        };
        match items {
            crate::cbor::Value::Array(values) => assert_eq!(values.len(), 0),
            _ => panic!("manifest items should be cbor array"),
        }

        let head = ShareHead {
            share_id: share.share_id().0,
            latest_seq: 2,
            latest_manifest_id: [5u8; 32],
            updated_at: 1_700_000_002,
            sig: vec![],
        };

        let unsigned_head: crate::cbor::Value =
            crate::cbor::from_slice(&head.signable_bytes().expect("head signable bytes"))
                .expect("decode head unsigned");
        match unsigned_head {
            crate::cbor::Value::Array(values) => assert_eq!(values.len(), 4),
            _ => panic!("share head unsigned form should be cbor array"),
        }
    }

    #[test]
    fn manifest_items_are_encoded_as_arrays_for_signature() {
        let mut rng = OsRng;
        let signing_key = SigningKey::generate(&mut rng);
        let share = ShareKeypair::new(signing_key);

        let manifest = ManifestV1 {
            version: 1,
            share_pubkey: share.verifying_key().to_bytes(),
            share_id: share.share_id().0,
            seq: 2,
            created_at: 1_700_000_001,
            expires_at: None,
            title: Some("sample".to_owned()),
            description: Some("desc".to_owned()),
            visibility: ShareVisibility::Public,
            communities: vec![[9u8; 32]],
            items: vec![ItemV1 {
                content_id: [1u8; 32],
                size: 42,
                name: "item-a".into(),
                path: None,
                mime: Some("application/octet-stream".into()),
                tags: vec!["t1".into(), "t2".into()],
                chunk_count: 2,
                chunk_list_hash: [2u8; 32],
            }],
            recommended_shares: vec![],
            signature: None,
        };

        let unsigned_manifest: crate::cbor::Value =
            crate::cbor::from_slice(&manifest.unsigned_bytes().expect("manifest unsigned bytes"))
                .expect("decode manifest unsigned");
        let items = match unsigned_manifest {
            crate::cbor::Value::Array(values) => {
                assert_eq!(values[8], crate::cbor::Value::Text("public".to_string()));
                match &values[9] {
                    crate::cbor::Value::Array(communities) => {
                        assert_eq!(communities.len(), 1);
                    }
                    _ => panic!("manifest communities should be cbor array"),
                }
                values[10].clone()
            }
            _ => panic!("manifest unsigned form should be cbor array"),
        };
        match items {
            crate::cbor::Value::Array(values) => {
                assert_eq!(values.len(), 1);
                match &values[0] {
                    crate::cbor::Value::Array(item_values) => {
                        assert_eq!(item_values.len(), 8);
                    }
                    _ => panic!("manifest item should be cbor array"),
                }
            }
            _ => panic!("manifest items should be cbor array"),
        }
    }

    #[test]
    fn manifest_visibility_defaults_to_private_when_omitted() {
        #[derive(Serialize)]
        struct LegacyManifestV1 {
            version: u8,
            share_pubkey: [u8; 32],
            share_id: [u8; 32],
            seq: u64,
            created_at: u64,
            expires_at: Option<u64>,
            title: Option<String>,
            description: Option<String>,
            items: Vec<ItemV1>,
            recommended_shares: Vec<[u8; 32]>,
            signature: Option<Vec<u8>>,
        }

        let legacy = crate::cbor::to_vec(&LegacyManifestV1 {
            version: 1,
            share_pubkey: [0u8; 32],
            share_id: [1u8; 32],
            seq: 1,
            created_at: 1_700_000_000,
            expires_at: None,
            title: None,
            description: None,
            items: vec![],
            recommended_shares: vec![],
            signature: None,
        })
        .expect("encode legacy manifest");

        let manifest: ManifestV1 = crate::cbor::from_slice(&legacy).expect("decode legacy");
        assert_eq!(manifest.visibility, ShareVisibility::Private);
        assert!(manifest.communities.is_empty());
    }
}
