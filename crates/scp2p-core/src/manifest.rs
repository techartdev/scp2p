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
    pub mime: Option<String>,
    pub tags: Vec<String>,
    pub chunks: Vec<[u8; 32]>,
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
    pub signature: Option<Vec<u8>>,
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
    &'a [String],
    &'a [[u8; 32]],
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
                    item.mime.as_deref(),
                    &item.tags,
                    &item.chunks,
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
        Ok(serde_cbor::to_vec(&signing_tuple)?)
    }

    pub fn sign(&mut self, key: &ShareKeypair) -> anyhow::Result<()> {
        let bytes = self.unsigned_bytes()?;
        let signature: Signature = key.signing_key.sign(&bytes);
        self.signature = Some(signature.to_bytes().to_vec());
        Ok(())
    }

    pub fn verify(&self) -> anyhow::Result<()> {
        let sig = self
            .signature
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("manifest missing signature"))?;
        if sig.len() != 64 {
            anyhow::bail!("manifest signature must be 64 bytes");
        }

        let pubkey = VerifyingKey::from_bytes(&self.share_pubkey)?;
        if ShareId::from_pubkey(&pubkey).0 != self.share_id {
            anyhow::bail!("manifest share_id does not match share_pubkey");
        }

        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(sig);
        let bytes = self.unsigned_bytes()?;
        pubkey.verify(&bytes, &Signature::from_bytes(&sig_arr))?;
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
            self.signature.as_deref(),
        );
        Ok(ManifestId::from_manifest_bytes(&serde_cbor::to_vec(
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
        Ok(serde_cbor::to_vec(&signing_tuple)?)
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

        let unsigned_manifest: serde_cbor::Value =
            serde_cbor::from_slice(&manifest.unsigned_bytes().expect("manifest unsigned bytes"))
                .expect("decode manifest unsigned");
        let items = match unsigned_manifest {
            serde_cbor::Value::Array(values) => {
                assert_eq!(values.len(), 12);
                assert_eq!(values[8], serde_cbor::Value::Text("private".to_string()));
                match &values[9] {
                    serde_cbor::Value::Array(communities) => assert!(communities.is_empty()),
                    _ => panic!("manifest communities should be cbor array"),
                }
                values[10].clone()
            }
            _ => panic!("manifest unsigned form should be cbor array"),
        };
        match items {
            serde_cbor::Value::Array(values) => assert_eq!(values.len(), 0),
            _ => panic!("manifest items should be cbor array"),
        }

        let head = ShareHead {
            share_id: share.share_id().0,
            latest_seq: 2,
            latest_manifest_id: [5u8; 32],
            updated_at: 1_700_000_002,
            sig: vec![],
        };

        let unsigned_head: serde_cbor::Value =
            serde_cbor::from_slice(&head.signable_bytes().expect("head signable bytes"))
                .expect("decode head unsigned");
        match unsigned_head {
            serde_cbor::Value::Array(values) => assert_eq!(values.len(), 4),
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
                mime: Some("application/octet-stream".into()),
                tags: vec!["t1".into(), "t2".into()],
                chunks: vec![[2u8; 32], [3u8; 32]],
            }],
            recommended_shares: vec![],
            signature: None,
        };

        let unsigned_manifest: serde_cbor::Value =
            serde_cbor::from_slice(&manifest.unsigned_bytes().expect("manifest unsigned bytes"))
                .expect("decode manifest unsigned");
        let items = match unsigned_manifest {
            serde_cbor::Value::Array(values) => {
                assert_eq!(values[8], serde_cbor::Value::Text("public".to_string()));
                match &values[9] {
                    serde_cbor::Value::Array(communities) => {
                        assert_eq!(communities.len(), 1);
                    }
                    _ => panic!("manifest communities should be cbor array"),
                }
                values[10].clone()
            }
            _ => panic!("manifest unsigned form should be cbor array"),
        };
        match items {
            serde_cbor::Value::Array(values) => {
                assert_eq!(values.len(), 1);
                match &values[0] {
                    serde_cbor::Value::Array(item_values) => {
                        assert_eq!(item_values.len(), 6);
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

        let legacy = serde_cbor::to_vec(&LegacyManifestV1 {
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

        let manifest: ManifestV1 = serde_cbor::from_slice(&legacy).expect("decode legacy");
        assert_eq!(manifest.visibility, ShareVisibility::Private);
        assert!(manifest.communities.is_empty());
    }
}
