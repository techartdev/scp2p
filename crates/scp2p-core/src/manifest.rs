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
    pub items: Vec<ItemV1>,
    pub recommended_shares: Vec<[u8; 32]>,
    pub signature: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize)]
struct ManifestUnsigned<'a> {
    version: u8,
    share_pubkey: [u8; 32],
    share_id: [u8; 32],
    seq: u64,
    created_at: u64,
    expires_at: Option<u64>,
    title: &'a Option<String>,
    description: &'a Option<String>,
    items: &'a [ItemV1],
    recommended_shares: &'a [[u8; 32]],
}

impl ManifestV1 {
    pub fn unsigned_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let unsigned = ManifestUnsigned {
            version: self.version,
            share_pubkey: self.share_pubkey,
            share_id: self.share_id,
            seq: self.seq,
            created_at: self.created_at,
            expires_at: self.expires_at,
            title: &self.title,
            description: &self.description,
            items: &self.items,
            recommended_shares: &self.recommended_shares,
        };
        Ok(serde_cbor::to_vec(&unsigned)?)
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
        Ok(ManifestId::from_manifest_bytes(&serde_cbor::to_vec(self)?))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareHead {
    pub share_id: [u8; 32],
    pub latest_seq: u64,
    pub latest_manifest_id: [u8; 32],
    pub updated_at: u64,
    pub sig: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
struct ShareHeadUnsigned {
    share_id: [u8; 32],
    latest_seq: u64,
    latest_manifest_id: [u8; 32],
    updated_at: u64,
}

impl ShareHead {
    pub fn signable_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let unsigned = ShareHeadUnsigned {
            share_id: self.share_id,
            latest_seq: self.latest_seq,
            latest_manifest_id: self.latest_manifest_id,
            updated_at: self.updated_at,
        };
        Ok(serde_cbor::to_vec(&unsigned)?)
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
}
