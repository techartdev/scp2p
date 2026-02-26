use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
};

use async_trait::async_trait;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    Key, XChaCha20Poly1305, XNonce,
};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::{
    api::{BlocklistRules, SubscriptionTrustLevel},
    manifest::{ManifestV1, ShareHead},
    peer::PeerAddr,
    peer_db::PeerRecord,
    search::SearchIndexSnapshot,
};

const KEY_KDF_ITERATIONS: u32 = 120_000;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PersistedState {
    pub peers: Vec<PeerRecord>,
    pub subscriptions: Vec<PersistedSubscription>,
    pub manifests: HashMap<[u8; 32], ManifestV1>,
    pub share_heads: HashMap<[u8; 32], ShareHead>,
    pub share_weights: HashMap<[u8; 32], f32>,
    pub search_index: Option<SearchIndexSnapshot>,
    pub partial_downloads: HashMap<[u8; 32], PersistedPartialDownload>,
    pub encrypted_node_key: Option<EncryptedSecret>,
    #[serde(default)]
    pub enabled_blocklist_shares: Vec<[u8; 32]>,
    #[serde(default)]
    pub blocklist_rules_by_share: HashMap<[u8; 32], BlocklistRules>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedSubscription {
    pub share_id: [u8; 32],
    pub share_pubkey: Option<[u8; 32]>,
    pub latest_seq: u64,
    pub latest_manifest_id: Option<[u8; 32]>,
    #[serde(default)]
    pub trust_level: SubscriptionTrustLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistedPartialDownload {
    pub content_id: [u8; 32],
    pub target_path: String,
    pub total_chunks: u32,
    pub completed_chunks: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedSecret {
    pub salt: [u8; 16],
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

#[async_trait]
pub trait Store: Send + Sync {
    async fn load_state(&self) -> anyhow::Result<PersistedState>;
    async fn save_state(&self, state: &PersistedState) -> anyhow::Result<()>;
}

#[derive(Default)]
pub struct MemoryStore {
    state: RwLock<PersistedState>,
}

impl MemoryStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
}

pub struct SqliteStore {
    path: PathBuf,
}

impl SqliteStore {
    pub fn open(path: impl AsRef<Path>) -> anyhow::Result<Arc<Self>> {
        let store = Arc::new(Self {
            path: path.as_ref().to_path_buf(),
        });
        store.ensure_schema()?;
        Ok(store)
    }

    fn open_connection(&self) -> anyhow::Result<Connection> {
        Ok(Connection::open(&self.path)?)
    }

    fn ensure_schema(&self) -> anyhow::Result<()> {
        let conn = self.open_connection()?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS peers (
                addr_key TEXT PRIMARY KEY,
                payload BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS subscriptions (
                share_id BLOB PRIMARY KEY,
                share_pubkey BLOB,
                latest_seq INTEGER NOT NULL,
                latest_manifest_id BLOB,
                trust_level TEXT NOT NULL DEFAULT 'normal'
            );
            CREATE TABLE IF NOT EXISTS manifests (
                manifest_id BLOB PRIMARY KEY,
                payload BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS share_weights (
                share_id BLOB PRIMARY KEY,
                weight REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS partial_downloads (
                content_id BLOB PRIMARY KEY,
                payload BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                payload BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS scp2p_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                payload BLOB NOT NULL
            );",
        )?;
        ensure_subscription_trust_column(&conn)?;
        Ok(())
    }
}

#[async_trait]
impl Store for MemoryStore {
    async fn load_state(&self) -> anyhow::Result<PersistedState> {
        Ok(self.state.read().await.clone())
    }

    async fn save_state(&self, state: &PersistedState) -> anyhow::Result<()> {
        *self.state.write().await = state.clone();
        Ok(())
    }
}

#[async_trait]
impl Store for SqliteStore {
    async fn load_state(&self) -> anyhow::Result<PersistedState> {
        self.ensure_schema()?;
        let conn = self.open_connection()?;
        let mut state = PersistedState::default();

        {
            let mut stmt = conn.prepare("SELECT payload FROM peers")?;
            let rows = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
            for row in rows {
                let record: PeerRecord = serde_cbor::from_slice(&row?)?;
                state.peers.push(record);
            }
        }

        {
            let mut stmt = conn.prepare(
                "SELECT share_id, share_pubkey, latest_seq, latest_manifest_id, trust_level FROM subscriptions",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, u64>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })?;
            for row in rows {
                let (share_id, share_pubkey, latest_seq, latest_manifest_id, trust_level) = row?;
                state.subscriptions.push(PersistedSubscription {
                    share_id: blob_to_array::<32>(&share_id, "subscriptions.share_id")?,
                    share_pubkey: share_pubkey
                        .map(|v| blob_to_array::<32>(&v, "subscriptions.share_pubkey"))
                        .transpose()?,
                    latest_seq,
                    latest_manifest_id: latest_manifest_id
                        .map(|v| blob_to_array::<32>(&v, "subscriptions.latest_manifest_id"))
                        .transpose()?,
                    trust_level: parse_trust_level(&trust_level),
                });
            }
        }

        {
            let mut stmt = conn.prepare("SELECT manifest_id, payload FROM manifests")?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?;
            for row in rows {
                let (manifest_id, payload) = row?;
                let manifest: ManifestV1 = serde_cbor::from_slice(&payload)?;
                state.manifests.insert(
                    blob_to_array::<32>(&manifest_id, "manifests.manifest_id")?,
                    manifest,
                );
            }
        }

        {
            let mut stmt = conn.prepare("SELECT share_id, weight FROM share_weights")?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, f32>(1)?))
            })?;
            for row in rows {
                let (share_id, weight) = row?;
                state.share_weights.insert(
                    blob_to_array::<32>(&share_id, "share_weights.share_id")?,
                    weight,
                );
            }
        }

        {
            let mut stmt = conn.prepare("SELECT content_id, payload FROM partial_downloads")?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            })?;
            for row in rows {
                let (content_id, payload) = row?;
                let partial: PersistedPartialDownload = serde_cbor::from_slice(&payload)?;
                state.partial_downloads.insert(
                    blob_to_array::<32>(&content_id, "partial_downloads.content_id")?,
                    partial,
                );
            }
        }

        state.search_index = conn
            .query_row(
                "SELECT payload FROM metadata WHERE key = 'search_index'",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|payload| serde_cbor::from_slice(&payload))
            .transpose()?;

        state.share_heads = conn
            .query_row(
                "SELECT payload FROM metadata WHERE key = 'share_heads'",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|payload| serde_cbor::from_slice(&payload))
            .transpose()?
            .unwrap_or_default();

        state.encrypted_node_key = conn
            .query_row(
                "SELECT payload FROM metadata WHERE key = 'encrypted_node_key'",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|payload| serde_cbor::from_slice(&payload))
            .transpose()?;

        state.enabled_blocklist_shares = conn
            .query_row(
                "SELECT payload FROM metadata WHERE key = 'enabled_blocklist_shares'",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|payload| serde_cbor::from_slice(&payload))
            .transpose()?
            .unwrap_or_default();

        state.blocklist_rules_by_share = conn
            .query_row(
                "SELECT payload FROM metadata WHERE key = 'blocklist_rules_by_share'",
                [],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|payload| serde_cbor::from_slice(&payload))
            .transpose()?
            .unwrap_or_default();

        let has_normalized_data = !state.peers.is_empty()
            || !state.subscriptions.is_empty()
            || !state.manifests.is_empty()
            || !state.share_heads.is_empty()
            || !state.share_weights.is_empty()
            || !state.partial_downloads.is_empty()
            || state.search_index.is_some()
            || state.encrypted_node_key.is_some()
            || !state.enabled_blocklist_shares.is_empty()
            || !state.blocklist_rules_by_share.is_empty();
        if has_normalized_data {
            return Ok(state);
        }

        // Backward-compatible fallback for older single-row snapshot format.
        let maybe_payload: Option<Vec<u8>> = conn
            .query_row("SELECT payload FROM scp2p_state WHERE id = 1", [], |row| {
                row.get(0)
            })
            .optional()?;
        if let Some(payload) = maybe_payload {
            return Ok(serde_cbor::from_slice(&payload)?);
        }
        Ok(state)
    }

    async fn save_state(&self, state: &PersistedState) -> anyhow::Result<()> {
        self.ensure_schema()?;
        let mut conn = self.open_connection()?;
        let tx = conn.transaction()?;
        tx.execute("DELETE FROM peers", [])?;
        tx.execute("DELETE FROM subscriptions", [])?;
        tx.execute("DELETE FROM manifests", [])?;
        tx.execute("DELETE FROM share_weights", [])?;
        tx.execute("DELETE FROM partial_downloads", [])?;
        tx.execute("DELETE FROM metadata", [])?;

        for peer in &state.peers {
            let addr_key = format!(
                "{}:{}:{:?}",
                peer.addr.ip, peer.addr.port, peer.addr.transport
            );
            tx.execute(
                "INSERT INTO peers(addr_key, payload) VALUES(?1, ?2)",
                params![addr_key, serde_cbor::to_vec(peer)?],
            )?;
        }

        for sub in &state.subscriptions {
            tx.execute(
                "INSERT INTO subscriptions(share_id, share_pubkey, latest_seq, latest_manifest_id, trust_level)
                 VALUES(?1, ?2, ?3, ?4, ?5)",
                params![
                    sub.share_id.to_vec(),
                    sub.share_pubkey.map(|v| v.to_vec()),
                    sub.latest_seq,
                    sub.latest_manifest_id.map(|v| v.to_vec()),
                    trust_level_str(sub.trust_level),
                ],
            )?;
        }

        for (manifest_id, manifest) in &state.manifests {
            tx.execute(
                "INSERT INTO manifests(manifest_id, payload) VALUES(?1, ?2)",
                params![manifest_id.to_vec(), serde_cbor::to_vec(manifest)?],
            )?;
        }

        for (share_id, weight) in &state.share_weights {
            tx.execute(
                "INSERT INTO share_weights(share_id, weight) VALUES(?1, ?2)",
                params![share_id.to_vec(), weight],
            )?;
        }

        for (content_id, partial) in &state.partial_downloads {
            tx.execute(
                "INSERT INTO partial_downloads(content_id, payload) VALUES(?1, ?2)",
                params![content_id.to_vec(), serde_cbor::to_vec(partial)?],
            )?;
        }

        if let Some(snapshot) = &state.search_index {
            tx.execute(
                "INSERT INTO metadata(key, payload) VALUES('search_index', ?1)",
                params![serde_cbor::to_vec(snapshot)?],
            )?;
        }
        if !state.share_heads.is_empty() {
            tx.execute(
                "INSERT INTO metadata(key, payload) VALUES('share_heads', ?1)",
                params![serde_cbor::to_vec(&state.share_heads)?],
            )?;
        }
        if let Some(encrypted_key) = &state.encrypted_node_key {
            tx.execute(
                "INSERT INTO metadata(key, payload) VALUES('encrypted_node_key', ?1)",
                params![serde_cbor::to_vec(encrypted_key)?],
            )?;
        }
        if !state.enabled_blocklist_shares.is_empty() {
            tx.execute(
                "INSERT INTO metadata(key, payload) VALUES('enabled_blocklist_shares', ?1)",
                params![serde_cbor::to_vec(&state.enabled_blocklist_shares)?],
            )?;
        }
        if !state.blocklist_rules_by_share.is_empty() {
            tx.execute(
                "INSERT INTO metadata(key, payload) VALUES('blocklist_rules_by_share', ?1)",
                params![serde_cbor::to_vec(&state.blocklist_rules_by_share)?],
            )?;
        }

        // Legacy compatibility snapshot (can be removed in a later migration window).
        let payload = serde_cbor::to_vec(state)?;
        tx.execute(
            "INSERT INTO scp2p_state(id, payload) VALUES(1, ?1)
             ON CONFLICT(id) DO UPDATE SET payload = excluded.payload",
            params![payload],
        )?;
        tx.commit()?;
        Ok(())
    }
}

fn ensure_subscription_trust_column(conn: &Connection) -> anyhow::Result<()> {
    let mut stmt = conn.prepare("PRAGMA table_info(subscriptions)")?;
    let columns = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for column in columns {
        if column? == "trust_level" {
            return Ok(());
        }
    }
    conn.execute(
        "ALTER TABLE subscriptions ADD COLUMN trust_level TEXT NOT NULL DEFAULT 'normal'",
        [],
    )?;
    Ok(())
}

fn parse_trust_level(value: &str) -> SubscriptionTrustLevel {
    match value {
        "trusted" => SubscriptionTrustLevel::Trusted,
        "untrusted" => SubscriptionTrustLevel::Untrusted,
        _ => SubscriptionTrustLevel::Normal,
    }
}

fn trust_level_str(level: SubscriptionTrustLevel) -> &'static str {
    match level {
        SubscriptionTrustLevel::Trusted => "trusted",
        SubscriptionTrustLevel::Normal => "normal",
        SubscriptionTrustLevel::Untrusted => "untrusted",
    }
}

fn blob_to_array<const N: usize>(blob: &[u8], field: &str) -> anyhow::Result<[u8; N]> {
    if blob.len() != N {
        anyhow::bail!(
            "invalid {} length: expected {}, got {}",
            field,
            N,
            blob.len()
        );
    }
    let mut out = [0u8; N];
    out.copy_from_slice(blob);
    Ok(out)
}

pub fn peer_record(addr: PeerAddr, last_seen_unix: u64) -> PeerRecord {
    PeerRecord {
        addr,
        last_seen_unix,
    }
}

pub fn encrypt_secret(secret: &[u8], passphrase: &str) -> anyhow::Result<EncryptedSecret> {
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 24];
    let mut rng = rand::rngs::OsRng;
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce);

    let mut key_bytes = [0u8; 32];
    pbkdf2_hmac::<sha2::Sha256>(
        passphrase.as_bytes(),
        &salt,
        KEY_KDF_ITERATIONS,
        &mut key_bytes,
    );
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), secret)
        .map_err(|_| anyhow::anyhow!("failed to encrypt secret"))?;

    Ok(EncryptedSecret {
        salt,
        nonce,
        ciphertext,
    })
}

pub fn decrypt_secret(secret: &EncryptedSecret, passphrase: &str) -> anyhow::Result<Vec<u8>> {
    let mut key_bytes = [0u8; 32];
    pbkdf2_hmac::<sha2::Sha256>(
        passphrase.as_bytes(),
        &secret.salt,
        KEY_KDF_ITERATIONS,
        &mut key_bytes,
    );
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&secret.nonce),
            secret.ciphertext.as_ref(),
        )
        .map_err(|_| anyhow::anyhow!("failed to decrypt secret"))?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::TransportProtocol;

    #[tokio::test]
    async fn memory_store_roundtrip() {
        let store = MemoryStore::new();
        let mut initial = PersistedState::default();
        initial.peers.push(peer_record(
            PeerAddr {
                ip: "127.0.0.1".parse().expect("valid ip"),
                port: 7000,
                transport: TransportProtocol::Tcp,
                pubkey_hint: None,
            },
            42,
        ));
        initial.subscriptions.push(PersistedSubscription {
            share_id: [1u8; 32],
            share_pubkey: None,
            latest_seq: 7,
            latest_manifest_id: Some([2u8; 32]),
            trust_level: SubscriptionTrustLevel::Normal,
        });
        initial.share_weights.insert([1u8; 32], 1.5);
        initial.enabled_blocklist_shares.push([3u8; 32]);
        initial.blocklist_rules_by_share.insert(
            [3u8; 32],
            BlocklistRules {
                blocked_share_ids: vec![[4u8; 32]],
                blocked_content_ids: vec![[5u8; 32]],
            },
        );

        store.save_state(&initial).await.expect("save");
        let loaded = store.load_state().await.expect("load");

        assert_eq!(loaded.peers.len(), 1);
        assert_eq!(loaded.subscriptions.len(), 1);
        assert_eq!(loaded.share_weights.get(&[1u8; 32]), Some(&1.5));
        assert_eq!(loaded.enabled_blocklist_shares, vec![[3u8; 32]]);
        assert_eq!(loaded.blocklist_rules_by_share.len(), 1);
    }

    #[tokio::test]
    async fn sqlite_store_roundtrip() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "scp2p_store_test_{}.db",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("now")
                .as_nanos()
        ));
        let store = SqliteStore::open(&path).expect("open sqlite");
        let mut initial = PersistedState::default();
        initial.subscriptions.push(PersistedSubscription {
            share_id: [7u8; 32],
            share_pubkey: Some([9u8; 32]),
            latest_seq: 3,
            latest_manifest_id: Some([5u8; 32]),
            trust_level: SubscriptionTrustLevel::Trusted,
        });
        initial.partial_downloads.insert(
            [8u8; 32],
            PersistedPartialDownload {
                content_id: [8u8; 32],
                target_path: "tmp.bin".into(),
                total_chunks: 4,
                completed_chunks: vec![1, 3],
            },
        );
        initial.encrypted_node_key = Some(encrypt_secret(b"k", "pw").expect("encrypt"));
        initial.enabled_blocklist_shares.push([7u8; 32]);
        initial.blocklist_rules_by_share.insert(
            [7u8; 32],
            BlocklistRules {
                blocked_share_ids: vec![[1u8; 32]],
                blocked_content_ids: vec![[2u8; 32]],
            },
        );

        store.save_state(&initial).await.expect("save");
        let loaded = store.load_state().await.expect("load");
        assert_eq!(loaded.subscriptions.len(), 1);
        assert_eq!(loaded.subscriptions[0].latest_seq, 3);
        assert_eq!(
            loaded.subscriptions[0].trust_level,
            SubscriptionTrustLevel::Trusted
        );
        assert_eq!(loaded.partial_downloads.len(), 1);
        assert!(loaded.encrypted_node_key.is_some());
        assert_eq!(loaded.enabled_blocklist_shares, vec![[7u8; 32]]);
        assert_eq!(loaded.blocklist_rules_by_share.len(), 1);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn persisted_subscription_legacy_defaults_trust_level() {
        #[derive(Serialize)]
        struct LegacySubscription {
            share_id: [u8; 32],
            share_pubkey: Option<[u8; 32]>,
            latest_seq: u64,
            latest_manifest_id: Option<[u8; 32]>,
        }

        let legacy = LegacySubscription {
            share_id: [3u8; 32],
            share_pubkey: None,
            latest_seq: 1,
            latest_manifest_id: None,
        };
        let encoded = serde_cbor::to_vec(&legacy).expect("encode");
        let decoded: PersistedSubscription = serde_cbor::from_slice(&encoded).expect("decode");
        assert_eq!(decoded.trust_level, SubscriptionTrustLevel::Normal);
    }

    #[test]
    fn encrypted_secret_roundtrip() {
        let secret = b"super-secret-material";
        let encrypted = encrypt_secret(secret, "passphrase").expect("encrypt");
        let decrypted = decrypt_secret(&encrypted, "passphrase").expect("decrypt");
        assert_eq!(decrypted, secret);
    }
}
