// Copyright (c) 2024-2026 Vanyo Vanev / Tech Art Ltd
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
use std::{
    collections::{HashMap, HashSet},
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

/// Bump when making schema changes; migrations are applied in order.
const CURRENT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PersistedState {
    pub peers: Vec<PeerRecord>,
    pub subscriptions: Vec<PersistedSubscription>,
    #[serde(default)]
    pub communities: Vec<PersistedCommunity>,
    #[serde(default)]
    pub publisher_identities: Vec<PersistedPublisherIdentity>,
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
    /// Maps content_id → file path for path-based seeding.
    /// Instead of keeping blob copies, chunks are served from the original
    /// file (publisher) or the downloaded file (subscriber).
    #[serde(default)]
    pub content_paths: HashMap<[u8; 32], PathBuf>,
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
pub struct PersistedCommunity {
    pub share_id: [u8; 32],
    pub share_pubkey: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistedPublisherIdentity {
    pub label: String,
    pub share_secret: [u8; 32],
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
        // Always create the baseline tables (idempotent).
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
            );",
        )?;

        // Read (or initialise) schema version.
        let current_version: u32 = conn
            .query_row(
                "SELECT payload FROM metadata WHERE key = 'schema_version'",
                [],
                |row| {
                    let blob: Vec<u8> = row.get(0)?;
                    Ok(u32::from_le_bytes(blob.try_into().unwrap_or([0, 0, 0, 0])))
                },
            )
            .unwrap_or(0);

        // Persist the schema version.
        if current_version != CURRENT_SCHEMA_VERSION {
            conn.execute(
                "INSERT INTO metadata(key, payload) VALUES('schema_version', ?1)
                 ON CONFLICT(key) DO UPDATE SET payload = excluded.payload",
                params![CURRENT_SCHEMA_VERSION.to_le_bytes().to_vec()],
            )?;
        }
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
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let store = SqliteStore { path };
            store.ensure_schema()?;
            let conn = store.open_connection()?;
            load_state_sync(&conn)
        })
        .await?
    }

    async fn save_state(&self, state: &PersistedState) -> anyhow::Result<()> {
        let path = self.path.clone();
        let state = state.clone();
        tokio::task::spawn_blocking(move || {
            let store = SqliteStore { path };
            store.ensure_schema()?;
            let mut conn = store.open_connection()?;
            save_state_sync(&mut conn, &state)
        })
        .await?
    }
}

/// All SQLite reads happen here, on a blocking thread.
fn load_state_sync(conn: &Connection) -> anyhow::Result<PersistedState> {
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

    state.communities = load_metadata_cbor(conn, "communities")?.unwrap_or_default();
    state.publisher_identities =
        load_metadata_cbor(conn, "publisher_identities")?.unwrap_or_default();

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

    state.search_index = load_metadata_cbor(conn, "search_index")?;
    state.share_heads = load_metadata_cbor(conn, "share_heads")?.unwrap_or_default();
    state.encrypted_node_key = load_metadata_cbor(conn, "encrypted_node_key")?;
    state.enabled_blocklist_shares =
        load_metadata_cbor(conn, "enabled_blocklist_shares")?.unwrap_or_default();
    state.blocklist_rules_by_share =
        load_metadata_cbor(conn, "blocklist_rules_by_share")?.unwrap_or_default();
    state.content_paths = load_metadata_cbor(conn, "content_paths")?.unwrap_or_default();

    Ok(state)
}

/// Helper to load a single CBOR-encoded metadata value.
fn load_metadata_cbor<T: serde::de::DeserializeOwned>(
    conn: &Connection,
    key: &str,
) -> anyhow::Result<Option<T>> {
    conn.query_row(
        "SELECT payload FROM metadata WHERE key = ?1",
        params![key],
        |row| row.get::<_, Vec<u8>>(0),
    )
    .optional()?
    .map(|payload| serde_cbor::from_slice(&payload).map_err(Into::into))
    .transpose()
}

/// All SQLite writes happen here, on a blocking thread.
/// Uses UPSERT (INSERT … ON CONFLICT DO UPDATE) so only changed rows are
/// written.  Stale rows that no longer exist in `state` are deleted by
/// comparing keys.
fn save_state_sync(conn: &mut Connection, state: &PersistedState) -> anyhow::Result<()> {
    let tx = conn.transaction()?;

    // --- peers: UPSERT + prune stale ---
    let mut live_peer_keys: HashSet<String> = HashSet::new();
    for peer in &state.peers {
        let addr_key = format!(
            "{}:{}:{:?}",
            peer.addr.ip, peer.addr.port, peer.addr.transport
        );
        tx.execute(
            "INSERT INTO peers(addr_key, payload) VALUES(?1, ?2)
             ON CONFLICT(addr_key) DO UPDATE SET payload = excluded.payload",
            params![addr_key, serde_cbor::to_vec(peer)?],
        )?;
        live_peer_keys.insert(addr_key);
    }
    delete_stale_text_keys(&tx, "peers", "addr_key", &live_peer_keys)?;

    // --- subscriptions: UPSERT + prune stale ---
    let mut live_sub_keys: HashSet<Vec<u8>> = HashSet::new();
    for sub in &state.subscriptions {
        tx.execute(
            "INSERT INTO subscriptions(share_id, share_pubkey, latest_seq, latest_manifest_id, trust_level)
             VALUES(?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(share_id) DO UPDATE SET
               share_pubkey = excluded.share_pubkey,
               latest_seq = excluded.latest_seq,
               latest_manifest_id = excluded.latest_manifest_id,
               trust_level = excluded.trust_level",
            params![
                sub.share_id.to_vec(),
                sub.share_pubkey.map(|v| v.to_vec()),
                sub.latest_seq,
                sub.latest_manifest_id.map(|v| v.to_vec()),
                trust_level_str(sub.trust_level),
            ],
        )?;
        live_sub_keys.insert(sub.share_id.to_vec());
    }
    delete_stale_blob_keys(&tx, "subscriptions", "share_id", &live_sub_keys)?;

    // --- metadata blobs (communities, publisher_identities, etc.) ---
    upsert_metadata_cbor(&tx, "communities", &state.communities)?;
    upsert_metadata_cbor(&tx, "publisher_identities", &state.publisher_identities)?;

    // --- manifests: UPSERT + prune stale ---
    let mut live_manifest_keys: HashSet<Vec<u8>> = HashSet::new();
    for (manifest_id, manifest) in &state.manifests {
        tx.execute(
            "INSERT INTO manifests(manifest_id, payload) VALUES(?1, ?2)
             ON CONFLICT(manifest_id) DO UPDATE SET payload = excluded.payload",
            params![manifest_id.to_vec(), serde_cbor::to_vec(manifest)?],
        )?;
        live_manifest_keys.insert(manifest_id.to_vec());
    }
    delete_stale_blob_keys(&tx, "manifests", "manifest_id", &live_manifest_keys)?;

    // --- share_weights: UPSERT + prune stale ---
    let mut live_weight_keys: HashSet<Vec<u8>> = HashSet::new();
    for (share_id, weight) in &state.share_weights {
        tx.execute(
            "INSERT INTO share_weights(share_id, weight) VALUES(?1, ?2)
             ON CONFLICT(share_id) DO UPDATE SET weight = excluded.weight",
            params![share_id.to_vec(), weight],
        )?;
        live_weight_keys.insert(share_id.to_vec());
    }
    delete_stale_blob_keys(&tx, "share_weights", "share_id", &live_weight_keys)?;

    // --- partial_downloads: UPSERT + prune stale ---
    let mut live_partial_keys: HashSet<Vec<u8>> = HashSet::new();
    for (content_id, partial) in &state.partial_downloads {
        tx.execute(
            "INSERT INTO partial_downloads(content_id, payload) VALUES(?1, ?2)
             ON CONFLICT(content_id) DO UPDATE SET payload = excluded.payload",
            params![content_id.to_vec(), serde_cbor::to_vec(partial)?],
        )?;
        live_partial_keys.insert(content_id.to_vec());
    }
    delete_stale_blob_keys(&tx, "partial_downloads", "content_id", &live_partial_keys)?;

    // --- remaining metadata ---
    upsert_metadata_cbor_opt(&tx, "search_index", &state.search_index)?;
    upsert_metadata_cbor(&tx, "share_heads", &state.share_heads)?;
    upsert_metadata_cbor_opt(&tx, "encrypted_node_key", &state.encrypted_node_key)?;
    upsert_metadata_cbor(
        &tx,
        "enabled_blocklist_shares",
        &state.enabled_blocklist_shares,
    )?;
    upsert_metadata_cbor(
        &tx,
        "blocklist_rules_by_share",
        &state.blocklist_rules_by_share,
    )?;
    upsert_metadata_cbor(&tx, "content_paths", &state.content_paths)?;

    tx.commit()?;
    Ok(())
}

/// UPSERT a CBOR value into the metadata table, or delete the row if the value
/// is empty/default.
fn upsert_metadata_cbor<T: Serialize>(
    tx: &rusqlite::Transaction<'_>,
    key: &str,
    value: &T,
) -> anyhow::Result<()> {
    let bytes = serde_cbor::to_vec(value)?;
    tx.execute(
        "INSERT INTO metadata(key, payload) VALUES(?1, ?2)
         ON CONFLICT(key) DO UPDATE SET payload = excluded.payload",
        params![key, bytes],
    )?;
    Ok(())
}

/// Like `upsert_metadata_cbor` but for `Option<T>` — deletes the row when `None`.
fn upsert_metadata_cbor_opt<T: Serialize>(
    tx: &rusqlite::Transaction<'_>,
    key: &str,
    value: &Option<T>,
) -> anyhow::Result<()> {
    match value {
        Some(v) => {
            let bytes = serde_cbor::to_vec(v)?;
            tx.execute(
                "INSERT INTO metadata(key, payload) VALUES(?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET payload = excluded.payload",
                params![key, bytes],
            )?;
        }
        None => {
            tx.execute("DELETE FROM metadata WHERE key = ?1", params![key])?;
        }
    }
    Ok(())
}

/// Delete rows whose TEXT primary-key is not in `live_keys`.
fn delete_stale_text_keys(
    tx: &rusqlite::Transaction<'_>,
    table: &str,
    pk_col: &str,
    live_keys: &HashSet<String>,
) -> anyhow::Result<()> {
    let mut stmt = tx.prepare(&format!("SELECT {pk_col} FROM {table}"))?;
    let existing: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(0))?
        .filter_map(|r| r.ok())
        .collect();
    for key in existing {
        if !live_keys.contains(&key) {
            tx.execute(
                &format!("DELETE FROM {table} WHERE {pk_col} = ?1"),
                params![key],
            )?;
        }
    }
    Ok(())
}

/// Delete rows whose BLOB primary-key is not in `live_keys`.
fn delete_stale_blob_keys(
    tx: &rusqlite::Transaction<'_>,
    table: &str,
    pk_col: &str,
    live_keys: &HashSet<Vec<u8>>,
) -> anyhow::Result<()> {
    let mut stmt = tx.prepare(&format!("SELECT {pk_col} FROM {table}"))?;
    let existing: Vec<Vec<u8>> = stmt
        .query_map([], |row| row.get::<_, Vec<u8>>(0))?
        .filter_map(|r| r.ok())
        .collect();
    for key in existing {
        if !live_keys.contains(&key) {
            tx.execute(
                &format!("DELETE FROM {table} WHERE {pk_col} = ?1"),
                params![key],
            )?;
        }
    }
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
                relay_via: None,
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
        // Regression: content_paths must survive a save/load cycle so that
        // chunk hashes can be rehydrated on restart and GetChunkHashes requests
        // succeed without re-registering files.
        initial
            .content_paths
            .insert([0xCCu8; 32], PathBuf::from("/some/file.bin"));

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
        assert_eq!(
            loaded.content_paths.get(&[0xCCu8; 32]),
            Some(&PathBuf::from("/some/file.bin")),
            "content_paths must be persisted so chunk hashes survive restart"
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn encrypted_secret_roundtrip() {
        let secret = b"super-secret-material";
        let encrypted = encrypt_secret(secret, "passphrase").expect("encrypt");
        let decrypted = decrypt_secret(&encrypted, "passphrase").expect("decrypt");
        assert_eq!(decrypted, secret);
    }
}
