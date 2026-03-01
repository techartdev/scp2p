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
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::{
    api::{BlocklistRules, SubscriptionTrustLevel},
    manifest::{ManifestV1, ShareHead},
    peer::PeerAddr,
    peer_db::PeerRecord,
    search::SearchIndexSnapshot,
};

const KEY_KDF_ITERATIONS: u32 = 600_000;

/// Bump when making schema changes; migrations are applied in order.
const CURRENT_SCHEMA_VERSION: u32 = 2;

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
    /// Optional cryptographic membership token signed by the community
    /// publisher key (§4.2).  When present, community membership is
    /// verifiable by any peer; when absent, membership is self-asserted.
    #[serde(default)]
    pub membership_token: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistedPublisherIdentity {
    pub label: String,
    /// Plaintext secret — present when no passphrase-based encryption is active.
    /// When encryption is enabled this field is zeroed out in persisted form.
    #[serde(default)]
    pub share_secret: Option<[u8; 32]>,
    /// Encrypted secret — present when the publisher identity has been
    /// locked with a passphrase via [`encrypt_publisher_identities`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_share_secret: Option<EncryptedSecret>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistedPartialDownload {
    pub content_id: [u8; 32],
    pub target_path: String,
    pub total_chunks: u32,
    pub completed_chunks: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedSecret {
    pub salt: [u8; 16],
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

/// Tracks which sections of persisted state have been mutated since the
/// last successful save.  When all flags are `false`, `persist_state`
/// short-circuits without cloning or writing anything.
#[derive(Debug, Clone, Copy, Default)]
pub struct DirtyFlags {
    pub peers: bool,
    pub subscriptions: bool,
    pub communities: bool,
    pub publisher_identities: bool,
    pub manifests: bool,
    pub share_heads: bool,
    pub share_weights: bool,
    pub search_index: bool,
    pub partial_downloads: bool,
    pub node_key: bool,
    pub blocklist: bool,
    pub content_paths: bool,
}

impl DirtyFlags {
    /// Return a flags set with every section marked dirty.
    pub fn all() -> Self {
        Self {
            peers: true,
            subscriptions: true,
            communities: true,
            publisher_identities: true,
            manifests: true,
            share_heads: true,
            share_weights: true,
            search_index: true,
            partial_downloads: true,
            node_key: true,
            blocklist: true,
            content_paths: true,
        }
    }

    /// `true` when at least one section is dirty.
    pub fn any(&self) -> bool {
        self.peers
            || self.subscriptions
            || self.communities
            || self.publisher_identities
            || self.manifests
            || self.share_heads
            || self.share_weights
            || self.search_index
            || self.partial_downloads
            || self.node_key
            || self.blocklist
            || self.content_paths
    }
}

#[async_trait]
pub trait Store: Send + Sync {
    async fn load_state(&self) -> anyhow::Result<PersistedState>;
    async fn save_state(&self, state: &PersistedState) -> anyhow::Result<()>;

    /// Save only the sections indicated by `dirty`.
    ///
    /// Default implementation falls back to `save_state`.  `SqliteStore`
    /// overrides this to skip unchanged tables.
    async fn save_incremental(
        &self,
        state: &PersistedState,
        dirty: &DirtyFlags,
    ) -> anyhow::Result<()> {
        if dirty.any() {
            self.save_state(state).await
        } else {
            Ok(())
        }
    }
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

        // --- Schema v2: FTS5 search index ---
        if current_version < 2 {
            conn.execute_batch(
                "CREATE VIRTUAL TABLE IF NOT EXISTS search_fts USING fts5(
                    share_id UNINDEXED,
                    content_id UNINDEXED,
                    name,
                    tags,
                    title,
                    description,
                    tokenize = 'unicode61'
                );",
            )?;
            // Drop the legacy CBOR search_index blob if present.
            conn.execute("DELETE FROM metadata WHERE key = 'search_index'", [])?;
        }

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
            save_state_sync(&mut conn, &state, &DirtyFlags::all())
        })
        .await?
    }

    async fn save_incremental(
        &self,
        state: &PersistedState,
        dirty: &DirtyFlags,
    ) -> anyhow::Result<()> {
        if !dirty.any() {
            return Ok(());
        }
        let path = self.path.clone();
        let state = state.clone();
        let dirty = *dirty;
        tokio::task::spawn_blocking(move || {
            let store = SqliteStore { path };
            store.ensure_schema()?;
            let mut conn = store.open_connection()?;
            save_state_sync(&mut conn, &state, &dirty)
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
            let record: PeerRecord = crate::cbor::from_slice(&row?)?;
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
            let manifest: ManifestV1 = crate::cbor::from_slice(&payload)?;
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
            let partial: PersistedPartialDownload = crate::cbor::from_slice(&payload)?;
            state.partial_downloads.insert(
                blob_to_array::<32>(&content_id, "partial_downloads.content_id")?,
                partial,
            );
        }
    }

    // --- FTS5 search index ---
    {
        // Try loading from the search_fts table (schema v2+).
        // Falls back to legacy CBOR blob for databases not yet migrated.
        let has_fts = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='search_fts'")
            .and_then(|mut s| s.query_row([], |_| Ok(())))
            .is_ok();

        if has_fts {
            let mut stmt = conn.prepare(
                "SELECT share_id, content_id, name, tags, title, description FROM search_fts",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })?;
            let mut items = Vec::new();
            for row in rows {
                let (share_id_hex, content_id_hex, name, tags_str, title, description) = row?;
                let share_id = hex_to_array::<32>(&share_id_hex, "search_fts.share_id")?;
                let content_id = hex_to_array::<32>(&content_id_hex, "search_fts.content_id")?;
                let tags: Vec<String> = tags_str
                    .split('\t')
                    .filter(|t| !t.is_empty())
                    .map(ToOwned::to_owned)
                    .collect();
                let title = if title.is_empty() { None } else { Some(title) };
                let description = if description.is_empty() {
                    None
                } else {
                    Some(description)
                };
                items.push(crate::search::IndexedItem {
                    share_id,
                    content_id,
                    name,
                    tags,
                    title,
                    description,
                });
            }
            if !items.is_empty() {
                state.search_index = Some(crate::search::SearchIndex::from_items(items).snapshot());
            }
        } else {
            state.search_index = load_metadata_cbor(conn, "search_index")?;
        }
    }

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
    .map(|payload| crate::cbor::from_slice(&payload).map_err(Into::into))
    .transpose()
}

/// All SQLite writes happen here, on a blocking thread.
/// Uses UPSERT (INSERT … ON CONFLICT DO UPDATE) so only changed rows are
/// written.  Stale rows that no longer exist in `state` are deleted by
/// comparing keys.  When `dirty` indicates a section is unchanged, the
/// corresponding table writes are skipped entirely.
fn save_state_sync(
    conn: &mut Connection,
    state: &PersistedState,
    dirty: &DirtyFlags,
) -> anyhow::Result<()> {
    let tx = conn.transaction()?;

    // --- peers: UPSERT + prune stale ---
    if dirty.peers {
        let mut live_peer_keys: HashSet<String> = HashSet::new();
        for peer in &state.peers {
            let addr_key = format!(
                "{}:{}:{:?}",
                peer.addr.ip, peer.addr.port, peer.addr.transport
            );
            tx.execute(
                "INSERT INTO peers(addr_key, payload) VALUES(?1, ?2)
                 ON CONFLICT(addr_key) DO UPDATE SET payload = excluded.payload",
                params![addr_key, crate::cbor::to_vec(peer)?],
            )?;
            live_peer_keys.insert(addr_key);
        }
        delete_stale_text_keys(&tx, "peers", "addr_key", &live_peer_keys)?;
    }

    // --- subscriptions: UPSERT + prune stale ---
    if dirty.subscriptions {
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
    }

    // --- metadata blobs (communities, publisher_identities, etc.) ---
    if dirty.communities {
        upsert_metadata_cbor(&tx, "communities", &state.communities)?;
    }
    if dirty.publisher_identities {
        upsert_metadata_cbor(&tx, "publisher_identities", &state.publisher_identities)?;
    }

    // --- manifests: UPSERT + prune stale ---
    if dirty.manifests {
        let mut live_manifest_keys: HashSet<Vec<u8>> = HashSet::new();
        for (manifest_id, manifest) in &state.manifests {
            tx.execute(
                "INSERT INTO manifests(manifest_id, payload) VALUES(?1, ?2)
                 ON CONFLICT(manifest_id) DO UPDATE SET payload = excluded.payload",
                params![manifest_id.to_vec(), crate::cbor::to_vec(manifest)?],
            )?;
            live_manifest_keys.insert(manifest_id.to_vec());
        }
        delete_stale_blob_keys(&tx, "manifests", "manifest_id", &live_manifest_keys)?;
    }

    // --- share_weights: UPSERT + prune stale ---
    if dirty.share_weights {
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
    }

    // --- partial_downloads: UPSERT + prune stale ---
    if dirty.partial_downloads {
        let mut live_partial_keys: HashSet<Vec<u8>> = HashSet::new();
        for (content_id, partial) in &state.partial_downloads {
            tx.execute(
                "INSERT INTO partial_downloads(content_id, payload) VALUES(?1, ?2)
                 ON CONFLICT(content_id) DO UPDATE SET payload = excluded.payload",
                params![content_id.to_vec(), crate::cbor::to_vec(partial)?],
            )?;
            live_partial_keys.insert(content_id.to_vec());
        }
        delete_stale_blob_keys(&tx, "partial_downloads", "content_id", &live_partial_keys)?;
    }

    // --- remaining metadata ---
    if dirty.search_index {
        // FTS5-backed search index: clear and repopulate.
        tx.execute("DELETE FROM search_fts", [])?;
        if let Some(ref snapshot) = state.search_index {
            let mut insert_stmt = tx.prepare(
                "INSERT INTO search_fts(share_id, content_id, name, tags, title, description) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            )?;
            for item in snapshot.items() {
                insert_stmt.execute(params![
                    hex::encode(item.share_id),
                    hex::encode(item.content_id),
                    &item.name,
                    item.tags.join("\t"),
                    item.title.as_deref().unwrap_or(""),
                    item.description.as_deref().unwrap_or(""),
                ])?;
            }
        }
    }
    if dirty.share_heads {
        upsert_metadata_cbor(&tx, "share_heads", &state.share_heads)?;
    }
    if dirty.node_key {
        upsert_metadata_cbor_opt(&tx, "encrypted_node_key", &state.encrypted_node_key)?;
    }
    if dirty.blocklist {
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
    }
    if dirty.content_paths {
        upsert_metadata_cbor(&tx, "content_paths", &state.content_paths)?;
    }

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
    let bytes = crate::cbor::to_vec(value)?;
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
            let bytes = crate::cbor::to_vec(v)?;
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
/// Validate that a SQL identifier contains only safe characters (alphanumeric + underscore).
fn validate_sql_identifier(ident: &str) -> anyhow::Result<()> {
    if ident.is_empty() || !ident.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        anyhow::bail!("invalid SQL identifier: {ident:?}");
    }
    Ok(())
}

fn delete_stale_text_keys(
    tx: &rusqlite::Transaction<'_>,
    table: &str,
    pk_col: &str,
    live_keys: &HashSet<String>,
) -> anyhow::Result<()> {
    validate_sql_identifier(table)?;
    validate_sql_identifier(pk_col)?;
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
    validate_sql_identifier(table)?;
    validate_sql_identifier(pk_col)?;
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

fn hex_to_array<const N: usize>(hex_str: &str, field: &str) -> anyhow::Result<[u8; N]> {
    let bytes =
        hex::decode(hex_str).map_err(|e| anyhow::anyhow!("invalid hex in {}: {}", field, e))?;
    blob_to_array::<N>(&bytes, field)
}

pub fn peer_record(addr: PeerAddr, last_seen_unix: u64) -> PeerRecord {
    PeerRecord {
        addr,
        last_seen_unix,
        capabilities: None,
        capabilities_seen_at: None,
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

    #[tokio::test]
    async fn sqlite_fts5_search_index_roundtrip() {
        use crate::search::{IndexedItem, SearchIndex};

        let mut path = std::env::temp_dir();
        path.push(format!(
            "scp2p_fts5_test_{}.db",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("now")
                .as_nanos()
        ));
        let store = SqliteStore::open(&path).expect("open sqlite");

        let mut initial = PersistedState::default();

        // Build a search index with two items.
        let items = vec![
            IndexedItem {
                share_id: [1u8; 32],
                content_id: [2u8; 32],
                name: "Ubuntu ISO".into(),
                tags: vec!["linux".into(), "ubuntu".into()],
                title: Some("Linux Downloads".into()),
                description: Some("Latest Ubuntu release".into()),
            },
            IndexedItem {
                share_id: [1u8; 32],
                content_id: [3u8; 32],
                name: "Fedora DVD".into(),
                tags: vec!["linux".into(), "fedora".into()],
                title: Some("Linux Downloads".into()),
                description: None,
            },
        ];
        let index = SearchIndex::from_items(items);
        initial.search_index = Some(index.snapshot());

        store.save_state(&initial).await.expect("save");
        let loaded = store.load_state().await.expect("load");

        let loaded_snapshot = loaded.search_index.expect("search_index should be Some");
        let loaded_items: Vec<_> = loaded_snapshot.items().collect();
        assert_eq!(loaded_items.len(), 2, "should load 2 FTS5 items");

        // Verify item content.
        let ubuntu = loaded_items
            .iter()
            .find(|i| i.name == "Ubuntu ISO")
            .expect("ubuntu item");
        assert_eq!(ubuntu.tags, vec!["linux", "ubuntu"]);
        assert_eq!(ubuntu.title.as_deref(), Some("Linux Downloads"));
        assert_eq!(ubuntu.description.as_deref(), Some("Latest Ubuntu release"));

        let fedora = loaded_items
            .iter()
            .find(|i| i.name == "Fedora DVD")
            .expect("fedora item");
        assert_eq!(fedora.tags, vec!["linux", "fedora"]);
        assert!(fedora.description.is_none());

        // Rebuild the search index and verify search works.
        let reloaded_index = SearchIndex::from_snapshot(loaded_snapshot);
        let mut subs = std::collections::HashSet::new();
        subs.insert([1u8; 32]);
        let hits = reloaded_index.search("ubuntu", &subs, &std::collections::HashMap::new());
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0.name, "Ubuntu ISO");

        let _ = std::fs::remove_file(path);
    }
}
