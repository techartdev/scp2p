// Copyright (c) 2024-2026 Vanyo Vanev / Tech Art Ltd
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//! Publishing operations on `NodeHandle`: publish shares, files, folders; list and download share items.

use std::path::{Path, PathBuf};

use anyhow::Context as _;

use crate::{
    content::describe_content,
    dht::DEFAULT_TTL_SECS,
    dht_keys::{content_provider_key, share_head_key},
    ids::ShareId,
    manifest::{ItemV1, ManifestV1, ShareHead, ShareKeypair, ShareVisibility},
    peer::PeerAddr,
    wire::Providers,
};

use super::{
    helpers::{
        check_manifest_limits, collect_files_recursive, mime_from_extension, normalize_item_path,
        now_unix_secs, persist_state,
    },
    NodeHandle, NodeState, ShareItemInfo,
};

impl NodeHandle {
    pub async fn publish_share(
        &self,
        mut manifest: ManifestV1,
        publisher: &ShareKeypair,
    ) -> anyhow::Result<[u8; 32]> {
        check_manifest_limits(&manifest)?;
        manifest.sign(publisher)?;
        manifest.verify()?;
        let manifest_id = manifest.manifest_id()?.0;
        let share_id = ShareId(manifest.share_id);

        let head = ShareHead::new_signed(
            share_id.0,
            manifest.seq,
            manifest_id,
            now_unix_secs()?,
            publisher,
        )?;

        let manifest_id = {
            let mut state = self.state.write().await;
            state.manifest_cache.insert(manifest_id, manifest);
            state.published_share_heads.insert(share_id.0, head.clone());
            state.dht.store(
                share_head_key(&share_id),
                serde_cbor::to_vec(&head)?,
                DEFAULT_TTL_SECS,
                now_unix_secs()?,
            )?;
            manifest_id
        };
        persist_state(self).await?;

        Ok(manifest_id)
    }

    /// Register a file at `path` as a locally-seedable content item.
    ///
    /// Chunks are served directly from `path` via seek-based reads, so no
    /// separate blob copy is made.
    pub async fn register_content_by_path(
        &self,
        peer: PeerAddr,
        content_bytes: &[u8],
        path: PathBuf,
    ) -> anyhow::Result<[u8; 32]> {
        let desc = describe_content(content_bytes);
        let content_id = desc.content_id.0;
        let now = now_unix_secs()?;
        let mut state = self.state.write().await;

        state.content_catalog.insert(content_id, desc);
        state.content_paths.insert(content_id, path);

        upsert_provider(&mut state, content_id, peer, now)?;

        Ok(content_id)
    }

    /// Register in-memory bytes as seedable content.
    ///
    /// Writes `content_bytes` to `{data_dir}/{hex_content_id}.dat` then
    /// delegates to [`Self::register_content_by_path`].  Use this for small
    /// payloads (e.g. text publishing) that are not already on disk.
    pub async fn register_content_from_bytes(
        &self,
        peer: PeerAddr,
        content_bytes: &[u8],
        data_dir: &Path,
    ) -> anyhow::Result<[u8; 32]> {
        let desc = describe_content(content_bytes);
        let content_id = desc.content_id.0;
        std::fs::create_dir_all(data_dir)?;
        let file_path = data_dir.join(format!("{}.dat", hex::encode(content_id)));
        std::fs::write(&file_path, content_bytes)?;
        self.register_content_by_path(peer, content_bytes, file_path)
            .await
    }

    /// Publish one or more files from disk as a single share.
    ///
    /// Each file becomes an `ItemV1` in the manifest.  If `base_dir` is
    /// `Some`, then `ItemV1.path` is set to the path of the file relative to
    /// `base_dir`; otherwise `path` is `None` and `name` is the plain
    /// filename.
    #[allow(clippy::too_many_arguments)]
    pub async fn publish_files(
        &self,
        files: &[PathBuf],
        base_dir: Option<&Path>,
        title: &str,
        description: Option<&str>,
        visibility: ShareVisibility,
        communities: &[[u8; 32]],
        provider: PeerAddr,
        publisher: &ShareKeypair,
    ) -> anyhow::Result<[u8; 32]> {
        let now = now_unix_secs()?;
        let next_seq = self
            .published_share_head(publisher.share_id())
            .await
            .map(|h| h.latest_seq.saturating_add(1))
            .unwrap_or(1);

        let mut items = Vec::with_capacity(files.len());
        for file_path in files {
            let bytes = tokio::fs::read(file_path)
                .await
                .with_context(|| format!("read {}", file_path.display()))?;
            let desc = describe_content(&bytes);
            let file_name = file_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            let rel_path = match base_dir {
                Some(base) => {
                    let raw = file_path
                        .strip_prefix(base)
                        .with_context(|| {
                            format!(
                                "file {} is not under base {}",
                                file_path.display(),
                                base.display()
                            )
                        })?
                        .to_string_lossy();
                    Some(normalize_item_path(&raw)?)
                }
                None => None,
            };
            let mime = mime_from_extension(&file_name);
            items.push(ItemV1 {
                content_id: desc.content_id.0,
                size: bytes.len() as u64,
                name: file_name,
                path: rel_path,
                mime,
                tags: vec![],
                chunk_count: desc.chunk_count,
                chunk_list_hash: desc.chunk_list_hash,
            });
            self.register_content_by_path(provider.clone(), &bytes, file_path.to_path_buf())
                .await?;
        }

        let manifest = ManifestV1 {
            version: 1,
            share_pubkey: publisher.verifying_key().to_bytes(),
            share_id: publisher.share_id().0,
            seq: next_seq,
            created_at: now,
            expires_at: None,
            title: Some(title.to_owned()),
            description: description.map(|d| d.to_owned()),
            visibility,
            communities: communities.to_vec(),
            items,
            recommended_shares: vec![],
            signature: None,
        };
        self.publish_share(manifest, publisher).await
    }

    /// Publish an entire folder tree as a new share revision.
    ///
    /// Every file under `folder` is recursively collected, hashed, and
    /// registered as a local provider.  Each item carries a `path`
    /// relative to `folder`.
    #[allow(clippy::too_many_arguments)]
    pub async fn publish_folder(
        &self,
        folder: &Path,
        title: &str,
        description: Option<&str>,
        visibility: ShareVisibility,
        communities: &[[u8; 32]],
        provider: PeerAddr,
        publisher: &ShareKeypair,
    ) -> anyhow::Result<[u8; 32]> {
        let files = collect_files_recursive(folder).await?;
        if files.is_empty() {
            anyhow::bail!("no files found under {}", folder.display());
        }
        self.publish_files(
            &files,
            Some(folder),
            title,
            description,
            visibility,
            communities,
            provider,
            publisher,
        )
        .await
    }

    /// List all items in a share manifest.
    pub async fn list_share_items(&self, share_id: [u8; 32]) -> anyhow::Result<Vec<ShareItemInfo>> {
        let state = self.state.read().await;
        let head = state.published_share_heads.get(&share_id);

        // Try to find the manifest from published heads first, then from
        // the manifest cache keyed by any known manifest_id for this share.
        let manifest = if let Some(head) = head {
            state.manifest_cache.get(&head.latest_manifest_id)
        } else {
            // Walk subscriptions to find the manifest.
            let sub = state.subscriptions.get(&share_id);
            sub.and_then(|s| s.latest_manifest_id)
                .and_then(|mid| state.manifest_cache.get(&mid))
        };

        let manifest = manifest.ok_or_else(|| anyhow::anyhow!("no manifest found for share"))?;

        Ok(manifest
            .items
            .iter()
            .map(|item| ShareItemInfo {
                content_id: item.content_id,
                size: item.size,
                name: item.name.clone(),
                path: item.path.clone(),
                mime: item.mime.clone(),
            })
            .collect())
    }
}

/// Insert or update a DHT provider entry for `content_id`.
fn upsert_provider(
    state: &mut NodeState,
    content_id: [u8; 32],
    peer: PeerAddr,
    now: u64,
) -> anyhow::Result<()> {
    let mut providers: Providers = state
        .dht
        .find_value(content_provider_key(&content_id), now)
        .and_then(|v| serde_cbor::from_slice(&v.value).ok())
        .unwrap_or(Providers {
            content_id,
            providers: vec![],
            updated_at: now,
        });

    if !providers.providers.contains(&peer) {
        providers.providers.push(peer);
    }
    providers.updated_at = now;

    state.dht.store(
        content_provider_key(&content_id),
        serde_cbor::to_vec(&providers)?,
        DEFAULT_TTL_SECS,
        now,
    )?;

    Ok(())
}
