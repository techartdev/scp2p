// Copyright (c) 2024-2026 Vanyo Vanev / Tech Art Ltd
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//! On-disk or in-memory content blob store for published provider payloads.
//!
//! When a `blob_dir` is configured the store writes each registered content
//! object to `{blob_dir}/{hex(content_id)}.blob` and serves chunk reads by
//! seeking into the file.  When no directory is set (unit-test default) the
//! store falls back to an in-memory `HashMap`.

use std::{
    collections::HashMap,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

use crate::content::CHUNK_SIZE;

/// Storage backend for locally-published content blobs.
///
/// * **File-backed** (`blob_dir` set) — content is written to disk and chunks
///   are served via seeking.  Only the requested 256 KiB slice is read into
///   memory per `read_chunk` call.
/// * **In-memory** (default) — content is held in a `HashMap`, matching the
///   pre-existing behaviour used by unit tests.
pub struct ContentBlobStore {
    blob_dir: Option<PathBuf>,
    /// Fallback in-memory store used when `blob_dir` is `None`.
    memory: HashMap<[u8; 32], Vec<u8>>,
}

impl ContentBlobStore {
    /// Create an in-memory-only store (for tests and configs without a
    /// persistent data directory).
    pub fn in_memory() -> Self {
        Self {
            blob_dir: None,
            memory: HashMap::new(),
        }
    }

    /// Create a file-backed store rooted at `dir`.
    ///
    /// The directory is created if it does not exist.
    pub fn on_disk(dir: PathBuf) -> anyhow::Result<Self> {
        std::fs::create_dir_all(&dir)?;
        Ok(Self {
            blob_dir: Some(dir),
            memory: HashMap::new(),
        })
    }

    /// Persist `content_bytes` under the given `content_id`.
    ///
    /// In file-backed mode the bytes are written atomically (write-to-temp
    /// then rename).  In in-memory mode they are inserted into the map.
    pub fn store(&mut self, content_id: [u8; 32], content_bytes: Vec<u8>) -> anyhow::Result<()> {
        match &self.blob_dir {
            Some(dir) => {
                let target = blob_path(dir, &content_id);
                if target.exists() {
                    // Already stored — skip redundant write.
                    return Ok(());
                }
                let tmp = target.with_extension("blob.tmp");
                std::fs::write(&tmp, &content_bytes)?;
                std::fs::rename(&tmp, &target)?;
                Ok(())
            }
            None => {
                self.memory.insert(content_id, content_bytes);
                Ok(())
            }
        }
    }

    /// Return `true` if content with the given ID exists in the store.
    pub fn contains(&self, content_id: &[u8; 32]) -> bool {
        match &self.blob_dir {
            Some(dir) => blob_path(dir, content_id).exists(),
            None => self.memory.contains_key(content_id),
        }
    }

    /// Read exactly one chunk (up to 256 KiB) from the stored content.
    ///
    /// Returns `None` if the content ID is unknown or the chunk index is out
    /// of range.  In file-backed mode only the requested slice is read.
    pub fn read_chunk(
        &self,
        content_id: &[u8; 32],
        chunk_index: u32,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        match &self.blob_dir {
            Some(dir) => read_chunk_from_file(dir, content_id, chunk_index),
            None => Ok(read_chunk_from_memory(
                &self.memory,
                content_id,
                chunk_index,
            )),
        }
    }

    /// Read the full content bytes.
    ///
    /// Prefer `read_chunk` for serving — this is kept for the local
    /// `download_swarm` path which reassembles content from providers.
    pub fn read_full(&self, content_id: &[u8; 32]) -> anyhow::Result<Option<Vec<u8>>> {
        match &self.blob_dir {
            Some(dir) => {
                let path = blob_path(dir, content_id);
                if path.exists() {
                    Ok(Some(std::fs::read(&path)?))
                } else {
                    Ok(None)
                }
            }
            None => Ok(self.memory.get(content_id).cloned()),
        }
    }
}

// ── internal helpers ─────────────────────────────────────────────────────

fn blob_path(dir: &Path, content_id: &[u8; 32]) -> PathBuf {
    dir.join(format!("{}.blob", hex::encode(content_id)))
}

fn read_chunk_from_file(
    dir: &Path,
    content_id: &[u8; 32],
    chunk_index: u32,
) -> anyhow::Result<Option<Vec<u8>>> {
    let path = blob_path(dir, content_id);
    let mut file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let file_len = file.metadata()?.len();
    let start = (chunk_index as u64) * (CHUNK_SIZE as u64);
    if start >= file_len {
        return Ok(None);
    }
    let end = ((chunk_index as u64 + 1) * (CHUNK_SIZE as u64)).min(file_len);
    let len = (end - start) as usize;

    file.seek(SeekFrom::Start(start))?;
    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf)?;
    Ok(Some(buf))
}

fn read_chunk_from_memory(
    map: &HashMap<[u8; 32], Vec<u8>>,
    content_id: &[u8; 32],
    chunk_index: u32,
) -> Option<Vec<u8>> {
    let bytes = map.get(content_id)?;
    let idx = chunk_index as usize;
    let start = idx * CHUNK_SIZE;
    if start >= bytes.len() {
        return None;
    }
    let end = ((idx + 1) * CHUNK_SIZE).min(bytes.len());
    Some(bytes[start..end].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_store_and_read_chunk() {
        let mut store = ContentBlobStore::in_memory();
        let data = vec![42u8; CHUNK_SIZE + 100];
        let id = *blake3::hash(&data).as_bytes();
        store.store(id, data.clone()).unwrap();

        assert!(store.contains(&id));

        // Chunk 0
        let c0 = store.read_chunk(&id, 0).unwrap().unwrap();
        assert_eq!(c0.len(), CHUNK_SIZE);
        assert_eq!(c0, &data[..CHUNK_SIZE]);

        // Chunk 1 (partial)
        let c1 = store.read_chunk(&id, 1).unwrap().unwrap();
        assert_eq!(c1.len(), 100);
        assert_eq!(c1, &data[CHUNK_SIZE..]);

        // Chunk 2 (out of range)
        assert!(store.read_chunk(&id, 2).unwrap().is_none());

        // Full read
        let full = store.read_full(&id).unwrap().unwrap();
        assert_eq!(full, data);

        // Unknown ID
        assert!(!store.contains(&[0u8; 32]));
        assert!(store.read_chunk(&[0u8; 32], 0).unwrap().is_none());
    }

    #[test]
    fn on_disk_store_and_read_chunk() {
        let tmp = tempfile::tempdir().unwrap();
        let mut store = ContentBlobStore::on_disk(tmp.path().to_path_buf()).unwrap();

        let data = vec![7u8; CHUNK_SIZE * 2 + 55];
        let id = *blake3::hash(&data).as_bytes();
        store.store(id, data.clone()).unwrap();

        assert!(store.contains(&id));

        let c0 = store.read_chunk(&id, 0).unwrap().unwrap();
        assert_eq!(c0.len(), CHUNK_SIZE);
        assert_eq!(c0, &data[..CHUNK_SIZE]);

        let c1 = store.read_chunk(&id, 1).unwrap().unwrap();
        assert_eq!(c1.len(), CHUNK_SIZE);
        assert_eq!(c1, &data[CHUNK_SIZE..CHUNK_SIZE * 2]);

        let c2 = store.read_chunk(&id, 2).unwrap().unwrap();
        assert_eq!(c2.len(), 55);

        assert!(store.read_chunk(&id, 3).unwrap().is_none());

        let full = store.read_full(&id).unwrap().unwrap();
        assert_eq!(full, data);
    }

    #[test]
    fn on_disk_idempotent_store() {
        let tmp = tempfile::tempdir().unwrap();
        let mut store = ContentBlobStore::on_disk(tmp.path().to_path_buf()).unwrap();

        let data = vec![1u8; 100];
        let id = *blake3::hash(&data).as_bytes();
        store.store(id, data.clone()).unwrap();
        // Storing again should not error
        store.store(id, data).unwrap();
    }
}
