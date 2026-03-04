// Copyright (c) 2024-2026 Vanyo Vanev / Tech Art Ltd
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
use std::path::Path;

use anyhow::Context;
use tokio::io::AsyncReadExt;

use crate::ids::ContentId;

pub const CHUNK_SIZE: usize = 256 * 1024;

#[derive(Debug, Clone)]
pub struct ChunkedContent {
    pub content_id: ContentId,
    pub chunks: Vec<[u8; 32]>,
    pub chunk_count: u32,
    pub chunk_list_hash: [u8; 32],
}

pub fn chunk_hashes(bytes: &[u8]) -> Vec<[u8; 32]> {
    if bytes.is_empty() {
        return vec![];
    }

    bytes
        .chunks(CHUNK_SIZE)
        .map(|chunk| *blake3::hash(chunk).as_bytes())
        .collect()
}

/// Compute the BLAKE3 hash over the concatenation of all chunk hashes.
///
/// This value is stored in the signed manifest so that chunk hashes
/// can be fetched on demand and verified without embedding them
/// directly in the manifest.
pub fn compute_chunk_list_hash(chunk_hashes: &[[u8; 32]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    for hash in chunk_hashes {
        hasher.update(hash);
    }
    *hasher.finalize().as_bytes()
}

pub fn describe_content(bytes: &[u8]) -> ChunkedContent {
    let chunks = chunk_hashes(bytes);
    assert!(
        chunks.len() <= u32::MAX as usize,
        "file too large: chunk count exceeds u32::MAX (~1 TiB limit)"
    );
    let chunk_count = chunks.len() as u32;
    let chunk_list_hash = compute_chunk_list_hash(&chunks);
    ChunkedContent {
        content_id: ContentId::from_bytes(bytes),
        chunks,
        chunk_count,
        chunk_list_hash,
    }
}

/// Like [`describe_content`] but reads the file in 256 KiB streaming chunks
/// so that memory usage stays constant regardless of file size.
///
/// Returns `(ChunkedContent, file_size_bytes)`.
pub async fn describe_content_file(path: &Path) -> anyhow::Result<(ChunkedContent, u64)> {
    let file = tokio::fs::File::open(path)
        .await
        .with_context(|| format!("open {}", path.display()))?;
    let file_len = file.metadata().await.map(|m| m.len()).unwrap_or(0);

    let mut reader = tokio::io::BufReader::with_capacity(CHUNK_SIZE, file);
    let mut content_hasher = blake3::Hasher::new();
    let mut chunk_hashes_vec: Vec<[u8; 32]> = Vec::new();
    let mut total_bytes: u64 = 0;

    let mut buf = vec![0u8; CHUNK_SIZE];
    loop {
        // Read exactly CHUNK_SIZE bytes (or less at EOF).
        let mut filled = 0;
        while filled < CHUNK_SIZE {
            let n = reader.read(&mut buf[filled..]).await?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        if filled == 0 {
            break;
        }
        let chunk = &buf[..filled];
        content_hasher.update(chunk);
        chunk_hashes_vec.push(*blake3::hash(chunk).as_bytes());
        total_bytes += filled as u64;
    }

    anyhow::ensure!(
        chunk_hashes_vec.len() <= u32::MAX as usize,
        "file too large: chunk count exceeds u32::MAX (~1 TiB limit)"
    );
    // Prefer metadata length (more reliable for sparse files etc.)
    let size = if file_len > 0 { file_len } else { total_bytes };

    let chunk_count = chunk_hashes_vec.len() as u32;
    let chunk_list_hash = compute_chunk_list_hash(&chunk_hashes_vec);
    let content_id = ContentId(*content_hasher.finalize().as_bytes());

    Ok((
        ChunkedContent {
            content_id,
            chunks: chunk_hashes_vec,
            chunk_count,
            chunk_list_hash,
        },
        size,
    ))
}

pub fn verify_chunk(expected_hash: &[u8; 32], chunk_bytes: &[u8]) -> anyhow::Result<()> {
    let actual = blake3::hash(chunk_bytes);
    if actual.as_bytes() != expected_hash {
        anyhow::bail!("chunk hash mismatch");
    }
    Ok(())
}

pub fn verify_content(expected_content_id: &ContentId, bytes: &[u8]) -> anyhow::Result<()> {
    let actual = ContentId::from_bytes(bytes);
    if &actual != expected_content_id {
        anyhow::bail!("content hash mismatch");
    }
    Ok(())
}

pub fn verify_chunked_content(expected: &ChunkedContent, bytes: &[u8]) -> anyhow::Result<()> {
    let observed = bytes.chunks(CHUNK_SIZE).collect::<Vec<_>>();
    if observed.len() != expected.chunks.len() {
        anyhow::bail!("chunk count mismatch");
    }

    for (idx, chunk) in observed.iter().enumerate() {
        verify_chunk(&expected.chunks[idx], chunk)
            .with_context(|| format!("chunk {idx} failed verification"))?;
    }

    verify_content(&expected.content_id, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunking_matches_256_kib_boundary() {
        let bytes = vec![1u8; CHUNK_SIZE * 2 + 3];
        let chunks = chunk_hashes(&bytes);
        assert_eq!(chunks.len(), 3);
    }

    #[test]
    fn chunk_and_content_verification_roundtrip() {
        let payload = vec![42u8; CHUNK_SIZE + 11];
        let desc = describe_content(&payload);
        verify_chunked_content(&desc, &payload).expect("valid chunked content");
    }

    #[test]
    fn verify_detects_chunk_corruption() {
        let payload = vec![9u8; CHUNK_SIZE + 1];
        let desc = describe_content(&payload);
        let mut corrupted = payload.clone();
        corrupted[0] = 8;

        let err = verify_chunked_content(&desc, &corrupted).expect_err("must fail verification");
        assert!(err.to_string().contains("chunk 0 failed verification"));
    }
}
