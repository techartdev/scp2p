use anyhow::Context;

use crate::ids::ContentId;

pub const CHUNK_SIZE: usize = 256 * 1024;

#[derive(Debug, Clone)]
pub struct ChunkedContent {
    pub content_id: ContentId,
    pub chunks: Vec<[u8; 32]>,
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

pub fn describe_content(bytes: &[u8]) -> ChunkedContent {
    ChunkedContent {
        content_id: ContentId::from_bytes(bytes),
        chunks: chunk_hashes(bytes),
    }
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
