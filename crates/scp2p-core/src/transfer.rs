use crate::{
    content::{verify_chunk, verify_content, CHUNK_SIZE},
    ids::ContentId,
    peer::PeerAddr,
};

#[derive(Debug, Clone)]
pub struct ChunkProvider {
    pub peer: PeerAddr,
    pub content_bytes: Vec<u8>,
}

pub fn download_swarm(
    content_id: [u8; 32],
    chunk_hashes: &[[u8; 32]],
    providers: &[ChunkProvider],
) -> anyhow::Result<Vec<u8>> {
    if providers.is_empty() {
        anyhow::bail!("no providers available");
    }

    let mut output = Vec::new();
    for (idx, expected_hash) in chunk_hashes.iter().enumerate() {
        let mut chunk = None;

        for offset in 0..providers.len() {
            let provider_idx = (idx + offset) % providers.len();
            if let Some(candidate) = chunk_from_provider(&providers[provider_idx], idx) {
                if verify_chunk(expected_hash, candidate).is_ok() {
                    chunk = Some(candidate.to_vec());
                    break;
                }
            }
        }

        let Some(bytes) = chunk else {
            anyhow::bail!("unable to retrieve verified chunk {idx}");
        };
        output.extend_from_slice(&bytes);
    }

    verify_content(&ContentId(content_id), &output)?;
    Ok(output)
}

fn chunk_from_provider(provider: &ChunkProvider, idx: usize) -> Option<&[u8]> {
    let start = idx * CHUNK_SIZE;
    if start >= provider.content_bytes.len() {
        return None;
    }
    let end = ((idx + 1) * CHUNK_SIZE).min(provider.content_bytes.len());
    Some(&provider.content_bytes[start..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::describe_content;
    use crate::peer::TransportProtocol;

    fn provider(ip: &str, bytes: Vec<u8>) -> ChunkProvider {
        ChunkProvider {
            peer: PeerAddr {
                ip: ip.parse().expect("valid ip"),
                port: 7000,
                transport: TransportProtocol::Quic,
                pubkey_hint: None,
            },
            content_bytes: bytes,
        }
    }

    #[test]
    fn swarm_download_verifies_and_recovers() {
        let data = vec![1u8; CHUNK_SIZE + 17];
        let desc = describe_content(&data);
        let providers = vec![
            provider("10.0.0.1", data.clone()),
            provider("10.0.0.2", data.clone()),
        ];

        let out = download_swarm(desc.content_id.0, &desc.chunks, &providers).expect("download");
        assert_eq!(out, data);
    }

    #[test]
    fn swarm_download_rejects_corrupted_only_sources() {
        let data = vec![2u8; CHUNK_SIZE + 3];
        let desc = describe_content(&data);
        let mut bad = data.clone();
        bad[0] ^= 1;

        let err = download_swarm(
            desc.content_id.0,
            &desc.chunks,
            &[provider("10.0.0.3", bad)],
        )
        .expect_err("must fail");
        assert!(err.to_string().contains("chunk 0"));
    }
}
