use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

use crate::manifest::ManifestV1;

type ItemKey = ([u8; 32], [u8; 32]);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedItem {
    pub share_id: [u8; 32],
    pub content_id: [u8; 32],
    pub name: String,
    pub tags: Vec<String>,
    pub title: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchIndexSnapshot {
    items: HashMap<ItemKey, IndexedItem>,
    by_share: HashMap<[u8; 32], Vec<ItemKey>>,
    inverted: HashMap<String, HashSet<ItemKey>>,
}

#[derive(Debug, Default, Clone)]
pub struct SearchIndex {
    items: HashMap<ItemKey, IndexedItem>,
    by_share: HashMap<[u8; 32], Vec<ItemKey>>,
    inverted: HashMap<String, HashSet<ItemKey>>,
}

impl SearchIndex {
    pub fn snapshot(&self) -> SearchIndexSnapshot {
        SearchIndexSnapshot {
            items: self.items.clone(),
            by_share: self.by_share.clone(),
            inverted: self.inverted.clone(),
        }
    }

    pub fn from_snapshot(snapshot: SearchIndexSnapshot) -> Self {
        Self {
            items: snapshot.items,
            by_share: snapshot.by_share,
            inverted: snapshot.inverted,
        }
    }

    pub fn index_manifest(&mut self, manifest: &ManifestV1) {
        let share_id = manifest.share_id;
        self.remove_share(share_id);

        for item in &manifest.items {
            let key = (share_id, item.content_id);
            let indexed = IndexedItem {
                share_id,
                content_id: item.content_id,
                name: item.name.clone(),
                tags: item.tags.clone(),
                title: manifest.title.clone(),
                description: manifest.description.clone(),
            };
            self.items.insert(key, indexed.clone());
            self.by_share.entry(share_id).or_default().push(key);

            for token in tokens_for_item(&indexed) {
                self.inverted.entry(token).or_default().insert(key);
            }
        }
    }

    pub fn search(
        &self,
        query: &str,
        subscribed_shares: &HashSet<[u8; 32]>,
        share_weights: &HashMap<[u8; 32], f32>,
    ) -> Vec<(IndexedItem, f32)> {
        let q = normalize_text(query).trim().to_string();
        if q.is_empty() {
            return vec![];
        }

        let mut candidate_keys = HashSet::new();
        for term in tokenize(&q) {
            if let Some(keys) = self.inverted.get(&term) {
                candidate_keys.extend(keys.iter().copied());
            }
        }

        if candidate_keys.is_empty() {
            for (k, item) in &self.items {
                if normalize_text(&item.name).contains(&q) {
                    candidate_keys.insert(*k);
                }
            }
        }

        let mut scored = candidate_keys
            .into_iter()
            .filter_map(|key| self.items.get(&key))
            .filter(|item| subscribed_shares.contains(&item.share_id))
            .map(|item| {
                let base = score_item(item, &q);
                let weight = *share_weights.get(&item.share_id).unwrap_or(&1.0);
                (item.clone(), base * weight)
            })
            .filter(|(_, score)| *score > 0.0)
            .collect::<Vec<_>>();

        scored.sort_by(|a, b| b.1.total_cmp(&a.1));
        scored
    }

    fn remove_share(&mut self, share_id: [u8; 32]) {
        let Some(keys) = self.by_share.remove(&share_id) else {
            return;
        };

        for key in keys {
            self.items.remove(&key);
        }

        self.inverted.retain(|_, keys| {
            keys.retain(|(sid, _)| sid != &share_id);
            !keys.is_empty()
        });
    }
}

fn score_item(item: &IndexedItem, q: &str) -> f32 {
    let mut score = 0.0;
    let name = normalize_text(&item.name);
    if name == q {
        score += 100.0;
    } else if name.split_whitespace().any(|t| t == q) {
        score += 85.0;
    } else if name.split_whitespace().any(|t| t.starts_with(q)) {
        score += 65.0;
    } else if name.contains(q) {
        score += 45.0;
    }

    for tag in &item.tags {
        let t = normalize_text(tag);
        if t == q {
            score += 30.0;
        } else if t.starts_with(q) {
            score += 20.0;
        }
    }

    if item
        .title
        .as_ref()
        .map(|t| normalize_text(t).contains(q))
        .unwrap_or(false)
    {
        score += 12.0;
    }

    if item
        .description
        .as_ref()
        .map(|d| normalize_text(d).contains(q))
        .unwrap_or(false)
    {
        score += 8.0;
    }

    score
}

fn tokens_for_item(item: &IndexedItem) -> Vec<String> {
    let mut out = tokenize(&item.name);
    for tag in &item.tags {
        out.extend(tokenize(tag));
    }
    if let Some(title) = &item.title {
        out.extend(tokenize(title));
    }
    if let Some(description) = &item.description {
        out.extend(tokenize(description));
    }
    out
}

fn tokenize(input: &str) -> Vec<String> {
    normalize_text(input)
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn normalize_text(input: &str) -> String {
    input.nfkc().collect::<String>().to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::ItemV1;
    use std::time::Instant;

    fn manifest(name: &str, tag: &str, share_id: [u8; 32]) -> ManifestV1 {
        ManifestV1 {
            version: 1,
            share_pubkey: [0u8; 32],
            share_id,
            seq: 1,
            created_at: 1,
            expires_at: None,
            title: Some("Cool Media".into()),
            description: Some("Decentralized catalog".into()),
            visibility: crate::manifest::ShareVisibility::Private,
            communities: vec![],
            items: vec![ItemV1 {
                content_id: [1u8; 32],
                size: 42,
                name: name.into(),
                path: None,
                mime: None,
                tags: vec![tag.into()],
                chunk_count: 0,
                chunk_list_hash: [0u8; 32],
            }],
            recommended_shares: vec![],
            signature: None,
        }
    }

    #[test]
    fn indexes_and_searches_subscription_scoped() {
        let mut idx = SearchIndex::default();
        let a = [1u8; 32];
        let b = [2u8; 32];
        idx.index_manifest(&manifest("Ubuntu ISO", "linux", a));
        idx.index_manifest(&manifest("Holiday Photo", "image", b));

        let mut subs = HashSet::new();
        subs.insert(a);
        let hits = idx.search("ubuntu", &subs, &HashMap::new());
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0.share_id, a);
    }

    #[test]
    fn share_weight_affects_rank_order() {
        let mut idx = SearchIndex::default();
        let a = [1u8; 32];
        let b = [2u8; 32];
        idx.index_manifest(&manifest("Movie Pack", "video", a));
        idx.index_manifest(&manifest("Movie Extras", "video", b));

        let mut subs = HashSet::new();
        subs.insert(a);
        subs.insert(b);

        let mut weights = HashMap::new();
        weights.insert(b, 2.0);

        let hits = idx.search("movie", &subs, &weights);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].0.share_id, b);
    }

    #[test]
    fn unicode_normalization_is_applied_in_search() {
        let mut idx = SearchIndex::default();
        let share_id = [3u8; 32];
        idx.index_manifest(&manifest("Cafe\u{301} Guide", "travel", share_id));
        let mut subs = HashSet::new();
        subs.insert(share_id);

        let hits = idx.search("CAF\u{00C9}", &subs, &HashMap::new());
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0.name, "Cafe\u{301} Guide");
    }

    fn read_env_usize(name: &str, default: usize, min: usize, max: usize) -> usize {
        std::env::var(name)
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .map(|v| v.clamp(min, max))
            .unwrap_or(default)
    }

    fn read_env_u128(name: &str, default: u128, min: u128, max: u128) -> u128 {
        std::env::var(name)
            .ok()
            .and_then(|v| v.parse::<u128>().ok())
            .map(|v| v.clamp(min, max))
            .unwrap_or(default)
    }

    #[test]
    fn large_catalog_benchmark_smoke() {
        let share_count = read_env_usize("SCP2P_SEARCH_BENCH_SHARE_COUNT", 40, 5, 200);
        let items_per_share = read_env_usize("SCP2P_SEARCH_BENCH_ITEMS_PER_SHARE", 200, 20, 1_000);
        let max_index_ms = read_env_u128("SCP2P_SEARCH_BENCH_MAX_INDEX_MS", 8_000, 200, 120_000);
        let max_query_ms = read_env_u128("SCP2P_SEARCH_BENCH_MAX_QUERY_MS", 600, 20, 20_000);

        let mut idx = SearchIndex::default();
        let mut subscribed = HashSet::new();
        let weights = HashMap::new();

        let index_started = Instant::now();
        for share_idx in 0..share_count {
            let mut share_id = [0u8; 32];
            share_id[..8].copy_from_slice(&(share_idx as u64).to_le_bytes());
            subscribed.insert(share_id);

            let mut items = Vec::with_capacity(items_per_share);
            for item_idx in 0..items_per_share {
                let mut content_id = [0u8; 32];
                content_id[..8].copy_from_slice(&(item_idx as u64).to_le_bytes());
                content_id[8..16].copy_from_slice(&(share_idx as u64).to_le_bytes());
                items.push(ItemV1 {
                    content_id,
                    size: 1_024 + item_idx as u64,
                    name: format!("movie-{share_idx}-{item_idx}"),
                    path: None,
                    mime: None,
                    tags: vec!["movie".into(), format!("share-{share_idx}")],
                    chunk_count: 0,
                    chunk_list_hash: [0u8; 32],
                });
            }

            idx.index_manifest(&ManifestV1 {
                version: 1,
                share_pubkey: [0u8; 32],
                share_id,
                seq: 1,
                created_at: 1,
                expires_at: None,
                title: Some(format!("Catalog {share_idx}")),
                description: Some("benchmark catalog".into()),
                visibility: crate::manifest::ShareVisibility::Private,
                communities: vec![],
                items,
                recommended_shares: vec![],
                signature: None,
            });
        }
        let index_ms = index_started.elapsed().as_millis();
        assert!(
            index_ms <= max_index_ms,
            "search index build {}ms exceeded threshold {}ms",
            index_ms,
            max_index_ms
        );

        let query_started = Instant::now();
        let hits = idx.search("movie", &subscribed, &weights);
        let query_ms = query_started.elapsed().as_millis();
        assert!(
            query_ms <= max_query_ms,
            "search query {}ms exceeded threshold {}ms",
            query_ms,
            max_query_ms
        );
        assert_eq!(hits.len(), share_count * items_per_share);
    }
}
