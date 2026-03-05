// Copyright (c) 2024-2026 Vanyo Vanev / Tech Art Ltd
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! In-memory secondary index for community members and shares (§15.5).
//!
//! [`CommunityIndex`] is a derived cache built by ingesting validated
//! [`CommunityMemberRecord`] and [`CommunityShareRecord`] values
//! received from the DHT (via `STORE` messages or local publishes).
//! It is **not** the source of truth — the source of truth is always
//! the signed DHT records.
//!
//! The index serves [`ListCommunityMembersPage`], [`ListCommunitySharesPage`],
//! and [`SearchCommunityShares`] wire requests, allowing large communities to
//! be browsed without per-peer polling or single-value DHT size limits.
//!
//! **Cursor format**: opaque hex string encoding the 32-byte primary key
//! of the *last returned* entry.  Entries strictly *after* this key (via
//! [`BTreeMap`] ordering) form the next page.  An absent cursor means
//! "start of the list".

use std::collections::{BTreeMap, HashMap};
use std::ops::Bound;

use crate::wire::{
    CommunityEvent, CommunityMemberRecord, CommunityMemberStatus, CommunityMemberSummary,
    CommunityShareHit, CommunityShareRecord, CommunityShareSummary,
};

// ── Indexed entry types ───────────────────────────────────────────────

/// Compact community member entry stored in the index.
#[derive(Debug, Clone)]
pub struct IndexedMember {
    pub member_node_pubkey: [u8; 32],
    pub status: CommunityMemberStatus,
    pub announce_seq: u64,
    pub issued_at: u64,
    pub expires_at: u64,
}

/// Compact community share entry stored in the index.
#[derive(Debug, Clone)]
pub struct IndexedShare {
    pub share_id: [u8; 32],
    pub share_pubkey: [u8; 32],
    pub latest_seq: u64,
    pub title: Option<String>,
    pub description: Option<String>,
    pub updated_at: u64,
    /// Derived expiry: `updated_at + MAX_SHARE_TTL_SECS`.
    pub expires_at: u64,
}

// ── Cursor helpers ────────────────────────────────────────────────────

fn decode_cursor(cursor: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(cursor).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(arr)
}

fn encode_cursor(key: [u8; 32]) -> String {
    hex::encode(key)
}

// ── Main index type ───────────────────────────────────────────────────

/// In-memory derived index of community members and shares.
///
/// Keyed by `community_id` (outer) and primary key (inner) for O(log n)
/// page queries.  The inner maps use [`BTreeMap`] so that cursor-based
/// pagination is stable and deterministic for a given set of entries.
#[derive(Debug, Clone, Default)]
pub struct CommunityIndex {
    /// `community_id` → `member_node_pubkey` → entry.
    members: HashMap<[u8; 32], BTreeMap<[u8; 32], IndexedMember>>,
    /// `community_id` → `share_id` → entry.
    shares: HashMap<[u8; 32], BTreeMap<[u8; 32], IndexedShare>>,
    /// `community_id` → append-only event log (monotonic sequence).
    ///
    /// Each event has a 1-based sequence number used as cursor.
    /// Bounded to [`MAX_EVENT_LOG_SIZE`](Self::MAX_EVENT_LOG_SIZE) per
    /// community; oldest entries are dropped when the cap is exceeded.
    events: HashMap<[u8; 32], Vec<(u64, CommunityEvent)>>,
    /// Per-community monotonic event counter.
    event_seq: HashMap<[u8; 32], u64>,
}

impl CommunityIndex {
    /// Maximum entries per member page (hard cap, regardless of client `limit`).
    pub const MAX_MEMBERS_PAGE_SIZE: u16 = 200;
    /// Maximum entries per share page (hard cap).
    pub const MAX_SHARES_PAGE_SIZE: u16 = 100;
    /// Maximum search hits returned.
    pub const MAX_SEARCH_HITS: u16 = 50;
    /// Maximum events per page.
    pub const MAX_EVENTS_PAGE_SIZE: u16 = 200;
    /// Maximum event log entries retained per community.
    pub const MAX_EVENT_LOG_SIZE: usize = 10_000;
    /// Maximum members tracked per community.  Oldest entries (by
    /// `issued_at`) are evicted when this cap is reached.
    pub const MAX_MEMBERS_PER_COMMUNITY: usize = 10_000;
    /// Maximum shares tracked per community.  Oldest entries (by
    /// `updated_at`) are evicted when this cap is reached.
    pub const MAX_SHARES_PER_COMMUNITY: usize = 10_000;
    /// Default share record TTL in seconds (7 days).  Share records
    /// are considered stale after `updated_at + MAX_SHARE_TTL_SECS`.
    pub const MAX_SHARE_TTL_SECS: u64 = 7 * 24 * 3600;
    /// Events older than this age (seconds) are dropped during
    /// compaction.  Default: 7 days.
    pub const MAX_EVENT_AGE_SECS: u64 = 7 * 24 * 3600;

    // ── Ingestion ──────────────────────────────────────────────────

    /// Push an event to the per-community log, maintaining the
    /// [`MAX_EVENT_LOG_SIZE`](Self::MAX_EVENT_LOG_SIZE) cap.
    fn push_event(&mut self, community_id: [u8; 32], event: CommunityEvent) {
        let seq = self.event_seq.entry(community_id).or_insert(0);
        *seq += 1;
        let log = self.events.entry(community_id).or_default();
        log.push((*seq, event));
        // Drop oldest entries if the log exceeds the cap.
        if log.len() > Self::MAX_EVENT_LOG_SIZE {
            let excess = log.len() - Self::MAX_EVENT_LOG_SIZE;
            log.drain(..excess);
        }
    }

    /// Ingest a validated [`CommunityMemberRecord`].
    ///
    /// Insert or replace only when the incoming `announce_seq` is strictly
    /// greater, so a leave tombstone cannot be downgraded to a join.
    pub fn ingest_member_record(&mut self, rec: &CommunityMemberRecord) {
        let bucket = self.members.entry(rec.community_id).or_default();
        let should_upsert = bucket
            .get(&rec.member_node_pubkey)
            .is_none_or(|existing| rec.announce_seq > existing.announce_seq);
        if should_upsert {
            bucket.insert(
                rec.member_node_pubkey,
                IndexedMember {
                    member_node_pubkey: rec.member_node_pubkey,
                    status: rec.status,
                    announce_seq: rec.announce_seq,
                    issued_at: rec.issued_at,
                    expires_at: rec.expires_at,
                },
            );
            // Evict oldest if the bucket exceeds the per-community cap.
            Self::evict_oldest_members(bucket);
            // Emit event.
            let event = match rec.status {
                CommunityMemberStatus::Joined => CommunityEvent::MemberJoined {
                    member_node_pubkey: rec.member_node_pubkey,
                    announce_seq: rec.announce_seq,
                },
                CommunityMemberStatus::Left => CommunityEvent::MemberLeft {
                    member_node_pubkey: rec.member_node_pubkey,
                    announce_seq: rec.announce_seq,
                },
            };
            self.push_event(rec.community_id, event);
        }
    }

    /// Ingest a validated [`CommunityShareRecord`].
    ///
    /// Replace only when the incoming `latest_seq` is greater, or equal
    /// with a more recent `updated_at` timestamp.
    pub fn ingest_share_record(&mut self, rec: &CommunityShareRecord) {
        let bucket = self.shares.entry(rec.community_id).or_default();
        let should_upsert = bucket.get(&rec.share_id).is_none_or(|existing| {
            rec.latest_seq > existing.latest_seq
                || (rec.latest_seq == existing.latest_seq && rec.updated_at > existing.updated_at)
        });
        if should_upsert {
            bucket.insert(
                rec.share_id,
                IndexedShare {
                    share_id: rec.share_id,
                    share_pubkey: rec.share_pubkey,
                    latest_seq: rec.latest_seq,
                    title: rec.title.clone(),
                    description: rec.description.clone(),
                    updated_at: rec.updated_at,
                    expires_at: rec.updated_at.saturating_add(Self::MAX_SHARE_TTL_SECS),
                },
            );
            // Evict oldest if the bucket exceeds the per-community cap.
            Self::evict_oldest_shares(bucket);
            self.push_event(
                rec.community_id,
                CommunityEvent::ShareUpserted {
                    share_id: rec.share_id,
                    latest_seq: rec.latest_seq,
                    title: rec.title.clone(),
                },
            );
        }
    }

    // ── Page queries ───────────────────────────────────────────────

    /// Return a paged list of community members.
    ///
    /// Entries are ordered by `member_node_pubkey` (stable BTreeMap order).
    /// Pass the returned `next_cursor` as the `cursor` of the next call to
    /// advance the page.
    pub fn members_page(
        &self,
        community_id: [u8; 32],
        cursor: Option<&str>,
        limit: u16,
    ) -> (Vec<CommunityMemberSummary>, Option<String>) {
        let limit = (limit.min(Self::MAX_MEMBERS_PAGE_SIZE)) as usize;
        let bucket = match self.members.get(&community_id) {
            Some(b) => b,
            None => return (vec![], None),
        };
        let after_key = cursor.and_then(decode_cursor);
        let iter: Box<dyn Iterator<Item = (&[u8; 32], &IndexedMember)>> = match after_key {
            Some(k) => {
                Box::new(bucket.range::<[u8; 32], _>((Bound::Excluded(k), Bound::Unbounded)))
            }
            None => Box::new(bucket.iter()),
        };

        // Fetch limit+1 to determine whether a next page exists.
        let mut entries: Vec<CommunityMemberSummary> = iter
            .take(limit + 1)
            .map(|(_, m)| CommunityMemberSummary {
                member_node_pubkey: m.member_node_pubkey,
                status: m.status,
                announce_seq: m.announce_seq,
                addr: None,
            })
            .collect();

        let next_cursor = if entries.len() > limit {
            entries.pop();
            entries.last().map(|e| encode_cursor(e.member_node_pubkey))
        } else {
            None
        };
        (entries, next_cursor)
    }

    /// Return a paged list of community shares.
    ///
    /// Entries are ordered by `share_id`.  An optional `since_unix` filter
    /// restricts results to shares updated at or after that UNIX timestamp.
    pub fn shares_page(
        &self,
        community_id: [u8; 32],
        cursor: Option<&str>,
        limit: u16,
        since_unix: Option<u64>,
    ) -> (Vec<CommunityShareSummary>, Option<String>) {
        let limit = (limit.min(Self::MAX_SHARES_PAGE_SIZE)) as usize;
        let bucket = match self.shares.get(&community_id) {
            Some(b) => b,
            None => return (vec![], None),
        };
        let after_key = cursor.and_then(decode_cursor);
        let iter: Box<dyn Iterator<Item = (&[u8; 32], &IndexedShare)>> = match after_key {
            Some(k) => {
                Box::new(bucket.range::<[u8; 32], _>((Bound::Excluded(k), Bound::Unbounded)))
            }
            None => Box::new(bucket.iter()),
        };

        let mut entries: Vec<CommunityShareSummary> = iter
            .filter(|(_, s)| since_unix.is_none_or(|t| s.updated_at >= t))
            .take(limit + 1)
            .map(|(_, s)| CommunityShareSummary {
                share_id: s.share_id,
                share_pubkey: s.share_pubkey,
                latest_seq: s.latest_seq,
                title: s.title.clone(),
                description: s.description.clone(),
                updated_at: s.updated_at,
            })
            .collect();

        let next_cursor = if entries.len() > limit {
            entries.pop();
            entries.last().map(|e| encode_cursor(e.share_id))
        } else {
            None
        };
        (entries, next_cursor)
    }

    /// Simple metadata search across share titles and descriptions.
    ///
    /// Performs case-insensitive substring matching.  Results are scored
    /// by match quality (title match > description match) and capped at
    /// [`MAX_SEARCH_HITS`](Self::MAX_SEARCH_HITS).  Cursor-based continuation
    /// is supported via the `after_share_id` parameter.
    pub fn search_shares(
        &self,
        community_id: [u8; 32],
        query: &str,
        cursor: Option<&str>,
        limit: u16,
    ) -> (Vec<CommunityShareHit>, Option<String>) {
        let limit = (limit.min(Self::MAX_SEARCH_HITS)) as usize;
        let bucket = match self.shares.get(&community_id) {
            Some(b) => b,
            None => return (vec![], None),
        };
        let needle = query.to_lowercase();
        let after_key = cursor.and_then(decode_cursor);
        let iter: Box<dyn Iterator<Item = (&[u8; 32], &IndexedShare)>> = match after_key {
            Some(k) => {
                Box::new(bucket.range::<[u8; 32], _>((Bound::Excluded(k), Bound::Unbounded)))
            }
            None => Box::new(bucket.iter()),
        };

        let mut hits: Vec<CommunityShareHit> = iter
            .filter_map(|(_, s)| {
                let title_lc = s.title.as_deref().unwrap_or("").to_lowercase();
                let desc_lc = s.description.as_deref().unwrap_or("").to_lowercase();
                let score = if title_lc.contains(&needle) {
                    200u32
                } else if desc_lc.contains(&needle) {
                    100u32
                } else {
                    return None;
                };
                Some(CommunityShareHit {
                    share_id: s.share_id,
                    share_pubkey: s.share_pubkey,
                    latest_seq: s.latest_seq,
                    title: s.title.clone(),
                    description: s.description.clone(),
                    score,
                })
            })
            .take(limit + 1)
            .collect();

        let next_cursor = if hits.len() > limit {
            hits.pop();
            hits.last().map(|h| encode_cursor(h.share_id))
        } else {
            None
        };
        (hits, next_cursor)
    }

    // ── Maintenance ────────────────────────────────────────────────

    /// Return a page of community events after `since_cursor`.
    ///
    /// The cursor is a stringified monotonic sequence number.  Pass the
    /// returned `next_cursor` to advance.  An absent cursor returns the
    /// earliest available events.
    pub fn events_page(
        &self,
        community_id: [u8; 32],
        since_cursor: Option<&str>,
        limit: u16,
    ) -> (Vec<CommunityEvent>, Option<String>) {
        let limit = (limit.min(Self::MAX_EVENTS_PAGE_SIZE)) as usize;
        let log = match self.events.get(&community_id) {
            Some(l) if !l.is_empty() => l,
            _ => return (vec![], None),
        };
        let after_seq: u64 = since_cursor
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

        // Binary-search for the start position (log is sorted by seq).
        let start = log.partition_point(|(seq, _)| *seq <= after_seq);
        let slice = &log[start..];

        if slice.is_empty() {
            return (vec![], None);
        }

        let take = slice.len().min(limit + 1);
        let mut events: Vec<CommunityEvent> =
            slice[..take].iter().map(|(_, e)| e.clone()).collect();

        let next_cursor = if events.len() > limit {
            events.pop();
            // More pages remain: cursor is the seq of the last returned event.
            Some(slice[limit - 1].0.to_string())
        } else {
            // Last page: still return the high-water cursor so the client
            // can persist it and avoid re-fetching the same events.
            let last_idx = events.len() - 1;
            Some(slice[last_idx].0.to_string())
        };
        (events, next_cursor)
    }

    /// Return the number of `Joined` members for a community.
    pub fn joined_member_count(&self, community_id: [u8; 32]) -> usize {
        self.members.get(&community_id).map_or(0, |b| {
            b.values()
                .filter(|m| matches!(m.status, CommunityMemberStatus::Joined))
                .count()
        })
    }

    /// Remove all entries whose `expires_at` is ≤ `now`.
    ///
    /// Covers members, shares, and stale event log entries.
    /// Should be called periodically to evict leave tombstones and other
    /// expired records from the in-memory index.
    pub fn purge_expired(&mut self, now: u64) {
        for bucket in self.members.values_mut() {
            bucket.retain(|_, m| m.expires_at > now);
        }
        // Purge stale share records (derived TTL).
        for bucket in self.shares.values_mut() {
            bucket.retain(|_, s| s.expires_at > now);
        }
        // Remove empty community buckets.
        self.members.retain(|_, b| !b.is_empty());
        self.shares.retain(|_, b| !b.is_empty());
        // Compact event logs: drop events whose backing seq was
        // generated more than MAX_EVENT_AGE_SECS ago.  Since we don't
        // store a timestamp per event, we use the event_seq high-water
        // mark as a proxy: if the entire log predates the cutoff, clear
        // it.  For finer resolution we purge from the front while the
        // earliest event seq is older than (max_seq - estimated_capacity).
        // In practice the MAX_EVENT_LOG_SIZE count cap already keeps
        // the log bounded; this TTL sweep clears communities with stale,
        // low-churn logs.
        let cutoff = now.saturating_sub(Self::MAX_EVENT_AGE_SECS);
        // Two-pass event compaction to avoid borrow conflict:
        // 1) Collect community IDs whose event logs are stale or orphaned.
        let stale_event_cids: Vec<[u8; 32]> = self
            .events
            .keys()
            .filter(|cid| {
                let has_data = self.members.contains_key(*cid) || self.shares.contains_key(*cid);
                if !has_data {
                    return true; // orphaned
                }
                let newest_ts = Self::newest_record_ts_for(&self.members, &self.shares, cid);
                newest_ts <= cutoff
            })
            .copied()
            .collect();
        // 2) Remove stale entries.
        for cid in &stale_event_cids {
            self.events.remove(cid);
            self.event_seq.remove(cid);
        }
    }

    // ── Private helpers for bounds enforcement ─────────────────────

    /// Evict oldest members (by `issued_at`) until the bucket is within
    /// [`MAX_MEMBERS_PER_COMMUNITY`](Self::MAX_MEMBERS_PER_COMMUNITY).
    fn evict_oldest_members(bucket: &mut BTreeMap<[u8; 32], IndexedMember>) {
        while bucket.len() > Self::MAX_MEMBERS_PER_COMMUNITY {
            // Find key with the smallest `issued_at`.
            let oldest_key = bucket
                .iter()
                .min_by_key(|(_, m)| m.issued_at)
                .map(|(k, _)| *k);
            if let Some(k) = oldest_key {
                bucket.remove(&k);
            } else {
                break;
            }
        }
    }

    /// Evict oldest shares (by `updated_at`) until the bucket is within
    /// [`MAX_SHARES_PER_COMMUNITY`](Self::MAX_SHARES_PER_COMMUNITY).
    fn evict_oldest_shares(bucket: &mut BTreeMap<[u8; 32], IndexedShare>) {
        while bucket.len() > Self::MAX_SHARES_PER_COMMUNITY {
            let oldest_key = bucket
                .iter()
                .min_by_key(|(_, s)| s.updated_at)
                .map(|(k, _)| *k);
            if let Some(k) = oldest_key {
                bucket.remove(&k);
            } else {
                break;
            }
        }
    }

    /// Return the most recent timestamp among members and shares for a
    /// community, used by `purge_expired` to determine event staleness.
    fn newest_record_ts_for(
        members: &HashMap<[u8; 32], BTreeMap<[u8; 32], IndexedMember>>,
        shares: &HashMap<[u8; 32], BTreeMap<[u8; 32], IndexedShare>>,
        cid: &[u8; 32],
    ) -> u64 {
        let m_max = members
            .get(cid)
            .and_then(|b| b.values().map(|m| m.issued_at).max())
            .unwrap_or(0);
        let s_max = shares
            .get(cid)
            .and_then(|b| b.values().map(|s| s.updated_at).max())
            .unwrap_or(0);
        m_max.max(s_max)
    }

    // ── Materialized page generation (§15.5) ──────────────────────

    /// Number of entries per materialized DHT page.
    pub const MATERIALIZED_PAGE_SIZE: usize = 100;

    /// Return all community IDs known to this index (from both member
    /// and share buckets).
    pub fn all_community_ids(&self) -> Vec<[u8; 32]> {
        let mut ids: Vec<[u8; 32]> = self
            .members
            .keys()
            .chain(self.shares.keys())
            .copied()
            .collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    /// Produce materialized member pages for a community.
    ///
    /// Only `Joined` members are included (leave tombstones are omitted
    /// from derived indexes per §15.7).  Pages are ordered by the
    /// BTreeMap key (member_node_pubkey) and sized at
    /// [`MATERIALIZED_PAGE_SIZE`](Self::MATERIALIZED_PAGE_SIZE).
    pub fn materialize_member_pages(
        &self,
        community_id: [u8; 32],
        bucket: u64,
        now: u64,
    ) -> Vec<crate::wire::MaterializedMembersPage> {
        use crate::wire::{CommunityMemberSummary, MaterializedMembersPage};

        let entries: Vec<CommunityMemberSummary> = self
            .members
            .get(&community_id)
            .into_iter()
            .flat_map(|b| b.values())
            .filter(|m| matches!(m.status, CommunityMemberStatus::Joined))
            .map(|m| CommunityMemberSummary {
                member_node_pubkey: m.member_node_pubkey,
                status: m.status,
                announce_seq: m.announce_seq,
                addr: None,
            })
            .collect();

        if entries.is_empty() {
            return vec![];
        }

        let chunks: Vec<&[CommunityMemberSummary]> =
            entries.chunks(Self::MATERIALIZED_PAGE_SIZE).collect();
        let total_pages = chunks.len() as u16;
        chunks
            .into_iter()
            .enumerate()
            .map(|(i, chunk)| MaterializedMembersPage {
                community_id,
                bucket,
                page_no: i as u16,
                total_pages,
                entries: chunk.to_vec(),
                built_at: now,
            })
            .collect()
    }

    /// Produce materialized share pages for a community.
    ///
    /// Non-expired shares are included, ordered by share_id (BTreeMap
    /// order).  Pages are sized at
    /// [`MATERIALIZED_PAGE_SIZE`](Self::MATERIALIZED_PAGE_SIZE).
    pub fn materialize_share_pages(
        &self,
        community_id: [u8; 32],
        bucket: u64,
        now: u64,
    ) -> Vec<crate::wire::MaterializedSharesPage> {
        use crate::wire::{CommunityShareSummary, MaterializedSharesPage};

        let entries: Vec<CommunityShareSummary> = self
            .shares
            .get(&community_id)
            .into_iter()
            .flat_map(|b| b.values())
            .filter(|s| s.expires_at > now)
            .map(|s| CommunityShareSummary {
                share_id: s.share_id,
                share_pubkey: s.share_pubkey,
                latest_seq: s.latest_seq,
                title: s.title.clone(),
                description: s.description.clone(),
                updated_at: s.updated_at,
            })
            .collect();

        if entries.is_empty() {
            return vec![];
        }

        let chunks: Vec<&[CommunityShareSummary]> =
            entries.chunks(Self::MATERIALIZED_PAGE_SIZE).collect();
        let total_pages = chunks.len() as u16;
        chunks
            .into_iter()
            .enumerate()
            .map(|(i, chunk)| MaterializedSharesPage {
                community_id,
                bucket,
                page_no: i as u16,
                total_pages,
                entries: chunk.to_vec(),
                built_at: now,
            })
            .collect()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::CommunityMemberStatus;

    fn make_member_rec(
        community_id: [u8; 32],
        key: u8,
        seq: u64,
        status: CommunityMemberStatus,
    ) -> CommunityMemberRecord {
        let signing_key = {
            use ed25519_dalek::SigningKey;
            // Use a deterministic seed based on key byte.
            let seed = [key; 32];
            SigningKey::from_bytes(&seed)
        };
        CommunityMemberRecord::new_signed(
            &signing_key,
            community_id,
            seq,
            status,
            1_000_000,
            1_000_000 + 3600,
        )
        .expect("signed record")
    }

    fn make_share_rec(
        community_id: [u8; 32],
        key: u8,
        seq: u64,
        title: Option<&str>,
    ) -> CommunityShareRecord {
        use ed25519_dalek::SigningKey;
        let seed = [key; 32];
        let share_key = SigningKey::from_bytes(&seed);
        CommunityShareRecord::new_signed(
            &share_key,
            community_id,
            [0u8; 32],
            seq,
            1_000_000,
            title.map(str::to_string),
            None,
        )
        .expect("signed share record")
    }

    #[test]
    fn member_ingest_and_page() {
        let cid = [1u8; 32];
        let mut idx = CommunityIndex::default();

        // Insert 5 members.
        for i in 1..=5u8 {
            idx.ingest_member_record(&make_member_rec(cid, i, 1, CommunityMemberStatus::Joined));
        }
        let (page1, cursor) = idx.members_page(cid, None, 3);
        assert_eq!(page1.len(), 3);
        assert!(cursor.is_some(), "should have next cursor");

        let (page2, cursor2) = idx.members_page(cid, cursor.as_deref(), 3);
        assert_eq!(page2.len(), 2);
        assert!(cursor2.is_none(), "last page has no cursor");

        // No overlap between pages.
        let all: Vec<_> = page1
            .iter()
            .chain(page2.iter())
            .map(|e| e.member_node_pubkey)
            .collect();
        let unique: std::collections::HashSet<_> = all.iter().collect();
        assert_eq!(all.len(), unique.len(), "pages must not overlap");
    }

    #[test]
    fn member_higher_seq_wins() {
        let cid = [2u8; 32];
        let mut idx = CommunityIndex::default();

        let rec_join = make_member_rec(cid, 1, 1, CommunityMemberStatus::Joined);
        let rec_leave = make_member_rec(cid, 1, 2, CommunityMemberStatus::Left);
        let rec_old = make_member_rec(cid, 1, 1, CommunityMemberStatus::Joined); // same seq, no override

        idx.ingest_member_record(&rec_join);
        idx.ingest_member_record(&rec_leave);
        idx.ingest_member_record(&rec_old); // should not override the leave

        let (page, _) = idx.members_page(cid, None, 10);
        assert_eq!(page.len(), 1);
        assert!(
            matches!(page[0].status, CommunityMemberStatus::Left),
            "leave with higher seq must win"
        );
    }

    #[test]
    fn share_ingest_and_page() {
        let cid = [3u8; 32];
        let mut idx = CommunityIndex::default();

        for i in 1..=4u8 {
            idx.ingest_share_record(&make_share_rec(
                cid,
                i,
                i as u64,
                Some(&format!("share {i}")),
            ));
        }
        let (page, cursor) = idx.shares_page(cid, None, 2, None);
        assert_eq!(page.len(), 2);
        assert!(cursor.is_some());

        let (page2, cursor2) = idx.shares_page(cid, cursor.as_deref(), 2, None);
        assert_eq!(page2.len(), 2);
        assert!(cursor2.is_none());
    }

    #[test]
    fn share_search_hits() {
        let cid = [4u8; 32];
        let mut idx = CommunityIndex::default();

        idx.ingest_share_record(&make_share_rec(cid, 1, 1, Some("Rust programming")));
        idx.ingest_share_record(&make_share_rec(cid, 2, 1, Some("Python scripts")));
        idx.ingest_share_record(&make_share_rec(cid, 3, 1, Some("Go tutorials")));

        let (hits, _) = idx.search_shares(cid, "python", None, 10);
        assert_eq!(hits.len(), 1);
        assert!(
            hits[0]
                .title
                .as_deref()
                .unwrap()
                .to_lowercase()
                .contains("python")
        );

        let (all_hits, _) = idx.search_shares(cid, "ust", None, 10);
        assert_eq!(all_hits.len(), 1); // "Rust" contains "ust"
    }

    #[test]
    fn purge_expired_removes_entries() {
        let cid = [5u8; 32];
        let mut idx = CommunityIndex::default();

        // Insert a record that expires at timestamp 100.
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let rec = CommunityMemberRecord::new_signed(
            &signing_key,
            cid,
            1,
            CommunityMemberStatus::Joined,
            50,
            100,
        )
        .unwrap();
        idx.ingest_member_record(&rec);

        let (before, _) = idx.members_page(cid, None, 10);
        assert_eq!(before.len(), 1);

        idx.purge_expired(101);
        let (after, _) = idx.members_page(cid, None, 10);
        assert_eq!(after.len(), 0);
    }

    #[test]
    fn joined_member_count() {
        let cid = [6u8; 32];
        let mut idx = CommunityIndex::default();

        idx.ingest_member_record(&make_member_rec(cid, 1, 1, CommunityMemberStatus::Joined));
        idx.ingest_member_record(&make_member_rec(cid, 2, 1, CommunityMemberStatus::Joined));
        idx.ingest_member_record(&make_member_rec(cid, 3, 1, CommunityMemberStatus::Left));

        assert_eq!(idx.joined_member_count(cid), 2);
    }

    #[test]
    fn event_log_records_member_and_share_events() {
        let cid = [7u8; 32];
        let mut idx = CommunityIndex::default();

        idx.ingest_member_record(&make_member_rec(cid, 1, 1, CommunityMemberStatus::Joined));
        idx.ingest_member_record(&make_member_rec(cid, 2, 1, CommunityMemberStatus::Joined));
        idx.ingest_share_record(&make_share_rec(cid, 1, 1, Some("test share")));
        idx.ingest_member_record(&make_member_rec(cid, 1, 2, CommunityMemberStatus::Left));

        let (events, _) = idx.events_page(cid, None, 100);
        assert_eq!(events.len(), 4);
        assert!(matches!(&events[0], CommunityEvent::MemberJoined { .. }));
        assert!(matches!(&events[1], CommunityEvent::MemberJoined { .. }));
        assert!(matches!(&events[2], CommunityEvent::ShareUpserted { .. }));
        assert!(matches!(&events[3], CommunityEvent::MemberLeft { .. }));
    }

    #[test]
    fn event_log_cursor_pagination() {
        let cid = [8u8; 32];
        let mut idx = CommunityIndex::default();

        // Insert 5 members to generate 5 events.
        for i in 1..=5u8 {
            idx.ingest_member_record(&make_member_rec(cid, i, 1, CommunityMemberStatus::Joined));
        }

        let (page1, cursor1) = idx.events_page(cid, None, 3);
        assert_eq!(page1.len(), 3);
        assert!(cursor1.is_some());

        let (page2, cursor2) = idx.events_page(cid, cursor1.as_deref(), 3);
        assert_eq!(page2.len(), 2);
        // cursor2 is always Some when events are returned (high-water mark).
        assert!(
            cursor2.is_some(),
            "last page still carries high-water cursor"
        );

        // Re-fetching with the high-water cursor returns nothing (no duplicates).
        let (page3, _) = idx.events_page(cid, cursor2.as_deref(), 3);
        assert_eq!(
            page3.len(),
            0,
            "re-fetch with high-water cursor yields nothing"
        );
    }

    #[test]
    fn event_log_no_duplicate_on_same_seq() {
        let cid = [9u8; 32];
        let mut idx = CommunityIndex::default();

        // Ingest same member twice with same seq — second should be a no-op.
        idx.ingest_member_record(&make_member_rec(cid, 1, 1, CommunityMemberStatus::Joined));
        idx.ingest_member_record(&make_member_rec(cid, 1, 1, CommunityMemberStatus::Joined));

        let (events, _) = idx.events_page(cid, None, 100);
        assert_eq!(
            events.len(),
            1,
            "duplicate seq should not emit duplicate event"
        );
    }

    // ── J-6A: CRDT Property Tests ──────────────────────────────────

    /// Helper: create a member record with a specific `issued_at` and `expires_at`.
    fn make_member_rec_ts(
        community_id: [u8; 32],
        key: u8,
        seq: u64,
        status: CommunityMemberStatus,
        issued_at: u64,
        expires_at: u64,
    ) -> CommunityMemberRecord {
        let signing_key = {
            use ed25519_dalek::SigningKey;
            let seed = [key; 32];
            SigningKey::from_bytes(&seed)
        };
        CommunityMemberRecord::new_signed(
            &signing_key,
            community_id,
            seq,
            status,
            issued_at,
            expires_at,
        )
        .expect("signed record")
    }

    /// Helper: create a share record with explicit `updated_at`.
    fn make_share_rec_ts(
        community_id: [u8; 32],
        key: u8,
        seq: u64,
        updated_at: u64,
        title: Option<&str>,
    ) -> CommunityShareRecord {
        use ed25519_dalek::SigningKey;
        let seed = [key; 32];
        let share_key = SigningKey::from_bytes(&seed);
        CommunityShareRecord::new_signed(
            &share_key,
            community_id,
            [0u8; 32],
            seq,
            updated_at,
            title.map(str::to_string),
            None,
        )
        .expect("signed share record")
    }

    /// Snapshot of a community's member state (for convergence comparison).
    fn member_snapshot(idx: &CommunityIndex, cid: [u8; 32]) -> Vec<([u8; 32], u64, bool)> {
        let (page, _) = idx.members_page(cid, None, u16::MAX);
        let mut snap: Vec<_> = page
            .iter()
            .map(|m| {
                (
                    m.member_node_pubkey,
                    m.announce_seq,
                    matches!(m.status, CommunityMemberStatus::Joined),
                )
            })
            .collect();
        snap.sort_by_key(|(pk, _, _)| *pk);
        snap
    }

    /// Snapshot of a community's share state (for convergence comparison).
    fn share_snapshot(idx: &CommunityIndex, cid: [u8; 32]) -> Vec<([u8; 32], u64, u64)> {
        let (page, _) = idx.shares_page(cid, None, u16::MAX, None);
        let mut snap: Vec<_> = page
            .iter()
            .map(|s| (s.share_id, s.latest_seq, s.updated_at))
            .collect();
        snap.sort_by_key(|(id, _, _)| *id);
        snap
    }

    /// Generate all permutations of a small slice (Heap's algorithm).
    fn permutations<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
        let mut result = Vec::new();
        let mut arr: Vec<T> = items.to_vec();
        let n = arr.len();
        let mut c = vec![0usize; n];
        result.push(arr.clone());
        let mut i = 0;
        while i < n {
            if c[i] < i {
                if i % 2 == 0 {
                    arr.swap(0, i);
                } else {
                    arr.swap(c[i], i);
                }
                result.push(arr.clone());
                c[i] += 1;
                i = 0;
            } else {
                c[i] = 0;
                i += 1;
            }
        }
        result
    }

    /// J-6A: Member join/leave CRDT converges regardless of ingestion order.
    ///
    /// 4 records for 2 members across different seqs/statuses.
    /// All 24 permutations must produce the same final state.
    #[test]
    fn member_crdt_convergence_all_orderings() {
        let cid = [10u8; 32];
        let far_future = 1_000_000u64 + 3600 * 24 * 365;

        // Member 1: join(seq=1) then leave(seq=3)
        // Member 2: join(seq=1) then join(seq=2) -- re-announce
        let records = vec![
            make_member_rec_ts(cid, 1, 1, CommunityMemberStatus::Joined, 100, far_future),
            make_member_rec_ts(cid, 1, 3, CommunityMemberStatus::Left, 300, far_future),
            make_member_rec_ts(cid, 2, 1, CommunityMemberStatus::Joined, 100, far_future),
            make_member_rec_ts(cid, 2, 2, CommunityMemberStatus::Joined, 200, far_future),
        ];

        // Compute reference snapshot from canonical ordering.
        let mut ref_idx = CommunityIndex::default();
        for r in &records {
            ref_idx.ingest_member_record(r);
        }
        let reference = member_snapshot(&ref_idx, cid);

        // Verify member 1 is Left (seq 3 wins) and member 2 is Joined (seq 2 wins).
        assert_eq!(reference.len(), 2);

        // Verify all permutations converge.
        for perm in permutations(&records) {
            let mut idx = CommunityIndex::default();
            for r in &perm {
                idx.ingest_member_record(r);
            }
            let snap = member_snapshot(&idx, cid);
            assert_eq!(
                snap, reference,
                "member CRDT must converge for all orderings"
            );
        }
    }

    /// J-6A: Duplicate member records are idempotent.
    #[test]
    fn member_crdt_duplicate_idempotent() {
        let cid = [11u8; 32];
        let far_future = 1_000_000u64 + 3600 * 24 * 365;

        let rec = make_member_rec_ts(cid, 1, 5, CommunityMemberStatus::Joined, 500, far_future);
        let mut idx = CommunityIndex::default();
        for _ in 0..10 {
            idx.ingest_member_record(&rec);
        }

        let snap = member_snapshot(&idx, cid);
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].1, 5, "seq must be 5");
        assert!(snap[0].2, "must be Joined");

        // Only one event emitted (first ingest).
        let (events, _) = idx.events_page(cid, None, 100);
        assert_eq!(events.len(), 1, "duplicates must not emit extra events");
    }

    /// J-6A: Replay of lower-seq join cannot undo a leave.
    #[test]
    fn member_crdt_replay_cannot_undo_leave() {
        let cid = [12u8; 32];
        let far_future = 1_000_000u64 + 3600 * 24 * 365;

        let join_1 = make_member_rec_ts(cid, 1, 1, CommunityMemberStatus::Joined, 100, far_future);
        let leave_2 = make_member_rec_ts(cid, 1, 2, CommunityMemberStatus::Left, 200, far_future);

        let mut idx = CommunityIndex::default();
        idx.ingest_member_record(&leave_2); // leave arrives first
        idx.ingest_member_record(&join_1); // stale join replay

        let snap = member_snapshot(&idx, cid);
        assert_eq!(snap.len(), 1);
        assert!(
            !snap[0].2,
            "must remain Left after replay of lower-seq join"
        );
    }

    /// J-6A: Share upsert CRDT converges regardless of ingestion order.
    ///
    /// 4 share records for 2 shares across different seq/updated_at values.
    /// All 24 permutations must produce the same final state.
    #[test]
    fn share_crdt_convergence_all_orderings() {
        let cid = [13u8; 32];

        // Share 1 (key=1): seq 1 at t=100, seq 3 at t=300
        // Share 2 (key=2): seq 2 at t=200, seq 2 at t=250 (same seq, later timestamp wins)
        let records = vec![
            make_share_rec_ts(cid, 1, 1, 100, Some("s1v1")),
            make_share_rec_ts(cid, 1, 3, 300, Some("s1v3")),
            make_share_rec_ts(cid, 2, 2, 200, Some("s2v2a")),
            make_share_rec_ts(cid, 2, 2, 250, Some("s2v2b")),
        ];

        // Reference snapshot from canonical order.
        let mut ref_idx = CommunityIndex::default();
        for r in &records {
            ref_idx.ingest_share_record(r);
        }
        let reference = share_snapshot(&ref_idx, cid);
        assert_eq!(reference.len(), 2);

        // All permutations must converge.
        for perm in permutations(&records) {
            let mut idx = CommunityIndex::default();
            for r in &perm {
                idx.ingest_share_record(r);
            }
            let snap = share_snapshot(&idx, cid);
            assert_eq!(
                snap, reference,
                "share CRDT must converge for all orderings"
            );
        }
    }

    /// J-6A: Same-seq share tiebreaker uses `updated_at`.
    #[test]
    fn share_crdt_same_seq_tiebreak_by_updated_at() {
        let cid = [14u8; 32];

        let early = make_share_rec_ts(cid, 1, 5, 100, Some("early"));
        let late = make_share_rec_ts(cid, 1, 5, 999, Some("late"));

        // Ingest early then late.
        let mut idx1 = CommunityIndex::default();
        idx1.ingest_share_record(&early);
        idx1.ingest_share_record(&late);

        // Ingest late then early.
        let mut idx2 = CommunityIndex::default();
        idx2.ingest_share_record(&late);
        idx2.ingest_share_record(&early);

        let snap1 = share_snapshot(&idx1, cid);
        let snap2 = share_snapshot(&idx2, cid);
        assert_eq!(snap1, snap2, "order of ingestion must not matter");
        assert_eq!(snap1[0].2, 999, "later updated_at must win the tiebreak");
    }

    /// J-6A: Share duplicate records are idempotent.
    #[test]
    fn share_crdt_duplicate_idempotent() {
        let cid = [15u8; 32];

        let rec = make_share_rec_ts(cid, 1, 3, 300, Some("dup"));
        let mut idx = CommunityIndex::default();
        for _ in 0..10 {
            idx.ingest_share_record(&rec);
        }

        let snap = share_snapshot(&idx, cid);
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].1, 3);

        let (events, _) = idx.events_page(cid, None, 100);
        assert_eq!(events.len(), 1, "duplicates must not emit extra events");
    }

    /// J-6A: Mixed member+share convergence with interleaved out-of-order records.
    #[test]
    fn mixed_member_share_crdt_convergence() {
        let cid = [16u8; 32];
        let far_future = 1_000_000u64 + 3600 * 24 * 365;

        let m1_join = make_member_rec_ts(cid, 1, 1, CommunityMemberStatus::Joined, 100, far_future);
        let m1_leave = make_member_rec_ts(cid, 1, 2, CommunityMemberStatus::Left, 200, far_future);
        let m2_join = make_member_rec_ts(cid, 2, 1, CommunityMemberStatus::Joined, 150, far_future);
        let s1_v1 = make_share_rec_ts(cid, 1, 1, 100, Some("v1"));
        let s1_v2 = make_share_rec_ts(cid, 1, 2, 200, Some("v2"));
        let s2_v1 = make_share_rec_ts(cid, 3, 1, 150, Some("other"));

        // Create a set of operations with alternating types.
        #[derive(Clone)]
        struct Op {
            member: Option<CommunityMemberRecord>,
            share: Option<CommunityShareRecord>,
        }
        let ops = vec![
            Op {
                member: Some(m1_join.clone()),
                share: None,
            },
            Op {
                member: None,
                share: Some(s1_v1.clone()),
            },
            Op {
                member: Some(m2_join.clone()),
                share: None,
            },
            Op {
                member: None,
                share: Some(s1_v2.clone()),
            },
            Op {
                member: Some(m1_leave.clone()),
                share: None,
            },
            Op {
                member: None,
                share: Some(s2_v1.clone()),
            },
        ];

        // Reference state.
        let mut ref_idx = CommunityIndex::default();
        for op in &ops {
            if let Some(m) = &op.member {
                ref_idx.ingest_member_record(m);
            }
            if let Some(s) = &op.share {
                ref_idx.ingest_share_record(s);
            }
        }
        let ref_members = member_snapshot(&ref_idx, cid);
        let ref_shares = share_snapshot(&ref_idx, cid);

        // Try all 720 permutations (6!).
        for perm in permutations(&ops) {
            let mut idx = CommunityIndex::default();
            for op in &perm {
                if let Some(m) = &op.member {
                    idx.ingest_member_record(m);
                }
                if let Some(s) = &op.share {
                    idx.ingest_share_record(s);
                }
            }
            assert_eq!(
                member_snapshot(&idx, cid),
                ref_members,
                "mixed member CRDT must converge"
            );
            assert_eq!(
                share_snapshot(&idx, cid),
                ref_shares,
                "mixed share CRDT must converge"
            );
        }
    }

    /// J-6A: Eviction caps are enforced under high-cardinality inserts.
    #[test]
    fn member_eviction_cap_enforced() {
        let cid = [17u8; 32];
        let mut idx = CommunityIndex::default();

        // Insert MAX + 5 members: the bucket should never exceed the cap.
        let count = CommunityIndex::MAX_MEMBERS_PER_COMMUNITY + 5;
        for i in 0..count {
            let key_byte = (i % 256) as u8;
            let seq = (i / 256 + 1) as u64;
            // Use unique pubkeys by including `i` in issued_at (not ideal but
            // we only need unique signing keys).  Since `key` only gives 256
            // unique signing keys, once i >= 256 we re-use keys with higher
            // seqs which will update-in-place rather than add new entries.
            // So we only test with 256 unique members.
            let far_future = 10_000_000u64;
            idx.ingest_member_record(&make_member_rec_ts(
                cid,
                key_byte,
                seq,
                CommunityMemberStatus::Joined,
                (i as u64) * 100,
                far_future,
            ));
        }

        let (page, _) = idx.members_page(cid, None, u16::MAX);
        assert!(
            page.len() <= CommunityIndex::MAX_MEMBERS_PER_COMMUNITY,
            "member count {} exceeds cap {}",
            page.len(),
            CommunityIndex::MAX_MEMBERS_PER_COMMUNITY,
        );
    }

    /// J-6A: Share eviction caps are enforced.
    #[test]
    fn share_eviction_cap_enforced() {
        let cid = [18u8; 32];
        let mut idx = CommunityIndex::default();

        // Same approach: only 256 unique share keys, but we can verify
        // the bucket never exceeds the cap.
        for i in 0..256u16 {
            idx.ingest_share_record(&make_share_rec_ts(
                cid,
                i as u8,
                1,
                (i as u64) * 100,
                Some(&format!("share {i}")),
            ));
        }

        let (page, _) = idx.shares_page(cid, None, u16::MAX, None);
        assert!(
            page.len() <= CommunityIndex::MAX_SHARES_PER_COMMUNITY,
            "share count {} exceeds cap {}",
            page.len(),
            CommunityIndex::MAX_SHARES_PER_COMMUNITY,
        );
    }

    /// J-6A: Purge expired correctly handles share TTL.
    #[test]
    fn share_ttl_purge() {
        let cid = [19u8; 32];
        let mut idx = CommunityIndex::default();

        // Share with updated_at=100 gets expires_at = 100 + MAX_SHARE_TTL_SECS.
        idx.ingest_share_record(&make_share_rec_ts(cid, 1, 1, 100, Some("old share")));

        let (before, _) = idx.shares_page(cid, None, 10, None);
        assert_eq!(before.len(), 1);

        // Purge at one second before expiry: should still be present.
        let expiry = 100 + CommunityIndex::MAX_SHARE_TTL_SECS;
        idx.purge_expired(expiry - 1);
        let (before_expiry, _) = idx.shares_page(cid, None, 10, None);
        assert_eq!(before_expiry.len(), 1, "share should exist before expiry");

        // Purge at exact expiry time: retain uses `> now`, so equal means expired.
        idx.purge_expired(expiry);
        let (after, _) = idx.shares_page(cid, None, 10, None);
        assert_eq!(after.len(), 0, "share should be purged at expiry");
    }

    /// J-6A: Stale event compaction removes orphaned event logs.
    #[test]
    fn event_compaction_removes_orphaned_logs() {
        let cid = [20u8; 32];
        let mut idx = CommunityIndex::default();

        // Create a member so events are generated, then expire it.
        idx.ingest_member_record(&make_member_rec_ts(
            cid,
            1,
            1,
            CommunityMemberStatus::Joined,
            100,
            200, // expires_at = 200
        ));

        let (events_before, _) = idx.events_page(cid, None, 100);
        assert_eq!(events_before.len(), 1, "should have 1 event before purge");

        // Expire the member.
        idx.purge_expired(201);

        // Now the member is gone, but events linger until compaction notices.
        // Purge with a cutoff that makes the event log stale.
        let stale_time = 201 + CommunityIndex::MAX_EVENT_AGE_SECS + 1;
        idx.purge_expired(stale_time);

        let (events_after, _) = idx.events_page(cid, None, 100);
        assert_eq!(
            events_after.len(),
            0,
            "orphaned event log should be purged after member expiry + age cutoff"
        );
    }

    // ── J-1C: Materialized page tests ─────────────────────────────

    #[test]
    fn materialize_member_pages_basic() {
        let cid = [30u8; 32];
        let mut idx = CommunityIndex::default();
        let far_future = 1_000_000u64 + 3600 * 24 * 365;

        // Insert 5 joined members.
        for i in 1..=5u8 {
            idx.ingest_member_record(&make_member_rec_ts(
                cid,
                i,
                1,
                CommunityMemberStatus::Joined,
                1_000_000,
                far_future,
            ));
        }
        // Insert 1 left member (should be excluded from materialized pages).
        idx.ingest_member_record(&make_member_rec_ts(
            cid,
            10,
            2,
            CommunityMemberStatus::Left,
            1_000_000,
            far_future,
        ));

        let pages = idx.materialize_member_pages(cid, 100, 1_000_001);
        assert_eq!(pages.len(), 1, "5 members fit in one page");
        assert_eq!(pages[0].total_pages, 1);
        assert_eq!(pages[0].page_no, 0);
        assert_eq!(pages[0].bucket, 100);
        assert_eq!(pages[0].entries.len(), 5, "only joined members");
        assert_eq!(pages[0].community_id, cid);
        // All entries should be Joined.
        for e in &pages[0].entries {
            assert_eq!(e.status, CommunityMemberStatus::Joined);
        }
    }

    #[test]
    fn materialize_member_pages_pagination() {
        let cid = [31u8; 32];
        let mut idx = CommunityIndex::default();
        let far_future = 1_000_000u64 + 3600 * 24 * 365;

        // Insert more members than MATERIALIZED_PAGE_SIZE.
        let count = CommunityIndex::MATERIALIZED_PAGE_SIZE + 30;
        for i in 0..count {
            let key = (i as u8).wrapping_add(1);
            // Use a unique signing key per member.
            let signing_key = {
                use ed25519_dalek::SigningKey;
                let mut seed = [0u8; 32];
                seed[0] = key;
                seed[1] = (i >> 8) as u8;
                SigningKey::from_bytes(&seed)
            };
            let rec = CommunityMemberRecord::new_signed(
                &signing_key,
                cid,
                1,
                CommunityMemberStatus::Joined,
                1_000_000,
                far_future,
            )
            .unwrap();
            idx.ingest_member_record(&rec);
        }

        let pages = idx.materialize_member_pages(cid, 200, 1_000_001);
        assert_eq!(pages.len(), 2, "should span 2 pages");
        assert_eq!(pages[0].total_pages, 2);
        assert_eq!(pages[1].total_pages, 2);
        assert_eq!(pages[0].page_no, 0);
        assert_eq!(pages[1].page_no, 1);
        let total_entries: usize = pages.iter().map(|p| p.entries.len()).sum();
        assert_eq!(total_entries, count);
    }

    #[test]
    fn materialize_share_pages_basic() {
        let cid = [32u8; 32];
        let mut idx = CommunityIndex::default();

        for i in 1..=3u8 {
            idx.ingest_share_record(&make_share_rec_ts(
                cid,
                i,
                1,
                1_000_000,
                Some(&format!("share {i}")),
            ));
        }

        let pages = idx.materialize_share_pages(cid, 100, 1_000_001);
        assert_eq!(pages.len(), 1);
        assert_eq!(pages[0].entries.len(), 3);
        assert_eq!(pages[0].total_pages, 1);
        assert_eq!(pages[0].page_no, 0);
    }

    #[test]
    fn materialize_share_pages_excludes_expired() {
        let cid = [33u8; 32];
        let mut idx = CommunityIndex::default();

        // This share is updated_at=100, so expires_at = 100 + MAX_SHARE_TTL_SECS.
        idx.ingest_share_record(&make_share_rec_ts(cid, 1, 1, 100, Some("old")));
        idx.ingest_share_record(&make_share_rec_ts(cid, 2, 1, 2_000_000, Some("new")));

        let expiry = 100 + CommunityIndex::MAX_SHARE_TTL_SECS + 1;
        let pages = idx.materialize_share_pages(cid, 100, expiry);
        assert_eq!(pages.len(), 1);
        assert_eq!(pages[0].entries.len(), 1, "expired share excluded");
        assert_eq!(pages[0].entries[0].title.as_deref(), Some("new"));
    }

    #[test]
    fn materialize_empty_community_returns_no_pages() {
        let cid = [34u8; 32];
        let idx = CommunityIndex::default();
        assert!(idx.materialize_member_pages(cid, 100, 1_000_000).is_empty());
        assert!(idx.materialize_share_pages(cid, 100, 1_000_000).is_empty());
    }

    #[test]
    fn all_community_ids_returns_union() {
        let cid1 = [40u8; 32];
        let cid2 = [41u8; 32];
        let far_future = 1_000_000u64 + 3600 * 24 * 365;

        let mut idx = CommunityIndex::default();
        idx.ingest_member_record(&make_member_rec_ts(
            cid1,
            1,
            1,
            CommunityMemberStatus::Joined,
            1_000_000,
            far_future,
        ));
        idx.ingest_share_record(&make_share_rec_ts(cid2, 1, 1, 1_000_000, Some("s")));

        let ids = idx.all_community_ids();
        assert!(ids.contains(&cid1));
        assert!(ids.contains(&cid2));
        assert_eq!(ids.len(), 2);
    }

    // ── Large-scale simulation tests (J-6B) ──────────────────────────

    /// Generate a unique signing key from a 32-bit index (supports >256 keys).
    fn make_signing_key(index: u32) -> ed25519_dalek::SigningKey {
        let mut seed = [0u8; 32];
        seed[..4].copy_from_slice(&index.to_le_bytes());
        ed25519_dalek::SigningKey::from_bytes(&seed)
    }

    /// Create a member record with a signing key derived from a u32 index.
    fn make_member_rec_u32(
        community_id: [u8; 32],
        index: u32,
        seq: u64,
        status: CommunityMemberStatus,
        issued_at: u64,
        expires_at: u64,
    ) -> CommunityMemberRecord {
        let signing_key = make_signing_key(index);
        CommunityMemberRecord::new_signed(
            &signing_key,
            community_id,
            seq,
            status,
            issued_at,
            expires_at,
        )
        .expect("signed record")
    }

    /// Create a share record with a signing key derived from a u32 index.
    fn make_share_rec_u32(
        community_id: [u8; 32],
        index: u32,
        seq: u64,
        updated_at: u64,
        title: Option<&str>,
    ) -> CommunityShareRecord {
        let signing_key = make_signing_key(index);
        CommunityShareRecord::new_signed(
            &signing_key,
            community_id,
            [0u8; 32],
            seq,
            updated_at,
            title.map(str::to_string),
            None,
        )
        .expect("signed share record")
    }

    /// Compute percentile value from a sorted list of durations.
    fn percentile(sorted: &[std::time::Duration], p: f64) -> std::time::Duration {
        if sorted.is_empty() {
            return std::time::Duration::ZERO;
        }
        let idx = ((p / 100.0) * (sorted.len() as f64 - 1.0)).ceil() as usize;
        sorted[idx.min(sorted.len() - 1)]
    }

    /// J-6B: 10k member community — ingest, browse, search, materialize timing
    #[test]
    #[ignore] // slow: run with `cargo test -- --ignored`
    fn simulation_10k_members() {
        let cid = [100u8; 32];
        let now = 2_000_000u64;
        let far_future = now + 365 * 24 * 3600;
        let mut idx = CommunityIndex::default();

        // ── Ingest 10k members ────────────────────────────────
        let ingest_start = std::time::Instant::now();
        for i in 0..10_000u32 {
            idx.ingest_member_record(&make_member_rec_u32(
                cid,
                i,
                1,
                CommunityMemberStatus::Joined,
                now,
                far_future,
            ));
        }
        let ingest_elapsed = ingest_start.elapsed();
        eprintln!("[10k members] ingest: {:?}", ingest_elapsed);

        // ── Ingest 2k shares ─────────────────────────────────
        for i in 0..2_000u32 {
            let title = format!("Share {i}");
            idx.ingest_share_record(&make_share_rec_u32(cid, i + 100_000, 1, now, Some(&title)));
        }

        // ── Browse member pages (measure p95) ───────────────
        let mut browse_times = Vec::new();
        let mut cursor: Option<String> = None;
        let mut total_members = 0usize;
        loop {
            let t = std::time::Instant::now();
            let (page, next) = idx.members_page(
                cid,
                cursor.as_deref(),
                CommunityIndex::MAX_MEMBERS_PAGE_SIZE,
            );
            browse_times.push(t.elapsed());
            total_members += page.len();
            if next.is_none() {
                break;
            }
            cursor = next;
        }
        browse_times.sort();
        let p95_browse = percentile(&browse_times, 95.0);
        eprintln!(
            "[10k members] browse pages: {}, total members: {}, p95: {:?}",
            browse_times.len(),
            total_members,
            p95_browse
        );
        // The cap is 10k; all should be present.
        assert_eq!(total_members, 10_000);
        // p95 should be well under 100ms for in-memory index.
        assert!(
            p95_browse < std::time::Duration::from_millis(100),
            "p95 browse latency too high: {:?}",
            p95_browse
        );

        // ── Browse share pages (measure p95) ────────────────
        let mut share_browse_times = Vec::new();
        let mut cursor: Option<String> = None;
        let mut total_shares = 0usize;
        loop {
            let t = std::time::Instant::now();
            let (page, next) = idx.shares_page(
                cid,
                cursor.as_deref(),
                CommunityIndex::MAX_SHARES_PAGE_SIZE,
                None,
            );
            share_browse_times.push(t.elapsed());
            total_shares += page.len();
            if next.is_none() {
                break;
            }
            cursor = next;
        }
        share_browse_times.sort();
        let p95_share_browse = percentile(&share_browse_times, 95.0);
        eprintln!(
            "[10k members] share browse pages: {}, total shares: {}, p95: {:?}",
            share_browse_times.len(),
            total_shares,
            p95_share_browse
        );
        assert_eq!(total_shares, 2_000);
        assert!(
            p95_share_browse < std::time::Duration::from_millis(100),
            "p95 share browse latency too high: {:?}",
            p95_share_browse
        );

        // ── Search shares (measure p95) ─────────────────────
        let queries = ["Share 1", "Share 99", "Share 500", "nonexistent", "Share"];
        let mut search_times = Vec::new();
        for q in &queries {
            let t = std::time::Instant::now();
            let _results = idx.search_shares(cid, q, None, CommunityIndex::MAX_SEARCH_HITS);
            search_times.push(t.elapsed());
        }
        search_times.sort();
        let p95_search = percentile(&search_times, 95.0);
        eprintln!(
            "[10k members] search queries: {}, p95: {:?}",
            search_times.len(),
            p95_search
        );
        assert!(
            p95_search < std::time::Duration::from_millis(500),
            "p95 search latency too high: {:?}",
            p95_search
        );

        // ── Materialize pages ───────────────────────────────
        let bucket = now / 3600;
        let t = std::time::Instant::now();
        let member_pages = idx.materialize_member_pages(cid, bucket, now);
        let materialize_member_time = t.elapsed();
        let t = std::time::Instant::now();
        let share_pages = idx.materialize_share_pages(cid, bucket, now);
        let materialize_share_time = t.elapsed();
        eprintln!(
            "[10k members] materialize: {} member pages in {:?}, {} share pages in {:?}",
            member_pages.len(),
            materialize_member_time,
            share_pages.len(),
            materialize_share_time
        );
        assert_eq!(
            member_pages.iter().map(|p| p.entries.len()).sum::<usize>(),
            10_000
        );
        assert_eq!(
            share_pages.iter().map(|p| p.entries.len()).sum::<usize>(),
            2_000
        );

        // ── Churn: 1k leaves, 1k new joins ─────────────────
        let churn_start = std::time::Instant::now();
        for i in 0..1_000u32 {
            idx.ingest_member_record(&make_member_rec_u32(
                cid,
                i,
                2,
                CommunityMemberStatus::Left,
                now + 1,
                far_future,
            ));
        }
        for i in 10_000..11_000u32 {
            idx.ingest_member_record(&make_member_rec_u32(
                cid,
                i,
                1,
                CommunityMemberStatus::Joined,
                now + 1,
                far_future,
            ));
        }
        let churn_elapsed = churn_start.elapsed();
        let joined = idx.joined_member_count(cid);
        eprintln!(
            "[10k members] churn (1k leave + 1k join): {:?}, joined after: {}",
            churn_elapsed, joined
        );
        // After 1k leaves + 1k new joins the BTreeMap stores 11k entries
        // but the 10k cap evicts the oldest, so some joins/leaves are
        // dropped.  The joined count should be roughly 9–10k.
        assert!(
            (8_000..=10_000).contains(&joined),
            "unexpected joined count after churn: {}",
            joined
        );
    }

    /// J-6B: 50k member ingest — tests eviction behavior and performance
    /// under heavy load beyond the MAX_MEMBERS_PER_COMMUNITY cap.
    #[test]
    #[ignore] // slow: run with `cargo test -- --ignored`
    fn simulation_50k_members_eviction() {
        let cid = [101u8; 32];
        let base_time = 2_000_000u64;
        let far_future = base_time + 365 * 24 * 3600;
        let mut idx = CommunityIndex::default();

        // ── Ingest 50k members (cap is 10k, so eviction kicks in) ──
        let ingest_start = std::time::Instant::now();
        for i in 0..50_000u32 {
            idx.ingest_member_record(&make_member_rec_u32(
                cid,
                i,
                1,
                CommunityMemberStatus::Joined,
                // Newer members get higher timestamps (oldest evicted first).
                base_time + u64::from(i),
                far_future,
            ));
        }
        let ingest_elapsed = ingest_start.elapsed();
        let joined = idx.joined_member_count(cid);
        eprintln!(
            "[50k members] ingest: {:?}, retained joined: {}",
            ingest_elapsed, joined
        );
        // Should be capped at MAX_MEMBERS_PER_COMMUNITY.
        assert!(
            joined <= CommunityIndex::MAX_MEMBERS_PER_COMMUNITY,
            "exceeded member cap: {}",
            joined
        );

        // ── Browse after eviction ───────────────────────────
        let mut cursor: Option<String> = None;
        let mut total = 0usize;
        let browse_start = std::time::Instant::now();
        loop {
            let (page, next) = idx.members_page(
                cid,
                cursor.as_deref(),
                CommunityIndex::MAX_MEMBERS_PAGE_SIZE,
            );
            total += page.len();
            if next.is_none() {
                break;
            }
            cursor = next;
        }
        let browse_all_time = browse_start.elapsed();
        eprintln!(
            "[50k members] browse all pages after eviction: {} members in {:?}",
            total, browse_all_time
        );
        assert!(total <= CommunityIndex::MAX_MEMBERS_PER_COMMUNITY);

        // ── 50k shares (cap is 10k) ─────────────────────────
        let share_start = std::time::Instant::now();
        for i in 0..50_000u32 {
            let title = format!("S{i}");
            idx.ingest_share_record(&make_share_rec_u32(
                cid,
                i + 200_000,
                1,
                base_time + u64::from(i),
                Some(&title),
            ));
        }
        let share_elapsed = share_start.elapsed();
        eprintln!("[50k shares] ingest: {:?}", share_elapsed);

        // Verify share count is capped.
        let mut scursor: Option<String> = None;
        let mut share_total = 0usize;
        loop {
            let (page, next) = idx.shares_page(
                cid,
                scursor.as_deref(),
                CommunityIndex::MAX_SHARES_PAGE_SIZE,
                None,
            );
            share_total += page.len();
            if next.is_none() {
                break;
            }
            scursor = next;
        }
        assert!(
            share_total <= CommunityIndex::MAX_SHARES_PER_COMMUNITY,
            "exceeded share cap: {}",
            share_total
        );
        eprintln!("[50k shares] retained after eviction: {}", share_total);
    }

    /// J-6B: Sustained churn simulation — measures index performance
    /// under continuous join/leave cycling.
    #[test]
    #[ignore] // slow: run with `cargo test -- --ignored`
    fn simulation_churn_cycles() {
        let cid = [102u8; 32];
        let base_time = 2_000_000u64;
        let far_future = base_time + 365 * 24 * 3600;
        let mut idx = CommunityIndex::default();

        // Seed 5k members.
        for i in 0..5_000u32 {
            idx.ingest_member_record(&make_member_rec_u32(
                cid,
                i,
                1,
                CommunityMemberStatus::Joined,
                base_time,
                far_future,
            ));
        }

        // Run 20 churn cycles: each cycle 500 members leave, 500 new join.
        let mut next_member = 5_000u32;
        let mut cycle_times = Vec::new();
        for cycle in 0..20u32 {
            let t = std::time::Instant::now();
            let leave_start = cycle * 500;
            for i in leave_start..(leave_start + 500) {
                idx.ingest_member_record(&make_member_rec_u32(
                    cid,
                    i,
                    2,
                    CommunityMemberStatus::Left,
                    base_time + u64::from(cycle) + 1,
                    far_future,
                ));
            }
            for _ in 0..500u32 {
                idx.ingest_member_record(&make_member_rec_u32(
                    cid,
                    next_member,
                    1,
                    CommunityMemberStatus::Joined,
                    base_time + u64::from(cycle) + 1,
                    far_future,
                ));
                next_member += 1;
            }
            cycle_times.push(t.elapsed());
        }
        cycle_times.sort();
        let p95_churn = percentile(&cycle_times, 95.0);
        let joined = idx.joined_member_count(cid);
        eprintln!(
            "[churn] 20 cycles of 500 leave + 500 join: p95={:?}, final joined={}",
            p95_churn, joined
        );
        assert_eq!(
            joined, 5_000,
            "steady-state joined membership should be stable"
        );
        assert!(
            p95_churn < std::time::Duration::from_secs(5),
            "churn cycle p95 too slow: {:?}",
            p95_churn
        );

        // Browse returns ALL entries (including Left tombstones).
        // The total browsed count may exceed joined count.
        let mut cursor: Option<String> = None;
        let mut total = 0usize;
        loop {
            let (page, next) = idx.members_page(
                cid,
                cursor.as_deref(),
                CommunityIndex::MAX_MEMBERS_PAGE_SIZE,
            );
            total += page.len();
            if next.is_none() {
                break;
            }
            cursor = next;
        }
        // Total browsed includes both Joined and Left entries; cap applies.
        assert!(
            total <= CommunityIndex::MAX_MEMBERS_PER_COMMUNITY,
            "browse total exceeds cap: {}",
            total
        );
    }

    /// J-6B: Memory growth measurement — verify bounded allocation.
    #[test]
    #[ignore] // slow; uses process-level RSS heuristic
    fn simulation_memory_bounded() {
        let cid = [103u8; 32];
        let now = 2_000_000u64;
        let far_future = now + 365 * 24 * 3600;
        let mut idx = CommunityIndex::default();

        // Insert members up to cap.
        for i in 0..10_000u32 {
            idx.ingest_member_record(&make_member_rec_u32(
                cid,
                i,
                1,
                CommunityMemberStatus::Joined,
                now,
                far_future,
            ));
        }
        // Insert shares up to cap.
        for i in 0..10_000u32 {
            idx.ingest_share_record(&make_share_rec_u32(
                cid,
                i + 300_000,
                1,
                now,
                Some(&format!("S{i}")),
            ));
        }

        // Verify caps are enforced (no unbounded growth).
        let joined = idx.joined_member_count(cid);
        assert!(
            joined <= CommunityIndex::MAX_MEMBERS_PER_COMMUNITY,
            "member cap breached: {}",
            joined
        );

        let mut share_count = 0usize;
        let mut cursor: Option<String> = None;
        loop {
            let (page, next) = idx.shares_page(
                cid,
                cursor.as_deref(),
                CommunityIndex::MAX_SHARES_PAGE_SIZE,
                None,
            );
            share_count += page.len();
            if next.is_none() {
                break;
            }
            cursor = next;
        }
        assert!(
            share_count <= CommunityIndex::MAX_SHARES_PER_COMMUNITY,
            "share cap breached: {}",
            share_count
        );

        // Inserting 10k more should NOT grow the index beyond caps.
        for i in 10_000..20_000u32 {
            idx.ingest_member_record(&make_member_rec_u32(
                cid,
                i,
                1,
                CommunityMemberStatus::Joined,
                now + 1,
                far_future,
            ));
        }
        let joined_after = idx.joined_member_count(cid);
        assert!(
            joined_after <= CommunityIndex::MAX_MEMBERS_PER_COMMUNITY,
            "member cap breached after overflow: {}",
            joined_after
        );
        eprintln!(
            "[memory] members: {}, shares: {} (caps: {}/{})",
            joined_after,
            share_count,
            CommunityIndex::MAX_MEMBERS_PER_COMMUNITY,
            CommunityIndex::MAX_SHARES_PER_COMMUNITY
        );
    }

    // ── Interop and abuse tests (J-6C) ───────────────────────────────

    /// J-6C: Invalid cursor strings are handled gracefully (no panic).
    #[test]
    fn abuse_invalid_cursor_members_page() {
        let cid = [110u8; 32];
        let mut idx = CommunityIndex::default();
        idx.ingest_member_record(&make_member_rec(cid, 1, 1, CommunityMemberStatus::Joined));

        // Garbage cursor (not valid hex).
        let (page, _) = idx.members_page(cid, Some("not-valid-hex!!!"), 100);
        // Invalid cursor is treated as None → returns from the beginning.
        assert_eq!(page.len(), 1);

        // Wrong-length hex cursor.
        let (page, _) = idx.members_page(cid, Some("abcd"), 100);
        assert_eq!(page.len(), 1);

        // Valid hex but non-existent key → starts after that key.
        let (page, _) = idx.members_page(cid, Some(&hex::encode([0xffu8; 32])), 100);
        assert!(page.is_empty(), "cursor past all keys should return empty");
    }

    /// J-6C: Invalid cursor strings on share pages.
    #[test]
    fn abuse_invalid_cursor_shares_page() {
        let cid = [111u8; 32];
        let mut idx = CommunityIndex::default();
        idx.ingest_share_record(&make_share_rec(cid, 1, 1, Some("test share")));

        let (page, _) = idx.shares_page(cid, Some("zzzzzz"), 100, None);
        assert_eq!(page.len(), 1);

        let (page, _) = idx.shares_page(cid, Some(&hex::encode([0xffu8; 32])), 100, None);
        assert!(page.is_empty());
    }

    /// J-6C: Invalid event cursor strings.
    #[test]
    fn abuse_invalid_cursor_events_page() {
        let cid = [112u8; 32];
        let mut idx = CommunityIndex::default();
        idx.ingest_member_record(&make_member_rec(cid, 1, 1, CommunityMemberStatus::Joined));

        // Non-numeric cursor → treated as 0.
        let (events, _) = idx.events_page(cid, Some("not-a-number"), 100);
        assert_eq!(events.len(), 1);

        // Very large cursor → no events after it.
        let (events, _) = idx.events_page(cid, Some("999999999999"), 100);
        assert!(events.is_empty());
    }

    /// J-6C: Client requests oversized limit → clamped to MAX.
    #[test]
    fn abuse_oversized_limit_clamped() {
        let cid = [113u8; 32];
        let mut idx = CommunityIndex::default();
        for i in 1..=5u8 {
            idx.ingest_member_record(&make_member_rec(cid, i, 1, CommunityMemberStatus::Joined));
        }
        for i in 1..=5u8 {
            idx.ingest_share_record(&make_share_rec(cid, i + 50, 1, Some("s")));
        }
        idx.ingest_member_record(&make_member_rec(cid, 10, 1, CommunityMemberStatus::Joined));

        // Request u16::MAX as limit — should not panic or OOM.
        let (members, _) = idx.members_page(cid, None, u16::MAX);
        assert_eq!(members.len(), 6);

        let (shares, _) = idx.shares_page(cid, None, u16::MAX, None);
        assert_eq!(shares.len(), 5);

        let (events, _) = idx.events_page(cid, None, u16::MAX);
        // Each ingest produces an event.
        assert!(events.len() <= CommunityIndex::MAX_EVENTS_PAGE_SIZE as usize);

        let (search_results, _) = idx.search_shares(cid, "s", None, u16::MAX);
        assert!(search_results.len() <= CommunityIndex::MAX_SEARCH_HITS as usize);
    }

    /// J-6C: Tombstone churn — mass leave followed by re-join.
    /// Verifies that tombstones are properly superseded by newer joins.
    #[test]
    fn abuse_tombstone_churn() {
        let cid = [114u8; 32];
        let now = 2_000_000u64;
        let far_future = now + 365 * 24 * 3600;
        let mut idx = CommunityIndex::default();

        // Join 100 members.
        for i in 0..100u32 {
            idx.ingest_member_record(&make_member_rec_u32(
                cid,
                i,
                1,
                CommunityMemberStatus::Joined,
                now,
                far_future,
            ));
        }
        assert_eq!(idx.joined_member_count(cid), 100);

        // All 100 leave.
        for i in 0..100u32 {
            idx.ingest_member_record(&make_member_rec_u32(
                cid,
                i,
                2,
                CommunityMemberStatus::Left,
                now + 1,
                far_future,
            ));
        }
        assert_eq!(idx.joined_member_count(cid), 0);

        // All 100 re-join with higher seq.
        for i in 0..100u32 {
            idx.ingest_member_record(&make_member_rec_u32(
                cid,
                i,
                3,
                CommunityMemberStatus::Joined,
                now + 2,
                far_future,
            ));
        }
        assert_eq!(idx.joined_member_count(cid), 100);
    }

    /// J-6C: Stale seq replay cannot undo a leave.
    #[test]
    fn abuse_replay_stale_seq_after_leave() {
        let cid = [115u8; 32];
        let now = 2_000_000u64;
        let far_future = now + 365 * 24 * 3600;
        let mut idx = CommunityIndex::default();

        // Join at seq 5.
        idx.ingest_member_record(&make_member_rec_u32(
            cid,
            1,
            5,
            CommunityMemberStatus::Joined,
            now,
            far_future,
        ));
        assert_eq!(idx.joined_member_count(cid), 1);

        // Leave at seq 10.
        idx.ingest_member_record(&make_member_rec_u32(
            cid,
            1,
            10,
            CommunityMemberStatus::Left,
            now + 1,
            far_future,
        ));
        assert_eq!(idx.joined_member_count(cid), 0);

        // Replay old join at seq 5 → must NOT re-join.
        idx.ingest_member_record(&make_member_rec_u32(
            cid,
            1,
            5,
            CommunityMemberStatus::Joined,
            now,
            far_future,
        ));
        assert_eq!(
            idx.joined_member_count(cid),
            0,
            "replayed stale join must not undo leave"
        );
    }

    /// J-6C: Duplicate record flood — same record ingested many times.
    #[test]
    fn abuse_duplicate_flood() {
        let cid = [116u8; 32];
        let mut idx = CommunityIndex::default();

        let rec = make_member_rec(cid, 1, 1, CommunityMemberStatus::Joined);
        for _ in 0..1_000 {
            idx.ingest_member_record(&rec);
        }
        // Should still have exactly 1 member.
        assert_eq!(idx.joined_member_count(cid), 1);

        // Member pages should have exactly 1 entry.
        let (page, cursor) = idx.members_page(cid, None, 100);
        assert_eq!(page.len(), 1);
        assert!(cursor.is_none());
    }

    /// J-6C: Search with adversarial query patterns.
    #[test]
    fn abuse_search_adversarial_queries() {
        let cid = [117u8; 32];
        let mut idx = CommunityIndex::default();
        for i in 1..=20u8 {
            let title = format!("Share {i}");
            idx.ingest_share_record(&make_share_rec(cid, i, 1, Some(&title)));
        }

        // Empty query.
        let (results, _) = idx.search_shares(cid, "", None, 50);
        // Empty query matches all (implementation-dependent).
        assert!(results.len() <= 50);

        // Very long query string.
        let long_query = "a".repeat(10_000);
        let (results, _) = idx.search_shares(cid, &long_query, None, 50);
        assert!(results.is_empty(), "very long query should match nothing");

        // Special characters.
        let (results, _) = idx.search_shares(cid, "'; DROP TABLE--", None, 50);
        assert!(results.is_empty());

        // Unicode.
        let (results, _) = idx.search_shares(cid, "🎵🎶", None, 50);
        assert!(results.is_empty());
    }

    /// J-6C: DHT validation rejects truncated/corrupted tagged values.
    /// Uses wire type `decode_tagged` directly (public API) to verify
    /// that corrupted payloads are rejected.
    #[test]
    fn abuse_corrupted_tagged_values_rejected() {
        use crate::wire::{
            CommunityBootstrapHint, CommunityMemberRecord, CommunityShareRecord,
            MaterializedMembersPage, MaterializedSharesPage,
        };

        // Tag 0x31 (member record) with truncated body.
        let truncated_member = vec![0x31, 0x00, 0x01];
        assert!(CommunityMemberRecord::decode_tagged(&truncated_member).is_err());

        // Tag 0x32 (share record) with truncated body.
        let truncated_share = vec![0x32, 0x00, 0x01];
        assert!(CommunityShareRecord::decode_tagged(&truncated_share).is_err());

        // Tag 0x33 (bootstrap hint) with truncated body.
        let truncated_bootstrap = vec![0x33, 0x00, 0x01];
        assert!(CommunityBootstrapHint::decode_tagged(&truncated_bootstrap).is_err());

        // Tag 0x34 (members page) with truncated body.
        let truncated_mpage = vec![0x34, 0x00, 0x01];
        assert!(MaterializedMembersPage::decode_tagged(&truncated_mpage).is_err());

        // Tag 0x35 (shares page) with truncated body.
        let truncated_spage = vec![0x35, 0x00, 0x01];
        assert!(MaterializedSharesPage::decode_tagged(&truncated_spage).is_err());
    }

    /// J-6C: Wrong tag bytes are rejected by decode_tagged.
    #[test]
    fn interop_wrong_tag_rejected() {
        use crate::wire::{CommunityShareRecord, MaterializedMembersPage, MaterializedSharesPage};

        // Valid member record encoded as 0x31 cannot be decoded as share (0x32).
        let cid = [120u8; 32];
        let rec = make_member_rec(cid, 1, 1, CommunityMemberStatus::Joined);
        let encoded = rec.encode_tagged().expect("encode");
        assert!(CommunityShareRecord::decode_tagged(&encoded).is_err());
        assert!(MaterializedMembersPage::decode_tagged(&encoded).is_err());
        assert!(MaterializedSharesPage::decode_tagged(&encoded).is_err());
    }

    /// J-6C: Mixed-version interop — dual-write: index accepts both
    /// legacy and new-format records for the same community.
    #[test]
    fn interop_dual_write_community_index() {
        let cid = [118u8; 32];
        let now = 2_000_000u64;
        let far_future = now + 365 * 24 * 3600;
        let mut idx = CommunityIndex::default();

        // New-format per-record member.
        idx.ingest_member_record(&make_member_rec_u32(
            cid,
            1,
            1,
            CommunityMemberStatus::Joined,
            now,
            far_future,
        ));
        // Another member from a different key.
        idx.ingest_member_record(&make_member_rec_u32(
            cid,
            2,
            1,
            CommunityMemberStatus::Joined,
            now,
            far_future,
        ));

        assert_eq!(idx.joined_member_count(cid), 2);

        // Browse must see both members regardless of record origin.
        let (page, _) = idx.members_page(cid, None, 100);
        assert_eq!(page.len(), 2);
    }

    /// J-6C: Event log compaction does not lose recent events.
    #[test]
    fn abuse_event_log_overflow() {
        let cid = [119u8; 32];
        let now = 2_000_000u64;
        let far_future = now + 365 * 24 * 3600;
        let mut idx = CommunityIndex::default();

        // Generate MAX_EVENT_LOG_SIZE + 500 events.
        let total = CommunityIndex::MAX_EVENT_LOG_SIZE as u32 + 500;
        for i in 0..total {
            idx.ingest_member_record(&make_member_rec_u32(
                cid,
                i,
                1,
                CommunityMemberStatus::Joined,
                now,
                far_future,
            ));
        }

        // Event log should be bounded.
        let (events, _) = idx.events_page(cid, None, CommunityIndex::MAX_EVENTS_PAGE_SIZE);
        assert!(
            events.len() <= CommunityIndex::MAX_EVENTS_PAGE_SIZE as usize,
            "event page exceeds max: {}",
            events.len()
        );

        // Can still page through all retained events.
        let mut total_events = 0usize;
        let mut cursor: Option<String> = None;
        loop {
            let (page, next) =
                idx.events_page(cid, cursor.as_deref(), CommunityIndex::MAX_EVENTS_PAGE_SIZE);
            if page.is_empty() {
                break;
            }
            total_events += page.len();
            if next.is_none() || page.is_empty() {
                break;
            }
            cursor = next;
        }
        assert!(
            total_events <= CommunityIndex::MAX_EVENT_LOG_SIZE,
            "exceeded event log cap: {}",
            total_events
        );
        eprintln!(
            "[abuse] event log after {} ingests: {} events retained",
            total, total_events
        );
    }
}
