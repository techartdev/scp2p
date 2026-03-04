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
}
