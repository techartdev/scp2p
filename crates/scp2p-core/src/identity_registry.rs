// Copyright (c) 2024-2026 Vanyo Vanev / Tech Art Ltd
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Key rotation and revocation state (§16).
//!
//! Tracks which identity keys have been retired or revoked, and resolves
//! rotation chains to a current active key.
//!
//! Two invariants drive the whole design:
//!
//! 1. **Revocation dominates rotation** (§16.4). A revoked key voids every
//!    rotation originating from it, whenever that rotation arrived. An
//!    attacker who steals a key can therefore always destroy the identity,
//!    but can never quietly inherit it.
//! 2. **Revocation is permanent** (§16.2.2). There is no un-revoke path, so
//!    a thief cannot undo the legitimate holder's revocation.

use std::collections::HashMap;

use crate::wire::{
    KeyRevocationRecord, KeyRotationRecord, MAX_ROTATION_CHAIN_DEPTH, RevocationReason,
};

/// Outcome of resolving a rotation chain (§16.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainResolution {
    /// The chain terminates at this currently-active key.
    Active([u8; 32]),
    /// Some key in the chain is revoked, so the identity is untrusted.
    ///
    /// Carries the specific revoked key to make operator diagnostics
    /// actionable rather than just "something in the chain is bad".
    Revoked { revoked_key: [u8; 32] },
    /// The chain exceeded [`MAX_ROTATION_CHAIN_DEPTH`] or contained a cycle.
    ///
    /// Treated as untrusted, not truncated — truncating would let an
    /// attacker hide a revocation past the depth cap (§16.5).
    TooDeep,
}

/// In-memory registry of rotation and revocation records (§16).
///
/// Enforcement is local and eventually consistent: a node enforces what it
/// knows. A partitioned node may keep trusting a revoked key until it learns
/// otherwise (§16.6).
#[derive(Debug, Default, Clone)]
pub struct IdentityRegistry {
    /// old_pubkey → accepted rotation record.
    rotations: HashMap<[u8; 32], KeyRotationRecord>,
    /// revoked pubkey → accepted revocation record.
    revocations: HashMap<[u8; 32], KeyRevocationRecord>,
}

impl IdentityRegistry {
    /// Ingest a verified rotation record.
    ///
    /// The caller must have already validated signatures (via the DHT
    /// validator or [`KeyRotationRecord::verify_at`]).
    ///
    /// Returns `true` when the registry changed. Rotations are accepted only
    /// with a strictly greater `rotation_seq`, so a replayed older record
    /// cannot roll the chain backwards.
    pub fn ingest_rotation(&mut self, record: &KeyRotationRecord) -> bool {
        if record.old_pubkey == record.new_pubkey {
            return false;
        }
        match self.rotations.get(&record.old_pubkey) {
            Some(existing) if record.rotation_seq <= existing.rotation_seq => false,
            _ => {
                self.rotations.insert(record.old_pubkey, record.clone());
                true
            }
        }
    }

    /// Ingest a verified revocation record.
    ///
    /// The earliest valid revocation wins; later ones are redundant rather
    /// than conflicting, so there is no monotonic counter here (§16.3).
    pub fn ingest_revocation(&mut self, record: &KeyRevocationRecord) -> bool {
        match self.revocations.get(&record.pubkey) {
            // Keep the earliest — a revocation is never rescinded, and the
            // earliest timestamp is the most conservative claim.
            Some(existing) if existing.issued_at <= record.issued_at => false,
            _ => {
                self.revocations.insert(record.pubkey, record.clone());
                true
            }
        }
    }

    /// Whether `pubkey` is known-revoked.
    pub fn is_revoked(&self, pubkey: &[u8; 32]) -> bool {
        self.revocations.contains_key(pubkey)
    }

    /// The revocation reason for `pubkey`, if revoked.
    pub fn revocation_reason(&self, pubkey: &[u8; 32]) -> Option<RevocationReason> {
        self.revocations.get(pubkey).map(|r| r.reason)
    }

    /// Number of known revocations (diagnostics).
    pub fn revocation_count(&self) -> usize {
        self.revocations.len()
    }

    /// Number of known rotations (diagnostics).
    pub fn rotation_count(&self) -> usize {
        self.rotations.len()
    }

    /// Resolve `start` to its current active key (§16.5).
    ///
    /// Walks the rotation chain, stopping at the first key with no successor.
    /// If any key in the chain — including `start` itself and the final key —
    /// is revoked, the whole chain is void.
    pub fn resolve_current_key(&self, start: [u8; 32]) -> ChainResolution {
        let mut current = start;
        // Cycle detection: a malicious pair of records could form A→B→A.
        let mut seen = Vec::with_capacity(4);

        for _ in 0..MAX_ROTATION_CHAIN_DEPTH {
            if self.is_revoked(&current) {
                return ChainResolution::Revoked {
                    revoked_key: current,
                };
            }
            if seen.contains(&current) {
                return ChainResolution::TooDeep;
            }
            seen.push(current);

            match self.rotations.get(&current) {
                Some(next) => current = next.new_pubkey,
                // No successor: this is the active key.
                None => return ChainResolution::Active(current),
            }
        }
        // Ran past the depth cap without terminating.
        ChainResolution::TooDeep
    }

    /// Whether an identity starting at `pubkey` is trusted (§16.6).
    ///
    /// False when the key itself is revoked, when any key along its rotation
    /// chain is revoked, or when the chain is malformed.
    pub fn is_trusted(&self, pubkey: &[u8; 32]) -> bool {
        matches!(
            self.resolve_current_key(*pubkey),
            ChainResolution::Active(_)
        )
    }

    /// All known revoked keys (for persistence).
    pub fn revocations(&self) -> impl Iterator<Item = &KeyRevocationRecord> {
        self.revocations.values()
    }

    /// All known rotation records (for persistence).
    pub fn rotations(&self) -> impl Iterator<Item = &KeyRotationRecord> {
        self.rotations.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::IdentitySubjectKind;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn pk(k: &SigningKey) -> [u8; 32] {
        k.verifying_key().to_bytes()
    }

    fn rotation(old: &SigningKey, new: &SigningKey, seq: u64) -> KeyRotationRecord {
        KeyRotationRecord::new_signed(IdentitySubjectKind::Node, old, new, seq, 1_700_000_000)
            .expect("sign rotation")
    }

    fn revocation(k: &SigningKey) -> KeyRevocationRecord {
        KeyRevocationRecord::new_signed(
            IdentitySubjectKind::Node,
            k,
            RevocationReason::Compromised,
            1_700_000_000,
        )
        .expect("sign revocation")
    }

    #[test]
    fn unknown_key_resolves_to_itself() {
        let reg = IdentityRegistry::default();
        let k = pk(&key());
        assert_eq!(reg.resolve_current_key(k), ChainResolution::Active(k));
        assert!(reg.is_trusted(&k));
    }

    #[test]
    fn single_rotation_resolves_to_new_key() {
        let (k0, k1) = (key(), key());
        let mut reg = IdentityRegistry::default();
        assert!(reg.ingest_rotation(&rotation(&k0, &k1, 1)));
        assert_eq!(
            reg.resolve_current_key(pk(&k0)),
            ChainResolution::Active(pk(&k1))
        );
    }

    #[test]
    fn multi_hop_chain_resolves_to_final_key() {
        let (k0, k1, k2) = (key(), key(), key());
        let mut reg = IdentityRegistry::default();
        reg.ingest_rotation(&rotation(&k0, &k1, 1));
        reg.ingest_rotation(&rotation(&k1, &k2, 1));
        assert_eq!(
            reg.resolve_current_key(pk(&k0)),
            ChainResolution::Active(pk(&k2))
        );
    }

    #[test]
    fn revoked_start_key_is_untrusted() {
        let k = key();
        let mut reg = IdentityRegistry::default();
        reg.ingest_revocation(&revocation(&k));
        assert_eq!(
            reg.resolve_current_key(pk(&k)),
            ChainResolution::Revoked {
                revoked_key: pk(&k)
            }
        );
        assert!(!reg.is_trusted(&pk(&k)));
    }

    #[test]
    fn revocation_anywhere_in_chain_voids_it() {
        // §16.4: revocation dominates rotation. k1 is revoked mid-chain, so
        // even though k0 rotated legitimately, the identity is void.
        let (k0, k1, k2) = (key(), key(), key());
        let mut reg = IdentityRegistry::default();
        reg.ingest_rotation(&rotation(&k0, &k1, 1));
        reg.ingest_rotation(&rotation(&k1, &k2, 1));
        reg.ingest_revocation(&revocation(&k1));
        assert_eq!(
            reg.resolve_current_key(pk(&k0)),
            ChainResolution::Revoked {
                revoked_key: pk(&k1)
            }
        );
        assert!(!reg.is_trusted(&pk(&k0)));
    }

    #[test]
    fn revocation_of_final_key_voids_chain() {
        let (k0, k1) = (key(), key());
        let mut reg = IdentityRegistry::default();
        reg.ingest_rotation(&rotation(&k0, &k1, 1));
        reg.ingest_revocation(&revocation(&k1));
        assert!(!reg.is_trusted(&pk(&k0)));
    }

    #[test]
    fn attacker_rotation_after_revocation_does_not_restore_trust() {
        // The core §16.4 scenario: a thief revokes-then-rotates, or races
        // the owner. Either way the revocation wins permanently.
        let (stolen, attacker) = (key(), key());
        let mut reg = IdentityRegistry::default();
        reg.ingest_revocation(&revocation(&stolen));
        // Attacker publishes a validly-signed rotation to their own key.
        reg.ingest_rotation(&rotation(&stolen, &attacker, 99));
        // Trust is not restored.
        assert!(!reg.is_trusted(&pk(&stolen)));
        assert_eq!(
            reg.resolve_current_key(pk(&stolen)),
            ChainResolution::Revoked {
                revoked_key: pk(&stolen)
            }
        );
    }

    #[test]
    fn rotation_replay_with_lower_seq_is_rejected() {
        let (k0, k1, k2) = (key(), key(), key());
        let mut reg = IdentityRegistry::default();
        assert!(reg.ingest_rotation(&rotation(&k0, &k2, 5)));
        // Older seq must not roll the chain back to k1.
        assert!(!reg.ingest_rotation(&rotation(&k0, &k1, 4)));
        assert_eq!(
            reg.resolve_current_key(pk(&k0)),
            ChainResolution::Active(pk(&k2))
        );
    }

    #[test]
    fn equal_seq_rotation_is_rejected() {
        let (k0, k1, k2) = (key(), key(), key());
        let mut reg = IdentityRegistry::default();
        assert!(reg.ingest_rotation(&rotation(&k0, &k1, 3)));
        assert!(!reg.ingest_rotation(&rotation(&k0, &k2, 3)));
    }

    #[test]
    fn rotation_cycle_is_rejected_not_looped_forever() {
        let (k0, k1) = (key(), key());
        let mut reg = IdentityRegistry::default();
        reg.ingest_rotation(&rotation(&k0, &k1, 1));
        reg.ingest_rotation(&rotation(&k1, &k0, 1));
        assert_eq!(reg.resolve_current_key(pk(&k0)), ChainResolution::TooDeep);
        assert!(!reg.is_trusted(&pk(&k0)));
    }

    #[test]
    fn chain_longer_than_cap_is_rejected() {
        let keys: Vec<SigningKey> = (0..MAX_ROTATION_CHAIN_DEPTH + 3).map(|_| key()).collect();
        let mut reg = IdentityRegistry::default();
        for pair in keys.windows(2) {
            reg.ingest_rotation(&rotation(&pair[0], &pair[1], 1));
        }
        assert_eq!(
            reg.resolve_current_key(pk(&keys[0])),
            ChainResolution::TooDeep
        );
    }

    #[test]
    fn earliest_revocation_is_retained() {
        let k = key();
        let mut reg = IdentityRegistry::default();
        let late = KeyRevocationRecord::new_signed(
            IdentitySubjectKind::Node,
            &k,
            RevocationReason::Retired,
            2_000_000_000,
        )
        .expect("sign");
        let early = KeyRevocationRecord::new_signed(
            IdentitySubjectKind::Node,
            &k,
            RevocationReason::Compromised,
            1_000_000_000,
        )
        .expect("sign");
        assert!(reg.ingest_revocation(&late));
        assert!(reg.ingest_revocation(&early));
        // Earlier record replaced the later one.
        assert_eq!(
            reg.revocation_reason(&pk(&k)),
            Some(RevocationReason::Compromised)
        );
        // A redundant later record is not re-applied.
        assert!(!reg.ingest_revocation(&late));
    }

    #[test]
    fn self_rotation_is_rejected() {
        let k = key();
        let mut reg = IdentityRegistry::default();
        // Construct by hand — new_signed refuses to build this.
        let mut rec = rotation(&k, &key(), 1);
        rec.new_pubkey = rec.old_pubkey;
        assert!(!reg.ingest_rotation(&rec));
    }
}
