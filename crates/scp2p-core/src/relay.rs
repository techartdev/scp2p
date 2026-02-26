use std::collections::{HashMap, HashSet};

pub const RELAY_SLOT_TTL_SECS: u64 = 10 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayPayloadKind {
    Control,
    Content,
}

#[derive(Debug, Clone)]
pub struct RelayLimits {
    pub max_control_bytes_per_day: u64,
    pub max_content_bytes_per_day: u64,
    pub max_streams_per_day: usize,
    pub content_relay_enabled: bool,
}

impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            max_control_bytes_per_day: 16 * 1024 * 1024,
            max_content_bytes_per_day: 4 * 1024 * 1024,
            max_streams_per_day: 1024,
            content_relay_enabled: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaySlot {
    pub relay_slot_id: u64,
    pub owner_peer: String,
    pub expires_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayLink {
    pub relay_slot_id: u64,
    pub owner_peer: String,
    pub requester_peer: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayStream {
    pub relay_slot_id: u64,
    pub stream_id: u32,
    pub kind: RelayPayloadKind,
    pub from_peer: String,
    pub to_peer: String,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
struct RelayUsage {
    day_bucket: u64,
    control_bytes: u64,
    content_bytes: u64,
    stream_ids: HashSet<u32>,
}

impl RelayUsage {
    fn new(day_bucket: u64) -> Self {
        Self {
            day_bucket,
            control_bytes: 0,
            content_bytes: 0,
            stream_ids: HashSet::new(),
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct RelayManager {
    next_slot_id: u64,
    slots: HashMap<u64, RelaySlot>,
    usage: HashMap<u64, RelayUsage>,
    limits: RelayLimits,
}

impl RelayManager {
    pub fn set_limits(&mut self, limits: RelayLimits) {
        self.limits = limits;
    }

    pub fn register(&mut self, owner_peer: String, now: u64) -> RelaySlot {
        self.next_slot_id = self.next_slot_id.saturating_add(1);
        let slot = RelaySlot {
            relay_slot_id: self.next_slot_id,
            owner_peer,
            expires_at: now.saturating_add(RELAY_SLOT_TTL_SECS),
        };
        self.slots.insert(slot.relay_slot_id, slot.clone());
        slot
    }

    pub fn register_or_renew(
        &mut self,
        owner_peer: String,
        relay_slot_id: Option<u64>,
        now: u64,
    ) -> anyhow::Result<RelaySlot> {
        self.evict_expired(now);
        let Some(slot_id) = relay_slot_id else {
            return Ok(self.register(owner_peer, now));
        };
        let slot = self
            .slots
            .get_mut(&slot_id)
            .ok_or_else(|| anyhow::anyhow!("relay slot not found"))?;
        if slot.owner_peer != owner_peer {
            anyhow::bail!("relay slot owner mismatch");
        }
        slot.expires_at = now.saturating_add(RELAY_SLOT_TTL_SECS);
        Ok(slot.clone())
    }

    pub fn connect(
        &mut self,
        requester_peer: String,
        relay_slot_id: u64,
        now: u64,
    ) -> anyhow::Result<RelayLink> {
        self.evict_expired(now);
        let slot = self
            .slots
            .get(&relay_slot_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("relay slot not found"))?;

        Ok(RelayLink {
            relay_slot_id,
            owner_peer: slot.owner_peer,
            requester_peer,
        })
    }

    pub fn relay_stream(
        &mut self,
        relay_slot_id: u64,
        stream_id: u32,
        kind: RelayPayloadKind,
        from_peer: String,
        payload: Vec<u8>,
        now: u64,
    ) -> anyhow::Result<RelayStream> {
        self.evict_expired(now);
        let slot = self
            .slots
            .get(&relay_slot_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("relay slot not found"))?;

        self.enforce_quota(relay_slot_id, stream_id, kind, payload.len(), now)?;

        let to_peer = if from_peer == slot.owner_peer {
            "connected-peer".to_string()
        } else {
            slot.owner_peer
        };

        Ok(RelayStream {
            relay_slot_id,
            stream_id,
            kind,
            from_peer,
            to_peer,
            payload,
        })
    }

    fn enforce_quota(
        &mut self,
        relay_slot_id: u64,
        stream_id: u32,
        kind: RelayPayloadKind,
        payload_len: usize,
        now: u64,
    ) -> anyhow::Result<()> {
        if matches!(kind, RelayPayloadKind::Content) && !self.limits.content_relay_enabled {
            anyhow::bail!("content relay is disabled");
        }

        let day_bucket = now / 86_400;
        let usage = self
            .usage
            .entry(relay_slot_id)
            .or_insert_with(|| RelayUsage::new(day_bucket));
        if usage.day_bucket != day_bucket {
            *usage = RelayUsage::new(day_bucket);
        }

        if usage.stream_ids.insert(stream_id)
            && usage.stream_ids.len() > self.limits.max_streams_per_day
        {
            anyhow::bail!("relay stream quota exceeded");
        }

        let bytes = payload_len as u64;
        match kind {
            RelayPayloadKind::Control => {
                if usage.control_bytes.saturating_add(bytes) > self.limits.max_control_bytes_per_day
                {
                    anyhow::bail!("relay control-byte quota exceeded");
                }
                usage.control_bytes = usage.control_bytes.saturating_add(bytes);
            }
            RelayPayloadKind::Content => {
                if usage.content_bytes.saturating_add(bytes) > self.limits.max_content_bytes_per_day
                {
                    anyhow::bail!("relay content-byte quota exceeded");
                }
                usage.content_bytes = usage.content_bytes.saturating_add(bytes);
            }
        }
        Ok(())
    }

    fn evict_expired(&mut self, now: u64) {
        self.slots.retain(|slot_id, slot| {
            let keep = slot.expires_at > now;
            if !keep {
                self.usage.remove(slot_id);
            }
            keep
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_and_connect_roundtrip() {
        let mut relay = RelayManager::default();
        let slot = relay.register("peer-a".into(), 100);
        let link = relay
            .connect("peer-b".into(), slot.relay_slot_id, 101)
            .expect("connect");
        assert_eq!(link.owner_peer, "peer-a");
        assert_eq!(link.requester_peer, "peer-b");
    }

    #[test]
    fn expired_slots_are_rejected() {
        let mut relay = RelayManager::default();
        let slot = relay.register("peer-a".into(), 100);
        let err = relay
            .connect(
                "peer-b".into(),
                slot.relay_slot_id,
                100 + RELAY_SLOT_TTL_SECS + 1,
            )
            .expect_err("must expire");
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn register_or_renew_extends_existing_slot() {
        let mut relay = RelayManager::default();
        let slot = relay.register("peer-a".into(), 100);
        let renewed = relay
            .register_or_renew("peer-a".into(), Some(slot.relay_slot_id), 150)
            .expect("renew");
        assert_eq!(renewed.relay_slot_id, slot.relay_slot_id);
        assert_eq!(renewed.expires_at, 150 + RELAY_SLOT_TTL_SECS);
    }

    #[test]
    fn renew_rejects_wrong_owner() {
        let mut relay = RelayManager::default();
        let slot = relay.register("peer-a".into(), 100);
        let err = relay
            .register_or_renew("peer-b".into(), Some(slot.relay_slot_id), 101)
            .expect_err("owner mismatch must fail");
        assert!(err.to_string().contains("owner mismatch"));
    }

    #[test]
    fn content_relay_disabled_by_default() {
        let mut relay = RelayManager::default();
        let slot = relay.register("peer-a".into(), 100);
        relay
            .connect("peer-b".into(), slot.relay_slot_id, 101)
            .expect("connect");
        let err = relay
            .relay_stream(
                slot.relay_slot_id,
                1,
                RelayPayloadKind::Content,
                "peer-b".into(),
                vec![1, 2, 3],
                102,
            )
            .expect_err("content relay disabled");
        assert!(err.to_string().contains("disabled"));
    }

    #[test]
    fn control_bytes_quota_is_enforced() {
        let mut relay = RelayManager::default();
        relay.set_limits(RelayLimits {
            max_control_bytes_per_day: 5,
            ..RelayLimits::default()
        });
        let slot = relay.register("peer-a".into(), 100);
        relay
            .connect("peer-b".into(), slot.relay_slot_id, 101)
            .expect("connect");
        relay
            .relay_stream(
                slot.relay_slot_id,
                1,
                RelayPayloadKind::Control,
                "peer-b".into(),
                vec![1, 2],
                102,
            )
            .expect("within quota");
        let err = relay
            .relay_stream(
                slot.relay_slot_id,
                2,
                RelayPayloadKind::Control,
                "peer-b".into(),
                vec![1, 2, 3, 4],
                103,
            )
            .expect_err("must exceed quota");
        assert!(err.to_string().contains("quota"));
    }

    #[test]
    fn stream_count_quota_is_enforced() {
        let mut relay = RelayManager::default();
        relay.set_limits(RelayLimits {
            max_streams_per_day: 1,
            ..RelayLimits::default()
        });
        let slot = relay.register("peer-a".into(), 100);
        relay
            .connect("peer-b".into(), slot.relay_slot_id, 101)
            .expect("connect");
        relay
            .relay_stream(
                slot.relay_slot_id,
                1,
                RelayPayloadKind::Control,
                "peer-b".into(),
                vec![1],
                102,
            )
            .expect("first stream id");
        let err = relay
            .relay_stream(
                slot.relay_slot_id,
                2,
                RelayPayloadKind::Control,
                "peer-b".into(),
                vec![1],
                103,
            )
            .expect_err("must exceed stream cap");
        assert!(err.to_string().contains("stream quota"));
    }
}
