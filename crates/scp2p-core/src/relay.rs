use std::collections::HashMap;

pub const RELAY_SLOT_TTL_SECS: u64 = 10 * 60;

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
    pub from_peer: String,
    pub to_peer: String,
    pub payload: Vec<u8>,
}

#[derive(Debug, Default, Clone)]
pub struct RelayManager {
    next_slot_id: u64,
    slots: HashMap<u64, RelaySlot>,
}

impl RelayManager {
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

        let to_peer = if from_peer == slot.owner_peer {
            "connected-peer".to_string()
        } else {
            slot.owner_peer
        };

        Ok(RelayStream {
            relay_slot_id,
            stream_id,
            from_peer,
            to_peer,
            payload,
        })
    }

    fn evict_expired(&mut self, now: u64) {
        self.slots.retain(|_, slot| slot.expires_at > now);
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
}
