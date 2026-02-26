use serde::{Deserialize, Serialize};

use crate::peer::PeerAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub r#type: u16,
    pub req_id: u32,
    pub flags: u16,
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
}

impl Envelope {
    pub fn encode(&self) -> anyhow::Result<Vec<u8>> {
        Ok(serde_cbor::to_vec(self)?)
    }

    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        Ok(serde_cbor::from_slice(bytes)?)
    }
}

#[repr(u16)]
#[derive(Debug, Clone, Copy)]
pub enum MsgType {
    PexOffer = 100,
    PexRequest = 101,
    FindNode = 200,
    FindValue = 201,
    Store = 202,
    GetManifest = 400,
    ManifestData = 401,
    RelayRegister = 450,
    RelayRegistered = 451,
    RelayConnect = 452,
    RelayStream = 453,
    HaveContent = 499,
    GetChunk = 500,
    ChunkData = 501,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PexOffer {
    pub peers: Vec<PeerAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PexRequest {
    pub max_peers: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindNode {
    pub target_node_id: [u8; 20],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindNodeResult {
    pub peers: Vec<PeerAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindValue {
    pub key: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Store {
    pub key: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub value: Vec<u8>,
    pub ttl_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FindValueResult {
    pub value: Option<Store>,
    pub closer_peers: Vec<PeerAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GetManifest {
    pub manifest_id: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestData {
    pub manifest_id: [u8; 32],
    #[serde(with = "serde_bytes")]
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayRegister {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayRegistered {
    pub relay_slot_id: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayConnect {
    pub relay_slot_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayStream {
    pub relay_slot_id: u64,
    pub stream_id: u32,
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HaveContent {
    pub content_id: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Providers {
    pub content_id: [u8; 32],
    pub providers: Vec<PeerAddr>,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GetChunk {
    pub content_id: [u8; 32],
    pub chunk_index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChunkData {
    pub content_id: [u8; 32],
    pub chunk_index: u32,
    #[serde(with = "serde_bytes")]
    pub bytes: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ids::NodeId, peer::TransportProtocol};

    #[test]
    fn envelope_roundtrip() {
        let payload = PexRequest { max_peers: 32 };
        let envelope = Envelope {
            r#type: MsgType::PexRequest as u16,
            req_id: 7,
            flags: 0,
            payload: serde_cbor::to_vec(&payload).expect("encode payload"),
        };

        let encoded = envelope.encode().expect("encode envelope");
        let decoded = Envelope::decode(&encoded).expect("decode envelope");
        let decoded_payload: PexRequest =
            serde_cbor::from_slice(&decoded.payload).expect("decode payload");

        assert_eq!(decoded.r#type, MsgType::PexRequest as u16);
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn pex_offer_roundtrip() {
        let offer = PexOffer {
            peers: vec![PeerAddr {
                ip: "10.0.0.5".parse().expect("valid ip"),
                port: 7001,
                transport: TransportProtocol::Tcp,
                pubkey_hint: Some([1u8; 32]),
            }],
        };

        let encoded = serde_cbor::to_vec(&offer).expect("encode pex offer");
        let decoded: PexOffer = serde_cbor::from_slice(&encoded).expect("decode pex offer");
        assert_eq!(decoded, offer);
    }

    #[test]
    fn dht_messages_roundtrip() {
        let find_node = FindNode {
            target_node_id: NodeId([1u8; 20]).0,
        };
        let find_node_roundtrip: FindNode =
            serde_cbor::from_slice(&serde_cbor::to_vec(&find_node).expect("encode find node"))
                .expect("decode find node");
        assert_eq!(find_node_roundtrip, find_node);

        let store = Store {
            key: [9u8; 32],
            value: vec![1, 2, 3],
            ttl_secs: 60,
        };
        let find_value_result = FindValueResult {
            value: Some(store),
            closer_peers: vec![PeerAddr {
                ip: "192.168.1.2".parse().expect("valid ip"),
                port: 7000,
                transport: TransportProtocol::Quic,
                pubkey_hint: None,
            }],
        };

        let encoded = serde_cbor::to_vec(&find_value_result).expect("encode find value result");
        let decoded: FindValueResult =
            serde_cbor::from_slice(&encoded).expect("decode find value result");
        assert_eq!(decoded, find_value_result);
    }

    #[test]
    fn relay_messages_roundtrip() {
        let reg = RelayRegister {};
        let reg_rt: RelayRegister =
            serde_cbor::from_slice(&serde_cbor::to_vec(&reg).expect("encode relay register"))
                .expect("decode relay register");
        assert_eq!(reg_rt, reg);

        let registered = RelayRegistered {
            relay_slot_id: 7,
            expires_at: 99,
        };
        let registered_rt: RelayRegistered = serde_cbor::from_slice(
            &serde_cbor::to_vec(&registered).expect("encode relay registered"),
        )
        .expect("decode relay registered");
        assert_eq!(registered_rt, registered);

        let stream = RelayStream {
            relay_slot_id: 7,
            stream_id: 1,
            payload: vec![1, 2, 3],
        };
        let stream_rt: RelayStream =
            serde_cbor::from_slice(&serde_cbor::to_vec(&stream).expect("encode relay stream"))
                .expect("decode relay stream");
        assert_eq!(stream_rt, stream);
    }

    #[test]
    fn provider_messages_roundtrip() {
        let have = HaveContent {
            content_id: [4u8; 32],
        };
        let have_rt: HaveContent =
            serde_cbor::from_slice(&serde_cbor::to_vec(&have).expect("encode have"))
                .expect("decode have");
        assert_eq!(have_rt, have);

        let prov = Providers {
            content_id: [4u8; 32],
            providers: vec![PeerAddr {
                ip: "10.1.0.2".parse().expect("valid ip"),
                port: 7777,
                transport: TransportProtocol::Quic,
                pubkey_hint: None,
            }],
            updated_at: 123,
        };
        let prov_rt: Providers =
            serde_cbor::from_slice(&serde_cbor::to_vec(&prov).expect("encode providers"))
                .expect("decode providers");
        assert_eq!(prov_rt, prov);
    }

    #[test]
    fn chunk_messages_roundtrip() {
        let get = GetChunk {
            content_id: [9u8; 32],
            chunk_index: 3,
        };
        let get_encoded = serde_cbor::to_vec(&get).expect("encode get chunk");
        let get_decoded: GetChunk = serde_cbor::from_slice(&get_encoded).expect("decode get chunk");
        assert_eq!(get_decoded, get);

        let data = ChunkData {
            content_id: [9u8; 32],
            chunk_index: 3,
            bytes: vec![1, 2, 3],
        };
        let data_encoded = serde_cbor::to_vec(&data).expect("encode chunk data");
        let data_decoded: ChunkData =
            serde_cbor::from_slice(&data_encoded).expect("decode chunk data");
        assert_eq!(data_decoded, data);
    }
}
