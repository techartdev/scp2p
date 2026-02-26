use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

use crate::peer::PeerAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub r#type: u16,
    pub req_id: u32,
    pub flags: u16,
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
}

/// Default upper bound for serialized envelope size accepted from the wire.
pub const MAX_ENVELOPE_BYTES: usize = 2 * 1024 * 1024;
/// Default upper bound for decoded payload bytes accepted from the wire.
pub const MAX_ENVELOPE_PAYLOAD_BYTES: usize = 1024 * 1024;

impl Envelope {
    pub fn encode(&self) -> anyhow::Result<Vec<u8>> {
        Ok(serde_cbor::to_vec(self)?)
    }

    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        Self::decode_with_limits(bytes, MAX_ENVELOPE_BYTES, MAX_ENVELOPE_PAYLOAD_BYTES)
    }

    pub fn decode_with_limits(
        bytes: &[u8],
        max_envelope_bytes: usize,
        max_payload_bytes: usize,
    ) -> anyhow::Result<Self> {
        if bytes.len() > max_envelope_bytes {
            anyhow::bail!(
                "envelope exceeds max size: {} > {}",
                bytes.len(),
                max_envelope_bytes
            );
        }

        let envelope: Self = serde_cbor::from_slice(bytes)?;
        if envelope.payload.len() > max_payload_bytes {
            anyhow::bail!(
                "envelope payload exceeds max size: {} > {}",
                envelope.payload.len(),
                max_payload_bytes
            );
        }
        Ok(envelope)
    }

    /// Decode the envelope payload into a typed protocol message.
    pub fn decode_typed(&self) -> anyhow::Result<WirePayload> {
        WirePayload::decode(self.r#type, &self.payload)
    }

    /// Build an envelope from a typed protocol payload.
    pub fn from_typed(req_id: u32, flags: u16, payload: &WirePayload) -> anyhow::Result<Self> {
        Ok(Self {
            r#type: u16::from(payload.msg_type()),
            req_id,
            flags,
            payload: payload.encode()?,
        })
    }
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MsgType {
    /// Peer exchange with known-good peer addresses.
    PexOffer = 100,
    /// Request peer exchange records from a remote peer.
    PexRequest = 101,
    /// Kademlia FIND_NODE query.
    FindNode = 200,
    /// Kademlia FIND_VALUE query.
    FindValue = 201,
    /// Kademlia STORE request.
    Store = 202,
    /// Subscription manifest request.
    GetManifest = 400,
    /// Serialized manifest response.
    ManifestData = 401,
    /// Relay registration request.
    RelayRegister = 450,
    /// Relay registration acknowledgement.
    RelayRegistered = 451,
    /// Relay connection request.
    RelayConnect = 452,
    /// Relay stream frame.
    RelayStream = 453,
    /// Provider hint response for a content object.
    Providers = 498,
    /// Provider hint advertisement for a content object.
    HaveContent = 499,
    /// Chunk request.
    GetChunk = 500,
    /// Chunk payload response.
    ChunkData = 501,
}

impl MsgType {
    /// Stable `u16` registry for protocol envelope types.
    pub const ALL: [Self; 15] = [
        Self::PexOffer,
        Self::PexRequest,
        Self::FindNode,
        Self::FindValue,
        Self::Store,
        Self::GetManifest,
        Self::ManifestData,
        Self::RelayRegister,
        Self::RelayRegistered,
        Self::RelayConnect,
        Self::RelayStream,
        Self::Providers,
        Self::HaveContent,
        Self::GetChunk,
        Self::ChunkData,
    ];
}

impl From<MsgType> for u16 {
    fn from(value: MsgType) -> Self {
        value as u16
    }
}

impl TryFrom<u16> for MsgType {
    type Error = anyhow::Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            100 => Ok(Self::PexOffer),
            101 => Ok(Self::PexRequest),
            200 => Ok(Self::FindNode),
            201 => Ok(Self::FindValue),
            202 => Ok(Self::Store),
            400 => Ok(Self::GetManifest),
            401 => Ok(Self::ManifestData),
            450 => Ok(Self::RelayRegister),
            451 => Ok(Self::RelayRegistered),
            452 => Ok(Self::RelayConnect),
            453 => Ok(Self::RelayStream),
            498 => Ok(Self::Providers),
            499 => Ok(Self::HaveContent),
            500 => Ok(Self::GetChunk),
            501 => Ok(Self::ChunkData),
            _ => anyhow::bail!("unknown message type {value}"),
        }
    }
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

/// Typed envelope payloads used by dispatcher-style message handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WirePayload {
    PexOffer(PexOffer),
    PexRequest(PexRequest),
    FindNode(FindNode),
    FindValue(FindValue),
    Store(Store),
    GetManifest(GetManifest),
    ManifestData(ManifestData),
    RelayRegister(RelayRegister),
    RelayRegistered(RelayRegistered),
    RelayConnect(RelayConnect),
    RelayStream(RelayStream),
    Providers(Providers),
    HaveContent(HaveContent),
    GetChunk(GetChunk),
    ChunkData(ChunkData),
}

impl WirePayload {
    pub fn msg_type(&self) -> MsgType {
        match self {
            Self::PexOffer(_) => MsgType::PexOffer,
            Self::PexRequest(_) => MsgType::PexRequest,
            Self::FindNode(_) => MsgType::FindNode,
            Self::FindValue(_) => MsgType::FindValue,
            Self::Store(_) => MsgType::Store,
            Self::GetManifest(_) => MsgType::GetManifest,
            Self::ManifestData(_) => MsgType::ManifestData,
            Self::RelayRegister(_) => MsgType::RelayRegister,
            Self::RelayRegistered(_) => MsgType::RelayRegistered,
            Self::RelayConnect(_) => MsgType::RelayConnect,
            Self::RelayStream(_) => MsgType::RelayStream,
            Self::Providers(_) => MsgType::Providers,
            Self::HaveContent(_) => MsgType::HaveContent,
            Self::GetChunk(_) => MsgType::GetChunk,
            Self::ChunkData(_) => MsgType::ChunkData,
        }
    }

    pub fn encode(&self) -> anyhow::Result<Vec<u8>> {
        Ok(match self {
            Self::PexOffer(msg) => serde_cbor::to_vec(msg)?,
            Self::PexRequest(msg) => serde_cbor::to_vec(msg)?,
            Self::FindNode(msg) => serde_cbor::to_vec(msg)?,
            Self::FindValue(msg) => serde_cbor::to_vec(msg)?,
            Self::Store(msg) => serde_cbor::to_vec(msg)?,
            Self::GetManifest(msg) => serde_cbor::to_vec(msg)?,
            Self::ManifestData(msg) => serde_cbor::to_vec(msg)?,
            Self::RelayRegister(msg) => serde_cbor::to_vec(msg)?,
            Self::RelayRegistered(msg) => serde_cbor::to_vec(msg)?,
            Self::RelayConnect(msg) => serde_cbor::to_vec(msg)?,
            Self::RelayStream(msg) => serde_cbor::to_vec(msg)?,
            Self::Providers(msg) => serde_cbor::to_vec(msg)?,
            Self::HaveContent(msg) => serde_cbor::to_vec(msg)?,
            Self::GetChunk(msg) => serde_cbor::to_vec(msg)?,
            Self::ChunkData(msg) => serde_cbor::to_vec(msg)?,
        })
    }

    pub fn decode(message_type: u16, payload: &[u8]) -> anyhow::Result<Self> {
        let msg_type = MsgType::try_from(message_type)?;
        Ok(match msg_type {
            MsgType::PexOffer => Self::PexOffer(serde_cbor::from_slice(payload)?),
            MsgType::PexRequest => Self::PexRequest(serde_cbor::from_slice(payload)?),
            MsgType::FindNode => Self::FindNode(serde_cbor::from_slice(payload)?),
            MsgType::FindValue => Self::FindValue(serde_cbor::from_slice(payload)?),
            MsgType::Store => Self::Store(serde_cbor::from_slice(payload)?),
            MsgType::GetManifest => Self::GetManifest(serde_cbor::from_slice(payload)?),
            MsgType::ManifestData => Self::ManifestData(serde_cbor::from_slice(payload)?),
            MsgType::RelayRegister => Self::RelayRegister(serde_cbor::from_slice(payload)?),
            MsgType::RelayRegistered => Self::RelayRegistered(serde_cbor::from_slice(payload)?),
            MsgType::RelayConnect => Self::RelayConnect(serde_cbor::from_slice(payload)?),
            MsgType::RelayStream => Self::RelayStream(serde_cbor::from_slice(payload)?),
            MsgType::Providers => Self::Providers(serde_cbor::from_slice(payload)?),
            MsgType::HaveContent => Self::HaveContent(serde_cbor::from_slice(payload)?),
            MsgType::GetChunk => Self::GetChunk(serde_cbor::from_slice(payload)?),
            MsgType::ChunkData => Self::ChunkData(serde_cbor::from_slice(payload)?),
        })
    }
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

    #[test]
    fn msg_type_registry_roundtrip_and_unique_values() {
        let mut sorted_values = MsgType::ALL
            .iter()
            .copied()
            .map(u16::from)
            .collect::<Vec<u16>>();

        for msg_type in MsgType::ALL {
            let wire_value = u16::from(msg_type);
            let roundtrip = MsgType::try_from(wire_value).expect("registry roundtrip");
            assert_eq!(roundtrip, msg_type);
        }

        let expected_len = sorted_values.len();
        sorted_values.sort_unstable();
        sorted_values.dedup();
        assert_eq!(sorted_values.len(), expected_len);
    }

    #[test]
    fn envelope_decode_rejects_large_payload_limit() {
        let envelope = Envelope {
            r#type: MsgType::ChunkData as u16,
            req_id: 9,
            flags: 0,
            payload: vec![7u8; 32],
        };
        let encoded = envelope.encode().expect("encode envelope");

        let err = Envelope::decode_with_limits(&encoded, 1024, 16)
            .expect_err("payload limit should reject envelope");
        assert!(err.to_string().contains("payload exceeds max size"));
    }

    #[test]
    fn envelope_decode_rejects_large_serialized_limit() {
        let envelope = Envelope {
            r#type: MsgType::PexOffer as u16,
            req_id: 10,
            flags: 0,
            payload: vec![1u8; 8],
        };
        let encoded = envelope.encode().expect("encode envelope");

        let err = Envelope::decode_with_limits(&encoded, 2, 1024)
            .expect_err("envelope bytes limit should reject envelope");
        assert!(err.to_string().contains("envelope exceeds max size"));
    }

    #[test]
    fn typed_payload_dispatch_roundtrip_for_all_registered_types() {
        let cases = vec![
            WirePayload::PexOffer(PexOffer {
                peers: vec![PeerAddr {
                    ip: "10.0.0.2".parse().expect("valid ip"),
                    port: 1234,
                    transport: TransportProtocol::Tcp,
                    pubkey_hint: None,
                }],
            }),
            WirePayload::PexRequest(PexRequest { max_peers: 8 }),
            WirePayload::FindNode(FindNode {
                target_node_id: NodeId([1u8; 20]).0,
            }),
            WirePayload::FindValue(FindValue { key: [2u8; 32] }),
            WirePayload::Store(Store {
                key: [3u8; 32],
                value: vec![1, 2, 3],
                ttl_secs: 15,
            }),
            WirePayload::GetManifest(GetManifest {
                manifest_id: [4u8; 32],
            }),
            WirePayload::ManifestData(ManifestData {
                manifest_id: [5u8; 32],
                bytes: vec![9, 8, 7],
            }),
            WirePayload::RelayRegister(RelayRegister {}),
            WirePayload::RelayRegistered(RelayRegistered {
                relay_slot_id: 77,
                expires_at: 88,
            }),
            WirePayload::RelayConnect(RelayConnect { relay_slot_id: 11 }),
            WirePayload::RelayStream(RelayStream {
                relay_slot_id: 11,
                stream_id: 3,
                payload: vec![5, 4, 3],
            }),
            WirePayload::Providers(Providers {
                content_id: [6u8; 32],
                providers: vec![PeerAddr {
                    ip: "10.0.0.3".parse().expect("valid ip"),
                    port: 9999,
                    transport: TransportProtocol::Quic,
                    pubkey_hint: Some([1u8; 32]),
                }],
                updated_at: 321,
            }),
            WirePayload::HaveContent(HaveContent {
                content_id: [7u8; 32],
            }),
            WirePayload::GetChunk(GetChunk {
                content_id: [8u8; 32],
                chunk_index: 2,
            }),
            WirePayload::ChunkData(ChunkData {
                content_id: [9u8; 32],
                chunk_index: 2,
                bytes: vec![6, 6, 6],
            }),
        ];

        for (idx, message) in cases.iter().enumerate() {
            let envelope = Envelope::from_typed(idx as u32, 0, message).expect("build envelope");
            let decoded = envelope.decode_typed().expect("decode typed payload");
            assert_eq!(&decoded, message);
        }
    }
}
