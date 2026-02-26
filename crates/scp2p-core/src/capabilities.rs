use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Capabilities {
    pub dht: bool,
    pub store: bool,
    pub relay: bool,
    pub content_seed: bool,
    pub mobile_light: bool,
}
