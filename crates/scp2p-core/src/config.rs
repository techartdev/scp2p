// Copyright (c) 2024-2026 Vanyo Vanev / Tech Art Ltd
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
use std::net::SocketAddr;
use std::path::PathBuf;

use crate::capabilities::Capabilities;

#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub bind_quic: Option<SocketAddr>,
    pub bind_tcp: Option<SocketAddr>,
    pub capabilities: Capabilities,
    pub bootstrap_peers: Vec<String>,
    /// Directory for storing content blobs on disk.
    ///
    /// When `Some`, published content is persisted to files and served via
    /// seek-based chunk reads instead of being held entirely in RAM.
    /// When `None`, content is kept in an in-memory map (suitable for tests).
    pub blob_dir: Option<PathBuf>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            bind_quic: Some("0.0.0.0:7000".parse().expect("valid socket")),
            bind_tcp: Some("0.0.0.0:7001".parse().expect("valid socket")),
            capabilities: Capabilities {
                dht: true,
                store: true,
                relay: false,
                content_seed: true,
                mobile_light: false,
            },
            bootstrap_peers: vec![],
            blob_dir: None,
        }
    }
}
