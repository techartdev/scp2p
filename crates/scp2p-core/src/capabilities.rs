// Copyright (c) 2024-2026 Vanyo Vanev / Tech Art Ltd
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct Capabilities {
    pub dht: bool,
    pub store: bool,
    pub relay: bool,
    pub content_seed: bool,
    pub mobile_light: bool,
    /// Supports paginated community member/share browse (§15.6.1).
    #[serde(default)]
    pub community_paged_browse: bool,
    /// Supports community metadata search (§15.6.2).
    #[serde(default)]
    pub community_search: bool,
    /// Supports community delta/event sync (§15.6.3).
    #[serde(default)]
    pub community_delta_sync: bool,
}
