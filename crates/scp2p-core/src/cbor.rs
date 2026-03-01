// Copyright (c) 2024-2026 Vanyo Vanev / Tech Art Ltd
// SPDX-License-Identifier: MPL-2.0
//
// Thin wrappers around `ciborium` providing `serde_cbor`-compatible
// function signatures (`to_vec`, `from_slice`).

use serde::{de::DeserializeOwned, Serialize};

/// Convenience re-export of the ciborium `Value` type.
pub use ciborium::Value;

/// Serialize `value` into a CBOR byte vector.
pub fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, ciborium::ser::Error<std::io::Error>> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)?;
    Ok(buf)
}

/// Deserialize `T` from a CBOR byte slice.
pub fn from_slice<T: DeserializeOwned>(
    bytes: &[u8],
) -> Result<T, ciborium::de::Error<std::io::Error>> {
    ciborium::from_reader(bytes)
}
