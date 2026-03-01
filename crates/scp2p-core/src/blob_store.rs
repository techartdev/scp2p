// Copyright (c) 2024-2026 Vanyo Vanev / Tech Art Ltd
// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//! Path-based chunk I/O for content seeding.
//!
//! Instead of copying file bytes into a separate blob store, the node serves
//! chunks directly from the original file (publisher) or the downloaded file
//! (subscriber).  This module provides the low-level seek-and-read helper.

use std::{
    io::{Read, Seek, SeekFrom},
    path::Path,
};

use crate::content::CHUNK_SIZE;

/// Validate that `path` does not contain any `..` components.
///
/// Returns an error if path traversal segments are detected.
/// This is a defence-in-depth check; callers should already sanitise paths.
pub fn validate_no_traversal(path: &Path) -> anyhow::Result<()> {
    for component in path.components() {
        if matches!(component, std::path::Component::ParentDir) {
            anyhow::bail!(
                "path contains disallowed '..' component: {}",
                path.display()
            );
        }
    }
    Ok(())
}

/// Read a single chunk (up to 256 KiB) from an arbitrary file on disk.
///
/// Seeks to `chunk_index * CHUNK_SIZE` and reads the lesser of `CHUNK_SIZE`
/// and the remaining bytes.  Returns `Ok(None)` if the file does not exist
/// or the chunk index is beyond the end of the file.
pub fn read_chunk_from_path(path: &Path, chunk_index: u32) -> anyhow::Result<Option<Vec<u8>>> {
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let file_len = file.metadata()?.len();
    let start = (chunk_index as u64) * (CHUNK_SIZE as u64);
    if start >= file_len {
        return Ok(None);
    }
    let end = ((chunk_index as u64 + 1) * (CHUNK_SIZE as u64)).min(file_len);
    let len = (end - start) as usize;

    file.seek(SeekFrom::Start(start))?;
    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf)?;
    Ok(Some(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_chunk_from_path_basic() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let data = vec![7u8; CHUNK_SIZE * 2 + 55];
        std::fs::write(tmp.path(), &data).unwrap();

        let c0 = read_chunk_from_path(tmp.path(), 0).unwrap().unwrap();
        assert_eq!(c0.len(), CHUNK_SIZE);
        assert_eq!(c0, &data[..CHUNK_SIZE]);

        let c1 = read_chunk_from_path(tmp.path(), 1).unwrap().unwrap();
        assert_eq!(c1.len(), CHUNK_SIZE);
        assert_eq!(c1, &data[CHUNK_SIZE..CHUNK_SIZE * 2]);

        let c2 = read_chunk_from_path(tmp.path(), 2).unwrap().unwrap();
        assert_eq!(c2.len(), 55);
        assert_eq!(c2, &data[CHUNK_SIZE * 2..]);

        // Out of range
        assert!(read_chunk_from_path(tmp.path(), 3).unwrap().is_none());

        // Non-existent file
        assert!(
            read_chunk_from_path(Path::new("/no/such/file"), 0)
                .unwrap()
                .is_none()
        );
    }
}
