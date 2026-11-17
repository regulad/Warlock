// SPDX-License-Identifier: GPL-2.0-only
//! Test helpers over `warlock-capture`: the local capture corpus (gitignored;
//! tests that need it skip when it's absent) and the committed fixture.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// The radiotap captures in the local corpus, sorted by name.
pub fn air_captures() -> Vec<PathBuf> {
    warlock_capture::corpus_files()
}

/// The MPDUs of a capture, with their Wireshark frame numbers.
pub fn mpdus(path: &Path) -> Vec<(usize, Vec<u8>)> {
    warlock_capture::read(path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
        .into_iter()
        .map(|c| (c.number, c.mpdu))
        .collect()
}

/// The committed, anonymized fixture (see `examples/scrub.rs`): bare MPDUs.
pub fn fixture_mpdus() -> Vec<Vec<u8>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/awdl-scrubbed.pcapng");
    mpdus(&path).into_iter().map(|(_, m)| m).collect()
}
