// SPDX-License-Identifier: GPL-2.0-only
//! Writes seed inputs for the fuzz targets into `fuzz/corpus/{frame,tlv}`
//! (gitignored): every AWDL frame of the committed fixture and of the local
//! capture corpus, and each of their distinct TLVs as type byte + value.
//!
//!     cargo run -p awdl-proto --example fuzz_seeds

#[path = "../tests/common/mod.rs"]
mod common;

use std::collections::BTreeSet;
use std::path::Path;

use awdl_proto::{Frame, parse};

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus");
    let (frame_dir, tlv_dir) = (root.join("frame"), root.join("tlv"));
    std::fs::create_dir_all(&frame_dir).unwrap();
    std::fs::create_dir_all(&tlv_dir).unwrap();

    let mut mpdus = common::fixture_mpdus();
    for f in common::air_captures() {
        mpdus.extend(common::mpdus(&f).into_iter().map(|(_, m)| m));
    }
    let (mut frames, mut tlvs) = (BTreeSet::new(), BTreeSet::new());
    for m in mpdus {
        let Ok(Some(frame)) = parse(&m) else { continue };
        if let Frame::Action { action, .. } = &frame {
            for t in action.tlvs() {
                tlvs.insert([&[t.kind][..], t.value].concat());
            }
        }
        frames.insert(m);
    }
    for (dir, set) in [(&frame_dir, &frames), (&tlv_dir, &tlvs)] {
        for (i, s) in set.iter().enumerate() {
            std::fs::write(dir.join(format!("seed-{i:05}")), s).unwrap();
        }
    }
    eprintln!("{} frame seeds, {} TLV seeds", frames.len(), tlvs.len());
}
