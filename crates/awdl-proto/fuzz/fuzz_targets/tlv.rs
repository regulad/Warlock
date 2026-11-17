// SPDX-License-Identifier: GPL-2.0-only
//! First byte: TLV type; the rest: its value. Any value a typed decoder
//! accepts must re-emit exactly.

#![no_main]

use awdl_proto::tlv::Tlv;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&kind, value)) = data.split_first() else { return };
    let Ok(body) = (Tlv { kind, value }).decode() else { return };
    let mut v = Vec::new();
    body.emit_value(&mut v).expect("emitting a parsed TLV");
    assert_eq!(v, value, "typed re-emit of TLV {kind}");
    let mut full = Vec::new();
    body.emit(&mut full).unwrap();
    assert_eq!(full[0], kind);
    assert_eq!(&full[3..], value);
});
