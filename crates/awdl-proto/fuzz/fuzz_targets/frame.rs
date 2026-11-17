// SPDX-License-Identifier: GPL-2.0-only
//! Any MPDU `parse` accepts must re-emit exactly: raw, TLV by TLV through the
//! typed decoders, and rebuilt through the builder. Accessors mustn't panic.

#![no_main]

use awdl_proto::action::ActionFrameBuilder;
use awdl_proto::tlv::{Rdata, TlvBody};
use awdl_proto::{Frame, parse};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(Some(frame)) = parse(data) else { return };
    let mut raw = Vec::new();
    frame.emit(&mut raw);
    assert_eq!(raw, data, "raw re-emit");

    let Frame::Action { header, action } = &frame else { return };
    let mut b = ActionFrameBuilder::new(header, &action.header);
    for t in action.tlvs() {
        match t.decode() {
            Ok(body) => {
                let mut v = Vec::new();
                body.emit_value(&mut v).expect("emitting a parsed TLV");
                assert_eq!(v, t.value, "typed re-emit of TLV {}", t.kind);
                touch(&body);
                b.tlv(&body).unwrap();
            }
            Err(_) => {
                b.raw_tlv(t.kind, t.value).unwrap();
            }
        }
    }
    let mut rebuilt = b.finish();
    rebuilt.extend_from_slice(action.trailer());
    assert_eq!(rebuilt, data, "rebuilt frame");
});

fn touch(body: &TlvBody<'_>) {
    match body {
        TlvBody::SyncParams(s) => s.channel_sequence.channels().for_each(|c| drop(c.number())),
        TlvBody::ChannelSequence(c) => c.sequence.channels().for_each(|c| drop(c.number())),
        TlvBody::ServiceResponse(s) => {
            drop(s.name.to_dotted());
            s.rdata.txt_strings().for_each(drop);
            match &s.rdata {
                Rdata::Srv { target, .. } => drop(target.to_dotted()),
                Rdata::Ptr(p) => drop(p.to_dotted()),
                _ => {}
            }
        }
        TlvBody::ServiceParams(s) => drop(s.set_values().count()),
        TlvBody::Ieee80211Container(c) => drop(c.elements().count()),
        TlvBody::SyncTree(t) => drop(t.addresses().count()),
        TlvBody::Arpa(a) => drop(a.name.to_dotted()),
        TlvBody::DataPathState(d) => drop(d.wire_flags()),
        _ => {}
    }
}
