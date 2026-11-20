// SPDX-License-Identifier: GPL-2.0-only
//! Cross-checks our decoding against Wireshark's AWDL dissector, field by
//! field, on every AWDL frame of the local capture corpus.
//!
//! The round-trip test can't catch a field read at the wrong offset, since
//! parse and emit would agree with each other. Wireshark's dissector was
//! written independently, so agreement with it is real evidence.
//!
//! Needs tshark: `TSHARK`, or `C:\Program Files\Wireshark\tshark.exe`, or
//! `tshark` on PATH. Skips without it or without the corpus.

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use awdl_proto::dns::{DnsName, Label};
use awdl_proto::tlv::{Channel, ChannelSequence, Rdata, Tlv, TlvBody};
use awdl_proto::{Frame, MacAddr, parse};

/// Wireshark fields compared. Each holds every occurrence in a frame, in
/// dissection order.
const FIELDS: &[&str] = &[
    "awdl.type",
    "awdl.version",
    "awdl.subtype",
    "awdl.reserved",
    "awdl.phytime",
    "awdl.targettime",
    "awdl.tag.number",
    "awdl.tag.length",
    "awdl.tag.padding",
    "awdl.tag.data",
    "awdl.unknown",
    "awdl.version.device_class",
    "awdl.syncparams.txchannel",
    "awdl.syncparams.txcounter",
    "awdl.syncparams.masterchan",
    "awdl.syncparams.guardtime",
    "awdl.syncparams.awperiod",
    "awdl.syncparams.afperiod",
    "awdl.syncparams.awdlflags",
    "awdl.syncparams.aw.ext_len",
    "awdl.syncparams.aw.common_len",
    "awdl.syncparams.aw.remaining",
    "awdl.syncparams.ext.min",
    "awdl.syncparams.ext.max_multicast",
    "awdl.syncparams.ext.max_unicast",
    "awdl.syncparams.ext.max_af",
    "awdl.syncparams.master",
    "awdl.syncparams.presencemode",
    "awdl.syncparams.awseqcounter",
    "awdl.syncparams.apbeaconalignment",
    "awdl.channelseq.channels",
    "awdl.channelseq.encoding",
    "awdl.channelseq.duplicate",
    "awdl.channelseq.step_count",
    "awdl.channelseq.fill_channel",
    "awdl.channelseq.channel.number",
    "awdl.channelseq.channel.operating_class",
    "awdl.channelseq.channel.flags",
    "awdl.electionparams.flags",
    "awdl.electionparams.id",
    "awdl.electionparams.distance",
    "awdl.electionparams.unknown",
    "awdl.electionparams.master",
    "awdl.electionparams.mastermetric",
    "awdl.electionparams.selfmetric",
    "awdl.electionparams.private.master",
    "awdl.electionparams.private.mastermetric",
    "awdl.electionparams.private.id",
    "awdl.electionparams.private.phc",
    "awdl.electionparams2.master",
    "awdl.electionparams2.other",
    "awdl.electionparams2.mastercounter",
    "awdl.electionparams2.disstance",
    "awdl.electionparams2.mastermetric",
    "awdl.electionparams2.selfmetric",
    "awdl.electionparams2.unknown",
    "awdl.electionparams2.reserved",
    "awdl.electionparams2.selfcounter",
    "awdl.serviceparams.sui",
    "awdl.serviceparams.bitmask",
    "awdl.serviceparams.values",
    "awdl.datastate.flags",
    "awdl.datastate.countrycode",
    "awdl.datastate.social_channel",
    "awdl.datastate.social_channel_map",
    "awdl.datastate.infra_bssid",
    "awdl.datastate.infra_channel",
    "awdl.datastate.infra_addr",
    "awdl.datastate.own_awdladdr",
    "awdl.datastate.umi",
    "awdl.datastate.unicast_options_length",
    "awdl.datastate.extflags",
    "awdl.datastate.logtrigger",
    "awdl.datastate.rlfc",
    "awdl.datastate.active_time",
    "awdl.datastate.aw_sequence_counter",
    "awdl.datastate.update_counter",
    "awdl.arpa.flags",
    "awdl.arpa.host",
    "awdl.arpa.domain",
    "awdl.dns.name.len",
    "awdl.dns.name.label",
    "awdl.dns.name.compressed",
    "awdl.dns.type",
    "awdl.dns.data_len",
    "awdl.dns.unknown",
    "awdl.dns.txt",
    "awdl.dns.ptr.label",
    "awdl.dns.ptr.short",
    "awdl.dns.priority",
    "awdl.dns.weight",
    "awdl.dns.port",
    "awdl.dns.target.label",
    "awdl.dns.target.compressed",
    "awdl.synctree.addr",
    "awdl_data.header",
    "awdl_data.seq",
    "awdl_data.ethertype",
];

const AGGREGATOR: char = '\u{1f}';

fn tshark() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("TSHARK") {
        return Some(p.into());
    }
    let default = Path::new(r"C:\Program Files\Wireshark\tshark.exe");
    if default.exists() {
        return Some(default.into());
    }
    Command::new("tshark").arg("-v").output().ok().filter(|o| o.status.success()).map(|_| "tshark".into())
}

type FrameFields = Vec<Vec<String>>;

fn run_tshark(tshark: &Path, file: &Path) -> BTreeMap<usize, FrameFields> {
    let mut cmd = Command::new(tshark);
    cmd.arg("-r").arg(file).args(["-Y", "awdl || awdl_data", "-T", "fields"]);
    cmd.args(["-E", "separator=/t", "-E", "occurrence=a"]);
    cmd.arg("-E").arg(format!("aggregator={AGGREGATOR}"));
    cmd.args(["-e", "frame.number"]);
    for f in FIELDS {
        cmd.args(["-e", f]);
    }
    let out = cmd.output().expect("running tshark");
    let stderr = String::from_utf8_lossy(&out.stderr);
    // A capture killed mid-write is "cut short"; tshark still prints every
    // whole frame, as our reader does.
    assert!(out.status.success() || stderr.contains("cut short"), "tshark failed: {stderr}");
    let text = String::from_utf8_lossy(&out.stdout);
    let mut map = BTreeMap::new();
    for line in text.lines() {
        let mut cols = line.split('\t');
        let num: usize = cols.next().unwrap().parse().unwrap();
        let fields = cols
            .map(|c| if c.is_empty() { Vec::new() } else { c.split(AGGREGATOR).map(str::to_owned).collect() })
            .collect::<Vec<_>>();
        assert_eq!(fields.len(), FIELDS.len());
        map.insert(num, fields);
    }
    map
}

/// Our decoding, in Wireshark's field vocabulary.
#[derive(Default)]
struct Ours(BTreeMap<&'static str, Vec<String>>);

impl Ours {
    fn n(&mut self, f: &'static str, v: impl Into<i64>) {
        self.0.entry(f).or_default().push(v.into().to_string());
    }
    fn s(&mut self, f: &'static str, v: String) {
        self.0.entry(f).or_default().push(v);
    }
    fn mac(&mut self, f: &'static str, m: MacAddr) {
        self.s(f, m.to_string());
    }
    fn hex(&mut self, f: &'static str, b: &[u8]) {
        self.s(f, b.iter().map(|x| format!("{x:02x}")).collect());
    }
    fn name(&mut self, label: &'static str, code: &'static str, n: &DnsName<'_>) {
        for l in n.labels() {
            match l {
                Label::Text(t) => self.s(label, ascii(t)),
                Label::Compressed(c) => self.n(code, c),
            }
        }
    }
    fn chanseq(&mut self, s: &ChannelSequence<'_>) {
        self.n("awdl.channelseq.channels", (s.len() - 1) as i64);
        self.n("awdl.channelseq.encoding", s.encoding);
        self.n("awdl.channelseq.duplicate", s.duplicate_count);
        self.n("awdl.channelseq.step_count", s.step_count);
        self.n("awdl.channelseq.fill_channel", s.fill_channel);
        for c in s.channels() {
            match c {
                Channel::Number(n) => self.n("awdl.channelseq.channel.number", n),
                Channel::Legacy { flags, number } => {
                    self.n("awdl.channelseq.channel.flags", flags);
                    self.n("awdl.channelseq.channel.number", number);
                }
                Channel::OpClass { number, opclass } => {
                    self.n("awdl.channelseq.channel.number", number);
                    self.n("awdl.channelseq.channel.operating_class", opclass);
                }
            }
        }
    }
    fn padding(&mut self, trailing: &[u8]) {
        if !trailing.is_empty() {
            self.hex("awdl.tag.padding", trailing);
        }
    }
    fn into_fields(mut self) -> FrameFields {
        FIELDS.iter().map(|f| self.0.remove(f).unwrap_or_default()).collect()
    }
}

/// Wireshark's ENC_ASCII: bytes above 0x7f become U+FFFD.
fn ascii(b: &[u8]) -> String {
    b.iter().map(|&c| if c < 0x80 { c as char } else { '\u{fffd}' }).collect()
}

/// Our values for one AWDL data body, as Wireshark names them.
fn data_fields(o: &mut Ours, data: &awdl_proto::data::DataFrame<'_>) {
    o.hex("awdl_data.header", &awdl_proto::data::MAGIC);
    o.n("awdl_data.seq", data.seq);
    match data.long_ext() {
        Some(l) => {
            o.hex("awdl_data.header", l.open);
            for t in &l.tlvs {
                tlv_fields(o, t);
            }
            o.hex("awdl_data.header", l.close);
        }
        None => o.hex("awdl_data.header", &data.ext),
    }
    o.n("awdl_data.ethertype", data.ethertype);
}

fn ours(frame: &Frame<'_>) -> FrameFields {
    let mut o = Ours::default();
    match frame {
        Frame::Data { data, .. } => data_fields(&mut o, data),
        // Wireshark dissects each subframe's AWDL data in turn.
        Frame::Amsdu { msdus, .. } => {
            for m in msdus {
                data_fields(&mut o, &m.data);
            }
        }
        Frame::Action { action, .. } => {
            let h = &action.header;
            o.n("awdl.type", awdl_proto::action::AWDL_TYPE);
            o.n("awdl.version", h.version.to_byte());
            o.n("awdl.subtype", h.subtype);
            o.n("awdl.reserved", h.reserved);
            o.n("awdl.phytime", h.phy_tx_time);
            o.n("awdl.targettime", h.target_tx_time);
            for t in action.tlvs() {
                tlv_fields(&mut o, &t);
            }
        }
    }
    o.into_fields()
}

/// Our values for one TLV, under Wireshark's field names.
fn tlv_fields(o: &mut Ours, t: &Tlv<'_>) {
    o.n("awdl.tag.number", t.kind);
    o.n("awdl.tag.length", t.value.len() as i64);
    let Ok(body) = t.decode() else {
        o.s("awdl.tag.number", "<our decode failed>".into());
        return;
    };
    match &body {
        TlvBody::SyncParams(s) => {
            o.n("awdl.syncparams.txchannel", s.tx_channel);
            o.n("awdl.syncparams.txcounter", s.tx_counter);
            o.n("awdl.syncparams.masterchan", s.master_channel);
            o.n("awdl.syncparams.guardtime", s.guard_time);
            o.n("awdl.syncparams.awperiod", s.aw_period);
            o.n("awdl.syncparams.afperiod", s.action_frame_period);
            o.n("awdl.syncparams.awdlflags", s.awdl_flags);
            o.n("awdl.syncparams.aw.ext_len", s.aw_ext_length);
            o.n("awdl.syncparams.aw.common_len", s.aw_common_length);
            o.n("awdl.syncparams.aw.remaining", s.aw_remaining);
            o.n("awdl.syncparams.ext.min", s.ext_min);
            o.n("awdl.syncparams.ext.max_multicast", s.ext_max_multicast);
            o.n("awdl.syncparams.ext.max_unicast", s.ext_max_unicast);
            o.n("awdl.syncparams.ext.max_af", s.ext_max_af);
            o.mac("awdl.syncparams.master", s.master);
            o.n("awdl.syncparams.presencemode", s.presence_mode);
            o.hex("awdl.unknown", &[s.unknown]);
            o.n("awdl.syncparams.awseqcounter", s.aw_seq_counter);
            o.n("awdl.syncparams.apbeaconalignment", s.ap_beacon_alignment);
            o.chanseq(&s.channel_sequence);
            o.padding(&s.trailing);
        }
        TlvBody::ChannelSequence(c) => {
            o.chanseq(&c.sequence);
            o.padding(&c.trailing);
        }
        TlvBody::ElectionParams(e) => {
            o.n("awdl.electionparams.flags", e.flags);
            o.n("awdl.electionparams.id", e.id);
            o.n("awdl.electionparams.distance", e.distance_to_master);
            o.n("awdl.electionparams.unknown", e.unknown);
            o.mac("awdl.electionparams.master", e.master);
            o.n("awdl.electionparams.mastermetric", e.master_metric);
            o.n("awdl.electionparams.selfmetric", e.self_metric);
            if let Some(p) = &e.private {
                o.hex("awdl.unknown", &p.unknown.to_le_bytes());
                o.mac("awdl.electionparams.private.master", p.master);
                o.n("awdl.electionparams.private.mastermetric", p.master_metric);
                o.n("awdl.electionparams.private.id", p.id);
                o.n("awdl.electionparams.private.phc", p.phc);
            }
            o.padding(&e.trailing);
        }
        TlvBody::ElectionParamsV2(e) => {
            o.mac("awdl.electionparams2.master", e.master);
            o.mac("awdl.electionparams2.other", e.other);
            o.n("awdl.electionparams2.mastercounter", e.master_counter);
            o.n("awdl.electionparams2.disstance", e.distance_to_master);
            o.n("awdl.electionparams2.mastermetric", e.master_metric);
            o.n("awdl.electionparams2.selfmetric", e.self_metric);
            o.n("awdl.electionparams2.unknown", e.unknown);
            o.n("awdl.electionparams2.reserved", e.reserved);
            o.n("awdl.electionparams2.selfcounter", e.self_counter);
            o.padding(&e.trailing);
        }
        TlvBody::ServiceParams(s) => {
            o.hex("awdl.unknown", &s.unknown);
            o.n("awdl.serviceparams.sui", s.sui);
            o.n("awdl.serviceparams.bitmask", s.bitmask);
            for v in s.values.iter() {
                o.n("awdl.serviceparams.values", *v);
            }
            o.padding(&s.trailing);
        }
        TlvBody::DataPathState(d) => {
            o.n("awdl.datastate.flags", d.wire_flags());
            if let Some(c) = &d.country_code {
                // Wireshark shows an FT_STRING up to its first NUL.
                o.s("awdl.datastate.countrycode", ascii(c).split('\0').next().unwrap().to_owned());
            }
            if let Some(s) = d.social_channels {
                if s & 1 != 0 {
                    o.n("awdl.datastate.social_channel_map", s);
                } else {
                    o.n("awdl.datastate.social_channel", s);
                }
            }
            if let Some(i) = &d.infra {
                o.mac("awdl.datastate.infra_bssid", i.bssid);
                o.n("awdl.datastate.infra_channel", i.channel);
            }
            if let Some(a) = d.infra_address {
                o.mac("awdl.datastate.infra_addr", a);
            }
            if let Some(a) = d.awdl_address {
                o.mac("awdl.datastate.own_awdladdr", a);
            }
            if let Some(u) = d.umi {
                o.n("awdl.datastate.umi", u);
            }
            if let Some(u) = &d.unicast_options {
                o.n("awdl.datastate.unicast_options_length", u.len() as i64);
            }
            if let Some(e) = &d.ext {
                o.n("awdl.datastate.extflags", e.wire_flags());
                if let Some(l) = e.log_trigger {
                    o.n("awdl.datastate.logtrigger", l);
                }
                if let Some(r) = e.rlfc {
                    o.n("awdl.datastate.rlfc", r);
                }
                if let Some((a, b, c)) = e.counters {
                    o.n("awdl.datastate.active_time", a);
                    o.n("awdl.datastate.aw_sequence_counter", b);
                    o.n("awdl.datastate.update_counter", c);
                }
            }
            o.padding(&d.trailing);
        }
        TlvBody::Arpa(a) => {
            o.n("awdl.arpa.flags", a.flags);
            o.name("awdl.arpa.host", "awdl.arpa.domain", &a.name);
        }
        TlvBody::ServiceResponse(s) => {
            o.n("awdl.dns.name.len", (s.name.as_bytes().len() + 1) as i64);
            o.name("awdl.dns.name.label", "awdl.dns.name.compressed", &s.name);
            o.n("awdl.dns.type", s.rdata.rtype());
            // name length, name, type, data length, unknown, data, trailing
            let fixed = 2 + s.name.as_bytes().len() + 1 + 2 + 2;
            o.n("awdl.dns.data_len", (t.value.len() - fixed - s.trailing.len()) as i64);
            o.n("awdl.dns.unknown", s.unknown);
            match &s.rdata {
                Rdata::Txt(_) => {
                    for t in s.rdata.txt_strings() {
                        o.s("awdl.dns.txt", ascii(t));
                    }
                }
                Rdata::Srv { priority, weight, port, target } => {
                    o.n("awdl.dns.priority", *priority);
                    o.n("awdl.dns.weight", *weight);
                    o.n("awdl.dns.port", *port);
                    o.name("awdl.dns.target.label", "awdl.dns.target.compressed", target);
                }
                Rdata::Ptr(p) => o.name("awdl.dns.ptr.label", "awdl.dns.ptr.short", p),
                Rdata::Other { .. } => {}
            }
            o.padding(&s.trailing);
        }
        TlvBody::Version(v) => {
            o.n("awdl.version", v.version.to_byte());
            o.n("awdl.version.device_class", v.device_class);
            o.padding(&v.trailing);
        }
        TlvBody::SyncTree(s) => {
            for a in s.addresses() {
                o.mac("awdl.synctree.addr", a);
            }
            o.padding(&s.trailing);
        }
        TlvBody::Ieee80211Container(_) => {
            // Wireshark dissects only the first element; the rest
            // is "padding" to it.
            let v = t.value;
            if v.len() >= 2 && 2 + (v[1] as usize) < v.len() {
                o.padding(&v[2 + v[1] as usize..]);
            }
        }
        TlvBody::HtCapabilities(h) => o.padding(&h.trailing),
        TlvBody::Unknown { value, .. } => o.hex("awdl.tag.data", value),
    }
}

fn same(a: &str, b: &str) -> bool {
    fn int(s: &str) -> Option<i64> {
        match s.strip_prefix("0x") {
            Some(h) => i64::from_str_radix(h, 16).ok(),
            None => s.parse().ok(),
        }
    }
    a == b || a.eq_ignore_ascii_case(b) || matches!((int(a), int(b)), (Some(x), Some(y)) if x == y)
}

#[test]
fn decoding_matches_wireshark() {
    let files = common::air_captures();
    let Some(ts) = tshark() else {
        eprintln!("skipping: tshark not found");
        return;
    };
    if files.is_empty() {
        eprintln!("skipping: no capture corpus");
        return;
    }
    let mut by_field: BTreeMap<&str, (usize, String)> = BTreeMap::new();
    let mut frame_issues = Vec::new();
    let (mut frames, mut values) = (0usize, 0usize);
    for file in &files {
        let name = file.file_name().unwrap().to_string_lossy().into_owned();
        let theirs = run_tshark(&ts, file);
        let mut mine = BTreeMap::new();
        for (num, mpdu) in common::mpdus(file) {
            if let Ok(Some(f)) = parse(&mpdu) {
                mine.insert(num, ours(&f));
            }
        }
        for num in theirs.keys().filter(|n| !mine.contains_key(n)) {
            frame_issues.push(format!("{name} #{num}: Wireshark sees AWDL, we don't"));
        }
        for (num, m) in &mine {
            let Some(t) = theirs.get(num) else {
                frame_issues.push(format!("{name} #{num}: we see AWDL, Wireshark doesn't"));
                continue;
            };
            frames += 1;
            for (i, f) in FIELDS.iter().enumerate() {
                values += t[i].len();
                let ok = t[i].len() == m[i].len() && t[i].iter().zip(&m[i]).all(|(a, b)| same(a, b));
                if !ok {
                    let e = by_field.entry(f).or_insert((0, String::new()));
                    if e.0 == 0 {
                        e.1 = format!("{name} #{num}: wireshark={:?} ours={:?}", t[i], m[i]);
                    }
                    e.0 += 1;
                }
            }
        }
    }
    eprintln!("compared {frames} frames, {values} Wireshark field values");
    for (f, (n, ex)) in &by_field {
        eprintln!("MISMATCH {f}: {n} frames, e.g. {ex}");
    }
    for i in frame_issues.iter().take(10) {
        eprintln!("{i}");
    }
    assert!(frames > 0);
    assert!(by_field.is_empty() && frame_issues.is_empty(), "decoding disagrees with Wireshark");
}
