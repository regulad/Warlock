// SPDX-License-Identifier: GPL-2.0-only
//! What the daemon tells the control API (`warlock-api`, `api/openapi.yaml`):
//! the engine's peers and records, in the contract's terms.

use awdl_core::Peer;
use awdl_proto::dns::DnsName;
use awdl_proto::tlv::{Rdata, ServiceResponse};
use warlock_api::types;
use warlock_tun::addr;
use windows_sys::Win32::System::SystemInformation::{ComputerNamePhysicalDnsHostname, GetComputerNameExW};

/// This computer's host name, lowercased: Windows answers mDNS for
/// `<it>.local`, so services register with it as their target.
pub fn host_name() -> String {
    let mut buf = vec![0u16; 256];
    let mut len = buf.len() as u32;
    // SAFETY: a buffer of the length we pass.
    let ok = unsafe { GetComputerNameExW(ComputerNamePhysicalDnsHostname, buf.as_mut_ptr(), &mut len) };
    if ok == 0 {
        return String::new();
    }
    String::from_utf16_lossy(&buf[..len as usize]).to_ascii_lowercase()
}

/// A name in DNS wire format, in presentation form: labels joined by dots,
/// with dots and backslashes inside labels escaped (RFC 1035 §5.1). Instance
/// names may contain dots.
fn presentation(wire: &[u8]) -> String {
    let mut out = String::new();
    let mut rest = wire;
    while let Some((&len, tail)) = rest.split_first() {
        if len == 0 || tail.len() < len as usize {
            break;
        }
        let (label, tail) = tail.split_at(len as usize);
        if !out.is_empty() {
            out.push('.');
        }
        for c in String::from_utf8_lossy(label).chars() {
            if c == '.' || c == '\\' {
                out.push('\\');
            }
            out.push(c);
        }
        rest = tail;
    }
    out
}

/// A name in the data of a record whose own name is `owner`, written out.
fn name_in(name: &DnsName<'_>, owner: &DnsName<'_>) -> String {
    name.to_wire_in(Some(owner)).map(|w| presentation(&w)).unwrap_or_else(|| name.to_dotted())
}

fn record(r: &ServiceResponse<'_>) -> types::ServiceRecord {
    let name = r.name.to_wire().map(|w| presentation(&w)).unwrap_or_else(|| r.name.to_dotted());
    match &r.rdata {
        Rdata::Ptr(target) => types::ServiceRecord::ptr(name, name_in(target, &r.name)),
        Rdata::Srv { priority, weight, port, target } => {
            types::ServiceRecord::srv(name, *priority, *weight, *port, name_in(target, &r.name))
        }
        Rdata::Txt(data) => {
            let mut strings = Vec::new();
            let mut rest: &[u8] = data;
            while let Some((&len, tail)) = rest.split_first() {
                let len = (len as usize).min(tail.len());
                strings.push(String::from_utf8_lossy(&tail[..len]).into_owned());
                rest = &tail[len..];
            }
            types::ServiceRecord::txt(name, strings)
        }
        Rdata::Other { rtype, data } => types::ServiceRecord::other(name, (*rtype).into(), data),
    }
}

/// A peer's records.
pub fn services(p: &Peer) -> types::ServiceSet {
    types::ServiceSet { update: p.services_sui, records: p.services.iter().map(record).collect() }
}

/// A peer, `now` being the radio's TSF.
pub fn peer(p: &Peer, now: Option<u64>) -> types::Peer {
    types::Peer {
        address: p.addr.to_string(),
        ipv6: addr::link_local(p.addr.0),
        host_name: p.hostname.clone(),
        awdl_version: p.version.map(|(v, _)| format!("{}.{}", v.major, v.minor)),
        device_class: p.version.map(|(_, class)| class),
        master: p.election.as_ref().map(|e| e.master.to_string()),
        channel: p.channel,
        rssi_dbm: p.rssi_dbm,
        since_last_frame_ms: now.map_or(0, |n| n.saturating_sub(p.last_seen) / 1000),
        frames: types::Frames { psf: p.psfs, mif: p.mifs, data: p.data_frames },
        sequence: p.schedule.as_ref().map(|s| s.slots.to_vec()),
        follow_channel_sequence: p.follow_channel_sequence,
        services: services(p),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_written_out_with_escapes() {
        assert_eq!(
            presentation(b"\x0bWarlockTest\x0c_warlocktest\x04_tcp\x05local\x00"),
            "WarlockTest._warlocktest._tcp.local"
        );
        assert_eq!(presentation(b"\x03a.b\x05local\x00"), r"a\.b.local");
    }

    #[test]
    fn records_from_a_peer_are_written_out() {
        // A PTR's data ends in 0xC000: the record's own name.
        let ptr = ServiceResponse::ptr("_airdrop._tcp", "0123456789ab").unwrap();
        let r = record(&ptr);
        assert_eq!(
            (r.name.as_str(), r.target.as_deref()),
            ("_airdrop._tcp.local", Some("0123456789ab._airdrop._tcp.local"))
        );
        let srv = ServiceResponse::srv("_airdrop._tcp", "0123456789ab", 8770, "host.local").unwrap();
        let r = record(&srv);
        assert_eq!((r.port, r.target.as_deref()), (Some(8770), Some("host.local")));
        let txt = ServiceResponse::txt("_airdrop._tcp", "0123456789ab", &["flags=1019", "x=y"]).unwrap();
        assert_eq!(record(&txt).strings, Some(vec!["flags=1019".into(), "x=y".into()]));
    }
}
