// SPDX-License-Identifier: GPL-2.0-only
//! Service response (type 2): one DNS-SD record, and service parameters
//! (type 6).
//!
//! A service response is:
//!
//! ```text
//! u16 LE  name length, counting the type byte that follows the name
//! name    an AWDL DNS name (see crate::dns)
//! u8      record type: PTR 12, TXT 16, SRV 33
//! u16 LE  record data length
//! u16 LE  unknown (0 in captures)
//! data    PTR: name · SRV: priority, weight, port (u16 BE each), target name
//!         · TXT: length-prefixed strings
//! ```
//!
//! Records carry no TTL: they live as long as the advertiser is present.
//!
//! Layout: Wireshark `packet-awdl.c`, `awdl_tag_service_response` and
//! `awdl_tag_service_params`. The dissector shows TXT strings one by one;
//! we keep TXT data raw, so malformed strings still round-trip.

use alloc::vec::Vec;

use crate::dns::DnsName;
use crate::wire::{Put, Reader, len_u16};
use crate::{Bytes, Error};

/// DNS record types seen in service responses.
pub mod rr_type {
    /// PTR.
    pub const PTR: u8 = 12;
    /// TXT.
    pub const TXT: u8 = 16;
    /// SRV.
    pub const SRV: u8 = 33;
}

/// A service-response record's data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rdata<'a> {
    /// PTR: the instance name the service type points to.
    Ptr(DnsName<'a>),
    /// SRV.
    Srv {
        /// Priority.
        priority: u16,
        /// Weight.
        weight: u16,
        /// TCP or UDP port.
        port: u16,
        /// Target host.
        target: DnsName<'a>,
    },
    /// TXT: length-prefixed strings, kept raw. See [`Rdata::txt_strings`].
    Txt(Bytes<'a>),
    /// Any other record type, or a PTR/SRV whose data doesn't parse.
    Other {
        /// Record type.
        rtype: u8,
        /// Record data.
        data: Bytes<'a>,
    },
}

impl<'a> Rdata<'a> {
    fn parse(rtype: u8, data: &'a [u8]) -> Self {
        let other = || Rdata::Other { rtype, data: Bytes::Borrowed(data) };
        match rtype {
            rr_type::PTR => DnsName::parse(data).map(Rdata::Ptr).unwrap_or_else(|_| other()),
            rr_type::SRV if data.len() >= 6 => match DnsName::parse(&data[6..]) {
                Ok(target) => Rdata::Srv {
                    priority: u16::from_be_bytes([data[0], data[1]]),
                    weight: u16::from_be_bytes([data[2], data[3]]),
                    port: u16::from_be_bytes([data[4], data[5]]),
                    target,
                },
                Err(_) => other(),
            },
            rr_type::TXT => Rdata::Txt(Bytes::Borrowed(data)),
            _ => other(),
        }
    }

    /// The record type.
    pub fn rtype(&self) -> u8 {
        match self {
            Rdata::Ptr(_) => rr_type::PTR,
            Rdata::Srv { .. } => rr_type::SRV,
            Rdata::Txt(_) => rr_type::TXT,
            Rdata::Other { rtype, .. } => *rtype,
        }
    }

    fn emit(&self, out: &mut Vec<u8>) {
        match self {
            Rdata::Ptr(n) => out.put(n.as_bytes()),
            Rdata::Srv { priority, weight, port, target } => {
                out.put_u16be(*priority);
                out.put_u16be(*weight);
                out.put_u16be(*port);
                out.put(target.as_bytes());
            }
            Rdata::Txt(b) | Rdata::Other { data: b, .. } => out.put(b),
        }
    }

    /// The data of a record named `owner`, in standard DNS wire format:
    /// names written out ([`DnsName::to_wire_in`], where `0xC000` stands for
    /// `owner`); TXT and other data as is, except that empty TXT data becomes
    /// one empty string, as DNS requires. `None` if a name can't be written
    /// out.
    pub fn to_wire(&self, owner: &DnsName<'_>) -> Option<Vec<u8>> {
        Some(match self {
            Rdata::Ptr(n) => n.to_wire_in(Some(owner))?,
            Rdata::Srv { priority, weight, port, target } => {
                let mut out = Vec::new();
                out.put_u16be(*priority);
                out.put_u16be(*weight);
                out.put_u16be(*port);
                out.put(&target.to_wire_in(Some(owner))?);
                out
            }
            Rdata::Txt(b) if b.is_empty() => alloc::vec![0],
            Rdata::Txt(b) | Rdata::Other { data: b, .. } => b.to_vec(),
        })
    }

    /// Converts to owned data.
    pub fn into_owned(self) -> Rdata<'static> {
        match self {
            Rdata::Ptr(n) => Rdata::Ptr(n.into_owned()),
            Rdata::Srv { priority, weight, port, target } => {
                Rdata::Srv { priority, weight, port, target: target.into_owned() }
            }
            Rdata::Txt(b) => Rdata::Txt(Bytes::Owned(b.into_owned())),
            Rdata::Other { rtype, data } => Rdata::Other { rtype, data: Bytes::Owned(data.into_owned()) },
        }
    }

    /// For TXT data: the strings, in order. A string that would run past the
    /// end is cut short.
    pub fn txt_strings(&self) -> impl Iterator<Item = &[u8]> {
        let mut rest: &[u8] = match self {
            Rdata::Txt(b) => b,
            _ => &[],
        };
        core::iter::from_fn(move || {
            let (&n, tail) = rest.split_first()?;
            let n = (n as usize).min(tail.len());
            let (s, tail) = tail.split_at(n);
            rest = tail;
            Some(s)
        })
    }

    /// Encodes TXT strings into TXT data.
    pub fn txt_from_strings<S: AsRef<[u8]>>(strings: &[S]) -> Result<Rdata<'static>, Error> {
        let mut b = Vec::new();
        for s in strings {
            let s = s.as_ref();
            b.push(u8::try_from(s.len()).map_err(|_| Error::TooLong("TXT string"))?);
            b.extend_from_slice(s);
        }
        Ok(Rdata::Txt(Bytes::Owned(b)))
    }
}

/// A service response (type 2): one DNS-SD record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceResponse<'a> {
    /// The record's owner name.
    pub name: DnsName<'a>,
    /// Unknown u16 after the data length.
    pub unknown: u16,
    /// The record data; its type is the record type.
    pub rdata: Rdata<'a>,
    /// Bytes after the record data.
    pub trailing: Bytes<'a>,
}

/// `service_type` (`_x._tcp`, with or without `.local`) as Apple devices
/// encode a record's owner name: lowercased, longest dictionary suffix.
fn type_name(service_type: &str) -> Result<DnsName<'static>, Error> {
    let t = service_type.trim_end_matches('.').to_ascii_lowercase();
    let t = if t.ends_with(".local") { t } else { alloc::format!("{t}.local") };
    DnsName::encode(&t)
}

/// An instance's owner name: its label lowercased (Apple devices lowercase
/// owner names, as mDNSResponder's D2D keys are), under its type.
fn instance_name(service_type: &str, instance: &str) -> Result<DnsName<'static>, Error> {
    let lower = instance.to_lowercase();
    let t = type_name(service_type)?;
    let mut labels = alloc::vec![crate::dns::Label::Text(lower.as_bytes())];
    labels.extend(t.labels());
    DnsName::from_labels(&labels)
}

impl ServiceResponse<'static> {
    /// A PTR from `service_type` to `instance` (its label), as Apple devices
    /// send it: the data is the label, case kept, then `0xC000`, the
    /// record's own name.
    pub fn ptr(service_type: &str, instance: &str) -> Result<Self, Error> {
        let data = DnsName::from_labels(&[
            crate::dns::Label::Text(instance.as_bytes()),
            crate::dns::Label::Compressed(0xC000),
        ])?;
        Ok(Self::new(type_name(service_type)?, Rdata::Ptr(data)))
    }

    /// The SRV of `instance`: `target` is a host name such as `host.local`.
    pub fn srv(service_type: &str, instance: &str, port: u16, target: &str) -> Result<Self, Error> {
        let rdata = Rdata::Srv { priority: 0, weight: 0, port, target: DnsName::encode(target)? };
        Ok(Self::new(instance_name(service_type, instance)?, rdata))
    }

    /// The TXT of `instance`.
    pub fn txt<S: AsRef<[u8]>>(service_type: &str, instance: &str, strings: &[S]) -> Result<Self, Error> {
        Ok(Self::new(instance_name(service_type, instance)?, Rdata::txt_from_strings(strings)?))
    }
}

impl<'a> ServiceResponse<'a> {
    /// Builds a record.
    pub fn new(name: DnsName<'a>, rdata: Rdata<'a>) -> Self {
        Self { name, unknown: 0, rdata, trailing: Bytes::Borrowed(&[]) }
    }

    /// Parses the value.
    pub fn parse(v: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(v);
        let name_len = r.u16le("service name length")? as usize;
        if name_len == 0 {
            return Err(Error::Invalid("service name length"));
        }
        let name = DnsName::parse(r.bytes(name_len - 1, "service name")?)?;
        let rtype = r.u8("service record type")?;
        let data_len = r.u16le("service data length")? as usize;
        let unknown = r.u16le("service unknown")?;
        let data = r.bytes(data_len, "service data")?;
        Ok(Self {
            name,
            unknown,
            rdata: Rdata::parse(rtype, data),
            trailing: Bytes::Borrowed(r.rest()),
        })
    }

    /// Converts to an owned record.
    pub fn into_owned(self) -> ServiceResponse<'static> {
        ServiceResponse {
            name: self.name.into_owned(),
            unknown: self.unknown,
            rdata: self.rdata.into_owned(),
            trailing: Bytes::Owned(self.trailing.into_owned()),
        }
    }

    /// Appends the value.
    pub fn emit(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        out.put_u16le(len_u16(self.name.as_bytes().len() + 1, "service name")?);
        out.put(self.name.as_bytes());
        out.put_u8(self.rdata.rtype());
        let len_at = out.len();
        out.put_u16le(0);
        out.put_u16le(self.unknown);
        let start = out.len();
        self.rdata.emit(out);
        let len = len_u16(out.len() - start, "service data")?;
        out[len_at..len_at + 2].copy_from_slice(&len.to_le_bytes());
        out.put(&self.trailing);
        Ok(())
    }
}

/// Service parameters (type 6). The SUI counter changes when the sender's
/// service records change. The set (bitmask and values) is what iOS 27's
/// `wifip2pd` calls the SSTH: a 256-bit table, sent compressed (the bitmask
/// says which of its 32 bytes follow), nonzero exactly while the sender
/// advertises records, about one bit per record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceParams<'a> {
    /// Three bytes at the start: `wifip2pd`'s `flags` (u8) and `dwellTime`
    /// (u16), meanings unknown.
    pub unknown: [u8; 3],
    /// Service update indicator.
    pub sui: u16,
    /// Which value bytes follow: one per set bit.
    pub bitmask: u32,
    /// The value bytes, one per set bit of `bitmask`.
    pub values: Bytes<'a>,
    /// Bytes after the values.
    pub trailing: Bytes<'a>,
}

impl<'a> ServiceParams<'a> {
    /// Parses the value.
    pub fn parse(v: &'a [u8]) -> Result<Self, Error> {
        let mut r = Reader::new(v);
        let unknown = r.array("service params unknown")?;
        let sui = r.u16le("service params SUI")?;
        let bitmask = r.u32le("service params bitmask")?;
        let values = r.bytes(bitmask.count_ones() as usize, "service params values")?;
        Ok(Self {
            unknown,
            sui,
            bitmask,
            values: Bytes::Borrowed(values),
            trailing: Bytes::Borrowed(r.rest()),
        })
    }

    /// Parameters carrying `sui` and the set of `members` (0–255), encoded
    /// as [`ServiceParams::set_values`] reads it.
    pub fn with_set(sui: u16, members: impl IntoIterator<Item = u8>) -> ServiceParams<'static> {
        let mut table = [0u8; 32];
        for m in members {
            table[m as usize / 8] |= 1 << (m % 8);
        }
        let bitmask = (0..32).filter(|&i| table[i] != 0).fold(0u32, |b, i| b | 1 << i);
        let values: Vec<u8> = table.iter().copied().filter(|&v| v != 0).collect();
        ServiceParams {
            unknown: [0; 3],
            sui,
            bitmask,
            values: Bytes::Owned(values),
            trailing: Bytes::Borrowed(&[]),
        }
    }

    /// The encoded set: for each set bit `i` of the bitmask, the set bits `k`
    /// of its value byte give `8 * i + k`.
    pub fn set_values(&self) -> impl Iterator<Item = u32> + '_ {
        (0..32u32)
            .filter(|i| self.bitmask >> i & 1 == 1)
            .zip(self.values.iter())
            .flat_map(|(i, &v)| (0..8u32).filter(move |k| v >> k & 1 == 1).map(move |k| 8 * i + k))
    }

    /// Appends the value. `values` must hold one byte per set bit of
    /// `bitmask`.
    pub fn emit(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        if self.values.len() != self.bitmask.count_ones() as usize {
            return Err(Error::Invalid("service params values for bitmask"));
        }
        out.put(&self.unknown);
        out.put_u16le(self.sui);
        out.put_u32le(self.bitmask);
        out.put(&self.values);
        out.put(&self.trailing);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(r: &ServiceResponse<'_>) -> Vec<u8> {
        let mut v = Vec::new();
        r.emit(&mut v).unwrap();
        v
    }

    /// Laid out as the captured records are: a Mac's AirDrop PTR is
    /// `c007` → `0c <12 hex> c000`, its SRV `0c <12 hex> c007` →
    /// `0000 0000 <port> <len> <uuid> c00c`; a companion-link PTR is
    /// `0f _companion-link c00a` → `12 CLink-<12 hex> c000`.
    #[test]
    fn records_are_encoded_as_apple_devices_send_them() {
        let ptr = ServiceResponse::ptr("_airdrop._tcp", "0123456789ab").unwrap();
        assert_eq!(value(&ptr), b"\x03\x00\xc0\x07\x0c\x0f\x00\x00\x00\x0c0123456789ab\xc0\x00");
        let srv = ServiceResponse::srv("_airdrop._tcp.local", "0123456789AB", 8770, "host.local").unwrap();
        assert_eq!(
            value(&srv),
            b"\x10\x00\x0c0123456789ab\xc0\x07\x21\x0d\x00\x00\x00\x00\x00\x00\x00\x22\x42\x04host\xc0\x0c"
        );
        let clink = ServiceResponse::ptr("_companion-link._tcp", "CLink-0123456789ab").unwrap();
        assert_eq!(clink.name.as_bytes(), b"\x0f_companion-link\xc0\x0a");
        assert_eq!(clink.rdata, Rdata::Ptr(DnsName::parse(b"\x12CLink-0123456789ab\xc0\x00").unwrap()));
        let txt = ServiceResponse::txt("_airdrop._tcp", "0123456789AB", &["flags=1019"]).unwrap();
        assert_eq!(txt.name, srv.name);
        assert_eq!(txt.rdata, Rdata::Txt(Bytes::Borrowed(b"\x0aflags=1019")));
        // Each converts back to the full standard names.
        assert_eq!(ptr.rdata.to_wire(&ptr.name).unwrap(), b"\x0c0123456789ab\x08_airdrop\x04_tcp\x05local\x00");
    }

    #[test]
    fn a_set_round_trips() {
        let p = ServiceParams::with_set(5, [104, 158, 165, 7]);
        assert_eq!(p.set_values().collect::<Vec<_>>(), [7, 104, 158, 165]);
        assert_eq!(ServiceParams::with_set(0, []).bitmask, 0);
    }
}
