// SPDX-License-Identifier: GPL-2.0-only
//! Advertising Windows' own DNS-SD registrations on AWDL
//! (`docs/service-discovery.md`).
//!
//! Apps register their services with Windows (`DnsServiceRegister` on the
//! Warlock adapter) and name the service types to Warlock: with the control
//! API's `POST /v1/advertising`, or `--advertise`. For each type, Warlock keeps a standing
//! mDNS query on the adapter, which Windows' own responder answers. An
//! instance is ours when its SRV target resolves to the adapter's address:
//! Windows answers AAAA only for its own host name, with the adapter's one
//! address, and no AWDL peer can have that address. Ours go into our MIFs as
//! Service Response TLVs, with the target as our ARPA host name.

use std::collections::BTreeMap;
use std::ffi::c_void;
use std::net::Ipv6Addr;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use awdl_proto::tlv::ServiceResponse;
use tracing::warn;
use windows_sys::Win32::NetworkManagement::Dns::{
    DNS_QUERY_REQUEST_VERSION1, DNS_QUERY_RESULT, DNS_RECORDW, DNS_TYPE_AAAA, DNS_TYPE_PTR, DNS_TYPE_SRV,
    DNS_TYPE_TEXT, DnsFree, DnsFreeRecordList, DnsStartMulticastQuery, DnsStopMulticastQuery, MDNS_QUERY_HANDLE,
    MDNS_QUERY_REQUEST,
};

/// One answer, as Windows reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Answer {
    /// The owner name, lowercased (DNS names compare without case).
    name: String,
    ttl: u32,
    data: Data,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Data {
    /// A PTR's target, case kept.
    Ptr(String),
    Srv {
        port: u16,
        target: String,
    },
    Txt(Vec<String>),
    Aaaa(Ipv6Addr),
}

/// A standing `DnsStartMulticastQuery`.
struct Query {
    handle: Box<MDNS_QUERY_HANDLE>,
    // Kept alive for the query's life.
    _request: Box<MDNS_QUERY_REQUEST>,
    _name: Vec<u16>,
}

impl Query {
    fn start(name: &str, rtype: u16, interface: u32, answers: &Sender<Vec<Answer>>) -> Result<Self, i32> {
        let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        // The context outlives the query: Windows may call back while it
        // stops, and nothing says when it's done. One small leak per query.
        let context = Box::into_raw(Box::new(answers.clone())) as *mut c_void;
        let request = Box::new(MDNS_QUERY_REQUEST {
            Version: DNS_QUERY_REQUEST_VERSION1,
            ulRefCount: 0,
            Query: wide.as_ptr(),
            QueryType: rtype,
            QueryOptions: 0,
            InterfaceIndex: interface,
            pQueryCallback: Some(on_answer),
            pQueryContext: context,
            fAnswerReceived: 0,
            ulResendCount: 0,
        });
        // SAFETY: plain data, filled in by Windows.
        let mut handle: Box<MDNS_QUERY_HANDLE> = Box::new(unsafe { std::mem::zeroed() });
        // SAFETY: the request, its name and the handle live in the Query,
        // which stops the query before dropping them.
        let rc = unsafe { DnsStartMulticastQuery(&*request, &mut *handle) };
        if rc != 0 {
            return Err(rc);
        }
        Ok(Self { handle, _request: request, _name: wide })
    }
}

impl Drop for Query {
    fn drop(&mut self) {
        // SAFETY: the handle of a started query.
        unsafe { DnsStopMulticastQuery(&mut *self.handle) };
    }
}

unsafe fn wide_str(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: a NUL-terminated wide string from Windows.
    unsafe {
        let len = (0..).take_while(|&i| *p.add(i) != 0).count();
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }
}

unsafe extern "system" fn on_answer(context: *const c_void, _: *mut MDNS_QUERY_HANDLE, result: *mut DNS_QUERY_RESULT) {
    // SAFETY: the context is the Sender `Query::start` leaked; the result
    // and its record list are Windows', and the list is ours to free. The
    // records are wide-string records: the mDNS API is Unicode-only.
    unsafe {
        if result.is_null() || (*result).QueryStatus != 0 {
            return;
        }
        let records = (*result).pQueryRecords as *const DNS_RECORDW;
        let mut answers = Vec::new();
        let mut r = records;
        while !r.is_null() {
            let data = match (*r).wType {
                DNS_TYPE_PTR => Some(Data::Ptr(wide_str((*r).Data.PTR.pNameHost))),
                DNS_TYPE_SRV => {
                    let s = &(*r).Data.SRV;
                    Some(Data::Srv { port: s.wPort, target: wide_str(s.pNameTarget).to_ascii_lowercase() })
                }
                DNS_TYPE_TEXT => {
                    let t = &(*r).Data.TXT;
                    Some(Data::Txt(
                        (0..t.dwStringCount as usize).map(|i| wide_str(*t.pStringArray.as_ptr().add(i))).collect(),
                    ))
                }
                DNS_TYPE_AAAA => Some(Data::Aaaa(Ipv6Addr::from((*r).Data.AAAA.Ip6Address.IP6Byte))),
                _ => None,
            };
            if let Some(data) = data {
                answers.push(Answer { name: wide_str((*r).pName).to_ascii_lowercase(), ttl: (*r).dwTtl, data });
            }
            r = (*r).pNext;
        }
        if !records.is_null() {
            DnsFree(records as *const c_void, DnsFreeRecordList);
        }
        let _ = (*(context as *const Sender<Vec<Answer>>)).send(answers);
    }
}

/// What we advertise.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Advertised {
    /// Our records, for our MIFs.
    pub records: Vec<ServiceResponse<'static>>,
    /// Our ARPA host name, without `.local`.
    pub host: Option<String>,
    /// The instances' names (case kept), by service type (`_x._tcp`): what
    /// the control API reports.
    pub instances: BTreeMap<String, Vec<String>>,
}

/// What's advertised for the named types.
pub struct Advertiser {
    interface: u32,
    address: Ipv6Addr,
    /// Watched types, as `_x._tcp.local`, lowercased.
    types: Vec<String>,
    queries: BTreeMap<(String, u16), Query>,
    answers: Receiver<Vec<Answer>>,
    sender: Sender<Vec<Answer>>,
    /// Live answers and when each expires.
    cache: BTreeMap<(String, Data), Instant>,
    /// What we advertise now.
    current: Advertised,
    /// The types changed since we last derived what to advertise.
    dirty: bool,
}

/// A service type as a query name: `_x._tcp.local`, lowercased.
fn type_name(t: &str) -> String {
    let t = t.trim_end_matches('.').to_ascii_lowercase();
    if t.ends_with(".local") { t } else { format!("{t}.local") }
}

impl Advertiser {
    /// Starts watching `types` on the adapter `interface`, whose address is
    /// `address`.
    pub fn new(interface: u32, address: Ipv6Addr, types: &[String]) -> Self {
        let (sender, answers) = channel();
        let mut a = Self {
            interface,
            address,
            types: Vec::new(),
            queries: BTreeMap::new(),
            answers,
            sender,
            cache: BTreeMap::new(),
            current: Advertised::default(),
            dirty: false,
        };
        a.set_types(types);
        a
    }

    /// Watches exactly `types` from now on: new ones get a standing query,
    /// dropped ones lose theirs and leave our frames at the next
    /// [`Advertiser::poll`].
    pub fn set_types(&mut self, types: &[String]) {
        let mut next: Vec<String> = types.iter().map(|t| type_name(t)).collect();
        next.sort();
        next.dedup();
        if next == self.types {
            return;
        }
        for gone in self.types.iter().filter(|t| !next.contains(t)) {
            self.queries.remove(&(gone.clone(), DNS_TYPE_PTR));
        }
        for t in &next {
            self.watch(t, DNS_TYPE_PTR);
        }
        self.types = next;
        self.dirty = true;
    }

    fn watch(&mut self, name: &str, rtype: u16) {
        let key = (name.to_string(), rtype);
        if self.queries.contains_key(&key) {
            return;
        }
        match Query::start(name, rtype, self.interface, &self.sender) {
            Ok(q) => {
                self.queries.insert(key, q);
            }
            Err(rc) => warn!(name, rtype, rc, "can't start an mDNS query"),
        }
    }

    /// Takes in Windows' answers; what we should advertise, if it changed.
    pub fn poll(&mut self, now: Instant) -> Option<Advertised> {
        let mut fresh = false;
        while let Ok(answers) = self.answers.try_recv() {
            for a in answers {
                let key = (a.name, a.data);
                if a.ttl == 0 {
                    fresh |= self.cache.remove(&key).is_some();
                } else {
                    fresh |= self.cache.insert(key, now + Duration::from_secs(a.ttl.into())).is_none();
                }
            }
        }
        let before = self.cache.len();
        self.cache.retain(|_, expires| *expires > now);
        fresh |= self.cache.len() != before;
        if !fresh && !self.dirty {
            return None;
        }
        self.dirty = false;
        let next = self.derive();
        (next != self.current).then(|| {
            self.current = next.clone();
            next
        })
    }

    /// Our instances from the cache, as records; AAAA queries for targets
    /// not yet resolved.
    fn derive(&mut self) -> Advertised {
        let mut records = Vec::new();
        let mut host = None;
        let mut instances: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut unresolved = Vec::new();
        for t in &self.types {
            for (name, data) in self.cache.keys() {
                let Data::Ptr(instance) = data else { continue };
                if name != t {
                    continue;
                }
                let instance_lc = instance.to_ascii_lowercase();
                // The instance's label: its name less `.<type>`.
                let Some(label) = instance_lc.strip_suffix(&format!(".{t}")).map(|l| &instance[..l.len()]) else {
                    continue;
                };
                let srv = self.cache.keys().find_map(|(n, d)| match d {
                    Data::Srv { port, target } if *n == instance_lc => Some((*port, target.clone())),
                    _ => None,
                });
                let Some((port, target)) = srv else { continue };
                let ours =
                    self.cache.keys().any(|(n, d)| *n == target && matches!(d, Data::Aaaa(a) if *a == self.address));
                if !ours {
                    unresolved.push(target);
                    continue;
                }
                let txt: Vec<String> = self
                    .cache
                    .keys()
                    .find_map(|(n, d)| match d {
                        Data::Txt(s) if *n == instance_lc => Some(s.clone()),
                        _ => None,
                    })
                    .unwrap_or_default();
                let service_type = t.trim_end_matches(".local");
                let built = [
                    ServiceResponse::ptr(service_type, label),
                    ServiceResponse::srv(service_type, label, port, &target),
                    ServiceResponse::txt(service_type, label, &txt),
                ];
                match built.into_iter().collect::<Result<Vec<_>, _>>() {
                    Ok(r) => {
                        records.extend(r);
                        instances.entry(service_type.to_string()).or_default().push(instance.clone());
                    }
                    Err(e) => warn!(instance, "can't encode for AWDL: {e}"),
                }
                let h = target.trim_end_matches('.').strip_suffix(".local").unwrap_or(&target).to_string();
                match &host {
                    None => host = Some(h),
                    Some(first) if *first != h => {
                        warn!(instance, target, "a second host name for our address; only {first} is in our ARPA TLV")
                    }
                    _ => {}
                }
            }
        }
        for target in unresolved {
            self.watch(&target, DNS_TYPE_AAAA);
        }
        Advertised { records, host, instances }
    }
}
