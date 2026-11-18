// SPDX-License-Identifier: GPL-2.0-only
//! Windows' own DNS-SD (`dnsapi.dll`) on one network interface: does it work
//! on the Warlock adapter? (`docs/service-discovery.md`, "To verify".)
//!
//!     dnssd browse   <type, e.g. _airplay._tcp.local> <ifindex> [seconds=20]
//!     dnssd resolve  <instance, e.g. Foo._airplay._tcp.local> <ifindex>
//!     dnssd register <instance name> <type> <port> <ifindex> <our IPv6> [seconds=60]
//!
//! Prints every record or instance Windows hands back.

use std::ffi::c_void;
use std::net::Ipv6Addr;
use std::ptr::{null, null_mut};
use std::time::Duration;

use windows_sys::Win32::Foundation::DNS_REQUEST_PENDING;
use windows_sys::Win32::NetworkManagement::Dns::*;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

unsafe fn wstr(p: *const u16) -> String {
    if p.is_null() {
        return "<null>".into();
    }
    // SAFETY: the caller passes a NUL-terminated wide string.
    unsafe {
        let len = (0..).take_while(|&i| *p.add(i) != 0).count();
        String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
    }
}

unsafe extern "system" fn on_browse(status: u32, _ctx: *const c_void, records: *const DNS_RECORDW) {
    // SAFETY: Windows hands us a record list it owns until we free it.
    unsafe {
        println!("[browse] status {status}");
        let mut r = records;
        while !r.is_null() {
            let name = wstr((*r).pName);
            match (*r).wType {
                DNS_TYPE_PTR => println!("  PTR  {name} → {}", wstr((*r).Data.PTR.pNameHost)),
                DNS_TYPE_SRV => {
                    let s = &(*r).Data.SRV;
                    println!("  SRV  {name} → {}:{}", wstr(s.pNameTarget), s.wPort)
                }
                DNS_TYPE_AAAA => println!("  AAAA {name} → {}", Ipv6Addr::from((*r).Data.AAAA.Ip6Address.IP6Byte)),
                DNS_TYPE_TEXT => {
                    let t = &(*r).Data.TXT;
                    let strings: Vec<String> =
                        (0..t.dwStringCount as usize).map(|i| wstr(*t.pStringArray.as_ptr().add(i))).collect();
                    println!("  TXT  {name} → {strings:?}")
                }
                t => println!("  type {t} {name}"),
            }
            r = (*r).pNext;
        }
        if !records.is_null() {
            DnsFree(records as *const c_void, DnsFreeRecordList);
        }
    }
}

unsafe fn print_instance(what: &str, status: u32, i: *const DNS_SERVICE_INSTANCE) {
    // SAFETY: an instance Windows owns until we free it.
    unsafe {
        println!("[{what}] status {status}");
        if i.is_null() {
            return;
        }
        let i = &*i;
        println!("  instance {}", wstr(i.pszInstanceName));
        println!("  host {} port {} interface {}", wstr(i.pszHostName), i.wPort, i.dwInterfaceIndex);
        if !i.ip6Address.is_null() {
            println!("  IPv6 {}", Ipv6Addr::from((*i.ip6Address).IP6Byte));
        }
        if !i.ip4Address.is_null() {
            println!("  IPv4 {}", std::net::Ipv4Addr::from(u32::from_be(*i.ip4Address)));
        }
        for k in 0..i.dwPropertyCount as usize {
            println!("  {}={}", wstr(*i.keys.add(k)), wstr(*i.values.add(k)));
        }
    }
}

unsafe extern "system" fn on_resolve(status: u32, _ctx: *const c_void, i: *const DNS_SERVICE_INSTANCE) {
    // SAFETY: as print_instance; freed after.
    unsafe {
        print_instance("resolve", status, i);
        if !i.is_null() {
            DnsServiceFreeInstance(i);
        }
    }
}

unsafe extern "system" fn on_register(status: u32, _ctx: *const c_void, i: *const DNS_SERVICE_INSTANCE) {
    // SAFETY: as print_instance.
    unsafe { print_instance("register", status, i) };
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let usage = "usage: dnssd browse <type> <ifindex> [s] | resolve <instance> <ifindex> | \
                 register <name> <type> <port> <ifindex> <ipv6> [s]";
    match args.first().map(String::as_str) {
        Some("browse") if args.len() >= 3 => {
            let name = wide(&args[1]);
            let req = DNS_SERVICE_BROWSE_REQUEST {
                Version: DNS_QUERY_REQUEST_VERSION1,
                InterfaceIndex: args[2].parse().expect("ifindex"),
                QueryName: name.as_ptr(),
                Anonymous: DNS_SERVICE_BROWSE_REQUEST_0 { pBrowseCallback: Some(on_browse) },
                pQueryContext: null_mut(),
            };
            let mut cancel = DNS_SERVICE_CANCEL { reserved: null_mut() };
            // SAFETY: the request and its strings outlive the browse (cancelled below).
            let rc = unsafe { DnsServiceBrowse(&req, &mut cancel) };
            println!("DnsServiceBrowse({}) on interface {}: {rc}", args[1], args[2]);
            if rc == DNS_REQUEST_PENDING {
                std::thread::sleep(Duration::from_secs(args.get(3).map_or(20, |s| s.parse().unwrap())));
                // SAFETY: the handle from the browse above.
                unsafe { DnsServiceBrowseCancel(&cancel) };
            }
        }
        Some("resolve") if args.len() >= 3 => {
            let mut name = wide(&args[1]);
            let req = DNS_SERVICE_RESOLVE_REQUEST {
                Version: DNS_QUERY_REQUEST_VERSION1,
                InterfaceIndex: args[2].parse().expect("ifindex"),
                QueryName: name.as_mut_ptr(),
                pResolveCompletionCallback: Some(on_resolve),
                pQueryContext: null_mut(),
            };
            let mut cancel = DNS_SERVICE_CANCEL { reserved: null_mut() };
            // SAFETY: as browse.
            let rc = unsafe { DnsServiceResolve(&req, &mut cancel) };
            println!("DnsServiceResolve({}) on interface {}: {rc}", args[1], args[2]);
            std::thread::sleep(Duration::from_secs(10));
        }
        Some("register") if args.len() >= 6 => {
            let full = format!("{}.{}", args[1], args[2]);
            let host = wide("warlock-test.local");
            let ip6: Ipv6Addr = args[5].parse().expect("IPv6 address");
            let ip6 = IP6_ADDRESS { IP6Byte: ip6.octets() };
            let (k, v) = (wide("note"), wide("warlock dnssd test"));
            let mut keys = [k.as_ptr()];
            let mut values = [v.as_ptr()];
            // SAFETY: valid strings and address; the instance is freed below.
            let instance = unsafe {
                DnsServiceConstructInstance(
                    wide(&full).as_ptr(),
                    host.as_ptr(),
                    null(),
                    &ip6,
                    args[3].parse().expect("port"),
                    0,
                    0,
                    1,
                    keys.as_mut_ptr(),
                    values.as_mut_ptr(),
                )
            };
            let req = DNS_SERVICE_REGISTER_REQUEST {
                Version: DNS_QUERY_REQUEST_VERSION1,
                InterfaceIndex: args[4].parse().expect("ifindex"),
                pServiceInstance: instance,
                pRegisterCompletionCallback: Some(on_register),
                pQueryContext: null_mut(),
                hCredentials: null_mut(),
                unicastEnabled: 0,
            };
            let mut cancel = DNS_SERVICE_CANCEL { reserved: null_mut() };
            // SAFETY: the request and instance outlive the registration.
            let rc = unsafe { DnsServiceRegister(&req, &mut cancel) };
            println!("DnsServiceRegister({full}) on interface {}: {rc}", args[4]);
            std::thread::sleep(Duration::from_secs(args.get(6).map_or(60, |s| s.parse().unwrap())));
            // SAFETY: as above.
            unsafe {
                let rc = DnsServiceDeRegister(&req, null_mut());
                println!("DnsServiceDeRegister: {rc}");
                std::thread::sleep(Duration::from_secs(2));
                DnsServiceFreeInstance(instance);
            }
        }
        _ => eprintln!("{usage}"),
    }
}
