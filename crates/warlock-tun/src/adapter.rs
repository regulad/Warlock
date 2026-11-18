// SPDX-License-Identifier: GPL-2.0-only
//! The Wintun adapter and its IPv6 setup (PLAN.md, "Wintun adapter"):
//! exactly one address, the EUI-64 link-local of our AWDL MAC; no router
//! discovery; no DAD; our MTU; a high metric so Windows never prefers it.

use std::io;
use std::net::Ipv6Addr;
use std::sync::Arc;

use windows_sys::Win32::Foundation::{ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateUnicastIpAddressEntry, DeleteUnicastIpAddressEntry, FreeMibTable, GetIpInterfaceEntry,
    GetUnicastIpAddressTable, InitializeIpInterfaceEntry, InitializeUnicastIpAddressEntry, MIB_IPINTERFACE_ROW,
    MIB_UNICASTIPADDRESS_ROW, MIB_UNICASTIPADDRESS_TABLE, SetIpInterfaceEntry,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET6, IpDadStatePreferred, IpPrefixOriginManual, IpSuffixOriginManual, RouterDiscoveryDisabled,
};
use wintun_bindings::{Adapter, Session, Wintun};

use crate::addr::link_local;

/// Wintun's ring between the driver and us, each way.
const RING: u32 = 0x40_0000;
/// The interface metric: high, so Windows never routes anything else here.
const METRIC: u32 = 9999;

fn other<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::other(e.to_string())
}

fn win32(what: &str, code: u32) -> io::Result<()> {
    if code == NO_ERROR {
        Ok(())
    } else {
        Err(io::Error::other(format!("{what}: {}", io::Error::from_raw_os_error(code as i32))))
    }
}

/// Warlock's virtual adapter, configured. It shows as connected only while a
/// session is open ([`Tun::connect`]): the daemon keeps the adapter for its
/// whole life and connects it while a radio is up, as a Mac keeps `awdl0`
/// while switching AWDL off and on (PLAN.md, W5).
pub struct Tun {
    session: Option<Arc<Session>>,
    // Keeps the adapter alive; Wintun removes an adapter we created when its
    // last handle closes.
    adapter: Arc<Adapter>,
    luid: NET_LUID_LH,
    /// Its interface index, for `ping fe80::…%<index>`.
    pub index: u32,
    /// Its one IPv6 address.
    pub address: Ipv6Addr,
    /// Its MTU.
    pub mtu: u32,
}

impl Tun {
    /// Opens the adapter `name`, creating it (with `guid`) if needed, and
    /// configures IPv6 for the AWDL address `mac`. It starts disconnected.
    /// Needs Administrator.
    pub fn open(wintun: &Wintun, name: &str, guid: u128, mac: [u8; 6], mtu: u32) -> io::Result<Self> {
        let adapter = match Adapter::open(wintun, name) {
            Ok(a) => a,
            Err(_) => Adapter::create(wintun, name, "Warlock", Some(guid)).map_err(other)?,
        };
        let tun = Self {
            luid: adapter.get_luid(),
            index: adapter.get_adapter_index().map_err(other)?,
            session: None,
            adapter,
            address: link_local(mac),
            mtu,
        };
        tun.configure_interface()?;
        tun.enforce_address()?;
        Ok(tun)
    }

    /// Opens a session: the adapter shows as connected and carries packets.
    pub fn connect(&mut self) -> io::Result<()> {
        if self.session.is_none() {
            self.session = Some(self.adapter.start_session(RING).map_err(other)?);
        }
        // Windows may add its own link-local as the adapter comes up.
        self.enforce_address()
    }

    /// Ends the session: the adapter shows as disconnected, and packets to
    /// it go nowhere.
    pub fn disconnect(&mut self) {
        self.session = None;
    }

    /// Whether a session is open.
    pub fn is_connected(&self) -> bool {
        self.session.is_some()
    }

    fn configure_interface(&self) -> io::Result<()> {
        // SAFETY: plain IP Helper calls on a row we own.
        unsafe {
            let mut row: MIB_IPINTERFACE_ROW = std::mem::zeroed();
            InitializeIpInterfaceEntry(&mut row);
            row.Family = AF_INET6;
            row.InterfaceLuid = self.luid;
            win32("reading the adapter's IPv6 settings", GetIpInterfaceEntry(&mut row))?;
            row.RouterDiscoveryBehavior = RouterDiscoveryDisabled;
            row.DadTransmits = 0;
            row.ManagedAddressConfigurationSupported = false;
            row.OtherStatefulConfigurationSupported = false;
            row.UseAutomaticMetric = false;
            row.Metric = METRIC;
            row.NlMtu = self.mtu;
            row.SitePrefixLength = 0;
            win32("setting the adapter's IPv6 settings", SetIpInterfaceEntry(&mut row))
        }
    }

    /// Makes our address the adapter's only unicast IPv6 address: Windows
    /// adds a random link-local of its own when the adapter comes up. Call
    /// again now and then; Windows may add it back.
    pub fn enforce_address(&self) -> io::Result<()> {
        // SAFETY: IP Helper's table is read within its bounds and freed; rows
        // are plain data.
        unsafe {
            let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
            win32("listing IPv6 addresses", GetUnicastIpAddressTable(AF_INET6, &mut table))?;
            let rows = std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize);
            let mut have_ours = false;
            for row in rows.iter().filter(|r| r.InterfaceLuid.Value == self.luid.Value) {
                if Ipv6Addr::from(row.Address.Ipv6.sin6_addr.u.Byte) == self.address {
                    have_ours = true;
                } else {
                    let _ = DeleteUnicastIpAddressEntry(row);
                }
            }
            FreeMibTable(table as _);
            if have_ours {
                return Ok(());
            }
            let mut row: MIB_UNICASTIPADDRESS_ROW = std::mem::zeroed();
            InitializeUnicastIpAddressEntry(&mut row);
            row.InterfaceLuid = self.luid;
            row.Address.Ipv6.sin6_family = AF_INET6;
            row.Address.Ipv6.sin6_addr.u.Byte = self.address.octets();
            row.OnLinkPrefixLength = 64;
            row.PrefixOrigin = IpPrefixOriginManual;
            row.SuffixOrigin = IpSuffixOriginManual;
            row.DadState = IpDadStatePreferred;
            match CreateUnicastIpAddressEntry(&row) {
                ERROR_OBJECT_ALREADY_EXISTS => Ok(()),
                code => win32("adding our link-local address", code),
            }
        }
    }

    /// A packet Windows sent into the adapter, if one is waiting (never while
    /// disconnected).
    pub fn try_recv(&self, buf: &mut [u8]) -> Option<usize> {
        self.session.as_ref()?.try_recv(buf).ok()
    }

    /// Hands a packet to Windows as if received on the adapter. Fails while
    /// disconnected.
    pub fn send(&self, packet: &[u8]) -> io::Result<()> {
        let session = self.session.as_ref().ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))?;
        session.send(packet).map(|_| ())
    }
}
