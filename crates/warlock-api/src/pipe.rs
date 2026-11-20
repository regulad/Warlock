// SPDX-License-Identifier: GPL-2.0-only
//! The named pipes the API is served on.
//!
//! - The first instance is created with `FILE_FLAG_FIRST_PIPE_INSTANCE`, so
//!   nothing can squat the name, and a second Warlock fails to start.
//! - Remote clients are rejected (named pipes are otherwise reachable over
//!   SMB).
//! - A spare instance is always listening: each accepted connection is
//!   replaced by a new instance before it's handed over.
//! - Who may open each of the service's pipes is its access list's to say,
//!   and so Windows' to enforce, never the server's (Parker, 2026-11-19).
//!   The API's pipe admits SYSTEM, Administrators, `warlock-users` and
//!   `warlock-admin`; the admin pipe, where captures are, SYSTEM,
//!   Administrators and `warlock-admin`. A group that doesn't exist yet is
//!   left out.
//! - Each connection is tagged with its client's process ID
//!   (`GetNamedPipeClientProcessId`), as a [`Client`].

use std::ffi::c_void;
use std::io;
use std::os::windows::io::AsRawHandle;
use std::ptr::null_mut;
use std::time::Duration;

use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tracing::warn;
use windows_sys::Win32::Foundation::{CloseHandle, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{LookupAccountNameW, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, SID_NAME_USE};
use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows_sys::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};

/// The local group allowed to use the service's API, like Docker's
/// `docker-users`.
pub const USERS_GROUP: &str = "warlock-users";

/// The local group allowed to use the admin API too: captures of the
/// radio, which hear every device nearby and Warlock's traffic for every
/// user of this PC (Parker, 2026-11-19).
pub const ADMIN_GROUP: &str = "warlock-admin";

/// Which of the service's pipes: what it serves, and who may open it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Surface {
    /// `api/openapi.yaml`: [`USERS_GROUP`] and [`ADMIN_GROUP`].
    Api,
    /// `api/admin.yaml`: [`ADMIN_GROUP`].
    Admin,
}

impl Surface {
    /// The groups its pipe admits, besides SYSTEM and Administrators.
    fn groups(self) -> &'static [&'static str] {
        match self {
            Surface::Api => &[USERS_GROUP, ADMIN_GROUP],
            Surface::Admin => &[ADMIN_GROUP],
        }
    }
}

/// Who may open the pipes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Security {
    /// SYSTEM, Administrators and the [`Surface`]'s groups: the service's
    /// pipes.
    Service,
    /// Windows' default for a pipe this process creates, which admits this
    /// user: for tests.
    Default,
}

/// A security descriptor from `LocalAlloc`, freed on drop.
struct Descriptor(PSECURITY_DESCRIPTOR);

// SAFETY: an immutable buffer, only read by `CreateNamedPipeW`.
unsafe impl Send for Descriptor {}
// SAFETY: as above.
unsafe impl Sync for Descriptor {}

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
        unsafe { LocalFree(self.0) };
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// The SID of a local account or group, as a string; `None` if there's no
/// such account.
fn sid_string(account: &str) -> Option<String> {
    let name = wide(account);
    let (mut sid_len, mut domain_len, mut kind): (u32, u32, SID_NAME_USE) = (0, 0, 0);
    // SAFETY: the first call only asks for the sizes.
    unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            name.as_ptr(),
            null_mut(),
            &mut sid_len,
            null_mut(),
            &mut domain_len,
            &mut kind,
        )
    };
    if sid_len == 0 {
        return None;
    }
    let mut sid = vec![0u8; sid_len as usize];
    let mut domain = vec![0u16; domain_len as usize];
    // SAFETY: buffers of the sizes Windows asked for.
    let ok = unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            name.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut kind,
        )
    };
    if ok == 0 {
        return None;
    }
    let mut text: *mut u16 = null_mut();
    // SAFETY: a valid SID; the string is ours to free.
    unsafe {
        if ConvertSidToStringSidW(sid.as_mut_ptr().cast(), &mut text) == 0 {
            return None;
        }
        let len = (0..).take_while(|&i| *text.add(i) != 0).count();
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
        LocalFree(text.cast());
        Some(s)
    }
}

/// The SDDL of a service pipe's access list: SYSTEM and Administrators get
/// full access, and each group with a SID in `groups` read and write.
/// Protected from inheritance.
fn sddl(groups: &[(&str, Option<String>)]) -> String {
    let mut sddl = String::from("D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    for (_, sid) in groups {
        if let Some(sid) = sid {
            sddl.push_str(&format!("(A;;GRGW;;;{sid})"));
        }
    }
    sddl
}

impl Descriptor {
    /// The access list of `surface`'s pipe ([`sddl`]), with the groups that
    /// exist.
    fn for_service(surface: Surface) -> io::Result<Self> {
        let groups: Vec<(&str, Option<String>)> = surface.groups().iter().map(|&g| (g, sid_string(g))).collect();
        for (group, sid) in &groups {
            if sid.is_none() {
                warn!(?surface, "no {group} group: it can't open this pipe");
            }
        }
        let text = wide(&sddl(&groups));
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: a NUL-terminated SDDL string; the descriptor is ours to free.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(text.as_ptr(), SDDL_REVISION_1, &mut sd, null_mut())
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(sd))
    }
}

fn create(options: &ServerOptions, name: &str, sd: Option<&Descriptor>) -> io::Result<NamedPipeServer> {
    match sd {
        None => options.create(name),
        Some(sd) => {
            let mut attrs = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd.0,
                bInheritHandle: 0,
            };
            // SAFETY: the attributes and the descriptor outlive the call.
            unsafe { options.create_with_security_attributes_raw(name, (&raw mut attrs).cast::<c_void>()) }
        }
    }
}

/// Who's on the other end of a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Client {
    /// Its process ID; `None` if Windows wouldn't say.
    pub pid: Option<u32>,
}

impl Client {
    /// The path of its executable; empty if Windows wouldn't say.
    pub fn image(&self) -> String {
        let Some(pid) = self.pid else { return String::new() };
        // SAFETY: a handle we close; a buffer of the size we pass.
        unsafe {
            let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
            if process.is_null() {
                return String::new();
            }
            let mut buf = vec![0u16; 1024];
            let mut len = buf.len() as u32;
            let ok = QueryFullProcessImageNameW(process, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len);
            CloseHandle(process);
            if ok == 0 { String::new() } else { String::from_utf16_lossy(&buf[..len as usize]) }
        }
    }
}

/// The API's pipe, accepting connections.
pub struct PipeListener {
    name: String,
    options: ServerOptions,
    sd: Option<Descriptor>,
    /// The instance waiting for the next client.
    next: NamedPipeServer,
}

impl PipeListener {
    /// Creates the first instance of `surface`'s pipe. Fails if the name is
    /// taken, by a running Warlock or anything else. Needs a Tokio runtime.
    pub fn bind(name: &str, surface: Surface, security: Security) -> io::Result<Self> {
        let sd = match security {
            Security::Service => Some(Descriptor::for_service(surface)?),
            Security::Default => None,
        };
        let mut options = ServerOptions::new();
        options.reject_remote_clients(true).first_pipe_instance(true);
        let next = create(&options, name, sd.as_ref())?;
        options.first_pipe_instance(false);
        Ok(Self { name: name.into(), options, sd, next })
    }

    fn replacement(&self) -> io::Result<NamedPipeServer> {
        create(&self.options, &self.name, self.sd.as_ref())
    }

    /// The next client's connection, and who it is.
    pub async fn accept(&mut self) -> (NamedPipeServer, Client) {
        loop {
            let connected = self.next.connect().await;
            // A fresh instance takes over listening, whatever happened.
            let spare = loop {
                match self.replacement() {
                    Ok(s) => break s,
                    Err(e) => {
                        warn!("can't create a pipe instance: {e}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            };
            let pipe = std::mem::replace(&mut self.next, spare);
            if let Err(e) = connected {
                warn!("a client failed to connect: {e}");
                continue;
            }
            let mut pid = 0u32;
            // SAFETY: a connected server instance's handle.
            let ok = unsafe { GetNamedPipeClientProcessId(pipe.as_raw_handle(), &mut pid) };
            return (pipe, Client { pid: (ok != 0).then_some(pid) });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The admin pipe admits warlock-admin and never warlock-users; the
    /// API's pipe admits both. Groups that don't exist are left out.
    #[test]
    fn each_pipe_admits_its_groups() {
        let with = |surface: Surface| -> Vec<(&str, Option<String>)> {
            surface.groups().iter().map(|&g| (g, Some(format!("S-1-5-21-{}", g.len())))).collect()
        };
        assert_eq!(Surface::Admin.groups(), [ADMIN_GROUP]);
        assert_eq!(Surface::Api.groups(), [USERS_GROUP, ADMIN_GROUP]);
        let admin = sddl(&with(Surface::Admin));
        assert_eq!(admin, format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;S-1-5-21-{})", ADMIN_GROUP.len()));
        let none = sddl(&[(ADMIN_GROUP, None)]);
        assert_eq!(none, "D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    }
}
