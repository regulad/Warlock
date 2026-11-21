// SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
//! What Warlock's programs share for their diagnostics, whichever of
//! Sentry's SDKs sends them (PLAN.md, "Diagnostics"): the daemon's native
//! one (`sentry-native-sys`), and the Rust one in warlockctl, the extcap and
//! the installer (`warlock-sentry`). Dual-licensed, like `warlock-client`, so
//! the GPL-2.0-only daemon and the AGPL programs use one copy (Parker,
//! 2026-11-21).
//!
//! - [`release`] and [`environment`]: one release per commit, the same for
//!   every program (Parker, 2026-11-21, after doppelganger's).
//! - [`dsn`]: a project's DSN in a release or a trial's build, none in any
//!   other.
//! - [`do_not_track`] and [`turned_off`]: each program reads its own
//!   environment.
//! - [`system`]: this computer, without anything that identifies it.
//! - [`redact`]: text without what could identify anyone.

use std::sync::LazyLock;

use regex_lite::Regex;

/// Warlock's version, which every program carries.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// The commit Warlock was built from (`build.rs`), if known.
pub const COMMIT: Option<&str> = option_env!("WARLOCK_COMMIT");
/// Whether this is a tagged release build (`build.rs`).
pub const TAGGED: bool = option_env!("WARLOCK_TAGGED").is_some();
/// Whether this build was made with `WARLOCK_DIAGNOSTICS=1`, for a trial
/// (`build.rs`).
pub const TRIAL: bool = option_env!("WARLOCK_DIAGNOSTICS_TRIAL").is_some();

/// `warlock@<version>`, with `+<commit>` for any build but a tagged one: the
/// same for every program, so a commit is one release in each of their
/// projects.
pub fn release() -> String {
    match COMMIT {
        Some(commit) if !TAGGED => format!("warlock@{VERSION}+{commit}"),
        _ => format!("warlock@{VERSION}"),
    }
}

/// `production` for a tagged release build, `development` otherwise.
pub fn environment() -> &'static str {
    if TAGGED { "production" } else { "development" }
}

/// `project`'s DSN in a release, or a build for a trial; none (`""`) in any
/// other, from source or a `testing` run, which so sends nothing (Parker,
/// 2026-11-21, as #1 asked).
pub const fn dsn(project: &'static str) -> &'static str {
    if TAGGED || TRIAL { project } else { "" }
}

/// Whether a `DO_NOT_TRACK` of `value` asks for no tracking: set to anything
/// but empty, `0` or `false`.
pub fn do_not_track(value: Option<&str>) -> bool {
    value.map(str::trim).is_some_and(|v| !v.is_empty() && v != "0" && !v.eq_ignore_ascii_case("false"))
}

/// Whether this process's environment asks for no tracking. Each program
/// reads its own: the service sees only the system's, warlockctl and the
/// extcap the user's too, the installer whatever msiexec gives it.
pub fn turned_off() -> bool {
    do_not_track(std::env::var("DO_NOT_TRACK").ok().as_deref())
}

/// A fact for a context or a transaction: never anything identifying.
#[derive(Clone, Debug, PartialEq)]
pub enum Fact {
    Text(String),
    Number(f64),
    Flag(bool),
}

impl From<&str> for Fact {
    fn from(s: &str) -> Self {
        Fact::Text(s.to_owned())
    }
}
impl From<String> for Fact {
    fn from(s: String) -> Self {
        Fact::Text(s)
    }
}
impl From<bool> for Fact {
    fn from(b: bool) -> Self {
        Fact::Flag(b)
    }
}
impl From<u32> for Fact {
    fn from(n: u32) -> Self {
        Fact::Number(f64::from(n))
    }
}
impl From<f64> for Fact {
    fn from(n: f64) -> Self {
        Fact::Number(n)
    }
}

/// This computer, without anything that identifies it: Windows' version and
/// build, the processor, its threads, the memory (in GiB) and the
/// architecture.
pub fn system() -> Vec<(&'static str, Fact)> {
    const VERSION: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    let mut facts = Vec::new();
    if let Some(v) = win::registry_string(VERSION, "DisplayVersion") {
        facts.push(("windows_version", v.into()));
    }
    if let Some(build) = win::registry_string(VERSION, "CurrentBuild") {
        let ubr = win::registry_dword(VERSION, "UBR").map_or(String::new(), |u| format!(".{u}"));
        facts.push(("windows_build", format!("{build}{ubr}").into()));
    }
    if let Some(cpu) = win::registry_string(r"HARDWARE\DESCRIPTION\System\CentralProcessor\0", "ProcessorNameString") {
        facts.push(("cpu", cpu.trim().into()));
    }
    if let Ok(threads) = std::thread::available_parallelism() {
        facts.push(("cpu_threads", (threads.get() as f64).into()));
    }
    if let Some(bytes) = win::memory() {
        facts.push(("memory_gib", (bytes as f64 / (1u64 << 30) as f64).round().into()));
    }
    facts.push(("arch", std::env::consts::ARCH.into()));
    facts
}

/// `text` without what could identify anyone: this computer's and the
/// user's names, the user's folder in paths, network (IP and MAC)
/// addresses, account SIDs, UUIDs (AWDL host names among them) and long
/// hexadecimal strings (Bonjour instances' Bluetooth identifiers, keys).
pub fn redact(text: &str) -> String {
    static USERS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)([\\/]Users[\\/])[^\\/\s<>]+").unwrap());
    static SID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\bS-1-\d+(?:-\d+)+\b").unwrap());
    static UUID: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b").unwrap());
    static MAC: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\b[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}\b").unwrap());
    static HEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\b[0-9a-f]{12,}\b").unwrap());
    // Candidates for IP addresses, with a zone or port: checked by parsing.
    static IP: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[0-9A-Za-z:.%]*[:.][0-9A-Za-z:.%]*").unwrap());
    static NAMES: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
        let mut names = vec![(host_name(), "<host>")];
        for (var, with) in [("COMPUTERNAME", "<host>"), ("USERNAME", "<user>")] {
            if let Ok(name) = std::env::var(var) {
                names.push((name, with));
            }
        }
        names
            .into_iter()
            .filter(|(name, _)| name.trim().trim_end_matches('$').len() >= 2)
            .filter_map(|(name, with)| {
                let name = name.trim().trim_end_matches('$').to_owned();
                Some((Regex::new(&format!("(?i){}", regex_lite::escape(&name))).ok()?, with))
            })
            .collect()
    });
    let mut out = text.to_owned();
    for (name, with) in NAMES.iter() {
        out = name.replace_all(&out, *with).into_owned();
    }
    out = USERS.replace_all(&out, "${1}<user>").into_owned();
    out = SID.replace_all(&out, "<sid>").into_owned();
    out = IP
        .replace_all(&out, |m: &regex_lite::Captures| {
            let token = &m[0];
            if is_ip(token) { "<addr>".to_owned() } else { token.to_owned() }
        })
        .into_owned();
    out = UUID.replace_all(&out, "<id>").into_owned();
    out = MAC.replace_all(&out, "<addr>").into_owned();
    HEX.replace_all(&out, "<hex>").into_owned()
}

/// Whether `token` is an IP address, maybe with a zone (`%49`) or a port.
fn is_ip(token: &str) -> bool {
    let token = token.trim_matches(|c| c == '.' || c == ':');
    let address = token.split('%').next().unwrap_or(token);
    address.parse::<std::net::Ipv6Addr>().is_ok()
        || address.parse::<std::net::Ipv4Addr>().is_ok()
        || address.parse::<std::net::SocketAddrV4>().is_ok()
}

/// A path's last component: modules keep only their file names, as their
/// paths can name the user's folder.
pub fn file_name(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_owned()
}

/// This computer's DNS host name, lower-cased, as Warlock names itself on
/// AWDL: one of the names [`redact`] takes out.
fn host_name() -> String {
    win::host_name().map(|h| h.to_ascii_lowercase()).unwrap_or_default()
}

/// What [`system`] and [`redact`] read from Windows.
mod win {
    use windows_sys::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RRF_RT_REG_SZ, RegGetValueW};
    use windows_sys::Win32::System::SystemInformation::{
        ComputerNamePhysicalDnsHostname, GetComputerNameExW, GlobalMemoryStatusEx, MEMORYSTATUSEX,
    };

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    /// A string value under `HKEY_LOCAL_MACHINE\key`.
    pub fn registry_string(key: &str, name: &str) -> Option<String> {
        let (key, name) = (wide(key), wide(name));
        let mut data = vec![0u16; 256];
        let mut size = (data.len() * 2) as u32;
        // SAFETY: NUL-terminated names, and a buffer of the size we pass.
        let status = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                name.as_ptr(),
                RRF_RT_REG_SZ,
                std::ptr::null_mut(),
                data.as_mut_ptr().cast(),
                &mut size,
            )
        };
        if status != 0 {
            return None;
        }
        let len = data.iter().position(|&c| c == 0).unwrap_or(data.len());
        Some(String::from_utf16_lossy(&data[..len]))
    }

    /// A DWORD value under `HKEY_LOCAL_MACHINE\key`.
    pub fn registry_dword(key: &str, name: &str) -> Option<u32> {
        let (key, name) = (wide(key), wide(name));
        let mut value = 0u32;
        let mut size = 4u32;
        // SAFETY: as above, with a DWORD.
        let status = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                key.as_ptr(),
                name.as_ptr(),
                RRF_RT_REG_DWORD,
                std::ptr::null_mut(),
                (&mut value as *mut u32).cast(),
                &mut size,
            )
        };
        (status == 0).then_some(value)
    }

    /// The physical memory, in bytes.
    pub fn memory() -> Option<u64> {
        // SAFETY: a plain C struct, its size set as the call requires.
        let mut status: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
        status.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        (unsafe { GlobalMemoryStatusEx(&mut status) } != 0).then_some(status.ullTotalPhys)
    }

    /// This computer's DNS host name.
    pub fn host_name() -> Option<String> {
        let mut buf = vec![0u16; 256];
        let mut len = buf.len() as u32;
        // SAFETY: a buffer of the length we pass.
        let ok = unsafe { GetComputerNameExW(ComputerNamePhysicalDnsHostname, buf.as_mut_ptr(), &mut len) };
        (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn do_not_track_is_anything_but_empty_zero_or_false() {
        for on in ["1", "true", "yes", " 1 "] {
            assert!(do_not_track(Some(on)), "{on:?}");
        }
        for off in [None, Some(""), Some("0"), Some("false"), Some("FALSE"), Some("  ")] {
            assert!(!do_not_track(off), "{off:?}");
        }
    }

    #[test]
    fn only_a_release_or_a_trial_has_a_dsn() {
        assert_eq!(dsn("https://key@example.invalid/1").is_empty(), !TAGGED && !TRIAL);
    }

    #[test]
    fn every_program_names_the_release_alike() {
        assert!(release().starts_with(&format!("warlock@{VERSION}")));
        assert_eq!(release().contains('+'), !TAGGED && COMMIT.is_some());
    }

    #[test]
    fn what_the_programs_log_of_peers_and_accounts_is_redacted() {
        let cases = [
            ("PeerFound(c6:45:45:ba:cd:d3)", "PeerFound(<addr>)"),
            (r#"host=Some("5e1f0892-f2ac-4e0c-b459-d625cd34a1f8.local")"#, r#"host=Some("<id>.local")"#),
            (
                "instances=[\"rdlink-03ad02a1fc20._rdlink._tcp.local\"]",
                "instances=[\"rdlink-<hex>._rdlink._tcp.local\"]",
            ),
            ("routing fddd:90e5:8ba0::8 to the adapter", "routing <addr> to the adapter"),
            ("ping fe80::7456:82ff:fe58:5770%49", "ping <addr>"),
            (r"device=USB\VID_2357&PID_012D\123456", r"device=USB\VID_2357&PID_012D\123456"),
            (r"C:\Users\someone\x.log", r"C:\Users\<user>\x.log"),
            (
                "S-1-5-21-3623811015-3361044348-30300820-1013 is already in warlock-users",
                "<sid> is already in warlock-users",
            ),
        ];
        for (text, expected) in cases {
            assert_eq!(redact(text), expected, "{text}");
        }
        for kept in
            ["Warlock 0.2.5", "channel 149 at 40 MHz", "build 26300.7019", "TP-Link Archer T3U v1", "error 1376"]
        {
            assert_eq!(redact(kept), kept);
        }
    }

    #[test]
    fn this_computers_and_users_names_are_redacted() {
        for name in [
            host_name(),
            std::env::var("COMPUTERNAME").unwrap_or_default(),
            std::env::var("USERNAME").unwrap_or_default(),
        ] {
            if name.trim().len() >= 2 {
                let out = redact(&format!(r"{name}.local C:\Users\{name}\x"));
                assert!(!out.to_lowercase().contains(&name.to_lowercase()), "{name}: {out}");
            }
        }
    }

    #[test]
    fn modules_keep_only_their_file_names() {
        assert_eq!(file_name(r"C:\Users\someone\Warlock\warlockctl.exe"), "warlockctl.exe");
        assert_eq!(file_name("warlock.pdb"), "warlock.pdb");
    }

    #[test]
    fn this_computer_is_described() {
        let facts = system();
        assert!(facts.iter().any(|(k, _)| *k == "arch"));
        let host = host_name();
        if host.len() >= 2 {
            assert!(facts.iter().all(|(_, v)| !matches!(v, Fact::Text(t) if t.to_lowercase().contains(&host))));
        }
    }
}
