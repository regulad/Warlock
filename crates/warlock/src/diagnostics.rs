// SPDX-License-Identifier: GPL-2.0-only
//! Diagnostics: crash reports, errors and usage statistics, sent to Sentry
//! through its native SDK (sentry-native, MIT, `sentry-native-sys`), with
//! nothing that identifies the user, this computer or the devices nearby
//! (`PRIVACY.md`; Parker, 2026-11-21). Not Sentry's Rust SDK: it needs crates
//! offered under Apache-2.0 alone, which GPL-2.0-only Warlock can't take
//! (PLAN.md, "Diagnostics").
//!
//! - **Only in releases:** a tagged build has the DSN built in, as does one
//!   built with `WARLOCK_DIAGNOSTICS=1`, for a trial. Any other, from source
//!   or a `testing` run, has none and sends nothing (Parker, 2026-11-21, as
//!   #1 asked).
//! - **Off** when the service's environment, which is the system-wide one,
//!   has `DO_NOT_TRACK` set to anything but empty, `0` or `false`. A user's
//!   own `DO_NOT_TRACK` doesn't reach the service.
//! - **Sent:** native crashes (in devourer's C++ too: sentry-native's
//!   in-process backend), panics, and what Warlock logs as errors, with its
//!   warnings before them as breadcrumbs; a session per run; a transaction
//!   per request to the API, named by its route (`/v1/peers/{address}`, not
//!   the address), with its status; this computer's Windows version,
//!   processor, memory and architecture ([`system`]), the Wi-Fi adapter's
//!   model and the radio's state, and the Bluetooth's.
//! - **Never sent:** names (the user's, this computer's, peers'), user or
//!   device IDs, network addresses (peers' AWDL MACs, IPv6 addresses), USB
//!   serial numbers, keys. Everything Warlock hands over goes through
//!   [`redact`] first. Two things sentry-native would add by itself are
//!   taken off, as a probe of 0.17.6 showed (2026-11-21):
//!   - the installation ID it keeps in its database and puts on every event
//!     and session: the user is set to the same `anonymous` on every
//!     computer instead, before the session starts;
//!   - its modules' full paths, which can name the user's folder: cut to
//!     file names in `before_send` ([`before_send`]).

use std::ffi::{CString, c_char, c_void};
use std::fmt::Write as _;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use regex_lite::Regex;
use sentry_native_sys::*;
use tracing::{Level, info, warn};
use warlock_api::Served;

/// Warlock's Sentry project (`regulad/warlock`, platform `native`, made by
/// the homelab's `tofu/sentry`, 2026-11-21). A DSN only lets a client send
/// events, so it isn't a secret.
const PROJECT: &str = "https://a44d5cf240aba5efe4c1f92f45a9a9c4@o4506961510596608.ingest.us.sentry.io/4512468117225472";

/// The DSN this build sends to: [`PROJECT`] in a release or a trial's build
/// (`build.rs`), and none in any other.
pub const DSN: &str = if TAGGED || TRIAL { PROJECT } else { "" };

/// The commit Warlock was built from (`build.rs`), if known.
const COMMIT: Option<&str> = option_env!("WARLOCK_COMMIT");
/// Whether this is a tagged release build (`build.rs`).
const TAGGED: bool = option_env!("WARLOCK_TAGGED").is_some();
/// Whether this build was made with `WARLOCK_DIAGNOSTICS=1`, for a trial
/// (`build.rs`).
const TRIAL: bool = option_env!("WARLOCK_DIAGNOSTICS_TRIAL").is_some();

/// Whether diagnostics are on: everything here does nothing while they're
/// off.
static ON: AtomicBool = AtomicBool::new(false);

/// `warlock@<version>`, with `+<commit>` for any build but a tagged one.
pub fn release() -> String {
    let version = env!("CARGO_PKG_VERSION");
    match COMMIT {
        Some(commit) if !TAGGED => format!("warlock@{version}+{commit}"),
        _ => format!("warlock@{version}"),
    }
}

/// `production` for a tagged release build, `development` otherwise.
pub fn environment() -> &'static str {
    if TAGGED { "production" } else { "development" }
}

/// Whether a `DO_NOT_TRACK` of `value` asks for no tracking: set to anything
/// but empty, `0` or `false`.
pub fn do_not_track(value: Option<&str>) -> bool {
    value.map(str::trim).is_some_and(|v| !v.is_empty() && v != "0" && !v.eq_ignore_ascii_case("false"))
}

/// Diagnostics for this run, until dropped, which ends the session and
/// sends what's left (for at most 2 s).
#[must_use]
pub struct Diagnostics {
    on: bool,
}

impl Drop for Diagnostics {
    fn drop(&mut self) {
        if self.on {
            ON.store(false, Ordering::SeqCst);
            // SAFETY: sentry_init succeeded; this is its one close.
            unsafe { sentry_close() };
        }
    }
}

/// Starts diagnostics for this run, if this build has a DSN and
/// `DO_NOT_TRACK` doesn't say not to.
pub fn start() -> Diagnostics {
    if DSN.is_empty() {
        info!("this build of Warlock isn't a release, so it sends no diagnostics");
        return Diagnostics { on: false };
    }
    if do_not_track(std::env::var("DO_NOT_TRACK").ok().as_deref()) {
        info!("DO_NOT_TRACK is set system-wide, so Warlock sends no diagnostics");
        return Diagnostics { on: false };
    }
    let root = std::env::var_os("ProgramData").map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from);
    init(DSN, &root.join("Warlock").join("sentry"), None)
}

/// Starts the SDK for `dsn` with its database at `database` (where it keeps
/// what it hasn't sent yet, and crashes until the next start), sending
/// through `transport` if given (tests), or WinHTTP.
fn init(dsn: &str, database: &Path, transport: sentry_send_function_t) -> Diagnostics {
    let path: Vec<u16> = database.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: options made here and handed to sentry_init, which owns them;
    // the strings outlive the calls, which copy them.
    let started = unsafe {
        let options = sentry_options_new();
        sentry_options_set_dsn(options, c(dsn).as_ptr());
        sentry_options_set_release(options, c(&release()).as_ptr());
        sentry_options_set_environment(options, c(environment()).as_ptr());
        sentry_options_set_database_pathw(options, path.as_ptr());
        sentry_options_set_traces_sample_rate(options, 1.0);
        // The session starts by hand, once the user is set: the SDK's own
        // would carry its installation ID.
        sentry_options_set_auto_session_tracking(options, 0);
        sentry_options_set_shutdown_timeout(options, 2000);
        sentry_options_set_before_send(options, Some(before_send), std::ptr::null_mut());
        if transport.is_some() {
            sentry_options_set_transport(options, sentry_transport_new(transport));
        }
        sentry_init(options) == 0
    };
    if !started {
        warn!("diagnostics: Sentry's SDK wouldn't start");
        return Diagnostics { on: false };
    }
    // SAFETY: the SDK is up; the value is handed over.
    unsafe {
        // The same user on every computer, in place of the installation ID
        // the SDK keeps and would put on everything.
        let user = sentry_value_new_object();
        set(user, "id", string("anonymous"));
        sentry_set_user(user);
        sentry_start_session();
    }
    ON.store(true, Ordering::SeqCst);
    context("system", &system());
    panic_hook();
    Diagnostics { on: true }
}

/// A fact for a context or a transaction: never anything identifying.
#[derive(Clone, Debug)]
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

fn value(fact: &Fact) -> sentry_value_t {
    // SAFETY: plain value constructors.
    unsafe {
        match fact {
            Fact::Text(s) => string(s),
            Fact::Number(n) => sentry_value_new_double(*n),
            Fact::Flag(b) => sentry_value_new_bool(i32::from(*b)),
        }
    }
}

/// Replaces the context `key` (`system`, `adapter`, `radio`, `bluetooth`)
/// with `facts`.
pub fn context(key: &str, facts: &[(&str, Fact)]) {
    if !ON.load(Ordering::SeqCst) {
        return;
    }
    // SAFETY: a new object, handed to the SDK.
    unsafe {
        let object = sentry_value_new_object();
        for (name, fact) in facts {
            set(object, name, value(fact));
        }
        sentry_set_context(c(key).as_ptr(), object);
    }
}

/// An error, redacted, as an event.
pub fn error(message: &str) {
    if !ON.load(Ordering::SeqCst) {
        return;
    }
    // SAFETY: the event is handed to the SDK.
    unsafe {
        let event =
            sentry_value_new_message_event(SENTRY_LEVEL_ERROR, c("warlock").as_ptr(), c(&redact(message)).as_ptr());
        sentry_capture_event(event);
    }
}

/// A step, redacted, as a breadcrumb: carried by the next event.
pub fn breadcrumb(message: &str) {
    if !ON.load(Ordering::SeqCst) {
        return;
    }
    // SAFETY: the breadcrumb is handed to the SDK.
    unsafe { sentry_add_breadcrumb(sentry_value_new_breadcrumb(c("default").as_ptr(), c(&redact(message)).as_ptr())) };
}

/// A request the API served, as a transaction of its own: `method route`,
/// from its arrival to its answer (for a lock, the start of its stream).
pub fn served(request: &Served) {
    if !ON.load(Ordering::SeqCst) {
        return;
    }
    let micros = |t: SystemTime| t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_micros() as u64);
    let status = match request.status {
        200..=299 => SENTRY_SPAN_STATUS_OK,
        400 => SENTRY_SPAN_STATUS_INVALID_ARGUMENT,
        403 => SENTRY_SPAN_STATUS_PERMISSION_DENIED,
        404 => SENTRY_SPAN_STATUS_NOT_FOUND,
        409 => SENTRY_SPAN_STATUS_ALREADY_EXISTS,
        500..=599 => SENTRY_SPAN_STATUS_INTERNAL_ERROR,
        _ => SENTRY_SPAN_STATUS_UNKNOWN,
    };
    let name = format!("{} {}", request.method, request.route);
    // SAFETY: the context goes to the transaction, which finishing frees.
    unsafe {
        let context = sentry_transaction_context_new(c(&name).as_ptr(), c("http.server").as_ptr());
        let transaction = sentry_transaction_start_ts(context, sentry_value_new_null(), micros(request.started));
        if transaction.is_null() {
            return;
        }
        sentry_transaction_set_data(transaction, c("http.request.method").as_ptr(), string(&request.method));
        sentry_transaction_set_data(transaction, c("http.route").as_ptr(), string(request.route));
        sentry_transaction_set_data(
            transaction,
            c("http.response.status_code").as_ptr(),
            sentry_value_new_int32(i32::from(request.status)),
        );
        sentry_transaction_set_data(transaction, c("warlock.pipe").as_ptr(), string(request.surface));
        sentry_transaction_set_status(transaction, status);
        sentry_transaction_finish_ts(transaction, micros(request.answered));
    }
}

/// Panics, as fatal events with their stack, before the panic goes on.
fn panic_hook() {
    static INSTALLED: AtomicBool = AtomicBool::new(false);
    if INSTALLED.swap(true, Ordering::SeqCst) {
        return;
    }
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if ON.load(Ordering::SeqCst) {
            let payload = info
                .payload()
                .downcast_ref::<&str>()
                .map(|s| (*s).to_owned())
                .or_else(|| info.payload().downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "a panic".into());
            let at = info.location().map_or_else(String::new, |l| format!(" at {}:{}", l.file(), l.line()));
            // SAFETY: the event is handed to the SDK.
            unsafe {
                let event = sentry_value_new_event();
                set(event, "level", string("fatal"));
                let exception =
                    sentry_value_new_exception(c("panic").as_ptr(), c(&redact(&format!("{payload}{at}"))).as_ptr());
                sentry_value_set_stacktrace(exception, std::ptr::null_mut(), 0);
                sentry_event_add_exception(event, exception);
                sentry_capture_event(event);
            }
        }
        previous(info);
    }));
}

/// What Warlock logs, for the diagnostics: errors as events, warnings as
/// breadcrumbs (carried by the next event), both redacted. Nothing below
/// warnings: Warlock's information names peers and their services.
pub struct Layer;

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Layer {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        let level = *event.metadata().level();
        if (level != Level::ERROR && level != Level::WARN) || !ON.load(Ordering::SeqCst) {
            return;
        }
        let mut text = String::new();
        event.record(&mut Fields(&mut text));
        let text = format!("{}: {}", event.metadata().target(), text.trim());
        if level == Level::ERROR { error(&text) } else { breadcrumb(&text) }
    }
}

/// An event's fields as text: the message, then `name=value`.
struct Fields<'a>(&'a mut String);

impl tracing::field::Visit for Fields<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let rest = std::mem::take(self.0);
            let _ = write!(self.0, "{value:?}{rest}");
        } else {
            let _ = write!(self.0, " {}={value:?}", field.name());
        }
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
/// addresses, UUIDs (AWDL host names among them) and long hexadecimal
/// strings (Bonjour instances' Bluetooth identifiers, keys).
pub fn redact(text: &str) -> String {
    static USERS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)([\\/]Users[\\/])[^\\/\s<>]+").unwrap());
    static UUID: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b").unwrap());
    static MAC: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\b[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}\b").unwrap());
    static HEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)\b[0-9a-f]{12,}\b").unwrap());
    // Candidates for IP addresses, with a zone or port: checked by parsing.
    static IP: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[0-9A-Za-z:.%]*[:.][0-9A-Za-z:.%]*").unwrap());
    static NAMES: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
        let mut names = vec![(crate::api::host_name(), "<host>")];
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

/// A path's last component.
fn file_name(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_owned()
}

/// The fields of a module the SDK lists in `debug_meta`.
const IMAGE_KEYS: [&str; 8] =
    ["type", "arch", "image_addr", "image_size", "code_file", "code_id", "debug_file", "debug_id"];

/// Cuts the paths of the modules an event lists to their file names, as
/// they would otherwise name the user's folder. The SDK's list is shared and
/// frozen, so it's rebuilt: each module copied, field by field.
unsafe extern "C" fn before_send(event: sentry_value_t, _: *mut sentry_hint_t, _: *mut c_void) -> sentry_value_t {
    // SAFETY: the SDK hands over the event, and takes back what's returned;
    // `get`'s results are borrowed, so they're increfed before being set.
    unsafe {
        let images = get(get(event, "debug_meta"), "images");
        let count = sentry_value_get_length(images);
        if count == 0 {
            return event;
        }
        let rebuilt = sentry_value_new_list();
        for i in 0..count {
            let image = sentry_value_get_by_index(images, i);
            let copy = sentry_value_new_object();
            for key in IMAGE_KEYS {
                let field = get(image, key);
                if sentry_value_is_null(field) != 0 {
                    continue;
                }
                if key == "code_file" || key == "debug_file" {
                    set(copy, key, string(&file_name(&as_string(field))));
                } else {
                    set(copy, key, sentry_value_incref(field));
                }
            }
            sentry_value_append(rebuilt, copy);
        }
        let meta = sentry_value_new_object();
        set(meta, "images", rebuilt);
        set(event, "debug_meta", meta);
        event
    }
}

/// A C string, without the NULs it can't hold.
fn c(s: &str) -> CString {
    CString::new(s.replace('\0', "")).expect("no NULs")
}

/// A new string value.
unsafe fn string(s: &str) -> sentry_value_t {
    // SAFETY: the SDK copies the string.
    unsafe { sentry_value_new_string(c(s).as_ptr()) }
}

/// Sets `key` of `object` to `value`, which the object takes.
unsafe fn set(object: sentry_value_t, key: &str, value: sentry_value_t) {
    // SAFETY: the SDK copies the key and takes the value.
    unsafe { sentry_value_set_by_key(object, c(key).as_ptr(), value) };
}

/// `key` of `object`, borrowed; null if absent.
unsafe fn get(object: sentry_value_t, key: &str) -> sentry_value_t {
    // SAFETY: the SDK copies the key; the value stays the object's.
    unsafe { sentry_value_get_by_key(object, c(key).as_ptr()) }
}

/// A string value's text; empty for anything else.
unsafe fn as_string(value: sentry_value_t) -> String {
    // SAFETY: a NUL-terminated string the value owns, or null.
    unsafe {
        let p: *const c_char = sentry_value_as_string(value);
        if p.is_null() { String::new() } else { std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned() }
    }
}

/// What [`system`] reads from Windows.
mod win {
    use windows_sys::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RRF_RT_REG_SZ, RegGetValueW};
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

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
    fn only_a_release_or_a_trial_has_the_dsn() {
        assert_eq!(DSN.is_empty(), !TAGGED && !TRIAL);
    }

    #[test]
    fn what_warlock_logs_of_peers_is_redacted() {
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
        ];
        for (text, expected) in cases {
            assert_eq!(redact(text), expected, "{text}");
        }
        for kept in ["Warlock 0.2.5", "channel 149 at 40 MHz", "build 26300.7019", "TP-Link Archer T3U v1"] {
            assert_eq!(redact(kept), kept);
        }
    }

    #[test]
    fn this_computers_name_is_redacted() {
        let host = crate::api::host_name();
        if host.len() >= 2 {
            assert!(!redact(&format!("{host}.local")).to_lowercase().contains(&host.to_lowercase()));
        }
    }

    /// What the SDK sends, captured by a transport of the test's: printed
    /// with `WARLOCK_SHOW_DIAGNOSTICS=1 cargo test -p warlock nothing_identifying
    /// -- --nocapture`.
    static SENT: Mutex<Vec<String>> = Mutex::new(Vec::new());

    unsafe extern "C" fn capture(envelope: *mut sentry_envelope_t, _: *mut c_void) {
        // SAFETY: the SDK hands over the envelope, which is freed here.
        unsafe {
            let mut len = 0usize;
            let text = sentry_envelope_serialize(envelope, &mut len);
            let bytes = std::slice::from_raw_parts(text.cast::<u8>(), len);
            SENT.lock().unwrap().push(String::from_utf8_lossy(bytes).into_owned());
            sentry_free(text.cast());
            sentry_envelope_free(envelope);
        }
    }

    /// End to end, through the SDK: a session, an error with a breadcrumb, a
    /// request's transaction and a context carry neither this computer's
    /// name, nor the user's, nor the SDK's installation ID, nor an address,
    /// and the modules keep only their file names. The SDK is global, so
    /// this is the one test that starts it.
    #[test]
    fn nothing_identifying_leaves() {
        let database = std::env::temp_dir().join(format!("warlock-diagnostics-{}", std::process::id()));
        let diagnostics = init(PROJECT, &database, Some(capture));
        assert!(diagnostics.on);
        let user = std::env::var("USERNAME").unwrap_or_default();
        breadcrumb("PeerFound(c6:45:45:ba:cd:d3)");
        error(&format!(r"opening C:\Users\{user}\x on {} from fe80::1%49", crate::api::host_name()));
        context("adapter", &[("model", "TP-Link Archer T3U v1".into()), ("reference", true.into())]);
        let now = SystemTime::now();
        served(&Served {
            surface: "api",
            method: "GET".into(),
            route: "/v1/peers/{address}",
            status: 200,
            started: now,
            answered: now,
        });
        drop(diagnostics);
        let installation = std::fs::read_to_string(database.join("installation_id")).unwrap_or_default();
        let installation = installation.lines().next().unwrap_or_default().to_owned();
        let sent = SENT.lock().unwrap().join("\n");
        if std::env::var_os("WARLOCK_SHOW_DIAGNOSTICS").is_some() {
            eprintln!("{sent}");
        }
        let lower = sent.to_lowercase();
        assert!(sent.contains(r#""id":"anonymous""#), "the fixed user: {sent}");
        assert!(sent.contains(r#""did":"anonymous""#), "the session's: {sent}");
        assert!(installation.is_empty() || !sent.contains(&installation), "the installation ID leaked: {sent}");
        assert!(!lower.contains(r"\\users\\") || lower.contains(r"\\users\\<user>"), "a user's folder: {sent}");
        for name in [crate::api::host_name(), user] {
            if name.len() >= 2 {
                assert!(!lower.contains(&name.to_lowercase()), "{name} leaked: {sent}");
            }
        }
        assert!(!lower.contains("c6:45:45:ba:cd:d3") && !lower.contains("fe80::1"), "an address leaked: {sent}");
        assert!(sent.contains("GET /v1/peers/{address}"), "the request's transaction: {sent}");
        let _ = std::fs::remove_dir_all(&database);
    }
}
