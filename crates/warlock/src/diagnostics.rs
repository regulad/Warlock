// SPDX-License-Identifier: GPL-2.0-only
//! Diagnostics: crash reports, errors and usage statistics, sent to Sentry
//! through its native SDK (sentry-native, MIT, `sentry-native-sys`), with
//! nothing that identifies the user, this computer or the devices nearby
//! (`PRIVACY.md`; Parker, 2026-11-21). Not Sentry's Rust SDK: it needs crates
//! offered under Apache-2.0 alone, which GPL-2.0-only Warlock can't take
//! (PLAN.md, "Diagnostics").
//!
//! What the programs share (the release, the DSN a build has, `DO_NOT_TRACK`,
//! this computer's facts, redaction) is `warlock-diagnostics`'s.
//!
//! - **Only in releases:** a tagged build has the DSN built in, as does one
//!   built with `WARLOCK_DIAGNOSTICS=1`, for a trial. Any other, from source
//!   or a `testing` run, has none and sends nothing (Parker, 2026-11-21, as
//!   #1 asked).
//! - **Every command reports here** (Parker, 2026-11-21): the daemon (`run`,
//!   `service`), and `setup` and `teardown`, which the MSI runs; each event
//!   is tagged with its command. Only the daemon's runs are sessions.
//! - **Off** when the service's environment, which is the system-wide one,
//!   has `DO_NOT_TRACK` set to anything but empty, `0` or `false`. A user's
//!   own `DO_NOT_TRACK` doesn't reach the service.
//! - **Sent:** native crashes (in devourer's C++ too: sentry-native's
//!   in-process backend), panics, and what Warlock logs as errors, with its
//!   warnings before them as breadcrumbs; a session per daemon run; a
//!   transaction per request to the API, named by its route
//!   (`/v1/peers/{address}`, not the address), with its status; this
//!   computer's Windows version, processor, memory and architecture, the
//!   Wi-Fi adapter's model and the radio's state, and the Bluetooth's.
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

use std::ffi::{CString, c_char, c_int, c_void};
use std::fmt::Write as _;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sentry_native_sys::*;
use tracing::{Level, warn};
use warlock_api::Served;
pub use warlock_diagnostics::Fact;
use warlock_diagnostics::{environment, file_name, redact, release, system};

/// Warlock's Sentry project (`regulad/warlock`, platform `native`, made by
/// the homelab's `tofu/sentry`, 2026-11-21). A DSN only lets a client send
/// events, so it isn't a secret.
const PROJECT: &str = "https://a44d5cf240aba5efe4c1f92f45a9a9c4@o4506961510596608.ingest.us.sentry.io/4512468117225472";

/// The DSN this build sends to: [`PROJECT`] in a release or a trial's
/// build, and none in any other.
pub const DSN: &str = warlock_diagnostics::dsn(PROJECT);

/// Whether diagnostics are on: everything here does nothing while they're
/// off.
static ON: AtomicBool = AtomicBool::new(false);

/// Diagnostics for this process, until dropped, which ends the session if
/// one started and sends what's left (for at most 2 s).
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

/// Starts diagnostics for this process, running `command` (`run`,
/// `service`, `setup`, ...), if this build has a DSN and `DO_NOT_TRACK`
/// doesn't say not to. Called before logging starts: [`state`] says which,
/// for the log.
pub fn start(command: &str) -> Diagnostics {
    if DSN.is_empty() || warlock_diagnostics::turned_off() {
        return Diagnostics { on: false };
    }
    let root = std::env::var_os("ProgramData").map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from);
    let diagnostics = init(DSN, &root.join("Warlock").join("sentry"), None);
    if diagnostics.on {
        // SAFETY: plain strings, which the SDK copies.
        unsafe { sentry_set_tag(c("command").as_ptr(), c(command).as_ptr()) };
    }
    diagnostics
}

/// The log's target for what the SDK says of itself, which [`Layer`] keeps
/// out of the diagnostics: the SDK reporting on its own reports.
const SDK_TARGET: &str = "warlock::sentry";

/// What the SDK says of itself (`warlock_sentry_set_logger`), to Warlock's
/// log.
unsafe extern "C" fn sdk_log(level: c_int, message: *const c_char) {
    if message.is_null() {
        return;
    }
    // SAFETY: the shim's NUL-terminated text, for the call.
    let text = unsafe { std::ffi::CStr::from_ptr(message) }.to_string_lossy();
    if level >= SENTRY_LEVEL_ERROR {
        tracing::error!(target: SDK_TARGET, "Sentry's SDK: {text}");
    } else {
        warn!(target: SDK_TARGET, "Sentry's SDK: {text}");
    }
}

/// Whether diagnostics are on, and why not, for the log.
pub fn state() -> &'static str {
    if ON.load(Ordering::SeqCst) {
        "Warlock sends diagnostics (PRIVACY.md)"
    } else if DSN.is_empty() {
        "this build of Warlock isn't a release, so it sends no diagnostics"
    } else if warlock_diagnostics::turned_off() {
        "DO_NOT_TRACK is set system-wide, so Warlock sends no diagnostics"
    } else {
        "Sentry's SDK wouldn't start, so Warlock sends no diagnostics"
    }
}

/// Starts this daemon run's session, for release health: the daemon's runs
/// are sessions, `setup` and `teardown` aren't.
pub fn session() {
    if ON.load(Ordering::SeqCst) {
        // SAFETY: the SDK is up, its user set.
        unsafe { sentry_start_session() };
    }
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
        // A session starts by hand ([`session`]), once the user is set: the
        // SDK's own would carry its installation ID, and would count
        // `setup`'s runs.
        sentry_options_set_auto_session_tracking(options, 0);
        sentry_options_set_shutdown_timeout(options, 2000);
        // What the SDK says of itself, from warnings up, to Warlock's log
        // ([`sdk_log`]): a service's stderr, where it would go, goes nowhere.
        // Not while crashing, when the log's locks may be held.
        sentry_options_set_debug(options, 1);
        sentry_options_set_logger_level(options, SENTRY_LEVEL_WARNING);
        sentry_options_set_logger_enabled_when_crashed(options, 0);
        warlock_sentry_set_logger(options, sdk_log);
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
    }
    ON.store(true, Ordering::SeqCst);
    context("system", &system());
    panic_hook();
    Diagnostics { on: true }
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
        if (level != Level::ERROR && level != Level::WARN)
            || !ON.load(Ordering::SeqCst)
            || event.metadata().target() == SDK_TARGET
        {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

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
        session();
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
