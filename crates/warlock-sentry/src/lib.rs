// SPDX-License-Identifier: AGPL-3.0-only
//! Diagnostics for Warlock's AGPL programs, through Sentry's Rust SDK (MIT):
//! warlockctl, warlock-extcap and the installer's custom actions
//! (`warlock-msi-ca`), each to a Sentry project of its own (Parker,
//! 2026-11-21). The daemon can't use it: the SDK needs crates offered under
//! Apache-2.0 alone, which its GPL-2.0-only licence can't take. So this
//! crate is AGPL, and only the AGPL programs depend on it (`deny.toml`).
//!
//! What every program shares (the release, the DSN a build has,
//! `DO_NOT_TRACK`, this computer's facts, redaction) is
//! `warlock-diagnostics`'s, as the daemon's is.
//!
//! - **Only in releases**, or a trial's build: [`start`] takes the DSN
//!   `warlock_diagnostics::dsn` gives, which is empty in any other.
//! - **Off** when `DO_NOT_TRACK` is set in the program's own environment.
//! - **Sent:** panics, and the errors a program reports ([`error`]), with
//!   the breadcrumbs before them ([`breadcrumb`]); this computer's Windows
//!   version, processor, memory and architecture; the installer's steps, as
//!   transactions ([`Timed`]). No sessions: a run of warlockctl lasts an
//!   instant. Requests to Warlock aren't transactions: the daemon records
//!   each.
//! - **Never sent:** names (the user's, this computer's, peers'), user or
//!   device IDs, network addresses, account SIDs, keys. `server_name`, which
//!   the SDK would set to this computer's name, is the program's. Every
//!   event and breadcrumb passes through `redact` before it leaves, and
//!   modules keep only their file names.

use std::sync::Arc;
use std::time::Instant;

use sentry::TransactionContext;
use sentry::protocol::{Breadcrumb, Context, DebugImage, Event, Level, Map, SpanStatus, Stacktrace, Value};
pub use warlock_diagnostics::{Fact, dsn};
use warlock_diagnostics::{environment, file_name, redact, release, system};

/// Diagnostics for this program, until dropped, which sends what's left
/// (for at most 2 s).
#[must_use]
pub struct Diagnostics {
    guard: Option<sentry::ClientInitGuard>,
}

impl Diagnostics {
    /// Whether anything is sent.
    pub fn on(&self) -> bool {
        self.guard.is_some()
    }
}

/// Starts diagnostics for `program` (`warlockctl`, `warlock-extcap`,
/// `warlock-installer`), sending to `dsn` (its project's, as
/// `warlock_diagnostics::dsn` gives it), unless it's empty or `DO_NOT_TRACK`
/// says not to.
pub fn start(program: &'static str, dsn: &'static str) -> Diagnostics {
    if dsn.is_empty() || warlock_diagnostics::turned_off() {
        return Diagnostics { guard: None };
    }
    let guard = sentry::init(options(program, dsn.parse().ok()));
    sentry::configure_scope(|scope| scope.set_context("system", context(&system())));
    Diagnostics { guard: Some(guard) }
}

/// The SDK's options for `program`.
fn options(program: &'static str, dsn: Option<sentry::types::Dsn>) -> sentry::ClientOptions {
    // Field by field: the struct is non-exhaustive.
    let mut options = sentry::ClientOptions::default().traces_sample_rate(1.0);
    options.dsn = dsn;
    options.release = Some(release().into());
    options.environment = Some(environment().into());
    // The program's name: without one, the SDK reports this computer's.
    options.server_name = Some(program.into());
    options.send_default_pii = false;
    options.before_send = Some(Arc::new(|event| Some(scrub_event(event))));
    options.before_breadcrumb = Some(Arc::new(|breadcrumb| Some(scrub_breadcrumb(breadcrumb))));
    options.auto_session_tracking = false;
    options
}

/// An error, as an event: what went wrong, never anything identifying (it's
/// redacted before it leaves, too).
pub fn error(message: &str) {
    sentry::capture_message(message, Level::Error);
}

/// A step, as a breadcrumb, carried by the next event.
pub fn breadcrumb(message: &str) {
    sentry::add_breadcrumb(Breadcrumb { message: Some(message.into()), level: Level::Info, ..Default::default() });
}

/// Replaces the context `key` with `facts`, for the events that follow.
pub fn set_context(key: &str, facts: &[(&str, Fact)]) {
    let context = context(facts);
    sentry::configure_scope(|scope| scope.set_context(key, context));
}

/// A tag for the events that follow: a fixed word, never anything
/// identifying.
pub fn tag(key: &str, value: &str) {
    sentry::configure_scope(|scope| scope.set_tag(key, value));
}

fn value(fact: &Fact) -> Value {
    match fact {
        Fact::Text(s) => s.clone().into(),
        Fact::Number(n) => (*n).into(),
        Fact::Flag(b) => (*b).into(),
    }
}

fn context(facts: &[(&str, Fact)]) -> Context {
    let mut map = Map::new();
    for (key, fact) in facts {
        map.insert((*key).into(), value(fact));
    }
    Context::Other(map)
}

/// A step of a program's, as a transaction: finished, with its length and
/// how it went, when dropped.
pub struct Timed {
    transaction: sentry::Transaction,
    started: Instant,
    status: SpanStatus,
}

impl Timed {
    /// Starts `name` (an installer step: `FindMembership`) of `op`
    /// (`msi.custom_action`).
    pub fn start(name: &str, op: &str) -> Self {
        Self {
            transaction: sentry::start_transaction(TransactionContext::new(name, op)),
            started: Instant::now(),
            status: SpanStatus::Ok,
        }
    }

    /// Records a non-identifying fact about it.
    pub fn set(&self, key: &str, fact: impl Into<Fact>) {
        self.transaction.set_data(key, value(&fact.into()));
    }

    /// It went wrong: `reason`, a fixed word such as `no-group`.
    pub fn fail(&mut self, reason: &str) {
        self.status = SpanStatus::InternalError;
        self.set("ended", reason);
    }
}

impl Drop for Timed {
    fn drop(&mut self) {
        self.transaction.set_data("seconds", ((self.started.elapsed().as_secs_f64() * 10.0).round() / 10.0).into());
        self.transaction.set_status(self.status);
        self.transaction.clone().finish();
    }
}

/// How something ended.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Outcome {
    Finished,
    Failed,
    Cancelled,
}

/// Something that ended (an install), as a transaction of no length: counted
/// by `name` and how it ended, with `facts`. A failure is an error event
/// too, so it shows among the issues.
pub fn ended(name: &str, op: &str, outcome: Outcome, facts: &[(&str, Fact)]) {
    let transaction = sentry::start_transaction(TransactionContext::new(name, op));
    for (key, fact) in facts {
        transaction.set_data(key, value(fact));
    }
    transaction.set_status(match outcome {
        Outcome::Finished => SpanStatus::Ok,
        Outcome::Failed => SpanStatus::InternalError,
        Outcome::Cancelled => SpanStatus::Cancelled,
    });
    transaction.finish();
    if outcome == Outcome::Failed {
        error(&format!("{name} failed"));
    }
}

fn redact_value(value: &mut Value) {
    match value {
        Value::String(s) => *s = redact(s),
        Value::Array(items) => items.iter_mut().for_each(redact_value),
        Value::Object(map) => map.values_mut().for_each(redact_value),
        _ => {}
    }
}

fn redact_stack(stack: &mut Option<Stacktrace>) {
    for frame in stack.iter_mut().flat_map(|s| s.frames.iter_mut()) {
        for path in [&mut frame.abs_path, &mut frame.filename].into_iter().flatten() {
            *path = redact(path);
        }
    }
}

/// An event as it may leave: no user or request, its texts redacted, its
/// modules' paths cut to their file names.
fn scrub_event(mut event: Event<'static>) -> Event<'static> {
    event.user = None;
    event.request = None;
    for text in [&mut event.message, &mut event.culprit, &mut event.transaction].into_iter().flatten() {
        *text = redact(text);
    }
    if let Some(entry) = &mut event.logentry {
        entry.message = redact(&entry.message);
        entry.params.iter_mut().for_each(redact_value);
    }
    for exception in &mut event.exception.values {
        if let Some(value) = &mut exception.value {
            *value = redact(value);
        }
        redact_stack(&mut exception.stacktrace);
        redact_stack(&mut exception.raw_stacktrace);
    }
    for thread in &mut event.threads.values {
        redact_stack(&mut thread.stacktrace);
        redact_stack(&mut thread.raw_stacktrace);
    }
    redact_stack(&mut event.stacktrace);
    for breadcrumb in &mut event.breadcrumbs.values {
        *breadcrumb = scrub_breadcrumb(std::mem::take(breadcrumb));
    }
    for tag in event.tags.values_mut() {
        *tag = redact(tag);
    }
    event.extra.values_mut().for_each(redact_value);
    for image in &mut event.debug_meta.to_mut().images {
        if let DebugImage::Symbolic(image) = image {
            image.name = file_name(&image.name);
            image.debug_file = image.debug_file.as_deref().map(file_name);
        }
    }
    event
}

fn scrub_breadcrumb(mut breadcrumb: Breadcrumb) -> Breadcrumb {
    if let Some(message) = &mut breadcrumb.message {
        *message = redact(message);
    }
    breadcrumb.data.values_mut().for_each(redact_value);
    breadcrumb
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What would leave, end to end, through the SDK with these options and
    /// the integrations `sentry::init` adds (contexts, debug images with
    /// their modules' paths; not the panic hook, which would take the other
    /// tests' panics): an error with a breadcrumb, and a step's transaction,
    /// carry neither this computer's name nor the user's, nor an address, a
    /// SID or a user.
    /// `WARLOCK_SHOW_DIAGNOSTICS=1 cargo test -p warlock-sentry -- --nocapture`
    /// shows what would leave.
    #[test]
    fn nothing_identifying_leaves() {
        let mut options = sentry::apply_defaults(options("warlock-test", None));
        options.integrations.retain(|integration| integration.name() != "panic");
        let envelopes = sentry::test::with_captured_envelopes_options(
            || {
                sentry::configure_scope(|scope| scope.set_context("system", context(&system())));
                breadcrumb("peer c6:45:45:ba:cd:d3");
                error(&format!(
                    r"opening C:\Users\{}\x.pcapng on {} from fe80::1%49 for S-1-5-21-1-2-3-1001",
                    std::env::var("USERNAME").unwrap_or_default(),
                    std::env::var("COMPUTERNAME").unwrap_or_default()
                ));
                let mut step = Timed::start("FindMembership", "msi.custom_action");
                step.set("groups", 2u32);
                step.fail("no-group");
                drop(step);
            },
            options,
        );
        let text: String = envelopes
            .iter()
            .map(|e| {
                let mut bytes = Vec::new();
                e.to_writer(&mut bytes).unwrap();
                String::from_utf8_lossy(&bytes).to_lowercase()
            })
            .collect();
        if std::env::var_os("WARLOCK_SHOW_DIAGNOSTICS").is_some() {
            eprintln!("{text}");
        }
        assert!(text.contains("\"server_name\":\"warlock-test\""), "the program's name, not the computer's: {text}");
        for var in ["COMPUTERNAME", "USERNAME"] {
            if let Ok(name) = std::env::var(var)
                && name.len() >= 2
            {
                assert!(!text.contains(&name.to_lowercase()), "{var} leaked: {text}");
            }
        }
        assert!(!text.contains("c6:45:45:ba:cd:d3") && !text.contains("fe80::1"), "an address leaked: {text}");
        assert!(!text.contains("s-1-5-21"), "a SID leaked: {text}");
        assert!(!text.contains("\"user\""), "a user: {text}");
        assert!(text.contains("<addr>") && text.contains("<user>") && text.contains("<sid>"), "redacted: {text}");
        assert!(text.contains("findmembership") && text.contains("no-group"), "the step's transaction: {text}");
    }
}
