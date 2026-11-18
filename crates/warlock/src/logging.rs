// SPDX-License-Identifier: GPL-2.0-only
//! Where logs go: the console in the foreground; as a service, and in
//! `setup` and `teardown`, Warlock's events (`events`), which Windows keeps
//! in the Event Log.

use tracing::Level;

use crate::events;

/// Logs to stderr.
pub fn console() {
    tracing_subscriber::fmt().with_writer(std::io::stderr).with_max_level(Level::INFO).init();
}

/// Logs to Warlock's events. The Event Log stamps each event with its time
/// and level, so the text leaves them out.
pub fn events() {
    tracing_subscriber::fmt()
        .with_writer(events::Writer::registered())
        .without_time()
        .with_level(false)
        .with_ansi(false)
        .with_max_level(Level::INFO)
        .init();
}
