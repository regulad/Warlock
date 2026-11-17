// SPDX-License-Identifier: GPL-2.0-only
//! Where logs go: the console in the foreground; `%ProgramData%\Warlock\warlock.log`
//! as a service (ETW comes with W5).

use std::fs::OpenOptions;
use std::sync::Mutex;

use tracing::Level;
use warlock_tun::dll;

/// Logs to stderr.
pub fn console() {
    tracing_subscriber::fmt().with_writer(std::io::stderr).with_max_level(Level::INFO).init();
}

/// Logs, appended, to `warlock.log` in Warlock's directory, which is created
/// admin-only first. Without a file, logs go nowhere.
pub fn file() {
    let root = dll::default_root();
    if dll::prepare_root(&root).is_err() {
        return;
    }
    if let Ok(f) = OpenOptions::new().create(true).append(true).open(root.join("warlock.log")) {
        tracing_subscriber::fmt().with_writer(Mutex::new(f)).with_ansi(false).with_max_level(Level::INFO).init();
    }
}
