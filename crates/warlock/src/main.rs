// SPDX-License-Identifier: GPL-2.0-only
//! Warlock: Apple Wireless Direct Link on Windows.
//!
//! ```text
//! warlock run [options]        in the foreground, as Administrator; Ctrl+C stops it
//! warlock install [options]    registers the Warlock service (manual start) with these options
//! warlock uninstall            stops and removes the service
//! warlock service [options]    what the service manager runs
//!
//! options: --channel N (149)  --width 20|40 (40)  --metric N (60)  --seconds N (run until stopped)
//!          --log-packets (log every packet crossing the adapter)
//! ```
//!
//! Either way it claims the TP-Link Archer T3U for WinUSB if Windows has its
//! own driver on it, takes part in AWDL (`awdl-core`), and bridges IPv6 to
//! the "Warlock AWDL" network adapter (`warlock-tun`), so Windows' own tools
//! reach AWDL peers: `ping -6 fe80::<peer's EUI-64>%<adapter index>`.

mod daemon;
mod logging;
mod service;

use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};

/// Set to stop the daemon: by Ctrl+C in the foreground, by the service
/// manager as a service.
pub static STOP: AtomicBool = AtomicBool::new(false);

const USAGE: &str = "usage: warlock run|install|uninstall|service [--channel N] [--width 20|40] [--metric N]";

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let command = args.next().unwrap_or_default();
    let options: Vec<String> = args.collect();
    let result = match command.as_str() {
        "run" => daemon::Options::parse(&options).and_then(|o| {
            logging::console();
            stop_on_ctrl_c();
            daemon::run(&o, &STOP)
        }),
        "install" => daemon::Options::parse(&options).and_then(|_| service::install(&options)),
        "uninstall" => service::uninstall(),
        "service" => service::dispatch(),
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("warlock: {e}");
            tracing::error!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn stop_on_ctrl_c() {
    use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
    unsafe extern "system" fn handler(_ctrl: u32) -> i32 {
        STOP.store(true, Ordering::Relaxed);
        1
    }
    // SAFETY: a plain handler that only sets an atomic.
    unsafe { SetConsoleCtrlHandler(Some(handler), 1) };
}
