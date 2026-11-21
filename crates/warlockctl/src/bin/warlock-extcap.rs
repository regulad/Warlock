// SPDX-License-Identifier: AGPL-3.0-only
//! warlock-extcap: Warlock's radio as a Wireshark capture interface, "Warlock
//! radio (802.11)", through Wireshark's extcap interface. It reads the admin
//! API's `GET /v1/capture` (`api/admin.yaml`, on `\\.\pipe\warlock-admin`)
//! and writes the pcapng to the pipe Wireshark gives it.
//!
//! Wireshark runs it from its `extcap` folder, where the MSI puts it if asked
//! (PLAN.md, W6):
//!
//! ```text
//! warlock-extcap --extcap-interfaces
//! warlock-extcap --extcap-interface warlock --extcap-dlts
//! warlock-extcap --extcap-interface warlock --extcap-config
//! warlock-extcap --extcap-interface warlock --capture --fifo PIPE [--peer MACS] [--kind awdl|other|all] [--tx]
//! ```
//!
//! Like `warlockctl capture`, it needs Administrator or the `warlock-admin`
//! group; Wireshark shows what went wrong from its standard error.
//!
//! Diagnostics (PRIVACY.md; `warlock-sentry`): a release reports its panics,
//! and its faults (`ClientError::is_fault`), to Sentry's `warlock-extcap`
//! project, unless `DO_NOT_TRACK` is set; how it's used (Warlock not
//! running, not allowed, a request turned down) isn't a fault.

use std::fs::OpenOptions;
use std::io::Write;
use std::process::ExitCode;

use warlock_client::{CaptureFilter, CaptureKind, Client, ClientError};

/// The one interface, as Wireshark names it in its options.
const INTERFACE: &str = "warlock";

/// The extcap's Sentry project (`regulad/warlock-extcap`), whose DSN the
/// homelab's `tofu/sentry` makes: none yet, so nothing is sent.
const PROJECT: &str = "";

/// `e` as text, reported first if it's a fault.
fn fault(e: ClientError) -> String {
    if e.is_fault() {
        warlock_sentry::error(&format!("warlock-extcap capture: {e}"));
    }
    e.to_string()
}

/// Arguments as Wireshark passes them: `--name value`, `--name=value`, or a
/// bare flag.
struct Args(Vec<(String, Option<String>)>);

impl Args {
    fn parse(raw: impl Iterator<Item = String>) -> Self {
        let raw: Vec<String> = raw.collect();
        let mut out = Vec::new();
        let mut i = 0;
        while i < raw.len() {
            let a = &raw[i];
            if let Some((name, value)) = a.split_once('=') {
                out.push((name.to_string(), Some(value.to_string())));
            } else if raw.get(i + 1).is_some_and(|next| !next.starts_with("--")) {
                out.push((a.clone(), Some(raw[i + 1].clone())));
                i += 1;
            } else {
                out.push((a.clone(), None));
            }
            i += 1;
        }
        Args(out)
    }

    fn has(&self, name: &str) -> bool {
        self.0.iter().any(|(n, _)| n == name)
    }

    fn value(&self, name: &str) -> Option<&str> {
        self.0.iter().find(|(n, _)| n == name).and_then(|(_, v)| v.as_deref())
    }
}

fn interfaces() {
    println!(
        "extcap {{version={}}}{{help=https://github.com/regulad/Warlock}}{{display=Warlock}}",
        env!("CARGO_PKG_VERSION")
    );
    println!("interface {{value={INTERFACE}}}{{display=Warlock radio (802.11)}}");
}

fn dlts() {
    println!("dlt {{number=127}}{{name=IEEE802_11_RADIOTAP}}{{display=802.11 with radiotap}}");
}

fn config() {
    // No validation regex: the format delimits values with braces, so a
    // quantifier such as {2} would end the field. Warlock answers a bad
    // address with an error, which Wireshark shows.
    println!(
        "arg {{number=0}}{{call=--peer}}{{display=Peers}}{{type=string}}{{tooltip=Only frames to or from these MAC \
         addresses, separated by commas; every frame if empty}}{{placeholder=76:56:82:58:57:70}}"
    );
    println!(
        "arg {{number=1}}{{call=--kind}}{{display=Frames}}{{type=selector}}{{tooltip=AWDL is what Warlock reads; \
         other is everything else it hears}}"
    );
    println!("value {{arg=1}}{{value=all}}{{display=All}}{{default=true}}");
    println!("value {{arg=1}}{{value=awdl}}{{display=AWDL only}}{{default=false}}");
    println!("value {{arg=1}}{{value=other}}{{display=Everything but AWDL}}{{default=false}}");
    println!(
        "arg {{number=2}}{{call=--tx}}{{display=Warlock's own frames}}{{type=boolflag}}{{default=false}}{{tooltip=Also \
         the frames Warlock sends}}"
    );
}

/// The filter the options ask for.
fn filter(args: &Args) -> Result<CaptureFilter, String> {
    let peers = args
        .value("--peer")
        .unwrap_or("")
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect();
    let kind = match args.value("--kind") {
        None | Some("all") => None,
        Some("awdl") => Some(CaptureKind::Awdl),
        Some("other") => Some(CaptureKind::Other),
        Some(k) => return Err(format!("unknown kind {k:?}")),
    };
    Ok(CaptureFilter { peers, kind: kind.or(Some(CaptureKind::All)), tx: args.has("--tx") })
}

/// Streams the capture into Wireshark's pipe until either end closes.
async fn capture(fifo: &str, filter: CaptureFilter) -> Result<(), String> {
    let mut out = OpenOptions::new().write(true).open(fifo).map_err(|e| format!("can't open {fifo}: {e}"))?;
    let mut chunks = Client::new(warlock_client::ADMIN_PIPE).capture(&filter).await.map_err(fault)?;
    while let Some(chunk) = chunks.next().await {
        let chunk = chunk.map_err(fault)?;
        if out.write_all(&chunk).and_then(|()| out.flush()).is_err() {
            // Wireshark stopped the capture.
            return Ok(());
        }
    }
    Err("the stream ended: Warlock stopped".into())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    // Until the program ends, which sends what's left.
    let _diagnostics = warlock_sentry::start("warlock-extcap", warlock_sentry::dsn(PROJECT));
    let args = Args::parse(std::env::args().skip(1));
    if args.has("--extcap-interfaces") {
        interfaces();
        return ExitCode::SUCCESS;
    }
    if let Some(i) = args.value("--extcap-interface")
        && i != INTERFACE
    {
        eprintln!("warlock-extcap: no interface {i:?}");
        return ExitCode::from(2);
    }
    if args.has("--extcap-dlts") {
        dlts();
        return ExitCode::SUCCESS;
    }
    if args.has("--extcap-config") {
        config();
        return ExitCode::SUCCESS;
    }
    if args.has("--capture") {
        let Some(fifo) = args.value("--fifo") else {
            eprintln!("warlock-extcap: --capture needs --fifo");
            return ExitCode::from(2);
        };
        let result = match filter(&args) {
            Ok(f) => capture(fifo, f).await,
            Err(e) => Err(e),
        };
        return match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("warlock-extcap: {e}");
                ExitCode::FAILURE
            }
        };
    }
    eprintln!("warlock-extcap: Wireshark's capture interface for Warlock; Wireshark runs it (--extcap-interfaces)");
    ExitCode::from(2)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Args {
        Args::parse(s.split(' ').map(str::to_string))
    }

    #[test]
    fn wiresharks_arguments_parse() {
        let a = args("--extcap-interfaces --extcap-version=4.6");
        assert!(a.has("--extcap-interfaces"));
        assert_eq!(a.value("--extcap-version"), Some("4.6"));
        let a = args(r"--capture --extcap-interface warlock --fifo \\.\pipe\x --peer 76:56:82:58:57:70 --tx");
        assert_eq!(a.value("--fifo"), Some(r"\\.\pipe\x"));
        assert_eq!(a.value("--extcap-interface"), Some("warlock"));
        assert!(a.has("--tx"));
        assert_eq!(a.value("--tx"), None);
    }

    #[test]
    fn options_become_a_filter() {
        let f = filter(&args("--peer 76:56:82:58:57:70,02:00:00:00:00:01 --kind other --tx")).unwrap();
        assert_eq!(f.peers, ["76:56:82:58:57:70", "02:00:00:00:00:01"]);
        assert_eq!((f.kind, f.tx), (Some(CaptureKind::Other), true));
        let f = filter(&args("--capture")).unwrap();
        assert!(f.peers.is_empty());
        assert_eq!((f.kind, f.tx), (Some(CaptureKind::All), false));
        assert!(filter(&args("--kind some")).is_err());
    }
}
