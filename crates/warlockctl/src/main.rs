// SPDX-License-Identifier: AGPL-3.0-only
//! warlockctl: Warlock's control API from the command line
//! (`api/openapi.yaml`), the way `docker` is a client of Docker's.
//!
//! ```text
//! warlockctl [--pipe NAME] COMMAND
//!
//!   info                 Warlock, its radio, adapter and AWDL state
//!   peers                the AWDL devices Warlock hears
//!   peer ADDRESS         one of them
//!   advertising          the service types advertised, and who asked
//!   holds                the open holds, and who holds them
//!   advertise TYPE       advertise a service type (e.g. _rdlink._tcp) until Ctrl+C
//!   hold REASON          keep AWDL active until Ctrl+C
//!   realtime             the open realtime locks, and who holds them
//!   realtime ADDRESS     run a realtime group with a peer until Ctrl+C
//!   request              the open requests, and who holds them
//!   request TYPE [--needs-keyboard]
//!                        ask nearby devices for a service (e.g. _rdlink._tcp) until Ctrl+C,
//!                        with the needs-keyboard flag if given
//!   events               follow events until Ctrl+C
//!   capture [--peer MAC]... [--kind awdl|other|all] [--tx] [-w FILE|-]
//!                        capture the radio's frames as pcapng until Ctrl+C
//! ```
//!
//! Prints JSON: state pretty-printed, streams a line at a time. A lock lasts
//! as long as the command runs. `capture` writes pcapng to FILE, or to
//! standard output with `-w -` (the default when that isn't a terminal), for
//! example into `wireshark -k -i -`; its frame count goes to standard error.
//!
//! Commands use the API's pipe, which admits Administrators and the
//! `warlock-users` and `warlock-admin` groups. `capture` uses the admin pipe
//! (`api/admin.yaml`), which admits Administrators and `warlock-admin`
//! only. `--pipe` names the pipe instead, for either.
//!
//! Diagnostics (PRIVACY.md; `warlock-sentry`): a release reports its panics,
//! and its faults ([`ClientError::is_fault`]), to Sentry's `warlockctl`
//! project, unless `DO_NOT_TRACK` is set; how it's used (Warlock not
//! running, not allowed, a request turned down) isn't a fault.

use std::fs::File;
use std::io::{self, IsTerminal, Write};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use warlock_client::types::ServiceRequest;
use warlock_client::{CaptureFilter, CaptureKind, Client, ClientError, Lines};

const USAGE: &str = "usage: warlockctl [--pipe NAME] info|peers|peer ADDRESS|advertising|holds|advertise TYPE|hold \
                     REASON|realtime [ADDRESS]|request [TYPE [--needs-keyboard]]|events|capture [--peer MAC]... [--kind awdl|other|all] [--tx] [-w \
                     FILE|-]";

/// warlockctl's Sentry project (`regulad/warlockctl`), whose DSN the
/// homelab's `tofu/sentry` makes: none yet, so nothing is sent.
const PROJECT: &str = "";

/// `e` as text, reported first if it's a fault.
fn fault(command: &str, e: ClientError) -> String {
    if e.is_fault() {
        warlock_sentry::error(&format!("warlockctl {command}: {e}"));
    }
    e.to_string()
}

fn print(v: &impl serde::Serialize) {
    println!("{}", serde_json::to_string_pretty(v).expect("JSON"));
}

/// Prints a stream's lines until it ends, which for a lock means Warlock
/// stopped.
async fn follow(mut lines: Lines) -> Result<(), ClientError> {
    while let Some(line) = lines.next_value().await {
        println!("{}", line?);
    }
    eprintln!("warlockctl: the stream ended: Warlock stopped");
    Ok(())
}

/// A capture's options, from its arguments.
struct Capture {
    filter: CaptureFilter,
    /// `None`: standard output.
    file: Option<String>,
}

impl Capture {
    fn parse(args: &[String]) -> Option<Self> {
        let mut capture = Capture { filter: CaptureFilter::default(), file: None };
        let mut args = args.iter();
        while let Some(a) = args.next() {
            match a.as_str() {
                "--peer" => capture.filter.peers.push(args.next()?.clone()),
                "--kind" => {
                    capture.filter.kind = Some(match args.next()?.as_str() {
                        "awdl" => CaptureKind::Awdl,
                        "other" => CaptureKind::Other,
                        "all" => CaptureKind::All,
                        _ => return None,
                    })
                }
                "--tx" => capture.filter.tx = true,
                "-w" => {
                    let file = args.next()?;
                    capture.file = (file != "-").then(|| file.clone());
                }
                _ => return None,
            }
        }
        Some(capture)
    }

    /// Writes the capture until Ctrl+C or Warlock stops.
    async fn run(&self, client: &Client) -> Result<(), String> {
        let mut out: Box<dyn Write> = match &self.file {
            Some(path) => Box::new(File::create(path).map_err(|e| format!("{path}: {e}"))?),
            None if io::stdout().is_terminal() => {
                return Err("won't write pcapng to a terminal: name a file with -w, or pipe it".into());
            }
            None => Box::new(io::stdout().lock()),
        };
        let mut chunks = client.capture(&self.filter).await.map_err(|e| fault("capture", e))?;
        // The first chunk is the pcapng header; each after it, one frame.
        let mut frames: u64 = 0;
        let mut header = true;
        let mut said = Instant::now();
        let ended = loop {
            let chunk = tokio::select! {
                c = chunks.next() => c,
                _ = tokio::signal::ctrl_c() => break None,
            };
            let chunk = match chunk {
                Some(Ok(c)) => c,
                Some(Err(e)) => break Some(fault("capture", e)),
                None => break Some("the stream ended: Warlock stopped".into()),
            };
            out.write_all(&chunk).and_then(|()| out.flush()).map_err(|e| format!("writing: {e}"))?;
            if !std::mem::replace(&mut header, false) {
                frames += 1;
            }
            if said.elapsed() >= Duration::from_secs(1) {
                eprint!("\r{frames} frames");
                said = Instant::now();
            }
        };
        eprintln!("\r{frames} frames");
        match ended {
            None => Ok(()),
            Some(why) => Err(why),
        }
    }
}

async fn run(client: &Client, command: &str, arg: Option<&str>, needs_keyboard: bool) -> Result<(), ClientError> {
    match (command, arg) {
        ("info", None) => print(&client.info().await?),
        ("peers", None) => print(&client.peers().await?),
        ("peer", Some(address)) => print(&client.peer(address).await?),
        ("advertising", None) => print(&client.advertising().await?),
        ("holds", None) => print(&client.holds().await?),
        ("advertise", Some(t)) => follow(client.advertise(t).await?).await?,
        ("hold", Some(reason)) => follow(client.hold(reason).await?).await?,
        ("realtime", None) => print(&client.realtime_locks().await?),
        ("realtime", Some(peer)) => follow(client.realtime(peer, "warlockctl").await?).await?,
        ("request", None) => print(&client.requests().await?),
        ("request", Some(service)) => {
            let request = ServiceRequest { service: service.into(), reason: "warlockctl".into(), needs_keyboard };
            follow(client.request(&request).await?).await?
        }
        ("events", None) => follow(client.events().await?).await?,
        _ => unreachable!("checked in main"),
    }
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    // Until the program ends, which sends what's left.
    let _diagnostics = warlock_sentry::start("warlockctl", warlock_sentry::dsn(PROJECT));
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut pipe = None;
    if args.first().map(String::as_str) == Some("--pipe") {
        if args.len() < 2 {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
        pipe = Some(args.remove(1));
        args.remove(0);
    }
    if args.first().map(String::as_str) == Some("capture") {
        let Some(capture) = Capture::parse(&args[1..]) else {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        };
        let client = Client::new(pipe.unwrap_or_else(|| warlock_client::ADMIN_PIPE.into()));
        warlock_sentry::tag("command", "capture");
        return match capture.run(&client).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("warlockctl: {e}");
                ExitCode::FAILURE
            }
        };
    }
    let client = Client::new(pipe.unwrap_or_else(|| warlock_client::PIPE.into()));
    let (command, arg, needs_keyboard) = match args.as_slice() {
        [c] if ["info", "peers", "advertising", "holds", "realtime", "request", "events"].contains(&c.as_str()) => {
            (c.clone(), None, false)
        }
        [c, a] if ["peer", "advertise", "hold", "realtime", "request"].contains(&c.as_str()) => {
            (c.clone(), Some(a.clone()), false)
        }
        [c, a, f] if c == "request" && f == "--needs-keyboard" => (c.clone(), Some(a.clone()), true),
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    warlock_sentry::tag("command", &command);
    match run(&client, &command, arg.as_deref(), needs_keyboard).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("warlockctl: {}", fault(&command, e));
            ExitCode::FAILURE
        }
    }
}
