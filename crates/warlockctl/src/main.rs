// SPDX-License-Identifier: GPL-2.0-only
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
//!   events               follow events until Ctrl+C
//! ```
//!
//! Prints JSON: state pretty-printed, streams a line at a time. A lock lasts
//! as long as the command runs. The service's pipe admits Administrators and
//! the `warlock-users` group.

use std::process::ExitCode;

use warlock_api::client::{Client, ClientError, Lines};

const USAGE: &str =
    "usage: warlockctl [--pipe NAME] info|peers|peer ADDRESS|advertising|holds|advertise TYPE|hold REASON|events";

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

async fn run(client: &Client, command: &str, arg: Option<&str>) -> Result<(), ClientError> {
    match (command, arg) {
        ("info", None) => print(&client.info().await?),
        ("peers", None) => print(&client.peers().await?),
        ("peer", Some(address)) => print(&client.peer(address).await?),
        ("advertising", None) => print(&client.advertising().await?),
        ("holds", None) => print(&client.holds().await?),
        ("advertise", Some(t)) => follow(client.advertise(t).await?).await?,
        ("hold", Some(reason)) => follow(client.hold(reason).await?).await?,
        ("events", None) => follow(client.events().await?).await?,
        _ => unreachable!("checked in main"),
    }
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut pipe = warlock_api::PIPE.to_string();
    if args.first().map(String::as_str) == Some("--pipe") {
        if args.len() < 2 {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
        pipe = args.remove(1);
        args.remove(0);
    }
    let (command, arg) = match args.as_slice() {
        [c] if ["info", "peers", "advertising", "holds", "events"].contains(&c.as_str()) => (c.clone(), None),
        [c, a] if ["peer", "advertise", "hold"].contains(&c.as_str()) => (c.clone(), Some(a.clone())),
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match run(&Client::new(pipe), &command, arg.as_deref()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("warlockctl: {e}");
            ExitCode::FAILURE
        }
    }
}
