// SPDX-License-Identifier: GPL-2.0-only
//! Third-party notices: the licences of everything built into Warlock's
//! programs that isn't Warlock's own, which the MSI installs as
//! `THIRD-PARTY-NOTICES.txt` (Parker, 2026-11-21). The licences of most of
//! those crates (MIT, BSD) ask for their notice to go with the program; the
//! Apache-2.0 ones in the AGPL programs (Sentry's Rust SDK's) ask for their
//! licence's text.
//!
//! `cargo run -p warlock-msi -- notices` writes `data/third-party-notices.txt`
//! from `cargo metadata`, as Koala's `tools/third_party_notices.py` does for
//! Koala: the crates the shipped programs (`warlock.exe`, `warlockctl.exe`
//! and `warlock-extcap.exe`, `warlock_msi_ca.dll`) link, through normal
//! dependencies only (build and dev ones aren't built in), with each crate's
//! licence files, identical texts once; and the C code built in besides,
//! which no crate's licence files cover ([`VENDORED`], [`LINKED`]). The file
//! ends with a hash of `Cargo.lock`: a test fails when they no longer match.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

use crate::Result;

/// The packages whose programs the MSI installs.
const SHIPPED: [&str; 3] = ["warlock", "warlockctl", "warlock-msi-ca"];
/// The target they're built for.
const TARGET: &str = "x86_64-pc-windows-msvc";
/// What a licence file's name starts with, lower-cased.
const LICENCE_PREFIXES: [&str; 6] = ["license", "licence", "copying", "copyright", "notice", "unlicense"];
/// C code built into a crate, under a licence of its own: the crate, what
/// the code is and its licence, and its licence files, under the crate's
/// directory.
const VENDORED: [(&str, &str, &[&str]); 1] = [("libusb1-sys", "libusb, LGPL-2.1-or-later", &["libusb/COPYING"])];

/// C code built in from the repository's submodules: name, the submodule,
/// licence, where it comes from, and its licence (a file, or the comment of
/// a source file from a line on).
struct Linked {
    name: &'static str,
    submodule: &'static str,
    licence: &'static str,
    source: &'static str,
    text: Text,
}

enum Text {
    File(&'static str),
    /// A source file's licence comment: from the line starting with
    /// `from` to the end of the comment.
    Comment {
        file: &'static str,
        from: &'static str,
    },
}

const LINKED: [Linked; 3] = [
    Linked {
        name: "devourer",
        submodule: "third_party/devourer",
        licence: "GPL-2.0-only",
        source: "https://github.com/OpenIPC/devourer",
        text: Text::File("third_party/devourer/LICENSE"),
    },
    Linked {
        name: "sentry-native",
        submodule: "third_party/sentry-native",
        licence: "MIT",
        source: "https://github.com/getsentry/sentry-native",
        text: Text::File("third_party/sentry-native/LICENSE"),
    },
    Linked {
        name: "stb_sprintf (in sentry-native)",
        submodule: "third_party/sentry-native",
        licence: "MIT OR Unlicense",
        source: "https://github.com/nothings/stb",
        text: Text::Comment {
            file: "third_party/sentry-native/vendor/stb_sprintf.h",
            from: "This software is available under 2 licenses",
        },
    },
];

/// Where the notices are kept, under the repository.
pub const FILE: &str = "crates/warlock-msi/data/third-party-notices.txt";

/// FNV-1a, 64 bits: what the notices name `Cargo.lock` by.
pub fn fnv1a64(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf2_9ce4_8422_2325, |h, &b| (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3))
}

/// `cargo metadata` for the target, as JSON.
fn metadata(root: &Path) -> Result<Value> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let out = Command::new(cargo)
        .args(["metadata", "--format-version", "1", "--locked", "--filter-platform", TARGET])
        .current_dir(root)
        .output()?;
    if !out.status.success() {
        return Err(format!("cargo metadata: {}", String::from_utf8_lossy(&out.stderr)).into());
    }
    Ok(serde_json::from_slice(&out.stdout)?)
}

/// The packages `roots` link (name, version), as `cargo tree` resolves them
/// for a build of theirs: normal dependencies only, with the features such
/// a build turns on (`cargo metadata` unifies dev-dependencies' too, which
/// would add crates no program links), and no proc macros, which run only
/// while compiling.
fn linked(root: &Path, roots: &[&str]) -> Result<BTreeSet<(String, String)>> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut command = Command::new(cargo);
    command.args([
        "tree",
        "--locked",
        "--target",
        TARGET,
        "-e",
        "normal,no-proc-macro",
        "--prefix",
        "none",
        "-f",
        "{p}",
    ]);
    for r in roots {
        command.args(["-p", r]);
    }
    let out = command.current_dir(root).output()?;
    if !out.status.success() {
        return Err(format!("cargo tree: {}", String::from_utf8_lossy(&out.stderr)).into());
    }
    // `name vX.Y.Z`, then ` (path)` for a path dependency or ` (*)` when seen.
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let mut words = l.split_whitespace();
            let (name, version) = (words.next()?, words.next()?.strip_prefix('v')?);
            Some((name.to_owned(), version.to_owned()))
        })
        .collect())
}

/// A licence text as kept: Unix line ends, no BOM, no trailing spaces.
fn tidy(text: &str) -> String {
    let text = text.replace("\r\n", "\n");
    let text = text.trim_start_matches('\u{feff}');
    text.lines().map(str::trim_end).collect::<Vec<_>>().join("\n").trim_matches('\n').to_owned()
}

/// The notices, as written to [`FILE`].
pub fn generate(root: &Path) -> Result<String> {
    let meta = metadata(root)?;
    let packages: BTreeMap<(&str, &str), &Value> = meta["packages"]
        .as_array()
        .map(|p| p.iter().filter_map(|p| Some(((p["name"].as_str()?, p["version"].as_str()?), p))).collect())
        .unwrap_or_default();
    let mut third: Vec<&Value> = linked(root, &SHIPPED)?
        .iter()
        .filter_map(|(name, version)| packages.get(&(name.as_str(), version.as_str())).copied())
        // Warlock's own crates are under its own licences, on the licence page.
        .filter(|p| !p["source"].is_null())
        .collect();
    third.sort_by_key(|p| {
        (p["name"].as_str().unwrap_or("").to_lowercase(), p["version"].as_str().unwrap_or("").to_owned())
    });

    // Each distinct text once, by number.
    let mut texts: Vec<String> = Vec::new();
    let mut number = |text: String| -> usize {
        match texts.iter().position(|t| *t == text) {
            Some(i) => i + 1,
            None => {
                texts.push(text);
                texts.len()
            }
        }
    };
    let mut out = vec![
        "Third-party software in Warlock".to_owned(),
        String::new(),
        "Warlock's programs are built from the following free software, under the".to_owned(),
        "licences given. Each package's licence files follow, by number, after the".to_owned(),
        "list. Warlock's own licences are in LICENSE.md, LICENSE-AGPL-3.0.md and".to_owned(),
        "LICENSE-WINTUN-EXCEPTION.md.".to_owned(),
        String::new(),
    ];
    for p in third {
        let manifest = PathBuf::from(p["manifest_path"].as_str().unwrap_or(""));
        let dir = manifest.parent().unwrap_or(Path::new("."));
        let name = p["name"].as_str().unwrap_or("");
        let mut files: Vec<String> = std::fs::read_dir(dir)?
            .flatten()
            .filter(|e| e.path().is_file())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|f| LICENCE_PREFIXES.iter().any(|prefix| f.to_lowercase().starts_with(prefix)))
            .collect();
        files.sort();
        let mut includes = None;
        for (crate_name, what, extra) in VENDORED {
            if crate_name == name {
                files.extend(extra.iter().map(|f| (*f).to_owned()));
                includes = Some(what);
            }
        }
        let mut refs = Vec::new();
        for f in &files {
            let text = std::fs::read(dir.join(f)).map_err(|e| format!("{name}: {f}: {e}"))?;
            refs.push(format!("[{}] {f}", number(tidy(&String::from_utf8_lossy(&text)))));
        }
        out.push(format!("{name} {}", p["version"].as_str().unwrap_or("")));
        out.push(format!("  Licence: {}", p["license"].as_str().unwrap_or("see its files")));
        if let Some(what) = includes {
            out.push(format!("  Includes: {what}"));
        }
        if let Some(repository) = p["repository"].as_str() {
            out.push(format!("  Source: {repository}"));
        }
        if !refs.is_empty() {
            out.push(format!("  Files: {}", refs.join(", ")));
        }
        out.push(String::new());
    }
    for l in &LINKED {
        let commit = Command::new("git")
            .args(["-C", l.submodule, "describe", "--tags", "--always"])
            .current_dir(root)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
            .unwrap_or_else(|| "the submodule's commit".into());
        let text = match l.text {
            Text::File(f) => std::fs::read_to_string(root.join(f)).map_err(|e| format!("{f}: {e}"))?,
            Text::Comment { file, from } => {
                let source = std::fs::read_to_string(root.join(file)).map_err(|e| format!("{file}: {e}"))?;
                let start = source.find(from).ok_or_else(|| format!("{file}: no {from:?}"))?;
                let end = source[start..].find("*/").map_or(source.len(), |e| start + e);
                source[start..end].to_owned()
            }
        };
        out.push(format!("{} {commit}", l.name));
        out.push(format!("  Licence: {}", l.licence));
        out.push(format!("  Source: {}", l.source));
        out.push(format!("  Files: [{}]", number(tidy(&text))));
        out.push(String::new());
    }
    out.extend([String::new(), "Licence texts".to_owned(), String::new()]);
    for (i, text) in texts.iter().enumerate() {
        out.extend([format!("[{}]", i + 1), String::new(), text.clone(), String::new(), String::new()]);
    }
    let lock = fnv1a64(&std::fs::read(root.join("Cargo.lock"))?);
    out.push(format!("Generated by `cargo run -p warlock-msi -- notices` from Cargo.lock {lock:016x}."));
    Ok(out.join("\n") + "\n")
}

/// Writes [`generate`]'s notices to [`FILE`].
pub fn write(root: &Path) -> Result<()> {
    let text = generate(root)?;
    let path = root.join(FILE);
    std::fs::create_dir_all(path.parent().unwrap())?;
    std::fs::write(&path, &text)?;
    let packages = text.lines().filter(|l| l.starts_with("  Licence: ")).count();
    println!("{} ({packages} packages)", path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    #[test]
    fn the_notices_are_for_the_dependencies_in_use() {
        let lock = fnv1a64(&std::fs::read(root().join("Cargo.lock")).unwrap());
        let notices = std::fs::read_to_string(root().join(FILE)).unwrap_or_default();
        assert!(
            notices.contains(&format!("from Cargo.lock {lock:016x}.")),
            "Cargo.lock changed: run `cargo run -p warlock-msi -- notices`"
        );
    }

    /// `deny.toml` lets crates offered under Apache-2.0 alone into the AGPL
    /// programs only: none may be linked into the GPL-2.0-only daemon,
    /// whichever way it would come.
    #[test]
    fn the_daemon_links_nothing_under_apache_alone() {
        let meta = metadata(&root()).unwrap();
        let names = linked(&root(), &["warlock"]).unwrap();
        let linked: Vec<&Value> = meta["packages"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|p| {
                names.contains(&(
                    p["name"].as_str().unwrap_or("").to_owned(),
                    p["version"].as_str().unwrap_or("").to_owned(),
                ))
            })
            .collect();
        let offending: Vec<String> = linked
            .iter()
            .filter(|p| {
                let licence = p["license"].as_str().unwrap_or("");
                licence.contains("Apache-2.0") && !licence.contains(" OR ") && !licence.contains('/')
            })
            .map(|p| format!("{} {}", p["name"].as_str().unwrap_or(""), p["license"]))
            .collect();
        assert!(offending.is_empty(), "the daemon links {offending:?}");
        assert!(linked.len() > 50, "the daemon's graph: {} packages", linked.len());
        assert!(!linked.iter().any(|p| p["name"] == "sentry"), "the daemon links Sentry's Rust SDK");
    }
}
