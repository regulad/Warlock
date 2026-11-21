// SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
//! Tells the crate what the release is named after: the commit
//! (`WARLOCK_COMMIT`), and whether this is a tagged build (`WARLOCK_TAGGED`,
//! from GitHub's runner); and whether to build the DSNs in for a trial
//! (`WARLOCK_DIAGNOSTICS=1` when building).

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=GITHUB_REF_TYPE");
    if env::var("GITHUB_REF_TYPE").as_deref() == Ok("tag") {
        println!("cargo:rustc-env=WARLOCK_TAGGED=1");
    }
    println!("cargo:rerun-if-env-changed=WARLOCK_DIAGNOSTICS");
    if env::var("WARLOCK_DIAGNOSTICS").as_deref() == Ok("1") {
        println!("cargo:rustc-env=WARLOCK_DIAGNOSTICS_TRIAL=1");
    }
    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("..").join("..");
    if let Ok(out) = Command::new("git").args(["rev-parse", "--short=12", "HEAD"]).current_dir(&root).output()
        && out.status.success()
    {
        println!("cargo:rustc-env=WARLOCK_COMMIT={}", String::from_utf8_lossy(&out.stdout).trim());
    }
    // A commit or a checkout changes these.
    for file in ["HEAD", "logs/HEAD"] {
        let path = root.join(".git").join(file);
        if path.exists() {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
}
