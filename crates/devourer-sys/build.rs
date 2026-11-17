// SPDX-License-Identifier: GPL-2.0-only
//
// Builds devourer (RTL8822BU backend only) and the dvr_shim C ABI with CMake,
// and links both statically. libusb comes from the libusb1-sys crate.
//
// devourer is built from a copy in OUT_DIR with Warlock's patches
// (third_party/patches/devourer/*.patch) applied, so the submodule itself
// stays a pristine upstream checkout.

use std::collections::hash_map::DefaultHasher;
use std::env;
use std::fs;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::process::Command;

/// devourer per-chip CMake options; only the 8822B (Jaguar2) backend that
/// drives the TP-Link Archer T3U is kept.
const CHIP_OPTIONS: &[(&str, &str)] = &[
    ("DEVOURER_JAGUAR1", "OFF"),
    ("DEVOURER_8814", "OFF"),
    ("DEVOURER_JAGUAR2_8822B", "ON"),
    ("DEVOURER_JAGUAR2_8821C", "OFF"),
    ("DEVOURER_JAGUAR3_8822C", "OFF"),
    ("DEVOURER_JAGUAR3_8822E", "OFF"),
    ("DEVOURER_8733B", "OFF"),
    ("DEVOURER_KESTREL_8852B", "OFF"),
    ("DEVOURER_KESTREL_8852C", "OFF"),
];

/// Top-level entries of the devourer checkout that the build doesn't need.
const SKIP: &[&str] = &[".git", ".github", "reference", "build", "docs"];

fn cmake_path(p: &Path) -> String {
    p.display().to_string().replace('\\', "/")
}

fn git(args: &[&str], dir: &Path) -> std::process::Output {
    Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("running git (needed to read the devourer revision and apply patches)")
}

/// `git apply` in `dir`, treating it as a plain directory. OUT_DIR lives inside
/// the Warlock repository, and inside a repository `git apply` resolves patch
/// paths against the repository root and silently skips files outside the
/// current directory, so repository discovery is stopped at `dir`'s parent.
fn git_apply(args: &[&str], dir: &Path) -> std::process::Output {
    Command::new("git")
        .arg("apply")
        .args(args)
        .current_dir(dir)
        .env("GIT_CEILING_DIRECTORIES", dir.parent().unwrap())
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .output()
        .expect("running git apply")
}

/// Copies `src` into `dst`, rewriting only files whose contents differ so that
/// unchanged files keep their timestamps and CMake doesn't rebuild them.
fn sync_tree(src: &Path, dst: &Path, top_level: bool) {
    fs::create_dir_all(dst).unwrap();
    for entry in fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        if top_level && SKIP.iter().any(|s| name == *s) {
            continue;
        }
        let (from, to) = (entry.path(), dst.join(&name));
        if entry.file_type().unwrap().is_dir() {
            sync_tree(&from, &to, false);
        } else {
            let data = fs::read(&from).unwrap();
            if fs::read(&to).ok().as_deref() != Some(&data[..]) {
                fs::write(&to, &data).unwrap();
            }
        }
    }
}

/// Produces the patched devourer source tree to build from.
fn prepare_devourer(devourer: &Path, patch_dir: &Path, out: &Path) -> PathBuf {
    let mut patches: Vec<PathBuf> = fs::read_dir(patch_dir)
        .map(|rd| {
            rd.filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.extension().is_some_and(|x| x == "patch"))
                .collect()
        })
        .unwrap_or_default();
    patches.sort();

    // A new upstream revision or patch set starts from a clean copy, so files
    // deleted upstream don't linger.
    let head = git(&["rev-parse", "HEAD"], devourer);
    let mut h = DefaultHasher::new();
    head.stdout.hash(&mut h);
    for p in &patches {
        fs::read(p).unwrap().hash(&mut h);
    }
    let fingerprint = format!("{:016x}", h.finish());
    let dst = out.join("devourer-src");
    let stamp = out.join("devourer-src.stamp");
    if fs::read_to_string(&stamp).ok().as_deref() != Some(fingerprint.as_str()) {
        let _ = fs::remove_dir_all(&dst);
    }

    sync_tree(devourer, &dst, true);
    for p in &patches {
        let patch = p.display().to_string();
        let out = git_apply(&["--whitespace=nowarn", &patch], &dst);
        // A clean reverse-check proves the patch really landed rather than
        // being skipped.
        let check = git_apply(&["--reverse", "--check", &patch], &dst);
        if !out.status.success() || !check.status.success() {
            panic!(
                "applying {} to devourer failed:\n{}{}",
                patch,
                String::from_utf8_lossy(&out.stderr),
                String::from_utf8_lossy(&check.stderr)
            );
        }
    }
    fs::write(&stamp, fingerprint).unwrap();
    dst
}

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let devourer = manifest.join("../../third_party/devourer");
    let patch_dir = manifest.join("../../third_party/patches/devourer");
    if !devourer.join("CMakeLists.txt").exists() {
        panic!(
            "devourer checkout missing at {}; run `git submodule update --init`",
            devourer.display()
        );
    }
    let devourer_src = prepare_devourer(&devourer, &patch_dir, &out);

    let usb_include = PathBuf::from(
        env::var("DEP_USB_1.0_INCLUDE").expect("libusb1-sys did not export its include directory"),
    );
    // devourer includes <libusb.h> on MSVC and <libusb-1.0/libusb.h> elsewhere;
    // offer whichever of the two layouts libusb1-sys produced.
    let libusb_includes = [usb_include.clone(), usb_include.join("libusb-1.0")]
        .iter()
        .filter(|d| d.is_dir())
        .map(|d| cmake_path(d))
        .collect::<Vec<_>>()
        .join(";");

    let mut cfg = cmake::Config::new(manifest.join("cmake"));
    cfg.profile("Release")
        .define("DEVOURER_SOURCE_DIR", cmake_path(&devourer_src))
        .define("WARLOCK_LIBUSB_INCLUDE_DIRS", libusb_includes)
        .build_target("warlock_dvr_shim");
    for (name, value) in CHIP_OPTIONS {
        cfg.define(name, value);
    }
    let dst = cfg.build();

    // Multi-config generators (Visual Studio) put libraries under a
    // per-configuration directory; single-config ones (Ninja) do not.
    let build = dst.join("build");
    for dir in [
        build.join("Release"),
        build.clone(),
        build.join("devourer").join("Release"),
        build.join("devourer"),
    ] {
        println!("cargo:rustc-link-search=native={}", dir.display());
    }
    println!("cargo:rustc-link-lib=static=warlock_dvr_shim");
    println!("cargo:rustc-link-lib=static=devourer");

    for p in ["shim", "cmake", "build.rs"] {
        println!("cargo:rerun-if-changed={}", manifest.join(p).display());
    }
    println!("cargo:rerun-if-changed={}", patch_dir.display());
    for p in ["CMakeLists.txt", "src", "hal"] {
        println!("cargo:rerun-if-changed={}", devourer.join(p).display());
    }
}
