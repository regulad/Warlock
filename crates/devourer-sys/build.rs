// SPDX-License-Identifier: GPL-2.0-only
//
// Builds devourer (RTL8822BU backend only) and the dvr_shim C ABI with CMake,
// and links both statically. libusb comes from the libusb1-sys crate.

use std::env;
use std::path::{Path, PathBuf};

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

fn cmake_path(p: &Path) -> String {
    p.display().to_string().replace('\\', "/")
}

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let devourer = manifest.join("../../third_party/devourer");
    if !devourer.join("CMakeLists.txt").exists() {
        panic!("devourer checkout missing at {}; run `git submodule update --init`", devourer.display());
    }

    let usb_include =
        PathBuf::from(env::var("DEP_USB_1.0_INCLUDE").expect("libusb1-sys did not export its include directory"));
    // devourer includes <libusb.h> on MSVC and <libusb-1.0/libusb.h> elsewhere;
    // offer whichever of the two layouts libusb1-sys produced.
    let libusb_includes = [usb_include.clone(), usb_include.join("libusb-1.0")]
        .iter()
        .filter(|d| d.is_dir())
        .map(|d| cmake_path(d))
        .collect::<Vec<_>>()
        .join(";");

    let mut cfg = cmake::Config::new(manifest.join("cmake"));
    // Debug information (/Z7, in the objects), which the linker puts in
    // warlock.pdb, so Sentry can name devourer's frames in a crash (PLAN.md,
    // "Diagnostics"). It doesn't change the code MSVC generates.
    //
    // Beware: with the Visual Studio generator, cmake-rs sets
    // CMAKE_<LANG>_FLAGS_RELEASE itself (to pass /MD), which replaces
    // CMake's /O2 /Ob2 /DNDEBUG: devourer is built unoptimised, with its
    // asserts on, and always has been.
    cfg.profile("Release")
        .cflag("-Z7")
        .cxxflag("-Z7")
        .define("DEVOURER_SOURCE_DIR", cmake_path(&devourer))
        .define("WARLOCK_LIBUSB_INCLUDE_DIRS", libusb_includes)
        .build_target("warlock_dvr_shim");
    for (name, value) in CHIP_OPTIONS {
        cfg.define(name, value);
    }
    let dst = cfg.build();

    // Multi-config generators (Visual Studio) put libraries under a
    // per-configuration directory; single-config ones (Ninja) do not.
    let build = dst.join("build");
    for dir in [build.join("Release"), build.clone(), build.join("devourer").join("Release"), build.join("devourer")] {
        println!("cargo:rustc-link-search=native={}", dir.display());
    }
    println!("cargo:rustc-link-lib=static=warlock_dvr_shim");
    println!("cargo:rustc-link-lib=static=devourer");

    for p in ["shim", "cmake", "build.rs"] {
        println!("cargo:rerun-if-changed={}", manifest.join(p).display());
    }
    for p in ["CMakeLists.txt", "src", "hal"] {
        println!("cargo:rerun-if-changed={}", devourer.join(p).display());
    }
}
