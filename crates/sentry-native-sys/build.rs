// SPDX-License-Identifier: GPL-2.0-only
//
// Builds sentry-native (third_party/sentry-native, MIT) with CMake as a static
// library, and links it with the Windows libraries it needs. Only
// sentry-native's own code is compiled: its in-process crash backend and
// Windows' own WinHTTP transport, so none of crashpad or libunwindstack
// (Apache-2.0, which GPL-2.0-only Warlock can't take) nor breakpad, and none
// of its submodules is needed (PLAN.md, "Diagnostics"). Its screenshots are
// left out of the build.

use std::env;
use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let sentry = manifest.join("../../third_party/sentry-native");
    if !sentry.join("CMakeLists.txt").exists() {
        panic!("sentry-native checkout missing at {}; run `git submodule update --init`", sentry.display());
    }
    // CMake's own Release flags, and debug information (/Z7, in the objects)
    // that the linker puts in warlock.pdb, so Sentry can name the SDK's
    // frames in a crash. Set here because, with the Visual Studio generator,
    // cmake-rs sets CMAKE_<LANG>_FLAGS_RELEASE itself unless it's given,
    // without /O2 /Ob2 /DNDEBUG: the SDK would be built unoptimised, and
    // without NDEBUG it logs everything it does to stderr
    // (sentry_options_new).
    let release = "-MD -O2 -Ob2 -DNDEBUG -Z7";
    let dst = cmake::Config::new(&sentry)
        .profile("Release")
        .define("CMAKE_C_FLAGS_RELEASE", release)
        .define("CMAKE_CXX_FLAGS_RELEASE", release)
        .define("SENTRY_BACKEND", "inproc")
        .define("SENTRY_TRANSPORT", "winhttp")
        // No screenshots, ever: not even compiled in (Windows' default is
        // to have them, and they'd show whatever is on the screen).
        .define("SENTRY_SCREENSHOT", "none")
        .define("SENTRY_BUILD_SHARED_LIBS", "OFF")
        .define("SENTRY_BUILD_TESTS", "OFF")
        .define("SENTRY_BUILD_EXAMPLES", "OFF")
        .define("SENTRY_BUILD_BENCHMARKS", "OFF")
        .build_target("sentry")
        .build();

    // Multi-config generators (Visual Studio) put the library under a
    // per-configuration directory; single-config ones (Ninja) do not.
    let build = dst.join("build");
    for dir in [build.join("Release"), build] {
        println!("cargo:rustc-link-search=native={}", dir.display());
    }
    println!("cargo:rustc-link-lib=static=sentry");
    // What sentry-native's CMakeLists links on Windows (_SENTRY_PLATFORM_LIBS),
    // and advapi32 (RegGetValueA, for its OS context), which CMake links by
    // default and Cargo doesn't: warlock.exe had it from other crates, the
    // crate's own test didn't.
    for lib in ["dbghelp", "shlwapi", "version", "winhttp", "synchronization", "advapi32"] {
        println!("cargo:rustc-link-lib=dylib={lib}");
    }

    // The logger's shim, against the SDK's header, built as the SDK is.
    cc::Build::new()
        .file(manifest.join("shim").join("logger.c"))
        .include(sentry.join("include"))
        .define("SENTRY_BUILD_STATIC", None)
        .compile("warlock_sentry_shim");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", manifest.join("shim").display());
    for p in ["CMakeLists.txt", "src", "include"] {
        println!("cargo:rerun-if-changed={}", sentry.join(p).display());
    }
}
