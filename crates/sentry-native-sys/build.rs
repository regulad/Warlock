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
    let dst = cmake::Config::new(&sentry)
        .profile("Release")
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
    // What sentry-native's CMakeLists links on Windows (_SENTRY_PLATFORM_LIBS).
    for lib in ["dbghelp", "shlwapi", "version", "winhttp", "synchronization"] {
        println!("cargo:rustc-link-lib=dylib={lib}");
    }

    println!("cargo:rerun-if-changed=build.rs");
    for p in ["CMakeLists.txt", "src", "include"] {
        println!("cargo:rerun-if-changed={}", sentry.join(p).display());
    }
}
