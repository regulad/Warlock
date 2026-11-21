// SPDX-License-Identifier: GPL-2.0-only
//! The shim (`shim/logger.c`) hands the SDK's log over formatted: a warning
//! the SDK makes with an argument arrives with it in place.

use std::ffi::{CStr, c_char, c_int};
use std::os::windows::ffi::OsStrExt;
use std::sync::Mutex;

use sentry_native_sys::*;

static SAID: Mutex<Vec<(c_int, String)>> = Mutex::new(Vec::new());

unsafe extern "C" fn log(level: c_int, message: *const c_char) {
    // SAFETY: the shim's NUL-terminated text, for the call.
    let text = unsafe { CStr::from_ptr(message) }.to_string_lossy().into_owned();
    SAID.lock().unwrap().push((level, text));
}

#[test]
fn the_sdks_log_arrives_formatted() {
    let database = std::env::temp_dir().join(format!("sentry-native-sys-logger-{}", std::process::id()));
    let path: Vec<u16> = database.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: options made here and handed to sentry_init, which owns them;
    // the strings outlive the calls, which copy them.
    unsafe {
        let options = sentry_options_new();
        // Not a DSN: sentry_init warns of it ("the provided DSN \"%s\" is
        // not valid"), and goes on.
        sentry_options_set_dsn(options, c"not-a-dsn".as_ptr());
        sentry_options_set_database_pathw(options, path.as_ptr());
        sentry_options_set_debug(options, 1);
        sentry_options_set_logger_level(options, SENTRY_LEVEL_WARNING);
        warlock_sentry_set_logger(options, log);
        sentry_init(options);
        sentry_close();
    }
    let _ = std::fs::remove_dir_all(&database);
    let said = SAID.lock().unwrap();
    assert!(
        said.iter()
            .any(|(level, text)| *level == SENTRY_LEVEL_WARNING
                && text == r#"the provided DSN "not-a-dsn" is not valid"#),
        "{said:?}"
    );
    assert!(said.iter().all(|(level, _)| *level >= SENTRY_LEVEL_WARNING), "below warnings: {said:?}");
}
