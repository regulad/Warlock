// SPDX-License-Identifier: GPL-2.0-only
//! Raw FFI to Sentry's native SDK, sentry-native 0.17 (MIT,
//! `third_party/sentry-native`, `include/sentry.h`): the functions Warlock
//! uses, declared by hand from that header. Built statically with its
//! in-process crash backend and WinHTTP transport (`build.rs`), and a shim
//! that formats its log for Warlock's (`shim/logger.c`).
//!
//! The native SDK, not Sentry's Rust one, because of licensing: the Rust
//! SDK needs crates offered under Apache-2.0 alone, which the GPL-2.0-only
//! daemon can't link (PLAN.md, "Diagnostics"; `deny.toml`). The AGPL
//! programs, which can, use the Rust SDK (`warlock-sentry`).
//!
//! Warlock's diagnostics (`crates/warlock/src/diagnostics.rs`) wrap these;
//! nothing else should call them.

#![allow(non_camel_case_types)]

use std::os::raw::{c_char, c_int, c_void};

/// `sentry_value_t`: a tagged 64-bit value, passed by value.
#[repr(C)]
#[derive(Clone, Copy)]
pub union sentry_value_t {
    pub _bits: u64,
    pub _double: f64,
}

/// `sentry_uuid_t`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct sentry_uuid_t {
    pub bytes: [c_char; 16],
}

#[repr(C)]
pub struct sentry_options_t {
    _private: [u8; 0],
}
#[repr(C)]
pub struct sentry_transport_t {
    _private: [u8; 0],
}
#[repr(C)]
pub struct sentry_envelope_t {
    _private: [u8; 0],
}
#[repr(C)]
pub struct sentry_hint_t {
    _private: [u8; 0],
}
#[repr(C)]
pub struct sentry_transaction_context_t {
    _private: [u8; 0],
}
#[repr(C)]
pub struct sentry_transaction_t {
    _private: [u8; 0],
}

/// `sentry_value_type_t`.
pub const SENTRY_VALUE_TYPE_NULL: c_int = 0;
pub const SENTRY_VALUE_TYPE_BOOL: c_int = 1;
pub const SENTRY_VALUE_TYPE_INT32: c_int = 2;
pub const SENTRY_VALUE_TYPE_INT64: c_int = 3;
pub const SENTRY_VALUE_TYPE_UINT64: c_int = 4;
pub const SENTRY_VALUE_TYPE_DOUBLE: c_int = 5;
pub const SENTRY_VALUE_TYPE_STRING: c_int = 6;
pub const SENTRY_VALUE_TYPE_LIST: c_int = 7;
pub const SENTRY_VALUE_TYPE_OBJECT: c_int = 8;

/// `sentry_level_t`.
pub const SENTRY_LEVEL_DEBUG: c_int = -1;
pub const SENTRY_LEVEL_INFO: c_int = 0;
pub const SENTRY_LEVEL_WARNING: c_int = 1;
pub const SENTRY_LEVEL_ERROR: c_int = 2;
pub const SENTRY_LEVEL_FATAL: c_int = 3;

/// `sentry_span_status_t`, those Warlock sets.
pub const SENTRY_SPAN_STATUS_OK: c_int = 0;
pub const SENTRY_SPAN_STATUS_UNKNOWN: c_int = 2;
pub const SENTRY_SPAN_STATUS_INVALID_ARGUMENT: c_int = 3;
pub const SENTRY_SPAN_STATUS_NOT_FOUND: c_int = 5;
pub const SENTRY_SPAN_STATUS_ALREADY_EXISTS: c_int = 6;
pub const SENTRY_SPAN_STATUS_PERMISSION_DENIED: c_int = 7;
pub const SENTRY_SPAN_STATUS_INTERNAL_ERROR: c_int = 13;
pub const SENTRY_SPAN_STATUS_UNAVAILABLE: c_int = 14;

/// `sentry_event_function_t`: `before_send`.
pub type sentry_event_function_t =
    Option<unsafe extern "C" fn(event: sentry_value_t, hint: *mut sentry_hint_t, data: *mut c_void) -> sentry_value_t>;
/// A transport's send function.
pub type sentry_send_function_t = Option<unsafe extern "C" fn(envelope: *mut sentry_envelope_t, state: *mut c_void)>;

unsafe extern "C" {
    pub fn sentry_options_new() -> *mut sentry_options_t;
    pub fn sentry_options_set_dsn(opts: *mut sentry_options_t, dsn: *const c_char);
    pub fn sentry_options_set_release(opts: *mut sentry_options_t, release: *const c_char);
    pub fn sentry_options_set_environment(opts: *mut sentry_options_t, environment: *const c_char);
    pub fn sentry_options_set_database_pathw(opts: *mut sentry_options_t, path: *const u16);
    pub fn sentry_options_set_traces_sample_rate(opts: *mut sentry_options_t, sample_rate: f64);
    pub fn sentry_options_set_auto_session_tracking(opts: *mut sentry_options_t, val: c_int);
    pub fn sentry_options_set_shutdown_timeout(opts: *mut sentry_options_t, shutdown_timeout: u64);
    pub fn sentry_options_set_debug(opts: *mut sentry_options_t, debug: c_int);
    pub fn sentry_options_set_logger_level(opts: *mut sentry_options_t, level: c_int);
    pub fn sentry_options_set_logger_enabled_when_crashed(opts: *mut sentry_options_t, enabled: c_int);
    /// The shim's (`shim/logger.c`): the SDK's log, each message formatted,
    /// to `log`, with its `sentry_level_t`.
    pub fn warlock_sentry_set_logger(
        opts: *mut sentry_options_t,
        log: unsafe extern "C" fn(level: c_int, message: *const c_char),
    );
    pub fn sentry_options_set_before_send(
        opts: *mut sentry_options_t,
        func: sentry_event_function_t,
        user_data: *mut c_void,
    );
    pub fn sentry_options_set_transport(opts: *mut sentry_options_t, transport: *mut sentry_transport_t);
    pub fn sentry_transport_new(send_func: sentry_send_function_t) -> *mut sentry_transport_t;
    pub fn sentry_envelope_serialize(envelope: *const sentry_envelope_t, size_out: *mut usize) -> *mut c_char;
    pub fn sentry_envelope_free(envelope: *mut sentry_envelope_t);
    pub fn sentry_free(ptr: *mut c_void);

    pub fn sentry_init(options: *mut sentry_options_t) -> c_int;
    pub fn sentry_close() -> c_int;

    pub fn sentry_set_user(user: sentry_value_t);
    pub fn sentry_set_context(key: *const c_char, value: sentry_value_t);
    pub fn sentry_set_tag(key: *const c_char, value: *const c_char);
    pub fn sentry_add_breadcrumb(breadcrumb: sentry_value_t);
    pub fn sentry_capture_event(event: sentry_value_t) -> sentry_uuid_t;
    pub fn sentry_start_session();
    pub fn sentry_end_session();

    pub fn sentry_value_new_null() -> sentry_value_t;
    pub fn sentry_value_new_bool(value: c_int) -> sentry_value_t;
    pub fn sentry_value_new_int32(value: i32) -> sentry_value_t;
    pub fn sentry_value_new_double(value: f64) -> sentry_value_t;
    pub fn sentry_value_new_string(value: *const c_char) -> sentry_value_t;
    pub fn sentry_value_new_list() -> sentry_value_t;
    pub fn sentry_value_new_object() -> sentry_value_t;
    pub fn sentry_value_new_event() -> sentry_value_t;
    pub fn sentry_value_new_message_event(level: c_int, logger: *const c_char, text: *const c_char) -> sentry_value_t;
    pub fn sentry_value_new_breadcrumb(ty: *const c_char, message: *const c_char) -> sentry_value_t;
    pub fn sentry_value_new_exception(ty: *const c_char, value: *const c_char) -> sentry_value_t;
    pub fn sentry_event_add_exception(event: sentry_value_t, exception: sentry_value_t);
    pub fn sentry_value_set_stacktrace(value: sentry_value_t, ips: *mut *mut c_void, len: usize);
    pub fn sentry_value_incref(value: sentry_value_t) -> sentry_value_t;
    pub fn sentry_value_decref(value: sentry_value_t) -> c_int;
    pub fn sentry_value_get_type(value: sentry_value_t) -> c_int;
    pub fn sentry_value_is_null(value: sentry_value_t) -> c_int;
    pub fn sentry_value_as_string(value: sentry_value_t) -> *const c_char;
    pub fn sentry_value_set_by_key(value: sentry_value_t, k: *const c_char, v: sentry_value_t) -> c_int;
    pub fn sentry_value_get_by_key(value: sentry_value_t, k: *const c_char) -> sentry_value_t;
    pub fn sentry_value_get_by_index(value: sentry_value_t, index: usize) -> sentry_value_t;
    pub fn sentry_value_get_length(value: sentry_value_t) -> usize;
    pub fn sentry_value_append(value: sentry_value_t, v: sentry_value_t) -> c_int;

    pub fn sentry_transaction_context_new(
        name: *const c_char,
        operation: *const c_char,
    ) -> *mut sentry_transaction_context_t;
    pub fn sentry_transaction_start_ts(
        tx_ctx: *mut sentry_transaction_context_t,
        custom_sampling_ctx: sentry_value_t,
        timestamp: u64,
    ) -> *mut sentry_transaction_t;
    pub fn sentry_transaction_finish_ts(tx: *mut sentry_transaction_t, timestamp: u64) -> sentry_uuid_t;
    pub fn sentry_transaction_set_data(tx: *mut sentry_transaction_t, key: *const c_char, value: sentry_value_t);
    pub fn sentry_transaction_set_status(tx: *mut sentry_transaction_t, status: c_int);
}
