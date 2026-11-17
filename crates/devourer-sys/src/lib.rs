// SPDX-License-Identifier: GPL-2.0-or-later
//! Raw FFI to the dvr_shim C ABI over the OpenIPC devourer userspace Realtek
//! Wi-Fi driver. Declarations mirror `shim/dvr_shim.h`, which also documents
//! the threading contract. Safe wrappers live in `warlock-radio`.

#![allow(non_camel_case_types)]

use std::ffi::{c_char, c_int, c_void};

// devourer calls into libusb; this crate's dependency builds and links it.
use libusb1_sys as _;

/// Opaque handle to an opened adapter.
#[repr(C)]
pub struct dvr_radio {
    _private: [u8; 0],
}

pub const DVR_OK: c_int = 0;
pub const DVR_E_ARG: c_int = -1;
pub const DVR_E_USB: c_int = -2;
pub const DVR_E_NOT_FOUND: c_int = -3;
pub const DVR_E_BUSY: c_int = -4;
pub const DVR_E_UNSUPPORTED: c_int = -5;
pub const DVR_E_FAILED: c_int = -6;
pub const DVR_E_EXCEPTION: c_int = -7;

pub const DVR_WIDTH_20: u8 = 0;
pub const DVR_WIDTH_40: u8 = 1;
pub const DVR_WIDTH_80: u8 = 2;

pub const DVR_LOG_TRACE: u8 = 0;
pub const DVR_LOG_DEBUG: u8 = 1;
pub const DVR_LOG_INFO: u8 = 2;
pub const DVR_LOG_WARN: u8 = 3;
pub const DVR_LOG_ERROR: u8 = 4;
pub const DVR_LOG_SILENT: u8 = 5;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct dvr_config {
    pub retry_limit: i32,
    pub fastretune_fw: i32,
    pub thermal_track: u8,
    pub rx_spsc: u8,
    pub usb_reset: u8,
    pub log_level: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct dvr_rx_frame {
    pub data: *const u8,
    pub len: usize,
    pub tsfl: u32,
    pub data_rate: u16,
    pub rssi: [u8; 2],
    pub bw: u8,
    pub crc_err: u8,
}

pub type dvr_rx_cb = unsafe extern "C" fn(user: *mut c_void, frame: *const dvr_rx_frame);

unsafe extern "C" {
    pub fn dvr_last_error() -> *const c_char;
    pub fn dvr_open(vid: u16, pid: u16, cfg: *const dvr_config, out: *mut *mut dvr_radio) -> c_int;
    pub fn dvr_init(r: *mut dvr_radio, channel: u8, width: u8, offset: u8) -> c_int;
    pub fn dvr_run_rx(r: *mut dvr_radio, cb: dvr_rx_cb, user: *mut c_void) -> c_int;
    pub fn dvr_stop_rx(r: *mut dvr_radio);
    pub fn dvr_send(r: *mut dvr_radio, buf: *const u8, len: usize) -> c_int;
    pub fn dvr_fast_retune(r: *mut dvr_radio, channel: u8) -> c_int;
    pub fn dvr_set_channel(r: *mut dvr_radio, channel: u8, width: u8, offset: u8) -> c_int;
    pub fn dvr_reapply_txpower(r: *mut dvr_radio) -> c_int;
    pub fn dvr_set_ack_responder(r: *mut dvr_radio, mac: *const u8) -> c_int;
    pub fn dvr_clear_ack_responder(r: *mut dvr_radio);
    pub fn dvr_read_tsf(r: *mut dvr_radio, out: *mut u64) -> c_int;
    pub fn dvr_close(r: *mut dvr_radio);
}
