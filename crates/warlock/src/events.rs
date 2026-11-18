// SPDX-License-Identifier: GPL-2.0-only
//! Warlock's events: the ETW provider `Regulad-Warlock` (`events.man`).
//!
//! Information, warnings and errors also go to the Event Log channel
//! `Regulad-Warlock/Operational`, which Windows keeps and caps in size: in
//! Event Viewer, Applications and Services Logs > Regulad > Warlock >
//! Operational; from a shell, `Get-WinEvent -LogName
//! Regulad-Warlock/Operational`. Verbose events go to ETW sessions only.
//!
//! The channel exists once the manifest is registered ([`install`], run by
//! `warlock setup`). Until then, and for anything not in it, events reach
//! only ETW sessions that enable the provider.

use std::error::Error;
use std::io;
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

use tracing::{Level, Metadata};
use tracing_subscriber::fmt::MakeWriter;
use windows_sys::Win32::System::Diagnostics::Etw::{
    EVENT_DATA_DESCRIPTOR, EVENT_DATA_DESCRIPTOR_0, EVENT_DESCRIPTOR, EventRegister, EventWrite, REGHANDLE,
};
use windows_sys::core::GUID;

// PROVIDER and the EVENT_* descriptors, from the manifest (build.rs).
include!(concat!(env!("OUT_DIR"), "/events.rs"));

/// The manifest, for `wevtutil`.
const MANIFEST: &str = include_str!("../events.man");

static HANDLE: OnceLock<REGHANDLE> = OnceLock::new();

/// Registers this process as the provider, once.
fn handle() -> REGHANDLE {
    *HANDLE.get_or_init(|| {
        let mut handle = 0;
        // SAFETY: a valid GUID and out-parameter; no callback.
        unsafe { EventRegister(&PROVIDER, None, std::ptr::null(), &mut handle) };
        handle
    })
}

fn descriptor(level: &Level) -> &'static EVENT_DESCRIPTOR {
    match *level {
        Level::ERROR => &EVENT_ERROR,
        Level::WARN => &EVENT_WARNING,
        Level::INFO => &EVENT_INFORMATION,
        _ => &EVENT_VERBOSE,
    }
}

/// A `tracing` writer: each event, as formatted, becomes the event of its
/// level, its text the message.
pub struct Writer;

impl Writer {
    /// The writer, with this process registered as the provider.
    pub fn registered() -> Self {
        handle();
        Self
    }
}

/// One event's text, written when dropped.
pub struct Line {
    descriptor: &'static EVENT_DESCRIPTOR,
    text: Vec<u8>,
}

impl<'a> MakeWriter<'a> for Writer {
    type Writer = Line;

    fn make_writer(&'a self) -> Line {
        Line { descriptor: &EVENT_INFORMATION, text: Vec::new() }
    }

    fn make_writer_for(&'a self, meta: &Metadata<'_>) -> Line {
        Line { descriptor: descriptor(meta.level()), text: Vec::new() }
    }
}

impl io::Write for Line {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.text.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for Line {
    fn drop(&mut self) {
        let text = String::from_utf8_lossy(&self.text);
        let text = text.trim_end();
        if text.is_empty() {
            return;
        }
        let wide: Vec<u16> = text.encode_utf16().chain(Some(0)).collect();
        let data = EVENT_DATA_DESCRIPTOR {
            Ptr: wide.as_ptr() as u64,
            Size: (wide.len() * 2) as u32,
            Anonymous: EVENT_DATA_DESCRIPTOR_0 { Reserved: 0 },
        };
        // SAFETY: a registered handle, a descriptor from the manifest, and
        // one NUL-terminated UTF-16 string, as its template says.
        unsafe { EventWrite(handle(), self.descriptor, 1, &data) };
    }
}

fn wevtutil(args: &[String]) -> Result<(), Box<dyn Error>> {
    // System32's, not whatever PATH finds first.
    let root = std::env::var_os("SystemRoot").map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from);
    let output = Command::new(root.join("System32").join("wevtutil.exe")).args(args).output()?;
    if !output.status.success() {
        let why = String::from_utf8_lossy(&output.stderr);
        return Err(format!("wevtutil {}: {}", args[0], why.trim()).into());
    }
    Ok(())
}

/// Runs `wevtutil` on the manifest, written to a temporary file for it.
fn with_manifest(f: impl FnOnce(String) -> Result<(), Box<dyn Error>>) -> Result<(), Box<dyn Error>> {
    let path = std::env::temp_dir().join(format!("warlock-events-{}.man", std::process::id()));
    std::fs::write(&path, MANIFEST)?;
    let result = f(path.display().to_string());
    let _ = std::fs::remove_file(&path);
    result
}

/// Registers the manifest with Windows, with this executable as its resource
/// and message file, replacing any earlier registration. Needs SYSTEM or
/// Administrator.
pub fn install() -> Result<(), Box<dyn Error>> {
    let exe = std::env::current_exe()?.display().to_string();
    with_manifest(|man| {
        // An earlier version's registration, if any, may point elsewhere.
        let _ = wevtutil(&["um".into(), man.clone()]);
        wevtutil(&["im".into(), man, format!("/rf:{exe}"), format!("/mf:{exe}")])
    })
}

/// Unregisters the manifest. The channel's log file stays, as Windows' own
/// do.
pub fn uninstall() -> Result<(), Box<dyn Error>> {
    with_manifest(|man| wevtutil(&["um".into(), man]))
}
