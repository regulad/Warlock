// SPDX-License-Identifier: GPL-2.0-only
//! Getting `wintun.dll` onto this machine without shipping it.
//!
//! The release is pinned, Wintun 0.14.1:
//! - the zip by the SHA-256 wintun.net publishes for it;
//! - each architecture's DLL by its SHA-256 inside that zip. All are signed
//!   by WireGuard LLC (Authenticode, checked 2026-11-17).
//!
//! [`ensure`] downloads and unpacks it once, into a directory only SYSTEM
//! and Administrators can write. [`load`] checks the DLL's hash again just
//! before loading it. Warlock's own GPL code permits the combination
//! (`LICENSE-WINTUN-EXCEPTION.md`).

use std::io::{self, Cursor, Read, Seek};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;

use sha2::{Digest, Sha256};

/// The Wintun release we use.
pub const VERSION: &str = "0.14.1";
const URL: &str = "https://www.wintun.net/builds/wintun-0.14.1.zip";
const ZIP_SHA256: &str = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51";

/// This build's architecture as Wintun names it, and that DLL's SHA-256.
fn arch() -> (&'static str, &'static str) {
    if cfg!(target_arch = "x86_64") {
        ("amd64", "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce")
    } else if cfg!(target_arch = "aarch64") {
        ("arm64", "f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80")
    } else if cfg!(target_arch = "x86") {
        ("x86", "d694fa46ab4cfebcb2632d094c7aa97278eef2f8052438621766d863ae98a931")
    } else {
        ("arm", "daad267411ecdc70a0535e274d2c3e9da3d0084bdac7662cb8424dd4a031b4d9")
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

fn check(what: &str, bytes: &[u8], want: &str) -> io::Result<()> {
    let got = sha256_hex(bytes);
    if got == want { Ok(()) } else { Err(io::Error::other(format!("{what} has SHA-256 {got}, not the pinned {want}"))) }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn wide_path(p: &Path) -> Vec<u16> {
    p.as_os_str().encode_wide().chain(Some(0)).collect()
}

/// Where Warlock keeps what it downloads: `%ProgramData%\Warlock`.
pub fn default_root() -> PathBuf {
    std::env::var_os("ProgramData").map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from).join("Warlock")
}

/// The DLL's path under `root`. The first time (or if the file there doesn't
/// match), downloads the release, checks it and unpacks this architecture's
/// DLL with Wintun's license beside it. Needs Administrator to create `root`.
pub fn ensure(root: &Path) -> io::Result<PathBuf> {
    let (arch, dll_sha) = arch();
    let dir = root.join(format!("wintun-{VERSION}")).join(arch);
    let dll = dir.join("wintun.dll");
    if std::fs::read(&dll).is_ok_and(|b| sha256_hex(&b) == dll_sha) {
        return Ok(dll);
    }
    prepare_root(root)?;
    std::fs::create_dir_all(&dir)?;
    let part = root.join(format!("wintun-{VERSION}.zip.part"));
    download(URL, &part)?;
    let zip = std::fs::read(&part);
    let _ = std::fs::remove_file(&part);
    let zip = zip?;
    check("the Wintun release zip", &zip, ZIP_SHA256)?;
    let mut archive = zip::ZipArchive::new(Cursor::new(zip)).map_err(io::Error::other)?;
    let bytes = read_entry(&mut archive, &format!("wintun/bin/{arch}/wintun.dll"))?;
    check("wintun.dll", &bytes, dll_sha)?;
    // Wintun's license stays with its DLL.
    std::fs::write(dir.join("LICENSE.txt"), read_entry(&mut archive, "wintun/LICENSE.txt")?)?;
    let tmp = dir.join("wintun.dll.part");
    std::fs::write(&tmp, &bytes)?;
    std::fs::rename(&tmp, &dll)?;
    Ok(dll)
}

/// Loads the DLL at `path`, after checking its hash once more.
pub fn load(path: &Path) -> io::Result<wintun_bindings::Wintun> {
    let (_, dll_sha) = arch();
    check("wintun.dll", &std::fs::read(path)?, dll_sha)?;
    // SAFETY: the file is the pinned release WireGuard LLC signed (its hash
    // was just checked); loading it runs only its DllMain.
    unsafe { wintun_bindings::load_from_path(path) }.map_err(|e| io::Error::other(e.to_string()))
}

fn read_entry<R: Read + Seek>(archive: &mut zip::ZipArchive<R>, name: &str) -> io::Result<Vec<u8>> {
    let mut f = archive.by_name(name).map_err(|e| io::Error::other(format!("{name} in the release zip: {e}")))?;
    let mut bytes = Vec::new();
    f.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn download(url: &str, to: &Path) -> io::Result<()> {
    use windows_sys::Win32::System::Com::Urlmon::URLDownloadToFileW;
    // SAFETY: valid NUL-terminated strings; no caller or callback.
    let hr = unsafe { URLDownloadToFileW(null_mut(), wide(url).as_ptr(), wide_path(to).as_ptr(), 0, null_mut()) };
    if hr != 0 {
        return Err(io::Error::other(format!("downloading {url}: HRESULT {hr:#010x}")));
    }
    Ok(())
}

/// Creates Warlock's directory (`root`) writable only by SYSTEM and
/// Administrators (Users may read and execute), inheriting nothing from
/// `%ProgramData%`, whose default lets any user create files. Whatever goes
/// in it (Wintun) should come after this. An existing
/// directory is left as it is; the hash check before loading still holds.
pub fn prepare_root(path: &Path) -> io::Result<()> {
    use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;

    const SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)";
    if path.is_dir() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut sd: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: a valid SDDL string; `sd` receives a LocalAlloc'd descriptor.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(wide(SDDL).as_ptr(), SDDL_REVISION_1, &mut sd, null_mut())
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let sa = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd,
        bInheritHandle: 0,
    };
    // SAFETY: a valid path and security attributes.
    let ok = unsafe { CreateDirectoryW(wide_path(path).as_ptr(), &sa) };
    let err = io::Error::last_os_error();
    // SAFETY: allocated by the conversion above.
    unsafe { LocalFree(sd) };
    if ok == 0 && err.raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32) {
        return Err(err);
    }
    Ok(())
}
