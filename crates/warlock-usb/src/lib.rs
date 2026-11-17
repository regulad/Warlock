// SPDX-License-Identifier: GPL-2.0-only
//! Claims Warlock's USB Wi-Fi adapter for WinUSB, and gives it back.
//!
//! Out of the box Windows binds the TP-Link Archer T3U to its in-box Realtek
//! Wi-Fi driver (`netrtwlanu.inf`). Warlock drives the radio from user space
//! through libusb, which needs the device on WinUSB instead.
//!
//! Binding uses only Microsoft-signed parts: it does what Device Manager's
//! "Have Disk" does with `%windir%\INF\winusb.inf`. It builds a driver list
//! from that one INF, picks its generic "WinUsb Device" node (hardware ID
//! `USB\MS_COMP_WINUSB`) and installs it with `DiInstallDevice`. SetupAPI only
//! lists drivers of the device's current setup class, so if the node is
//! missing the device is first moved to the USBDevice class. No catalog is
//! generated and no certificate is added to the machine.
//!
//! Releasing asks Windows to install the best-matching driver from the driver
//! store again, which for the T3U is `netrtwlanu.inf`.
//!
//! Every mutating call needs administrator rights (Warlock runs as
//! LocalSystem).

use std::fmt;
use std::mem::{offset_of, size_of, zeroed};
use std::ptr::{null, null_mut};

use windows_sys::Win32::Devices::DeviceAndDriverInstallation::*;
use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_NO_MORE_ITEMS, GetLastError};
use windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW;

/// The adapter Warlock is built around.
pub const T3U_VID: u16 = 0x2357;
pub const T3U_PID: u16 = 0x012d;

/// Setup class of the generic WinUSB driver node in winusb.inf.
const USBDEVICE_CLASS_GUID: &str = "{88BAE032-5A81-49f0-BC3D-A4FF138216D6}";
/// Hardware ID of winusb.inf's generic "WinUsb Device" model.
const WINUSB_GENERIC_HWID: &str = "USB\\MS_COMP_WINUSB";

#[derive(Debug)]
pub struct Error {
    pub op: &'static str,
    pub code: u32,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} failed (Win32 error {:#x})", self.op, self.code)?;
        if self.code == ERROR_ACCESS_DENIED {
            write!(f, ": administrator rights are required")?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

fn last_error(op: &'static str) -> Error {
    Error { op, code: unsafe { GetLastError() } }
}

/// A present USB device, as Windows currently sees it.
#[derive(Clone, Debug)]
pub struct UsbDevice {
    pub instance_id: String,
    pub hardware_ids: Vec<String>,
    /// Name of the function driver's service, e.g. `WinUSB` or `rtwlanu`.
    pub service: Option<String>,
    /// Setup class name, e.g. `Net` or `USBDevice`.
    pub class: Option<String>,
}

impl UsbDevice {
    pub fn is_winusb(&self) -> bool {
        self.service
            .as_deref()
            .is_some_and(|s| s.eq_ignore_ascii_case("WinUSB"))
    }
}

/// Outcome of a driver change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Installed {
    pub reboot_required: bool,
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

fn multi_sz(buf: &[u16]) -> Vec<String> {
    buf.split(|&c| c == 0)
        .take_while(|s| !s.is_empty())
        .map(String::from_utf16_lossy)
        .collect()
}

/// Owned SetupAPI device information set.
struct DevInfoSet(HDEVINFO);

impl Drop for DevInfoSet {
    fn drop(&mut self) {
        unsafe { SetupDiDestroyDeviceInfoList(self.0) };
    }
}

impl DevInfoSet {
    /// All present devices enumerated by the USB bus driver.
    fn present_usb() -> Result<Self> {
        let usb = wide("USB");
        let h = unsafe {
            SetupDiGetClassDevsW(null(), usb.as_ptr(), null_mut(), DIGCF_ALLCLASSES | DIGCF_PRESENT)
        };
        if h as isize == -1 {
            return Err(last_error("SetupDiGetClassDevsW"));
        }
        Ok(Self(h))
    }

    fn devices(&self) -> impl Iterator<Item = SP_DEVINFO_DATA> + '_ {
        (0u32..).map_while(move |i| {
            let mut d: SP_DEVINFO_DATA = unsafe { zeroed() };
            d.cbSize = size_of::<SP_DEVINFO_DATA>() as u32;
            (unsafe { SetupDiEnumDeviceInfo(self.0, i, &mut d) } != 0).then_some(d)
        })
    }

    fn instance_id(&self, d: &SP_DEVINFO_DATA) -> Option<String> {
        let mut buf = [0u16; 512];
        let ok = unsafe {
            SetupDiGetDeviceInstanceIdW(self.0, d, buf.as_mut_ptr(), buf.len() as u32, null_mut())
        };
        (ok != 0).then(|| from_wide(&buf))
    }

    fn property(&self, d: &SP_DEVINFO_DATA, prop: u32) -> Option<Vec<u16>> {
        let mut buf = vec![0u16; 1024];
        let ok = unsafe {
            SetupDiGetDeviceRegistryPropertyW(
                self.0,
                d,
                prop,
                null_mut(),
                buf.as_mut_ptr().cast(),
                (buf.len() * 2) as u32,
                null_mut(),
            )
        };
        (ok != 0).then_some(buf)
    }

    fn describe(&self, d: &SP_DEVINFO_DATA) -> Option<UsbDevice> {
        Some(UsbDevice {
            instance_id: self.instance_id(d)?,
            hardware_ids: self.property(d, SPDRP_HARDWAREID).map(|b| multi_sz(&b)).unwrap_or_default(),
            service: self.property(d, SPDRP_SERVICE).map(|b| from_wide(&b)),
            class: self.property(d, SPDRP_CLASS).map(|b| from_wide(&b)),
        })
    }

    fn find(&self, instance_id: &str) -> Option<SP_DEVINFO_DATA> {
        self.devices().find(|d| {
            self.instance_id(d)
                .is_some_and(|id| id.eq_ignore_ascii_case(instance_id))
        })
    }
}

/// Finds a present USB device by vendor and product ID.
pub fn find(vid: u16, pid: u16) -> Result<Option<UsbDevice>> {
    let want = format!("USB\\VID_{vid:04X}&PID_{pid:04X}");
    let set = DevInfoSet::present_usb()?;
    let found = set
        .devices()
        .filter_map(|d| set.describe(&d))
        .find(|dev| {
            dev.hardware_ids
                .iter()
                .any(|h| h.to_ascii_uppercase().starts_with(&want))
        });
    Ok(found)
}

fn winusb_inf_path() -> Vec<u16> {
    let mut buf = [0u16; 260];
    let n = unsafe { GetWindowsDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    let windir = String::from_utf16_lossy(&buf[..n]);
    wide(&format!("{windir}\\INF\\winusb.inf"))
}

/// Builds the device's class driver list from winusb.inf alone and returns
/// the generic WinUSB node, if the device's current class allows it.
fn winusb_driver_node(set: &DevInfoSet, d: &mut SP_DEVINFO_DATA) -> Result<Option<SP_DRVINFO_DATA_V2_W>> {
    unsafe { SetupDiDestroyDriverInfoList(set.0, d, SPDIT_CLASSDRIVER) };

    let mut params: SP_DEVINSTALL_PARAMS_W = unsafe { zeroed() };
    params.cbSize = size_of::<SP_DEVINSTALL_PARAMS_W>() as u32;
    if unsafe { SetupDiGetDeviceInstallParamsW(set.0, d, &mut params) } == 0 {
        return Err(last_error("SetupDiGetDeviceInstallParamsW"));
    }
    let inf = winusb_inf_path();
    params.DriverPath = [0; 260];
    params.DriverPath[..inf.len()].copy_from_slice(&inf);
    params.Flags |= DI_ENUMSINGLEINF;
    params.FlagsEx |= DI_FLAGSEX_ALLOWEXCLUDEDDRVS;
    if unsafe { SetupDiSetDeviceInstallParamsW(set.0, d, &params) } == 0 {
        return Err(last_error("SetupDiSetDeviceInstallParamsW"));
    }
    if unsafe { SetupDiBuildDriverInfoList(set.0, d, SPDIT_CLASSDRIVER) } == 0 {
        return Err(last_error("SetupDiBuildDriverInfoList"));
    }

    // SP_DRVINFO_DETAIL_DATA_W ends in a variable-length HardwareID; read it
    // into a u64-aligned buffer large enough for any of winusb.inf's nodes.
    let mut detail_buf = vec![0u64; 1024];
    for i in 0u32.. {
        let mut drv: SP_DRVINFO_DATA_V2_W = unsafe { zeroed() };
        drv.cbSize = size_of::<SP_DRVINFO_DATA_V2_W>() as u32;
        if unsafe { SetupDiEnumDriverInfoW(set.0, d, SPDIT_CLASSDRIVER, i, &mut drv) } == 0 {
            let err = last_error("SetupDiEnumDriverInfoW");
            if err.code == ERROR_NO_MORE_ITEMS {
                break;
            }
            return Err(err);
        }
        detail_buf.fill(0);
        let detail = detail_buf.as_mut_ptr().cast::<SP_DRVINFO_DETAIL_DATA_W>();
        unsafe { (*detail).cbSize = size_of::<SP_DRVINFO_DETAIL_DATA_W>() as u32 };
        let ok = unsafe {
            SetupDiGetDriverInfoDetailW(set.0, d, &drv, detail, (detail_buf.len() * 8) as u32, null_mut())
        };
        if ok == 0 {
            continue;
        }
        let hwid_ptr = unsafe {
            detail_buf
                .as_ptr()
                .cast::<u8>()
                .add(offset_of!(SP_DRVINFO_DETAIL_DATA_W, HardwareID))
                .cast::<u16>()
        };
        let words = detail_buf.len() * 4 - offset_of!(SP_DRVINFO_DETAIL_DATA_W, HardwareID) / 2;
        let hwid = from_wide(unsafe { std::slice::from_raw_parts(hwid_ptr, words) });
        if hwid.eq_ignore_ascii_case(WINUSB_GENERIC_HWID) {
            return Ok(Some(drv));
        }
    }
    Ok(None)
}

fn open(instance_id: &str) -> Result<(DevInfoSet, SP_DEVINFO_DATA)> {
    let set = DevInfoSet::present_usb()?;
    let d = set.find(instance_id).ok_or(Error {
        op: "locating the device",
        code: windows_sys::Win32::Foundation::ERROR_NOT_FOUND,
    })?;
    Ok((set, d))
}

/// Installs Windows' generic WinUSB driver on the device.
pub fn bind_winusb(instance_id: &str) -> Result<Installed> {
    let (set, mut d) = open(instance_id)?;

    let mut node = winusb_driver_node(&set, &mut d)?;
    if node.is_none() {
        // The device sits in another setup class (Net, for the T3U), so its
        // class driver list cannot contain winusb.inf's nodes. Move it to the
        // USBDevice class first; SetupAPI cleans up the old software key.
        let guid = wide(USBDEVICE_CLASS_GUID);
        let ok = unsafe {
            SetupDiSetDeviceRegistryPropertyW(set.0, &mut d, SPDRP_CLASSGUID, guid.as_ptr().cast(), (guid.len() * 2) as u32)
        };
        if ok == 0 {
            return Err(last_error("SetupDiSetDeviceRegistryPropertyW(ClassGUID)"));
        }
        node = winusb_driver_node(&set, &mut d)?;
    }
    let node = node.ok_or(Error {
        op: "finding the generic WinUSB node in winusb.inf",
        code: windows_sys::Win32::Foundation::ERROR_NOT_FOUND,
    })?;

    let mut reboot = 0;
    if unsafe { DiInstallDevice(null_mut(), set.0, &d, &node, 0, &mut reboot) } == 0 {
        return Err(last_error("DiInstallDevice(WinUSB)"));
    }
    Ok(Installed { reboot_required: reboot != 0 })
}

/// Gives the device back to Windows: installs the best-matching driver from
/// the driver store (for the T3U, the in-box `netrtwlanu.inf`).
pub fn release(instance_id: &str) -> Result<Installed> {
    let (set, d) = open(instance_id)?;
    let mut reboot = 0;
    if unsafe { DiInstallDevice(null_mut(), set.0, &d, null(), 0, &mut reboot) } == 0 {
        return Err(last_error("DiInstallDevice(best match)"));
    }
    Ok(Installed { reboot_required: reboot != 0 })
}
