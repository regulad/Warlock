// SPDX-License-Identifier: GPL-2.0-or-later
//! Developer CLI over warlock-usb: show which driver owns the T3U, bind it to
//! WinUSB, or give it back to Windows.
//!
//! Usage: warlock-usb [status|bind|release]

use warlock_usb::{T3U_PID, T3U_VID, UsbDevice};

fn show(dev: &UsbDevice) {
    println!("instance:  {}", dev.instance_id);
    println!("class:     {}", dev.class.as_deref().unwrap_or("-"));
    println!("service:   {}", dev.service.as_deref().unwrap_or("-"));
    println!("winusb:    {}", dev.is_winusb());
}

fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_else(|| "status".into());
    let dev = match warlock_usb::find(T3U_VID, T3U_PID) {
        Ok(Some(dev)) => dev,
        Ok(None) => {
            eprintln!("no {T3U_VID:04x}:{T3U_PID:04x} adapter is present");
            std::process::exit(2);
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    let result = match cmd.as_str() {
        "status" => {
            show(&dev);
            return;
        }
        "bind" if dev.is_winusb() => {
            println!("already bound to WinUSB");
            return;
        }
        "bind" => warlock_usb::bind_winusb(&dev.instance_id),
        "release" => warlock_usb::release(&dev.instance_id),
        other => {
            eprintln!("unknown command {other:?}; expected status, bind or release");
            std::process::exit(2);
        }
    };
    match result {
        Ok(installed) => {
            if installed.reboot_required {
                println!("done; Windows says a reboot is required");
            }
            match warlock_usb::find(T3U_VID, T3U_PID) {
                Ok(Some(dev)) => show(&dev),
                Ok(None) => println!("adapter not present after the change"),
                Err(e) => eprintln!("{e}"),
            }
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}
