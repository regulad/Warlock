// SPDX-License-Identifier: GPL-2.0-only
//! Developer CLI over warlock-usb: show which driver owns Warlock's adapter
//! (the T3U v1, or another supported RTL8812BU/RTL8822BU), bind it to WinUSB,
//! or give it back to Windows.
//!
//! Usage: warlock-usb [status|bind|release]

use warlock_usb::{Model, REFERENCE, UsbDevice};

fn show(dev: &UsbDevice, model: &Model) {
    println!("model:     {} ({:04x}:{:04x})", model.name, model.vid, model.pid);
    println!("instance:  {}", dev.instance_id);
    println!("class:     {}", dev.class.as_deref().unwrap_or("-"));
    println!("service:   {}", dev.service.as_deref().unwrap_or("-"));
    println!("winusb:    {}", dev.is_winusb());
}

fn find() -> (UsbDevice, Model) {
    match warlock_usb::find_supported() {
        Ok(Some(found)) => found,
        Ok(None) => {
            eprintln!("no supported adapter is present");
            std::process::exit(2);
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_else(|| "status".into());
    let (dev, model) = find();
    if !model.is_reference() {
        eprintln!("warning: not the {} Warlock is tested with", REFERENCE.name);
    }
    let result = match cmd.as_str() {
        "status" => {
            show(&dev, &model);
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
            let (dev, model) = find();
            show(&dev, &model);
        }
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}
