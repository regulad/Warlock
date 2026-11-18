// SPDX-License-Identifier: GPL-2.0-only
//! WinRT's DNS-SD watcher: Windows' push-style feed of DNS-SD services
//! (a `DeviceWatcher` over association endpoint services with the DNS-SD
//! protocol). Does it report Windows' own registrations?
//!
//!     dnssdwatch <service, e.g. _warlocktest._tcp, or * for all> [seconds=30]
//!
//! Prints each added, updated and removed service as it happens.

use std::time::{Duration, Instant};

use windows::Devices::Enumeration::{DeviceInformation, DeviceInformationKind, DeviceInformationUpdate, DeviceWatcher};
use windows::Foundation::{IPropertyValue, TypedEventHandler};
use windows::core::{HSTRING, IInspectable, Interface, Ref};
use windows_collections::{IIterable, IMapView};

/// The DNS-SD protocol's id among association endpoint protocols.
const DNSSD_PROTOCOL: &str = "{4526e8c1-8aac-4153-9b16-55e86ada0e54}";
const PROPERTIES: [&str; 5] = [
    "System.Devices.Dnssd.InstanceName",
    "System.Devices.Dnssd.HostName",
    "System.Devices.Dnssd.PortNumber",
    "System.Devices.IpAddress",
    "System.Devices.Dnssd.TextAttributes",
];

/// A property value as text, for the kinds these properties come in.
fn show(v: &IInspectable) -> String {
    let Ok(p) = v.cast::<IPropertyValue>() else { return "?".into() };
    if let Ok(s) = p.GetString() {
        return s.to_string();
    }
    if let Ok(n) = p.GetUInt32() {
        return n.to_string();
    }
    let mut strings = windows::core::Array::<HSTRING>::new();
    if p.GetStringArray(&mut strings).is_ok() {
        return format!("{:?}", strings.iter().map(|s| s.to_string()).collect::<Vec<_>>());
    }
    "?".into()
}

fn print(what: &str, started: Instant, id: &HSTRING, props: windows::core::Result<IMapView<HSTRING, IInspectable>>) {
    println!("[{:>6.2} s] {what} {id}", started.elapsed().as_secs_f64());
    if let Ok(props) = props {
        for key in PROPERTIES {
            if let Ok(v) = props.Lookup(&HSTRING::from(key)) {
                println!("           {} = {}", key.trim_start_matches("System.Devices."), show(&v));
            }
        }
    }
}

fn main() -> windows::core::Result<()> {
    let mut args = std::env::args().skip(1);
    let service = args.next().expect("usage: dnssdwatch <service, e.g. _warlocktest._tcp> [seconds]");
    let seconds: u64 = args.next().map_or(30, |s| s.parse().expect("seconds"));
    // "*" watches every DNS-SD service Windows knows of.
    let aqs = match service.as_str() {
        "*" => format!("System.Devices.AepService.ProtocolId:={DNSSD_PROTOCOL}"),
        _ => format!(
            "System.Devices.AepService.ProtocolId:={DNSSD_PROTOCOL} AND System.Devices.Dnssd.Domain:=\"local\" \
             AND System.Devices.Dnssd.ServiceName:=\"{service}\""
        ),
    };
    let props: IIterable<HSTRING> = PROPERTIES.iter().map(|p| HSTRING::from(*p)).collect::<Vec<_>>().into();
    let watcher = DeviceInformation::CreateWatcherWithKindAqsFilterAndAdditionalProperties(
        &HSTRING::from(aqs),
        &props,
        DeviceInformationKind::AssociationEndpointService,
    )?;
    let started = Instant::now();
    watcher.Added(&TypedEventHandler::new(move |_: Ref<DeviceWatcher>, info: Ref<DeviceInformation>| {
        if let Some(info) = info.as_ref() {
            print("added", started, &info.Id()?, info.Properties());
        }
        Ok(())
    }))?;
    watcher.Updated(&TypedEventHandler::new(move |_: Ref<DeviceWatcher>, u: Ref<DeviceInformationUpdate>| {
        if let Some(u) = u.as_ref() {
            print("updated", started, &u.Id()?, u.Properties());
        }
        Ok(())
    }))?;
    watcher.Removed(&TypedEventHandler::new(move |_: Ref<DeviceWatcher>, u: Ref<DeviceInformationUpdate>| {
        if let Some(u) = u.as_ref() {
            println!("[{:>6.2} s] removed {}", started.elapsed().as_secs_f64(), u.Id()?);
        }
        Ok(())
    }))?;
    watcher.EnumerationCompleted(&TypedEventHandler::new(move |_: Ref<DeviceWatcher>, _: Ref<IInspectable>| {
        println!("[{:>6.2} s] initial enumeration complete", started.elapsed().as_secs_f64());
        Ok(())
    }))?;
    println!("watching DNS-SD {service} for {seconds} s");
    watcher.Start()?;
    std::thread::sleep(Duration::from_secs(seconds));
    watcher.Stop()?;
    Ok(())
}
