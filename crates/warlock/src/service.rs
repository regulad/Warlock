// SPDX-License-Identifier: GPL-2.0-only
//! Running as a Windows service, and installing as one.
//!
//! The service runs as LocalSystem, starts manually (`sc start Warlock`), and
//! keeps the options it was installed with on its command line.

use std::error::Error;
use std::ffi::OsString;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode, ServiceInfo,
    ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

use crate::{STOP, daemon, logging};

/// The service's name.
pub const NAME: &str = "Warlock";

define_windows_service!(ffi_service_main, service_main);

/// Hands the process to the service manager; returns when the service stops.
pub fn dispatch() -> Result<(), Box<dyn Error>> {
    service_dispatcher::start(NAME, ffi_service_main)?;
    Ok(())
}

fn service_main(_start_args: Vec<OsString>) {
    logging::file();
    if let Err(e) = run_service() {
        tracing::error!("{e}");
    }
}

fn run_service() -> Result<(), Box<dyn Error>> {
    let status = service_control_handler::register(NAME, |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            STOP.store(true, Ordering::Relaxed);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;
    let report = |state, controls_accepted, code| {
        status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted,
            exit_code: ServiceExitCode::Win32(code),
            checkpoint: 0,
            wait_hint: Duration::from_secs(30),
            process_id: None,
        })
    };
    report(ServiceState::Running, ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN, 0)?;
    // The options installed with the service follow "service" on its command line.
    let options: Vec<String> = std::env::args().skip(2).collect();
    let result = daemon::Options::parse(&options).and_then(|o| daemon::run(&o, &STOP));
    if let Err(e) = &result {
        tracing::error!("{e}");
    }
    // ERROR_SERVICE_SPECIFIC_ERROR would need a code of its own; 1 is "failed".
    report(ServiceState::Stopped, ServiceControlAccept::empty(), if result.is_ok() { 0 } else { 1 })?;
    Ok(())
}

/// Registers the service with `options` on its command line. Needs
/// Administrator.
pub fn install(options: &[String]) -> Result<(), Box<dyn Error>> {
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;
    let mut launch_arguments = vec![OsString::from("service")];
    launch_arguments.extend(options.iter().map(OsString::from));
    let info = ServiceInfo {
        name: NAME.into(),
        display_name: "Warlock (AWDL)".into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::OnDemand,
        error_control: ServiceErrorControl::Normal,
        executable_path: std::env::current_exe()?,
        launch_arguments,
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let service = manager.create_service(&info, ServiceAccess::CHANGE_CONFIG)?;
    service.set_description(
        "Apple Wireless Direct Link on a USB Wi-Fi adapter, with a network adapter that carries it for Windows",
    )?;
    let command: Vec<String> = info.launch_arguments.iter().map(|a| a.to_string_lossy().into_owned()).collect();
    println!("installed {NAME}, running {} {}", info.executable_path.display(), command.join(" "));
    println!("start it with `sc start {NAME}`; it logs to %ProgramData%\\Warlock\\warlock.log");
    Ok(())
}

/// Stops the service if it's running, and removes it. Needs Administrator.
pub fn uninstall() -> Result<(), Box<dyn Error>> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service =
        manager.open_service(NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE)?;
    if service.query_status()?.current_state != ServiceState::Stopped {
        service.stop()?;
        let deadline = Instant::now() + Duration::from_secs(30);
        while service.query_status()?.current_state != ServiceState::Stopped && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(250));
        }
    }
    service.delete()?;
    println!("removed {NAME}");
    Ok(())
}
