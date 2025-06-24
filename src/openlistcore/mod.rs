pub mod core;
mod data;
mod http_api;
mod process;

pub use core::get_service_log_file_path;

use self::http_api::run_ipc_server;
use log::{error, info};
use tokio::runtime::Runtime;

#[cfg(target_os = "macos")]
use openlist_desktop_service::utils;

#[cfg(windows)]
use std::{ffi::OsString, time::Duration};
#[cfg(windows)]
use windows_service::{
    Result, define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

#[cfg(windows)]
const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

async fn auto_start_core() {
    use self::core::CORE_MANAGER;

    info!("Attempting to auto-start core application...");

    let mut core_manager = CORE_MANAGER.lock();

    if let Err(e) = core_manager.auto_start_processes() {
        error!("Failed to auto-start processes: {}", e);
    } else {
        info!("Auto-start completed successfully");
    }
}

pub async fn run_service() -> anyhow::Result<()> {
    #[cfg(windows)]
    let status_handle = service_control_handler::register(
        "openlist_desktop_service",
        move |event| -> ServiceControlHandlerResult {
            match event {
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                ServiceControl::Stop => std::process::exit(0),
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        },
    )?;
    #[cfg(windows)]
    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    info!("Starting Service - HTTP API mode");

    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        auto_start_core().await;
    });

    if let Err(err) = run_ipc_server().await {
        error!("HTTP API server error: {}", err);
    }

    Ok(())
}

#[cfg(target_os = "windows")]
pub fn stop_service() -> Result<()> {
    let status_handle = service_control_handler::register("openlist_desktop_service", |_| {
        ServiceControlHandlerResult::NoError
    })?;

    status_handle.set_service_status(ServiceStatus {
        service_type: SERVICE_TYPE,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    Ok(())
}

#[cfg(target_os = "linux")]
pub fn stop_service() -> anyhow::Result<()> {
    match openlist_desktop_service::utils::detect_linux_init_system() {
        "openrc" => {
            std::process::Command::new("rc-service")
                .args(&["openlist-desktop-service", "stop"])
                .output()
                .map_err(|e| anyhow::anyhow!("Failed to execute rc-service stop: {}", e))?;
        }
        _ => {
            std::process::Command::new("systemctl")
                .arg("stop")
                .arg("openlist_desktop_service")
                .output()
                .map_err(|e| anyhow::anyhow!("Failed to execute systemctl stop: {}", e))?;
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn stop_service() -> anyhow::Result<()> {
    let _ = utils::run_command(
        "launchctl",
        &["stop", "io.github.openlistteam.openlist.service"],
    );

    Ok(())
}

#[cfg(windows)]
pub fn main() -> Result<()> {
    service_dispatcher::start("openlist_desktop_service", ffi_service_main)
}

#[cfg(not(windows))]
pub fn main() {
    if let Ok(rt) = Runtime::new() {
        rt.block_on(async {
            let _ = run_service().await;
        });
    }
}

#[cfg(windows)]
define_windows_service!(ffi_service_main, my_service_main);

#[cfg(windows)]
pub fn my_service_main(_arguments: Vec<OsString>) {
    if let Ok(rt) = Runtime::new() {
        rt.block_on(async {
            let _ = run_service().await;
        });
    }
}
