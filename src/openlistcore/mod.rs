pub mod core;
mod data;
mod http_api;
mod process;

use self::core::CORE_MANAGER;
use self::http_api::run_ipc_server;
use log::{error, info};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::runtime::Runtime;
use tokio::sync::broadcast;

#[cfg(any(target_os = "macos", target_os = "linux"))]
use crate::utils;

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
        error!("Failed to auto-start processes: {e}");
    } else {
        info!("Auto-start completed successfully");
    }
}

fn ensure_config_loaded() {
    use self::core::CORE_MANAGER;

    info!("Ensuring process configurations are loaded...");
    let mut core_manager = CORE_MANAGER.lock();

    if let Err(e) = core_manager.load_config() {
        error!("Failed to load process configurations: {e}");
    }
}

pub async fn run_service() -> anyhow::Result<()> {
    let shutdown_signal = Arc::new(AtomicBool::new(false));
    let (shutdown_tx, _) = broadcast::channel(1);

    // Register signal handlers for graceful shutdown on Unix-like systems
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let shutdown_signal_clone = shutdown_signal.clone();
        let shutdown_tx_clone = shutdown_tx.clone();

        tokio::spawn(async move {
            let mut sigterm = signal(SignalKind::terminate()).expect("Failed to register SIGTERM");
            let mut sigint = signal(SignalKind::interrupt()).expect("Failed to register SIGINT");

            tokio::select! {
                _ = sigterm.recv() => {
                    info!("Received SIGTERM, initiating graceful shutdown...");
                }
                _ = sigint.recv() => {
                    info!("Received SIGINT, initiating graceful shutdown...");
                }
            }

            shutdown_signal_clone.store(true, Ordering::SeqCst);
            let _ = shutdown_tx_clone.send(());
        });
    }

    // Register Windows service control handler with proper shutdown mechanism
    #[cfg(windows)]
    let status_handle = {
        let shutdown_signal_clone = shutdown_signal.clone();
        let shutdown_tx_clone = shutdown_tx.clone();

        let status_handle = service_control_handler::register(
            "openlist_desktop_service",
            move |event| -> ServiceControlHandlerResult {
                match event {
                    ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                    ServiceControl::Stop => {
                        info!("Service stop requested, initiating graceful shutdown...");
                        shutdown_signal_clone.store(true, Ordering::SeqCst);
                        let _ = shutdown_tx_clone.send(());
                        ServiceControlHandlerResult::NoError
                    }
                    _ => ServiceControlHandlerResult::NotImplemented,
                }
            },
        )?;

        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;

        status_handle
    };

    info!("Starting Service - HTTP API mode");

    // Load configuration immediately before starting any processes
    ensure_config_loaded();

    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        auto_start_core().await;
    });

    // Start process monitoring loop for auto-restart
    let shutdown_signal_monitor = shutdown_signal.clone();
    tokio::spawn(async move {
        info!("Starting process monitoring loop for auto-restart");
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if shutdown_signal_monitor.load(Ordering::SeqCst) {
                        break;
                    }
                    
                    let mut core_manager = CORE_MANAGER.lock();
                    core_manager.monitor_processes();
                }
                else => break,
            }
        }
        
        info!("Process monitoring loop stopped");
    });

    let mut shutdown_rx = shutdown_tx.subscribe();
    let server_handle = tokio::spawn(async move {
        if let Err(err) = run_ipc_server().await {
            error!("HTTP API server error: {err}");
        }
    });

    // Wait for shutdown signal
    let _ = shutdown_rx.recv().await;
    info!("Shutdown signal received, cleaning up...");

    // Shutdown all managed processes
    {
        use self::core::CORE_MANAGER;
        let mut core_manager = CORE_MANAGER.lock();
        if let Err(e) = core_manager.shutdown_all_processes() {
            error!("Failed to shutdown all processes: {e}");
        } else {
            info!("All managed processes shut down successfully");
        }
    }

    // Give server more time to gracefully finish pending requests
    info!("Waiting for HTTP server to finish pending requests...");
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Abort server task
    server_handle.abort();
    info!("HTTP server stopped");

    // Update service status to Stopped on Windows
    #[cfg(windows)]
    {
        info!("Setting Windows service status to Stopped");
        if let Err(e) = status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        }) {
            error!("Failed to set service status to Stopped: {e}");
        } else {
            info!("Service status updated to Stopped successfully");
        }
    }

    info!("Service shutdown completed");
    Ok(())
}

#[cfg(target_os = "windows")]
pub fn stop_service() -> Result<()> {
    info!("stop_service called - this should be handled by service control handler");
    // The service stop is now handled gracefully in run_service()
    // This function is kept for compatibility but should not be called directly
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn stop_service() -> anyhow::Result<()> {
    match utils::detect_linux_init_system() {
        "openrc" => {
            std::process::Command::new("rc-service")
                .args(["openlist-desktop-service", "stop"])
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
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
