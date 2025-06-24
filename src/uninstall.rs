#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn main() {
    panic!("This program is not intended to run on this platform.");
}

#[cfg(unix)]
use anyhow::Result;

use openlist_desktop_service::openlistcore::core::CORE_MANAGER;

fn stop_all_processes() {
    println!("Stopping all managed processes...");
    let mut core_manager = CORE_MANAGER.lock();
    match core_manager.shutdown_all_processes() {
        Ok(_) => println!("All managed processes stopped successfully."),
        Err(e) => {
            eprintln!("Warning: Failed to stop some processes: {}", e);
            println!("Continuing with uninstallation...");
        }
    }
}

#[cfg(target_os = "macos")]
mod constants {
    pub const SERVICE_ID: &str = "io.github.openlistteam.openlist.service";

    pub fn get_user_bundle_path() -> String {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/Users/unknown".to_string());
        format!(
            "{}/Library/Application Support/io.github.openlistteam.openlist.service.bundle",
            home
        )
    }

    pub fn get_user_plist_path() -> String {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/Users/unknown".to_string());
        format!(
            "{}/Library/LaunchAgents/io.github.openlistteam.openlist.service.plist",
            home
        )
    }

    pub fn get_user_config_path() -> String {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/Users/unknown".to_string());
        format!(
            "{}/Library/Application Support/io.github.openlistteam.openlist/install_config.json",
            home
        )
    }

    pub fn get_service_config_dir() -> String {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/Users/unknown".to_string());
        format!(
            "{}/Library/Application Support/openlist-service-config",
            home
        )
    }
}

#[cfg(target_os = "linux")]
mod constants {
    pub const SERVICE_NAME: &str = "openlist-desktop-service";

    pub fn get_service_config_dir() -> std::path::PathBuf {
        use std::env;
        if let Ok(xdg_config) = env::var("XDG_CONFIG_HOME") {
            std::path::PathBuf::from(xdg_config).join("openlist-service-config")
        } else {
            let home = env::var("HOME").unwrap_or_else(|_| "/home/unknown".to_string());
            std::path::PathBuf::from(home)
                .join(".config")
                .join("openlist-service-config")
        }
    }
}

#[cfg(windows)]
mod constants {
    pub const SERVICE_NAME: &str = "openlist_desktop_service";
}

#[cfg(unix)]
fn remove_path_if_exists(path: &str, description: &str, is_dir: bool) -> Result<()> {
    use std::path::Path;

    let path_obj = Path::new(path);
    if path_obj.exists() {
        if is_dir {
            std::fs::remove_dir_all(path)
                .map_err(|e| anyhow::anyhow!("Failed to remove {}: {}", description, e))?;
        } else {
            std::fs::remove_file(path)
                .map_err(|e| anyhow::anyhow!("Failed to remove {}: {}", description, e))?;
        }
        println!("Removed {}: {}", description, path);
    } else {
        println!("{} not found: {}", description, path);
    }
    Ok(())
}

#[cfg(unix)]
fn run_service_command(program: &str, args: &[&str], description: &str) {
    use openlist_desktop_service::utils::run_command;

    println!("{}...", description);
    if let Err(e) = run_command(program, args) {
        eprintln!("Warning: {}: {}", description, e);
    }
}

#[cfg(target_os = "macos")]
fn main() -> Result<()> {
    use constants::*;
    use openlist_desktop_service::utils::uninstall_old_service;

    println!("Starting macOS service uninstallation...");

    stop_all_processes();

    let _ = uninstall_old_service();

    let plist_path = get_user_plist_path();
    let bundle_path = get_user_bundle_path();
    let config_path = get_user_config_path();

    run_service_command("launchctl", &["stop", SERVICE_ID], "Stopping service");
    run_service_command("launchctl", &["unload", &plist_path], "Unloading service");
    remove_path_if_exists(&plist_path, "plist file", false)?;
    remove_path_if_exists(&bundle_path, "bundle directory", true)?;
    remove_path_if_exists(&config_path, "install config file", false)?;

    // Clean up service config directory (contains process_configs.json and service logs)
    let service_config_dir = get_service_config_dir();
    remove_path_if_exists(&service_config_dir, "service config directory", true)?;

    let config_dir = std::path::Path::new(&config_path).parent();
    if let Some(dir) = config_dir {
        let _ = std::fs::remove_dir(dir);
    }

    println!("macOS service uninstallation completed successfully.");
    Ok(())
}

#[cfg(target_os = "linux")]
fn main() -> Result<()> {
    use constants::SERVICE_NAME;

    println!("Starting Linux service uninstallation...");

    stop_all_processes();

    match openlist_desktop_service::utils::detect_linux_init_system() {
        "openrc" => {
            println!("Detected OpenRC init system");
            uninstall_openrc_service(SERVICE_NAME)?;
        }
        _ => {
            println!("Detected systemd init system");
            uninstall_systemd_service(SERVICE_NAME)?;
        }
    }

    // Clean up service config directory (contains process_configs.json and service logs)
    let service_config_dir = constants::get_service_config_dir();
    if service_config_dir.exists() {
        match std::fs::remove_dir_all(&service_config_dir) {
            Ok(_) => println!(
                "Removed service config directory: {}",
                service_config_dir.display()
            ),
            Err(e) => eprintln!(
                "Warning: Failed to remove service config directory {}: {}",
                service_config_dir.display(),
                e
            ),
        }
    } else {
        println!(
            "Service config directory not found: {}",
            service_config_dir.display()
        );
    }

    println!("Linux service uninstallation completed successfully.");
    Ok(())
}

#[cfg(target_os = "linux")]
fn uninstall_systemd_service(service_name: &str) -> Result<()> {
    let service_name_with_ext = format!("{}.service", service_name);

    run_service_command(
        "systemctl",
        &["stop", &service_name_with_ext],
        "Stopping systemd service",
    );
    run_service_command(
        "systemctl",
        &["disable", &service_name_with_ext],
        "Disabling systemd service",
    );

    let unit_file = format!("/etc/systemd/system/{}", service_name_with_ext);
    remove_path_if_exists(&unit_file, "systemd service file", false)?;

    run_service_command("systemctl", &["daemon-reload"], "Reloading systemd daemon");

    Ok(())
}

#[cfg(target_os = "linux")]
fn uninstall_openrc_service(service_name: &str) -> Result<()> {
    run_service_command(
        "rc-service",
        &[service_name, "stop"],
        "Stopping OpenRC service",
    );
    run_service_command(
        "rc-update",
        &["del", service_name, "default"],
        "Removing OpenRC service from default runlevel",
    );

    let script_file = format!("/etc/init.d/{}", service_name);
    remove_path_if_exists(&script_file, "OpenRC service script", false)?;

    Ok(())
}

#[cfg(windows)]
fn main() -> windows_service::Result<()> {
    use constants::SERVICE_NAME;
    use std::{io::Write, thread, time::Duration};
    use windows_service::{
        service::{ServiceAccess, ServiceState},
        service_manager::{ServiceManager, ServiceManagerAccess},
    };

    println!("Starting Windows service uninstallation...");

    stop_all_processes();

    let manager_access = ServiceManagerAccess::CONNECT;
    let service_manager =
        ServiceManager::local_computer(None::<&str>, manager_access).map_err(|e| {
            eprintln!("Failed to connect to service manager: {}", e);
            e
        })?;

    let service_access = ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE;
    let service = service_manager
        .open_service(SERVICE_NAME, service_access)
        .map_err(|e| {
            eprintln!("Failed to open service '{}': {}", SERVICE_NAME, e);
            e
        })?;
    let service_status = service.query_status()?;
    if service_status.current_state != ServiceState::Stopped {
        println!("Stopping service...");
        match service.stop() {
            Ok(_) => {
                println!("Service stop command sent successfully.");
                let mut attempts = 0;
                loop {
                    thread::sleep(Duration::from_millis(500));
                    attempts += 1;

                    match service.query_status() {
                        Ok(status) if status.current_state == ServiceState::Stopped => {
                            println!("Service stopped successfully.");
                            break;
                        }
                        Ok(_) if attempts < 10 => {
                            print!(".");
                            std::io::stdout().flush().unwrap_or(());
                            continue;
                        }
                        Ok(_) => {
                            println!(
                                "\nService is taking longer than expected to stop, but continuing with removal..."
                            );
                            break;
                        }
                        Err(_) => {
                            println!("\nCannot query service status, assuming it has stopped.");
                            break;
                        }
                    }
                }
            }
            Err(err) => {
                eprintln!("Warning: Failed to send stop command to service: {}", err);
                println!(
                    "This may be because the service is already stopped or in an invalid state."
                );
                println!("Continuing with service removal...");
            }
        }
    } else {
        println!("Service was already stopped.");
    }
    println!("Removing service...");
    service.delete().map_err(|e| {
        eprintln!("Failed to delete service: {}", e);
        e
    })?;

    cleanup_config_files();

    println!("Windows service uninstallation completed successfully.");
    println!("Note: Any resource cleanup warnings can be safely ignored.");

    Ok(())
}

#[cfg(windows)]
fn get_config_dir() -> std::path::PathBuf {
    use std::env;
    if let Ok(programdata) = env::var("PROGRAMDATA") {
        std::path::PathBuf::from(programdata).join("openlist-service-config")
    } else {
        std::path::PathBuf::from("C:\\ProgramData\\openlist-service-config")
    }
}

#[cfg(windows)]
fn cleanup_config_files() {
    let config_dir = get_config_dir();

    if config_dir.exists() {
        match std::fs::remove_dir_all(&config_dir) {
            Ok(_) => println!("Removed config directory: {}", config_dir.display()),
            Err(e) => eprintln!(
                "Warning: Failed to remove config directory {}: {}",
                config_dir.display(),
                e
            ),
        }
    } else {
        println!("Config directory not found: {}", config_dir.display());
    }
}
