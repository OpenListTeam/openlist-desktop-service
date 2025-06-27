#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn main() {
    panic!("This program is not intended to run on this platform.");
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
use anyhow::Result;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

fn get_api_key() -> String {
    std::env::var("PROCESS_MANAGER_API_KEY")
        .unwrap_or_else(|_| "yeM6PCcZGaCpapyBKAbjTp2YAhcku6cUr".to_string())
}

fn get_server_info() -> (String, u16) {
    let host = std::env::var("PROCESS_MANAGER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = std::env::var("PROCESS_MANAGER_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(53211);

    (host, port)
}

fn make_http_request(
    host: &str,
    port: u16,
    method: &str,
    path: &str,
    api_key: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let addr = format!("{host}:{port}");
    let mut stream = TcpStream::connect(&addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;

    let request = format!(
        "{method} {path} HTTP/1.1\r\n\
         Host: {addr}\r\n\
         Authorization: {api_key}\r\n\
         Content-Type: application/json\r\n\
         Connection: close\r\n\
         \r\n"
    );

    stream.write_all(request.as_bytes())?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;

    Ok(response)
}

fn parse_json_response(response: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    if let Some(body_start) = response.find("\r\n\r\n") {
        let body = &response[body_start + 4..];
        if !body.trim().is_empty() {
            return Ok(serde_json::from_str(body)?);
        }
    }
    Err("No JSON body found in response".into())
}

fn is_success_response(response: &str) -> bool {
    response.starts_with("HTTP/1.1 2") || response.starts_with("HTTP/1.0 2")
}

fn stop_all_processes() {
    println!("Stopping all managed processes via HTTP API...");

    let api_key = get_api_key();
    let (host, port) = get_server_info();

    match make_http_request(&host, port, "GET", "/api/v1/processes", &api_key) {
        Ok(response) => {
            if is_success_response(&response) {
                match parse_json_response(&response) {
                    Ok(api_response) => {
                        if let Some(data) = api_response.get("data") {
                            if let Some(processes) = data.as_array() {
                                println!("Found {} managed processes to stop", processes.len());

                                for process in processes {
                                    if let Some(id) = process.get("id").and_then(|v| v.as_str()) {
                                        let stop_path = format!("/api/v1/processes/{id}/stop");

                                        match make_http_request(
                                            &host, port, "POST", &stop_path, &api_key,
                                        ) {
                                            Ok(stop_response) => {
                                                if is_success_response(&stop_response) {
                                                    println!("Successfully stopped process: {id}");
                                                } else {
                                                    eprintln!(
                                                        "Warning: Failed to stop process {id}"
                                                    );
                                                }
                                            }
                                            Err(e) => {
                                                eprintln!(
                                                    "Warning: Failed to send stop request for process {id}: {e}"
                                                );
                                            }
                                        }

                                        std::thread::sleep(Duration::from_millis(100));
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Warning: Failed to parse process list response: {e}");
                    }
                }
            } else {
                eprintln!("Warning: Failed to get process list - server returned error");
            }
        }
        Err(e) => {
            eprintln!("Warning: Failed to connect to service for process list: {e}");
        }
    }

    match make_http_request(&host, port, "POST", "/api/v1/shutdown", &api_key) {
        Ok(response) => {
            if is_success_response(&response) {
                println!("Successfully sent shutdown request to service");
                std::thread::sleep(Duration::from_millis(2000));
            } else {
                eprintln!("Warning: Shutdown request failed");
            }
        }
        Err(e) => {
            eprintln!("Warning: Failed to send shutdown request: {e}");
        }
    }

    println!("All managed processes stopped successfully.");
}

#[cfg(target_os = "macos")]
mod constants {
    pub const SERVICE_ID: &str = "io.github.openlistteam.openlist.service";

    pub fn get_user_bundle_path() -> String {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/Users/unknown".to_string());
        format!("{home}/Library/Application Support/io.github.openlistteam.openlist.service.bundle")
    }

    pub fn get_user_plist_path() -> String {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/Users/unknown".to_string());
        format!("{home}/Library/LaunchAgents/io.github.openlistteam.openlist.service.plist")
    }

    pub fn get_user_config_path() -> String {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/Users/unknown".to_string());
        format!(
            "{home}/Library/Application Support/io.github.openlistteam.openlist/install_config.json"
        )
    }

    pub fn get_service_config_dir() -> String {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/Users/unknown".to_string());
        format!("{home}/Library/Application Support/openlist-service-config")
    }
}

#[cfg(target_os = "linux")]
mod constants {
    pub const SERVICE_NAME: &str = "openlist-desktop-service";

    pub fn get_service_config_dir() -> std::path::PathBuf {
        use std::env;
        let config_dir = [
            env::current_exe()
                .ok()
                .and_then(|exe| exe.parent().map(|p| p.join("openlist-service-config"))),
            Some(std::path::PathBuf::from("openlist-service-config")),
            Some(std::env::temp_dir().join("openlist-service-config")),
        ];
        // the first is not None, use it
        config_dir
            .into_iter()
            .find(|p| p.is_some())
            .flatten()
            .unwrap_or_else(|| std::path::PathBuf::from("/var/lib/openlist-service-config"))
    }
}

#[cfg(windows)]
mod constants {
    pub const SERVICE_NAME: &str = "openlist_desktop_service";
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
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
        println!("Removed {description}: {path}");
    } else {
        println!("{description} not found: {path}");
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn run_service_command(program: &str, args: &[&str], description: &str) {
    use openlist_desktop_service::utils::run_command;

    println!("{description}...");
    if let Err(e) = run_command(program, args) {
        eprintln!("Warning: {description}: {e}");
    }
}

#[cfg(target_os = "macos")]
fn main() -> Result<()> {
    use constants::*;

    println!("Starting macOS service uninstallation...");

    stop_all_processes();

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
    let service_name_with_ext = format!("{service_name}.service");

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

    let unit_file = format!("/etc/systemd/system/{service_name_with_ext}");
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

    let script_file = format!("/etc/init.d/{service_name}");
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
            eprintln!("Failed to connect to service manager: {e}");
            e
        })?;

    let service_access = ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE;
    let service = service_manager
        .open_service(SERVICE_NAME, service_access)
        .map_err(|e| {
            eprintln!("Failed to open service '{SERVICE_NAME}': {e}");
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
                eprintln!("Warning: Failed to send stop command to service: {err}");
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
        eprintln!("Failed to delete service: {e}");
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
