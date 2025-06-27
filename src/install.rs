use std::env;
use std::path::PathBuf;

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn main() {
    panic!("This program is not intended to run on this platform.");
}

fn get_service_binary_path() -> anyhow::Result<PathBuf> {
    let binary_name = if cfg!(windows) {
        "openlist-desktop-service.exe"
    } else {
        "openlist-desktop-service"
    };

    let service_binary_path = env::current_exe()
        .map_err(|e| anyhow::anyhow!("Failed to get current executable path: {}", e))?
        .with_file_name(binary_name);

    if !service_binary_path.exists() {
        return Err(anyhow::anyhow!(
            "Service binary not found at: {}. Please ensure the {} binary is in the same directory as this installer.",
            service_binary_path.display(),
            binary_name
        ));
    }

    Ok(service_binary_path)
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use anyhow::Error;
    use openlist_desktop_service::utils::run_command;
    const SERVICE_IDENTIFIER: &str = "io.github.openlistteam.openlist.service";

    fn get_user_bundle_path() -> String {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/Users/unknown".to_string());
        format!("{home}/Library/Application Support/io.github.openlistteam.openlist.service.bundle")
    }

    fn get_user_plist_path() -> String {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/Users/unknown".to_string());
        format!("{home}/Library/LaunchAgents/io.github.openlistteam.openlist.service.plist")
    }

    struct ServicePaths {
        bundle_path: String,
        macos_path: String,
        target_binary_path: String,
        info_plist_path: String,
    }
    impl ServicePaths {
        fn new() -> Self {
            let bundle_path = get_user_bundle_path();
            Self {
                macos_path: format!("{bundle_path}/Contents/MacOS"),
                target_binary_path: format!(
                    "{bundle_path}/Contents/MacOS/openlist-desktop-service"
                ),
                info_plist_path: format!("{bundle_path}/Contents/Info.plist"),
                bundle_path,
            }
        }
    }

    pub fn install() -> Result<(), Error> {
        println!("Starting macOS service installation...");

        let service_binary_path = get_service_binary_path()?;
        println!("Service binary found at: {}", service_binary_path.display());
        let bundle_paths = install_service_bundle(&service_binary_path)?;
        save_install_config(&service_binary_path)?;
        install_launchd_plist()?;
        set_service_permissions(&bundle_paths)?;
        start_launchd_service()?;

        println!("macOS service installation completed successfully");
        Ok(())
    }

    fn install_service_bundle(
        service_binary_path: &std::path::Path,
    ) -> Result<ServicePaths, Error> {
        println!("Installing service bundle...");

        let paths = ServicePaths::new();
        std::fs::create_dir_all(&paths.macos_path)
            .map_err(|e| anyhow::anyhow!("Failed to create bundle directories: {}", e))?;

        std::fs::copy(service_binary_path, &paths.target_binary_path)
            .map_err(|e| anyhow::anyhow!("Failed to copy service binary: {}", e))?;

        std::fs::write(
            &paths.info_plist_path,
            include_str!("files/info.plist.tmpl"),
        )
        .map_err(|e| anyhow::anyhow!("Failed to write Info.plist: {}", e))?;

        println!("Service bundle installed successfully");
        Ok(paths)
    }
    fn install_launchd_plist() -> Result<(), Error> {
        println!("Installing launchd plist...");

        let plist_path = get_user_plist_path();
        let plist_dir = std::path::Path::new(&plist_path).parent().unwrap();

        if !plist_dir.exists() {
            std::fs::create_dir_all(plist_dir)
                .map_err(|e| anyhow::anyhow!("Failed to create plist directory: {}", e))?;
        }

        let bundle_path = get_user_bundle_path();
        let plist_content =
            include_str!("files/launchd.plist.tmpl").replace("{BUNDLE_PATH}", &bundle_path);

        std::fs::write(&plist_path, plist_content)
            .map_err(|e| anyhow::anyhow!("Failed to write plist file: {}", e))?;

        println!("Launchd plist installed successfully");
        Ok(())
    }
    fn set_service_permissions(paths: &ServicePaths) -> Result<(), Error> {
        println!("Setting service permissions...");

        let plist_path = get_user_plist_path();
        let permission_tasks = [
            (
                "chmod",
                vec!["644", &plist_path],
                "Failed to set plist permissions",
            ),
            (
                "chmod",
                vec!["755", &paths.target_binary_path],
                "Failed to set binary permissions",
            ),
            (
                "chmod",
                vec!["755", &paths.bundle_path],
                "Failed to set bundle permissions",
            ),
        ];

        for (cmd, args, error_msg) in permission_tasks {
            run_command(cmd, &args).map_err(|e| anyhow::anyhow!("{}: {}", error_msg, e))?;
        }

        println!("Service permissions set successfully");
        Ok(())
    }
    fn start_launchd_service() -> Result<(), Error> {
        println!("Starting launchd service...");

        let plist_path = get_user_plist_path();

        let _ = run_command("launchctl", &["unload", &plist_path]);

        run_command("launchctl", &["load", &plist_path])
            .map_err(|e| anyhow::anyhow!("Failed to load service: {}", e))?;

        run_command("launchctl", &["start", SERVICE_IDENTIFIER])
            .map_err(|e| anyhow::anyhow!("Failed to start service: {}", e))?;

        println!("Launchd service started successfully");
        Ok(())
    }
    fn save_install_config(service_binary_path: &std::path::Path) -> Result<(), Error> {
        println!("Saving installation configuration...");
        let install_dir = service_binary_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Failed to get installation directory"))?;

        let home = std::env::var("HOME").unwrap_or_else(|_| "/Users/unknown".to_string());
        let config_dir = std::path::Path::new(&home)
            .join("Library/Application Support/io.github.openlistteam.openlist");

        std::fs::create_dir_all(&config_dir)
            .map_err(|e| anyhow::anyhow!("Failed to create config directory: {}", e))?;

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let config = serde_json::json!({
            "install_directory": install_dir.to_string_lossy(),
            "installed_at": timestamp,
            "service_version": env!("CARGO_PKG_VERSION")
        });
        let config_file = config_dir.join("install_config.json");
        std::fs::write(&config_file, serde_json::to_string_pretty(&config).unwrap())
            .map_err(|e| anyhow::anyhow!("Failed to write install config: {}", e))?;
        println!(
            "Installation configuration saved to: {}",
            config_file.display()
        );
        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use anyhow::Error;
    use log::info;
    use openlist_desktop_service::utils::run_command;
    use std::path::Path;

    const SERVICE_NAME: &str = "openlist-desktop-service";

    #[derive(PartialEq)]
    enum InitSystem {
        Systemd,
        OpenRC,
    }

    #[derive(PartialEq)]
    enum ServiceStatus {
        Active = 0,
        Inactive = 1,
        Activating = 2,
        Failed = 3,
        NotFound = 4,
    }

    impl From<i32> for ServiceStatus {
        fn from(code: i32) -> Self {
            match code {
                0 => ServiceStatus::Active,
                1 => ServiceStatus::Inactive,
                2 => ServiceStatus::Activating,
                3 => ServiceStatus::Failed,
                4 => ServiceStatus::NotFound,
                _ => ServiceStatus::NotFound,
            }
        }
    }
    fn detect_init_system() -> InitSystem {
        if openlist_desktop_service::utils::detect_linux_init_system() == "openrc" {
            println!("Detected OpenRC init system");
            InitSystem::OpenRC
        } else {
            println!("Detected systemd init system");
            InitSystem::Systemd
        }
    }

    pub fn install() -> Result<(), Error> {
        println!("Starting Linux service installation for {SERVICE_NAME}");

        let service_binary_path = get_service_binary_path()?;
        println!("Service binary found at: {}", service_binary_path.display());

        let init_system = detect_init_system();

        match init_system {
            InitSystem::Systemd => install_systemd(&service_binary_path),
            InitSystem::OpenRC => install_openrc(&service_binary_path),
        }
    }
    fn install_systemd(service_binary_path: &Path) -> Result<(), Error> {
        match check_systemd_service_status()? {
            ServiceStatus::Active => {
                println!("Service is already running");
                return Ok(());
            }
            ServiceStatus::Inactive | ServiceStatus::Activating | ServiceStatus::Failed => {
                println!("Service exists but is not running, attempting to start...");
                start_existing_systemd_service()?;
                return Ok(());
            }
            ServiceStatus::NotFound => {
                println!("Service not found, creating new systemd service...");
            }
        }

        create_systemd_service_unit_file(service_binary_path)?;
        install_and_start_systemd_service()?;

        println!("systemd service installation completed successfully");
        Ok(())
    }
    fn install_openrc(service_binary_path: &Path) -> Result<(), Error> {
        if check_openrc_service_exists()? {
            if check_openrc_service_running()? {
                println!("OpenRC service is already running");
                return Ok(());
            } else {
                println!("OpenRC service exists but is not running, attempting to start...");
                start_existing_openrc_service()?;
                return Ok(());
            }
        }

        println!("OpenRC service not found, creating new service...");
        create_openrc_service_script(service_binary_path)?;
        install_and_start_openrc_service()?;

        println!("OpenRC service installation completed successfully");
        Ok(())
    }

    fn check_systemd_service_status() -> Result<ServiceStatus, Error> {
        println!("Checking systemd service status for {SERVICE_NAME}");

        let status_output = std::process::Command::new("systemctl")
            .args(["status", &format!("{SERVICE_NAME}.service"), "--no-pager"])
            .output()
            .map_err(|e| anyhow::anyhow!("Failed to execute systemctl status: {}", e))?;

        let exit_code = status_output.status.code().unwrap_or(-1);
        let status = ServiceStatus::from(exit_code);

        let status_description = match status {
            ServiceStatus::Active => "active and running",
            ServiceStatus::Inactive => "inactive (dead)",
            ServiceStatus::Activating => "activating",
            ServiceStatus::Failed => "failed",
            ServiceStatus::NotFound => "not found",
        };
        info!("systemd service status: {status_description} (exit code: {exit_code})");

        Ok(status)
    }

    fn start_existing_systemd_service() -> Result<(), Error> {
        println!("Starting existing systemd service: {SERVICE_NAME}");

        run_command("systemctl", &["start", &format!("{SERVICE_NAME}.service")]).map_err(|e| {
            anyhow::anyhow!(
                "Failed to start existing systemd service {}: {}",
                SERVICE_NAME,
                e
            )
        })
    }

    fn create_systemd_service_unit_file(binary_path: &Path) -> Result<(), Error> {
        let unit_file_path = format!("/etc/systemd/system/{SERVICE_NAME}.service");
        println!("Creating systemd service unit file at: {unit_file_path}");

        let binary_path_str = binary_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Service binary path contains invalid UTF-8"))?;

        let unit_file_content = format!(
            include_str!("files/systemd_service_unit.tmpl"),
            binary_path_str
        );

        std::fs::write(&unit_file_path, unit_file_content).map_err(|e| {
            anyhow::anyhow!(
                "Failed to write systemd service unit file to {}: {}",
                unit_file_path,
                e
            )
        })?;

        println!("systemd service unit file created successfully");
        Ok(())
    }

    fn install_and_start_systemd_service() -> Result<(), Error> {
        println!("Reloading systemd daemon...");
        run_command("systemctl", &["daemon-reload"])
            .map_err(|e| anyhow::anyhow!("Failed to reload systemd daemon: {}", e))?;

        println!("Enabling and starting systemd service: {SERVICE_NAME}");
        run_command("systemctl", &["enable", SERVICE_NAME, "--now"]).map_err(|e| {
            anyhow::anyhow!(
                "Failed to enable and start systemd service {}: {}",
                SERVICE_NAME,
                e
            )
        })?;

        println!("systemd service {SERVICE_NAME} has been enabled");

        run_command("systemctl", &["start", SERVICE_NAME]).map_err(|e| {
            anyhow::anyhow!("Failed to start systemd service {}: {}", SERVICE_NAME, e)
        })?;
        println!("systemd service {SERVICE_NAME} has been started successfully");
        Ok(())
    }

    fn check_openrc_service_exists() -> Result<bool, Error> {
        let script_path = format!("/etc/init.d/{SERVICE_NAME}");
        Ok(Path::new(&script_path).exists())
    }

    fn check_openrc_service_running() -> Result<bool, Error> {
        println!("Checking OpenRC service status for {SERVICE_NAME}");

        let status_output = std::process::Command::new("rc-service")
            .args([SERVICE_NAME, "status"])
            .output()
            .map_err(|e| anyhow::anyhow!("Failed to check OpenRC service status: {}", e))?;

        let is_running = status_output.status.success();
        println!(
            "OpenRC service {} is {}",
            SERVICE_NAME,
            if is_running { "running" } else { "not running" }
        );

        Ok(is_running)
    }

    fn start_existing_openrc_service() -> Result<(), Error> {
        println!("Starting existing OpenRC service: {SERVICE_NAME}");

        run_command("rc-service", &[SERVICE_NAME, "start"]).map_err(|e| {
            anyhow::anyhow!(
                "Failed to start existing OpenRC service {}: {}",
                SERVICE_NAME,
                e
            )
        })
    }

    fn create_openrc_service_script(binary_path: &Path) -> Result<(), Error> {
        let script_path = format!("/etc/init.d/{SERVICE_NAME}");
        println!("Creating OpenRC service script at: {script_path}");

        let binary_path_str = binary_path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("Service binary path contains invalid UTF-8"))?;

        let script_content = include_str!("files/openrc_service_unit.tmpl");
        let unit_file_content = script_content.replace("{SERVICE-BIN}", binary_path_str);

        std::fs::write(&script_path, unit_file_content).map_err(|e| {
            anyhow::anyhow!(
                "Failed to write OpenRC service script to {}: {}",
                script_path,
                e
            )
        })?;

        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(&script_path)
            .map_err(|e| anyhow::anyhow!("Failed to get script metadata: {}", e))?;
        let mut permissions = metadata.permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script_path, permissions)
            .map_err(|e| anyhow::anyhow!("Failed to set script permissions: {}", e))?;

        println!("OpenRC service script created successfully");
        Ok(())
    }

    fn install_and_start_openrc_service() -> Result<(), Error> {
        println!("Adding OpenRC service {SERVICE_NAME} to default runlevel");

        run_command("rc-update", &["add", SERVICE_NAME, "default"]).map_err(|e| {
            anyhow::anyhow!("Failed to add OpenRC service to default runlevel: {}", e)
        })?;

        println!("Starting OpenRC service: {SERVICE_NAME}");
        run_command("rc-service", &[SERVICE_NAME, "start"]).map_err(|e| {
            anyhow::anyhow!("Failed to start OpenRC service {}: {}", SERVICE_NAME, e)
        })?;

        println!("OpenRC service {SERVICE_NAME} has been added to default runlevel and started");
        Ok(())
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::ffi::{OsStr, OsString};
    use windows_service::{
        service::{
            ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceState,
            ServiceType,
        },
        service_manager::{ServiceManager, ServiceManagerAccess},
    };

    const SERVICE_NAME: &str = "openlist_desktop_service";
    const SERVICE_DISPLAY_NAME: &str = "OpenList Desktop Service";
    const SERVICE_DESCRIPTION: &str =
        "OpenList Desktop Service helps to launch openlist application";

    pub fn install() -> windows_service::Result<()> {
        println!("Starting Windows service installation...");

        let service_binary_path = get_service_binary_path().map_err(|_| {
            println!("Failed to get service binary path");
            std::process::exit(1);
        })?;

        println!("Service binary found at: {}", service_binary_path.display());

        let service_manager = create_service_manager()?;

        if let Some(existing_service) = try_open_existing_service(&service_manager)? {
            handle_existing_service(existing_service)?;
            return Ok(());
        }

        create_new_service(&service_manager, service_binary_path)?;
        println!("Service installation completed successfully");
        Ok(())
    }

    fn create_service_manager() -> windows_service::Result<ServiceManager> {
        let manager_access = ServiceManagerAccess::CONNECT
            | ServiceManagerAccess::CREATE_SERVICE
            | ServiceManagerAccess::ENUMERATE_SERVICE;
        ServiceManager::local_computer(None::<&str>, manager_access)
    }

    fn try_open_existing_service(
        service_manager: &ServiceManager,
    ) -> windows_service::Result<Option<windows_service::service::Service>> {
        let service_access = ServiceAccess::QUERY_STATUS
            | ServiceAccess::START
            | ServiceAccess::STOP
            | ServiceAccess::CHANGE_CONFIG;

        match service_manager.open_service(SERVICE_NAME, service_access) {
            Ok(service) => {
                println!("Service already exists, checking status...");
                Ok(Some(service))
            }
            Err(_) => {
                println!("Service does not exist, creating new service...");
                Ok(None)
            }
        }
    }

    fn handle_existing_service(
        service: windows_service::service::Service,
    ) -> windows_service::Result<()> {
        match service.query_status() {
            Ok(status) => {
                println!("Service status: {:?}", status.current_state);

                match status.current_state {
                    ServiceState::Running => {
                        println!("Service is already running");
                        return Ok(());
                    }
                    ServiceState::StartPending => {
                        println!("Service is starting...");
                        return Ok(());
                    }
                    ServiceState::StopPending => {
                        println!("Service is stopping, waiting and then starting...");
                        std::thread::sleep(std::time::Duration::from_millis(1000));
                    }
                    _ => {
                        println!("Starting existing service...");
                    }
                }
                service.start(&Vec::<&OsStr>::new())
            }
            Err(e) => {
                println!("Failed to query service status: {e:?}, attempting to start anyway");
                let _ = service.start(&Vec::<&OsStr>::new());
                Ok(())
            }
        }
    }

    fn create_new_service(
        service_manager: &ServiceManager,
        service_binary_path: PathBuf,
    ) -> windows_service::Result<()> {
        let service_info = ServiceInfo {
            name: OsString::from(SERVICE_NAME),
            display_name: OsString::from(SERVICE_DISPLAY_NAME),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: service_binary_path,
            launch_arguments: vec![],
            dependencies: vec![],
            account_name: None,
            account_password: None,
        };

        println!("Creating service with configuration: {SERVICE_DISPLAY_NAME}");

        let create_access =
            ServiceAccess::CHANGE_CONFIG | ServiceAccess::START | ServiceAccess::QUERY_STATUS;
        let service = service_manager.create_service(&service_info, create_access)?;

        println!("Service created successfully");

        if let Err(e) = service.set_description(SERVICE_DESCRIPTION) {
            println!("Warning: Failed to set service description: {e:?}");
        }

        println!("Starting service...");
        service.start(&Vec::<&OsStr>::new())?;
        println!("Service started successfully");

        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn main() -> anyhow::Result<()> {
    macos::install()
}

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    linux::install()
}

#[cfg(windows)]
fn main() -> windows_service::Result<()> {
    windows::install()
}
