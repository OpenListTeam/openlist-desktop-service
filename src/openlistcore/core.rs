use super::{
    data::{CoreManager, OpenListStatus, StartBody, StatusInner, VersionResponse},
    process,
};
use anyhow::{Context, Result, anyhow};
use log::{error, info};
use once_cell::sync::Lazy;
use std::{
    fs::File,
    sync::{Arc, Mutex, atomic::Ordering},
};

const SERVICE_NAME: &str = "OpenList Desktop Service";
const SERVER_COMMAND: &str = "server";
const INVALID_PID: i32 = -1;

impl CoreManager {
    pub fn new() -> Self {
        CoreManager {
            openlist_status: StatusInner::new(OpenListStatus::default()),
        }
    }

    pub fn get_version(&self) -> Result<VersionResponse> {
        Ok(VersionResponse {
            service: SERVICE_NAME.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        })
    }

    fn with_status<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&OpenListStatus) -> Result<R>,
    {
        let status = self
            .openlist_status
            .inner
            .lock()
            .map_err(|e| anyhow!("Status lock failed: {}", e))?;
        f(&status)
    }

    fn with_config<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&Option<StartBody>) -> Result<R>,
    {
        self.with_status(|status| {
            let config = status
                .runtime_config
                .lock()
                .map_err(|e| anyhow!("Config lock failed: {}", e))?;
            f(&config)
        })
    }

    pub fn get_status(&self) -> Result<StartBody> {
        self.with_config(|config| match config.as_ref() {
            Some(cfg) => Ok(cfg.clone()),
            None => self.get_default_config(),
        })
    }

    pub fn start(&self) -> Result<()> {
        info!("Starting OpenList service");

        self.stop()?;
        self.cleanup_other_processes()?;

        let config = self.get_runtime_config()?;

        if !std::path::Path::new(&config.bin_path).exists() {
            return Err(anyhow!("OpenList binary not found at: {}", config.bin_path));
        }

        process::ensure_executable_permissions(&config.bin_path).with_context(|| {
            format!("Failed to set execute permissions for: {}", config.bin_path)
        })?;

        let log_file = File::options()
            .create(true)
            .append(true)
            .open(&config.log_file)
            .with_context(|| format!("Failed to open log file: {}", config.log_file))?;

        let pid = process::spawn_process(&config.bin_path, &[SERVER_COMMAND], log_file)
            .with_context(|| format!("Failed to spawn process: {}", config.bin_path))?;

        self.update_process_status(pid as i32, true)?;
        info!("OpenList service started with PID: {}", pid);
        Ok(())
    }

    fn get_runtime_config(&self) -> Result<StartBody> {
        self.with_config(|config| match config.as_ref() {
            Some(cfg) => Ok(cfg.clone()),
            None => {
                let default_config = self.get_default_config()?;
                Ok(default_config)
            }
        })
    }

    fn get_default_config(&self) -> Result<StartBody> {
        let exe_path = std::env::current_exe()
            .map_err(|e| anyhow!("Failed to get current executable path: {}", e))?;

        let exe_dir = exe_path
            .parent()
            .ok_or_else(|| anyhow!("Failed to get executable directory"))?;

        let (binary_name, target_dir) = if cfg!(target_os = "macos") {
            let current_path_str = exe_path.to_string_lossy();

            if current_path_str.contains(
                "/Library/Application Support/io.github.openlistteam.openlist.service.bundle/",
            ) {
                let home = std::env::var("HOME").unwrap_or_else(|_| "/Users/unknown".to_string());
                let config_file = std::path::Path::new(&home)
                    .join("Library/Application Support/io.github.openlistteam.openlist/install_config.json");

                if let Ok(config_content) = std::fs::read_to_string(&config_file) {
                    if let Ok(install_config) =
                        serde_json::from_str::<serde_json::Value>(&config_content)
                    {
                        if let Some(install_dir) = install_config
                            .get("install_directory")
                            .and_then(|v| v.as_str())
                        {
                            let install_path = std::path::Path::new(install_dir);
                            let bin_path = install_path.join("openlist");

                            let home = std::env::var("HOME")
                                .unwrap_or_else(|_| "/Users/unknown".to_string());
                            let log_dir = std::path::Path::new(&home).join("Library/Logs/OpenList");

                            if let Err(e) = std::fs::create_dir_all(&log_dir) {
                                info!(
                                    "Failed to create log directory {}: {}, falling back to install directory",
                                    log_dir.display(),
                                    e
                                );
                                let log_file = install_path.join("openlist.log");
                                let bin_path_abs =
                                    bin_path.canonicalize().unwrap_or_else(|_| bin_path.clone());
                                let log_file_abs =
                                    log_file.canonicalize().unwrap_or_else(|_| log_file.clone());

                                info!("Using stored install directory: {}", install_dir);
                                info!("Default config - Binary path: {}", bin_path_abs.display());
                                info!("Default config - Log file: {}", log_file_abs.display());

                                return Ok(StartBody {
                                    bin_path: bin_path_abs.to_string_lossy().to_string(),
                                    log_file: log_file_abs.to_string_lossy().to_string(),
                                });
                            }

                            let log_file = log_dir.join("openlist.log");
                            let bin_path_abs =
                                bin_path.canonicalize().unwrap_or_else(|_| bin_path.clone());

                            info!("Using stored install directory: {}", install_dir);
                            info!("Default config - Binary path: {}", bin_path_abs.display());
                            info!("Default config - Log file: {}", log_file.display());

                            return Ok(StartBody {
                                bin_path: bin_path_abs.to_string_lossy().to_string(),
                                log_file: log_file.to_string_lossy().to_string(),
                            });
                        }
                    }
                } else {
                    info!("Install config not found at: {}", config_file.display());
                }
                let common_paths = ["/usr/local/bin", "/usr/bin", "/opt/openlist/bin"];

                for path_str in &common_paths {
                    let path = std::path::Path::new(path_str);
                    let openlist_path = path.join("openlist");
                    if openlist_path.exists() {
                        let home =
                            std::env::var("HOME").unwrap_or_else(|_| "/Users/unknown".to_string());
                        let log_dir = std::path::Path::new(&home).join("Library/Logs/OpenList");

                        let log_file = if std::fs::create_dir_all(&log_dir).is_ok() {
                            log_dir.join("openlist.log")
                        } else {
                            info!("Failed to create log directory, using temp directory");
                            std::env::temp_dir().join("openlist.log")
                        };

                        let bin_path_abs = openlist_path
                            .canonicalize()
                            .unwrap_or_else(|_| openlist_path.clone());

                        info!("Found openlist binary at: {}", bin_path_abs.display());
                        info!("Default config - Binary path: {}", bin_path_abs.display());
                        info!("Default config - Log file: {}", log_file.display());

                        return Ok(StartBody {
                            bin_path: bin_path_abs.to_string_lossy().to_string(),
                            log_file: log_file.to_string_lossy().to_string(),
                        });
                    }
                }

                info!("Warning: Could not locate openlist binary, using current directory");
                ("openlist", exe_dir)
            } else {
                ("openlist", exe_dir)
            }
        } else if cfg!(windows) {
            ("openlist.exe", exe_dir)
        } else {
            ("openlist", exe_dir)
        };

        let bin_path = target_dir.join(binary_name);
        let log_file = Self::get_log_file_path(target_dir);

        let bin_path_abs = bin_path.canonicalize().unwrap_or_else(|_| bin_path.clone());

        info!("Default config - Binary path: {}", bin_path_abs.display());
        info!("Default config - Log file: {}", log_file.display());
        info!(
            "Default config - Working directory will be: {}",
            target_dir.display()
        );

        Ok(StartBody {
            bin_path: bin_path_abs.to_string_lossy().to_string(),
            log_file: log_file.to_string_lossy().to_string(),
        })
    }

    fn update_process_status(&self, pid: i32, is_running: bool) -> Result<()> {
        self.with_status(|status| {
            status.running_pid.store(pid, Ordering::Relaxed);
            status.is_running.store(is_running, Ordering::Relaxed);
            Ok(())
        })
    }

    pub fn stop(&self) -> Result<()> {
        let openlist_pid =
            self.with_status(|status| Ok(status.running_pid.load(Ordering::Relaxed)))?;

        if openlist_pid <= 0 {
            info!("No OpenList process is currently running");
            return Ok(());
        }

        info!("Terminating OpenList process with PID: {}", openlist_pid);

        let kill_result = process::kill_process(openlist_pid as u32);
        self.update_process_status(INVALID_PID, false)?;

        match kill_result {
            Ok(_) => info!("Process {} terminated successfully", openlist_pid),
            Err(e) => error!("Failed to terminate process {}: {}", openlist_pid, e),
        }

        Ok(())
    }

    pub fn cleanup_other_processes(&self) -> Result<()> {
        let current_pid = std::process::id();
        let tracked_pid =
            self.with_status(|status| Ok(status.running_pid.load(Ordering::Relaxed) as u32))?;

        let process_pids = process::find_processes("openlist").unwrap_or_default();

        let terminated_count = process_pids
            .into_iter()
            .filter(|&pid| pid != current_pid && (tracked_pid == 0 || pid != tracked_pid))
            .filter(|&pid| match process::kill_process(pid) {
                Ok(_) => {
                    info!("Terminated process {}", pid);
                    true
                }
                Err(e) => {
                    error!("Failed to terminate process {}: {}", pid, e);
                    false
                }
            })
            .count();

        if terminated_count > 0 {
            info!("Terminated {} other OpenList process(es)", terminated_count);
        }

        Ok(())
    }

    pub fn start_with_config(&self, body: StartBody) -> Result<()> {
        info!("Starting OpenList service with configuration");
        self.set_runtime_config(body)?;
        self.stop()?;
        self.start().context("Failed to start OpenList service")
    }

    fn set_runtime_config(&self, config: StartBody) -> Result<()> {
        self.with_status(|status| {
            let mut runtime_config = status
                .runtime_config
                .lock()
                .map_err(|e| anyhow!("Config lock failed: {}", e))?;
            *runtime_config = Some(config);
            Ok(())
        })
    }

    pub fn get_openlist_status(&self) -> Result<serde_json::Value> {
        let is_running =
            self.with_status(|status| Ok(status.is_running.load(Ordering::Relaxed)))?;
        let running_pid =
            self.with_status(|status| Ok(status.running_pid.load(Ordering::Relaxed)))?;
        let config = self.get_status().unwrap_or_else(|_| StartBody::default());

        Ok(serde_json::json!({
            "is_running": is_running,
            "running_pid": running_pid,
            "config": config
        }))
    }

    pub fn start_openlist_service(&self, body: StartBody) -> Result<()> {
        self.start_with_config(body)
    }

    pub fn shutdown_openlist(&self) -> Result<()> {
        self.shutdown()
    }

    pub fn shutdown(&self) -> Result<()> {
        info!("Shutting down OpenList service");

        if let Err(e) = self.stop() {
            error!("Error during main process shutdown: {}", e);
        }

        if let Err(e) = self.cleanup_other_processes() {
            error!("Error during cleanup of other processes: {}", e);
        }

        info!("OpenList service shutdown completed");
        Ok(())
    }

    fn get_log_file_path(fallback_dir: &std::path::Path) -> std::path::PathBuf {
        if cfg!(target_os = "macos") {
            if let Ok(home) = std::env::var("HOME") {
                let log_dir = std::path::Path::new(&home).join("Library/Logs/OpenList");
                if std::fs::create_dir_all(&log_dir).is_ok() {
                    return log_dir.join("openlist.log");
                }
            }
        } else if cfg!(target_os = "linux") {
            if let Ok(home) = std::env::var("HOME") {
                let log_dir = std::path::Path::new(&home).join(".local/share/OpenList");
                if std::fs::create_dir_all(&log_dir).is_ok() {
                    return log_dir.join("openlist.log");
                }
            }
        }

        let log_file = fallback_dir.join("openlist.log");
        if let Ok(test_file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_file)
        {
            drop(test_file);
            return log_file;
        }

        info!("Cannot write to preferred log locations, using temp directory");
        std::env::temp_dir().join("openlist.log")
    }
}

impl Default for CoreManager {
    fn default() -> Self {
        Self::new()
    }
}

pub static CORE_MANAGER: Lazy<Arc<Mutex<CoreManager>>> =
    Lazy::new(|| Arc::new(Mutex::new(CoreManager::default())));
