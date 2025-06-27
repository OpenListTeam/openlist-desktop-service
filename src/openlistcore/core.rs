use crate::openlistcore::process::is_process_running;

use super::{data::*, process};
use anyhow::{Context, Result, anyhow};
use log::{error, info, warn};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::{
    env,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    sync::atomic::Ordering,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

const SERVICE_NAME: &str = "OpenList Desktop Service";
const INVALID_PID: i32 = -1;
const CONFIG_FILE_NAME: &str = "process_configs.json";

pub fn get_config_dir() -> Result<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        if let Ok(programdata) = env::var("PROGRAMDATA") {
            Ok(PathBuf::from(programdata).join("openlist-service-config"))
        } else {
            Ok(PathBuf::from("C:\\ProgramData\\openlist-service-config"))
        }
    }

    #[cfg(target_os = "macos")]
    {
        let home = env::var("HOME").context("Could not determine home directory")?;
        Ok(PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("openlist-service-config"))
    }

    #[cfg(target_os = "linux")]
    {
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
            .ok_or_else(|| anyhow!("Failed to determine config directory"))
            .map(|p| p.unwrap())
    }
}

pub fn get_config_file_path() -> Result<PathBuf> {
    let config_dir = get_config_dir()?;
    Ok(config_dir.join(CONFIG_FILE_NAME))
}

fn get_current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub static CORE_MANAGER: Lazy<Mutex<CoreManager>> = Lazy::new(|| {
    let mut manager = CoreManager::new();
    if let Err(e) = manager.load_config() {
        error!("Failed to load process configurations: {}", e);
    }
    Mutex::new(manager)
});

impl CoreManager {
    pub fn new() -> Self {
        CoreManager {
            process_manager: StatusInner::new(ProcessManager::default()),
        }
    }

    pub fn load_config(&mut self) -> Result<()> {
        let config_path = get_config_file_path()?;

        if !config_path.exists() {
            if let Some(parent) = config_path.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("Failed to create config directory: {:?}", parent))?;
            }
            File::create(&config_path)
                .with_context(|| format!("Failed to create config file: {:?}", config_path))?;
            info!(
                "No configuration file found at {:?}, starting with empty configuration",
                config_path
            );
            return Ok(());
        }

        info!("Loading process configurations from {:?}", config_path);

        let file = File::open(&config_path)
            .with_context(|| format!("Failed to open config file: {:?}", config_path))?;

        let reader = BufReader::new(file);
        let configs: Vec<ProcessConfig> = serde_json::from_reader(reader)
            .with_context(|| format!("Failed to parse config file: {:?}", config_path))?;

        let process_manager = self.process_manager.inner.lock();
        let mut processes = process_manager.processes.lock();
        let mut runtime_states = process_manager.runtime_states.lock();

        for config in configs {
            processes.insert(config.id.clone(), config.clone());
            runtime_states.insert(config.id.clone(), ProcessRuntime::default());
            info!(
                "Loaded process configuration: {} ({})",
                config.name, config.id
            );
        }

        info!(
            "Successfully loaded {} process configurations",
            processes.len()
        );
        Ok(())
    }

    pub fn save_config(&self) -> Result<()> {
        let config_path = get_config_file_path()?;

        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create config directory: {:?}", parent))?;
        }

        let process_manager = self.process_manager.inner.lock();
        let processes = process_manager.processes.lock();

        let configs: Vec<ProcessConfig> = processes.values().cloned().collect();

        info!(
            "Saving {} process configurations to {:?}",
            configs.len(),
            config_path
        );

        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&config_path)
            .with_context(|| format!("Failed to create config file: {:?}", config_path))?;

        serde_json::to_writer_pretty(file, &configs)
            .with_context(|| format!("Failed to write config file: {:?}", config_path))?;

        info!("Successfully saved process configurations");
        Ok(())
    }

    pub fn get_version(&self) -> Result<VersionResponse> {
        Ok(VersionResponse {
            service: SERVICE_NAME.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        })
    }
    pub fn create_process(&mut self, request: CreateProcessRequest) -> Result<ProcessConfig> {
        let process_manager = self.process_manager.inner.lock();
        let mut processes = process_manager.processes.lock();
        let mut runtime_states = process_manager.runtime_states.lock();
        let id = Uuid::new_v4().to_string();
        let timestamp = get_current_timestamp();

        let log_file = if let Some(log_file) = request.log_file {
            log_file
        } else {
            let config_dir = get_config_dir()?;
            config_dir
                .join(format!("process_{}.log", id))
                .to_string_lossy()
                .to_string()
        };

        let config = ProcessConfig {
            id: id.clone(),
            name: request.name,
            bin_path: request.bin_path,
            args: request.args.unwrap_or_default(),
            log_file,
            working_dir: request.working_dir,
            env_vars: request.env_vars,
            auto_restart: request.auto_restart.unwrap_or(false),
            auto_start: request.auto_start.unwrap_or(false),
            run_as_admin: request.run_as_admin.unwrap_or(false),
            created_at: timestamp,
            updated_at: timestamp,
        };

        if !Path::new(&config.bin_path).exists() {
            return Err(anyhow!("Binary not found at: {}", config.bin_path));
        }
        processes.insert(id.clone(), config.clone());
        runtime_states.insert(id.clone(), ProcessRuntime::default());

        drop(processes);
        drop(runtime_states);
        drop(process_manager);

        // Save configuration to disk
        if let Err(e) = self.save_config() {
            error!("Failed to save configuration after creating process: {}", e);
        }

        info!(
            "Created process configuration: {} ({})",
            config.name, config.id
        );
        Ok(config)
    }

    pub fn update_process(
        &mut self,
        id: &str,
        request: UpdateProcessRequest,
    ) -> Result<ProcessConfig> {
        let process_manager = self.process_manager.inner.lock();
        let mut processes = process_manager.processes.lock();

        let config = processes
            .get_mut(id)
            .ok_or_else(|| anyhow!("Process not found: {}", id))?;

        if let Some(name) = request.name {
            config.name = name;
        }
        if let Some(bin_path) = request.bin_path {
            if !Path::new(&bin_path).exists() {
                return Err(anyhow!("Binary not found at: {}", bin_path));
            }
            config.bin_path = bin_path;
        }
        if let Some(args) = request.args {
            config.args = args;
        }
        if let Some(log_file) = request.log_file {
            config.log_file = log_file;
        }
        if let Some(working_dir) = request.working_dir {
            config.working_dir = Some(working_dir);
        }
        if let Some(env_vars) = request.env_vars {
            config.env_vars = Some(env_vars);
        }
        if let Some(auto_restart) = request.auto_restart {
            config.auto_restart = auto_restart;
        }
        if let Some(auto_start) = request.auto_start {
            config.auto_start = auto_start;
        }
        if let Some(run_as_admin) = request.run_as_admin {
            config.run_as_admin = run_as_admin;
        }
        config.updated_at = get_current_timestamp();

        let updated_config = config.clone();

        drop(processes);
        drop(process_manager);

        if let Err(e) = self.save_config() {
            error!("Failed to save configuration after updating process: {}", e);
        }

        info!(
            "Updated process configuration: {} ({})",
            updated_config.name, updated_config.id
        );
        Ok(updated_config)
    }

    pub fn delete_process(&mut self, id: &str) -> Result<()> {
        self.stop_process(id)?;

        let process_manager = self.process_manager.inner.lock();
        let mut processes = process_manager.processes.lock();
        let mut runtime_states = process_manager.runtime_states.lock();
        let config = processes
            .remove(id)
            .ok_or_else(|| anyhow!("Process not found: {}", id))?;
        runtime_states.remove(id);

        drop(processes);
        drop(runtime_states);
        drop(process_manager);

        if let Err(e) = self.save_config() {
            error!("Failed to save configuration after deleting process: {}", e);
        }

        info!(
            "Deleted process configuration: {} ({})",
            config.name, config.id
        );
        Ok(())
    }

    pub fn list_processes(&self) -> Result<Vec<ProcessStatus>> {
        let process_manager = self.process_manager.inner.lock();
        let processes = process_manager.processes.lock();
        let runtime_states = process_manager.runtime_states.lock();

        let mut status_list = Vec::new();

        for (id, config) in processes.iter() {
            if let Some(runtime) = runtime_states.get(id) {
                let status = ProcessStatus {
                    id: id.clone(),
                    name: config.name.clone(),
                    is_running: is_process_running(runtime.running_pid.load(Ordering::Relaxed)),
                    pid: {
                        let pid = runtime.running_pid.load(Ordering::Relaxed);
                        if pid > 0 { Some(pid as u32) } else { None }
                    },
                    started_at: runtime.started_at.lock().clone(),
                    restart_count: runtime.restart_count.load(Ordering::Relaxed) as u32,
                    last_exit_code: {
                        let code = runtime.last_exit_code.load(Ordering::Relaxed);
                        if code != 0 { Some(code) } else { None }
                    },
                    config: config.clone(),
                };
                status_list.push(status);
            }
        }

        Ok(status_list)
    }

    pub fn get_process(&self, id: &str) -> Result<ProcessStatus> {
        let process_manager = self.process_manager.inner.lock();
        let processes = process_manager.processes.lock();
        let runtime_states = process_manager.runtime_states.lock();

        let config = processes
            .get(id)
            .ok_or_else(|| anyhow!("Process not found: {}", id))?;

        let runtime = runtime_states
            .get(id)
            .ok_or_else(|| anyhow!("Runtime state not found: {}", id))?;

        let status = ProcessStatus {
            id: id.to_string(),
            name: config.name.clone(),
            is_running: is_process_running(runtime.running_pid.load(Ordering::Relaxed)),
            pid: {
                let pid = runtime.running_pid.load(Ordering::Relaxed);
                if pid > 0 { Some(pid as u32) } else { None }
            },
            started_at: runtime.started_at.lock().clone(),
            restart_count: runtime.restart_count.load(Ordering::Relaxed) as u32,
            last_exit_code: {
                let code = runtime.last_exit_code.load(Ordering::Relaxed);
                if code != 0 { Some(code) } else { None }
            },
            config: config.clone(),
        };

        Ok(status)
    }

    pub fn start_process(&mut self, id: &str) -> Result<()> {
        info!("Starting process: {}", id);

        let process_manager = self.process_manager.inner.lock();
        let processes = process_manager.processes.lock();
        let runtime_states = process_manager.runtime_states.lock();

        let config = processes
            .get(id)
            .ok_or_else(|| anyhow!("Process not found: {}", id))?;

        let runtime = runtime_states
            .get(id)
            .ok_or_else(|| anyhow!("Runtime state not found: {}", id))?;
        let pid = runtime.running_pid.load(Ordering::Relaxed);

        if is_process_running(pid) {
            return Err(anyhow!("Process {} is already running", config.name));
        }

        if !Path::new(&config.bin_path).exists() {
            return Err(anyhow!("Binary not found at: {}", config.bin_path));
        }

        process::ensure_executable_permissions(&config.bin_path).with_context(|| {
            format!("Failed to set execute permissions for: {}", config.bin_path)
        })?;

        let log_file = File::options()
            .create(true)
            .append(true)
            .open(&config.log_file)
            .with_context(|| format!("Failed to open log file: {}", config.log_file))?; // Spawn process
        let args_strs: Vec<&str> = config.args.iter().map(|s| s.as_str()).collect();
        let pid = process::spawn_process_with_privileges(
            &config.bin_path,
            &args_strs,
            log_file,
            config.run_as_admin,
        )
        .with_context(|| format!("Failed to spawn process: {}", config.bin_path))?;

        runtime.is_running.store(true, Ordering::Relaxed);
        runtime.running_pid.store(pid as i32, Ordering::Relaxed);
        *runtime.started_at.lock() = Some(get_current_timestamp());

        info!("Process {} started with PID: {}", config.name, pid);
        Ok(())
    }

    pub fn stop_process(&mut self, id: &str) -> Result<()> {
        info!("Stopping process: {}", id);

        let process_manager = self.process_manager.inner.lock();
        let processes = process_manager.processes.lock();
        let runtime_states = process_manager.runtime_states.lock();

        let config = processes
            .get(id)
            .ok_or_else(|| anyhow!("Process not found: {}", id))?;

        let runtime = runtime_states
            .get(id)
            .ok_or_else(|| anyhow!("Runtime state not found: {}", id))?;

        let pid = runtime.running_pid.load(Ordering::Relaxed);

        if pid <= 0 {
            warn!("Process {} is not running", config.name);
            return Ok(());
        }

        let kill_result = process::kill_process(pid as u32);

        runtime.is_running.store(false, Ordering::Relaxed);
        runtime.running_pid.store(INVALID_PID, Ordering::Relaxed);
        *runtime.started_at.lock() = None;

        match kill_result {
            Ok(_) => {
                info!(
                    "Process {} (PID: {}) terminated successfully",
                    config.name, pid
                );
                runtime.last_exit_code.store(0, Ordering::Relaxed);
            }
            Err(e) => {
                error!(
                    "Failed to terminate process {} (PID: {}): {}",
                    config.name, pid, e
                );
                runtime.last_exit_code.store(-1, Ordering::Relaxed);
                return Err(anyhow!("Failed to stop process: {}", e));
            }
        }

        Ok(())
    }

    pub fn get_process_logs(&self, id: &str, lines: Option<usize>) -> Result<LogResponse> {
        let process_manager = self.process_manager.inner.lock();
        let processes = process_manager.processes.lock();

        let config = processes
            .get(id)
            .ok_or_else(|| anyhow!("Process not found: {}", id))?;

        if !Path::new(&config.log_file).exists() {
            return Ok(LogResponse {
                id: id.to_string(),
                name: config.name.clone(),
                log_content: String::new(),
                total_lines: 0,
                fetched_lines: 0,
            });
        }

        let file = File::open(&config.log_file)
            .with_context(|| format!("Failed to open log file: {}", config.log_file))?;

        let reader = BufReader::new(file);
        let all_lines: Vec<String> = reader
            .lines()
            .collect::<Result<Vec<_>, _>>()
            .with_context(|| format!("Failed to read log file: {}", config.log_file))?;

        let total_lines = all_lines.len();
        let lines_to_fetch = lines.unwrap_or(100).min(total_lines);

        let start_index = if total_lines > lines_to_fetch {
            total_lines - lines_to_fetch
        } else {
            0
        };

        let log_content = all_lines[start_index..].join("\n");

        Ok(LogResponse {
            id: id.to_string(),
            name: config.name.clone(),
            log_content,
            total_lines,
            fetched_lines: lines_to_fetch,
        })
    }
    pub fn auto_start_processes(&mut self) -> Result<()> {
        info!("Auto-starting configured processes...");

        let process_ids: Vec<String> = {
            let process_manager = self.process_manager.inner.lock();
            let processes = process_manager.processes.lock();
            processes
                .iter()
                .filter(|(_, config)| config.auto_start)
                .map(|(id, _)| id.clone())
                .collect()
        };

        if process_ids.is_empty() {
            info!("No processes configured for auto-start");
            return Ok(());
        }

        info!(
            "Found {} processes configured for auto-start",
            process_ids.len()
        );

        for id in process_ids {
            //check if the process is already running
            if let Err(e) = self.start_process(&id) {
                error!("Failed to auto-start process {}: {}", id, e);
            } else {
                info!("Successfully auto-started process {}", id);
            }
        }

        Ok(())
    }

    pub fn shutdown_all_processes(&mut self) -> Result<()> {
        let process_ids: Vec<String> = {
            let process_manager = self.process_manager.inner.lock();
            let processes = process_manager.processes.lock();
            processes.keys().cloned().collect()
        };

        for id in process_ids {
            if let Err(e) = self.stop_process(&id) {
                error!("Failed to stop process {}: {}", id, e);
            }
        }

        Ok(())
    }

    pub fn get_openlist_status(&self) -> Result<serde_json::Value> {
        let processes = self.list_processes()?;
        Ok(serde_json::json!({
            "processes": processes,
            "total_processes": processes.len(),
            "running_processes": processes.iter().filter(|p| p.is_running).count(),
        }))
    }
}
