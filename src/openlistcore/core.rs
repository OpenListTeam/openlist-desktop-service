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

type ProcessInfo = (String, String); // (id, name)

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
        error!("Failed to load process configurations: {e}");
    }
    Mutex::new(manager)
});

impl Default for CoreManager {
    fn default() -> Self {
        Self::new()
    }
}

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
                    .with_context(|| format!("Failed to create config directory: {parent:?}"))?;
            }
            // Initialize with empty JSON array instead of empty file
            std::fs::write(&config_path, "[]")
                .with_context(|| format!("Failed to create config file: {config_path:?}"))?;
            info!("Created new config file at {config_path:?} with empty configuration");
            return Ok(());
        }

        info!("Loading process configurations from {config_path:?}");

        let file = File::open(&config_path)
            .with_context(|| format!("Failed to open config file: {config_path:?}"))?;

        let reader = BufReader::new(file);

        // Parse configuration with fallback for empty or malformed files
        let configs: Vec<ProcessConfig> = match serde_json::from_reader(reader) {
            Ok(configs) => configs,
            Err(e) => {
                warn!("Failed to parse config file: {e}, treating as empty configuration");
                warn!("Config file may be empty or corrupted, starting with zero processes");
                // Re-initialize with valid empty JSON array
                if let Err(write_err) = std::fs::write(&config_path, "[]") {
                    error!("Failed to reset corrupted config file: {write_err}");
                }
                Vec::new()
            }
        };

        let process_manager = self.process_manager.inner.lock();
        let mut processes = process_manager.processes.lock();
        let mut runtime_states = process_manager.runtime_states.lock();

        for config in configs {
            processes.insert(config.id.clone(), config.clone());

            // Initialize runtime state with clean state
            // Process state will be determined by actual process checks
            let runtime = ProcessRuntime::default();

            runtime_states.insert(config.id.clone(), runtime);
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
                .with_context(|| format!("Failed to create config directory: {parent:?}"))?;
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
            .with_context(|| format!("Failed to create config file: {config_path:?}"))?;

        serde_json::to_writer_pretty(file, &configs)
            .with_context(|| format!("Failed to write config file: {config_path:?}"))?;

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
                .join(format!("process_{id}.log"))
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
            max_restart_attempts: request.max_restart_attempts,
            restart_delay_seconds: request.restart_delay_seconds,
            restart_backoff_multiplier: request.restart_backoff_multiplier,
            restart_window_minutes: request.restart_window_minutes,
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
            error!("Failed to save configuration after creating process: {e}");
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
        if let Some(max_restart_attempts) = request.max_restart_attempts {
            config.max_restart_attempts = Some(max_restart_attempts);
        }
        if let Some(restart_delay_seconds) = request.restart_delay_seconds {
            config.restart_delay_seconds = Some(restart_delay_seconds);
        }
        if let Some(restart_backoff_multiplier) = request.restart_backoff_multiplier {
            config.restart_backoff_multiplier = Some(restart_backoff_multiplier);
        }
        if let Some(restart_window_minutes) = request.restart_window_minutes {
            config.restart_window_minutes = Some(restart_window_minutes);
        }
        config.updated_at = get_current_timestamp();

        let updated_config = config.clone();

        drop(processes);
        drop(process_manager);

        if let Err(e) = self.save_config() {
            error!("Failed to save configuration after updating process: {e}");
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
            error!("Failed to save configuration after deleting process: {e}");
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
                    started_at: *runtime.started_at.lock(),
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
            started_at: *runtime.started_at.lock(),
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
        info!("Starting process: {id}");

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
        info!("Stopping process: {id}");

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
            runtime.is_running.store(false, Ordering::Relaxed);
            runtime.running_pid.store(INVALID_PID, Ordering::Relaxed);
            *runtime.started_at.lock() = None;
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

        let start_index = total_lines.saturating_sub(lines_to_fetch);

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

        let (priority_processes, other_processes): (Vec<ProcessInfo>, Vec<ProcessInfo>) = {
            let process_manager = self.process_manager.inner.lock();
            let processes = process_manager.processes.lock();

            let auto_start_processes: Vec<ProcessInfo> = processes
                .iter()
                .filter(|(_, config)| config.auto_start)
                .map(|(id, config)| (id.clone(), config.name.clone()))
                .collect();

            auto_start_processes.into_iter().partition(|(_, name)| {
                name == "single_openlist_core_process" || name == "single_rclone_backend_process"
            })
        };

        let total_processes = priority_processes.len() + other_processes.len();

        if total_processes == 0 {
            info!("No processes configured for auto-start");
            return Ok(());
        }

        info!("Found {total_processes} processes configured for auto-start");

        if !priority_processes.is_empty() {
            info!(
                "Starting priority processes first: {}",
                priority_processes
                    .iter()
                    .map(|(_, name)| name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );

            for (id, name) in priority_processes {
                if let Err(e) = self.start_process(&id) {
                    error!("Failed to auto-start priority process {name} ({id}): {e}");
                } else {
                    info!("Successfully auto-started priority process {name} ({id})");
                }
            }

            info!("Waiting for priority processes to fully initialize...");
            std::thread::sleep(std::time::Duration::from_secs(15));
        }

        if !other_processes.is_empty() {
            info!("Starting remaining {} processes...", other_processes.len());

            for (id, name) in other_processes {
                if let Err(e) = self.start_process(&id) {
                    error!("Failed to auto-start process {name} ({id}): {e}");
                } else {
                    info!("Successfully auto-started process {name} ({id})");
                }
            }
        }

        info!("Auto-start process completed");
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
                error!("Failed to stop process {id}: {e}");
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

    // Auto-restart monitoring and management

    fn should_restart_process(
        config: &ProcessConfig,
        runtime: &ProcessRuntime,
        current_time: u64,
    ) -> bool {
        if !config.auto_restart {
            return false;
        }

        let restart_count = runtime.restart_count.load(Ordering::Relaxed) as u32;

        // Check for rapid crash loop (5+ crashes within 20 seconds)
        {
            let restart_history = runtime.restart_history.lock();
            let rapid_crash_window = 20u64; // 20 seconds
            let rapid_crash_threshold = 5usize;
            let window_start = current_time.saturating_sub(rapid_crash_window);

            let recent_crashes = restart_history
                .iter()
                .filter(|&&timestamp| timestamp >= window_start)
                .count();

            if recent_crashes >= rapid_crash_threshold {
                error!(
                    "Process {} is in rapid crash loop ({} crashes in {} seconds), stopping auto-restart until manual intervention",
                    config.name, recent_crashes, rapid_crash_window
                );
                return false;
            }
        }

        // Check max restart attempts limit
        if let Some(max_attempts) = config.max_restart_attempts {
            if restart_count >= max_attempts {
                warn!(
                    "Process {} has reached max restart attempts ({}/{})",
                    config.name, restart_count, max_attempts
                );
                return false;
            }
        }

        // Check restart window
        if let Some(window_minutes) = config.restart_window_minutes {
            let restart_history = runtime.restart_history.lock();
            let window_seconds = (window_minutes as u64) * 60;
            let window_start = current_time.saturating_sub(window_seconds);

            let restarts_in_window = restart_history
                .iter()
                .filter(|&&timestamp| timestamp >= window_start)
                .count();

            if let Some(max_attempts) = config.max_restart_attempts {
                if restarts_in_window >= max_attempts as usize {
                    warn!(
                        "Process {} has exceeded restart limit ({}/{}) within {}min window",
                        config.name, restarts_in_window, max_attempts, window_minutes
                    );
                    return false;
                }
            }
        }

        // Check cooldown period since last restart
        if let Some(last_restart) = *runtime.last_restart_at.lock() {
            let delay_seconds = config.restart_delay_seconds.unwrap_or(5) as u64;
            let restart_count = runtime.restart_count.load(Ordering::Relaxed) as u32;
            
            // Apply backoff multiplier if configured
            let effective_delay = if let Some(multiplier) = config.restart_backoff_multiplier {
                let backoff_factor = multiplier.powf(restart_count.saturating_sub(1) as f32);
                (delay_seconds as f32 * backoff_factor).min(300.0) as u64 // Cap at 5 minutes
            } else {
                delay_seconds
            };

            let time_since_restart = current_time.saturating_sub(last_restart);
            if time_since_restart < effective_delay {
                return false;
            }
        }

        true
    }

    fn attempt_restart(&mut self, id: &str) -> Result<()> {
        info!("Attempting to restart process: {}", id);

        let process_manager = self.process_manager.inner.lock();
        let processes = process_manager.processes.lock();
        let runtime_states = process_manager.runtime_states.lock();

        let config = processes
            .get(id)
            .ok_or_else(|| anyhow!("Process not found: {}", id))?;

        let runtime = runtime_states
            .get(id)
            .ok_or_else(|| anyhow!("Runtime state not found: {}", id))?;

        // Increment restart counter
        let new_restart_count = runtime.restart_count.fetch_add(1, Ordering::Relaxed) + 1;
        info!(
            "Restarting process {} (attempt {}/{})",
            config.name,
            new_restart_count,
            config
                .max_restart_attempts
                .map(|m| m.to_string())
                .unwrap_or_else(|| "unlimited".to_string())
        );

        let current_time = get_current_timestamp();

        // Update restart history
        {
            let mut history = runtime.restart_history.lock();
            history.push(current_time);
            
            // Keep only recent history (last 100 restarts or within window)
            let history_len = history.len();
            if history_len > 100 {
                history.drain(0..history_len - 100);
            }
        }

        *runtime.last_restart_at.lock() = Some(current_time);

        // Clean up old process if still running
        let old_pid = runtime.running_pid.load(Ordering::Relaxed);
        if old_pid > 0 && is_process_running(old_pid) {
            warn!("Process {} still running with PID {}, terminating", config.name, old_pid);
            if let Err(e) = process::kill_process(old_pid as u32) {
                error!("Failed to kill old process: {}", e);
            }
        }

        // Reset runtime state
        runtime.is_running.store(false, Ordering::Relaxed);
        runtime.running_pid.store(-1, Ordering::Relaxed);

        drop(processes);
        drop(runtime_states);
        drop(process_manager);

        // Start the process
        if let Err(e) = self.start_process(id) {
            error!("Failed to restart process {}: {}", id, e);
            return Err(e);
        }

        info!("Process {} restarted successfully", id);
        Ok(())
    }

    pub fn restart_process(&mut self, id: &str) -> Result<()> {
        info!("Manual restart requested for process: {}", id);

        let process_manager = self.process_manager.inner.lock();
        let runtime_states = process_manager.runtime_states.lock();

        // Reset restart counter for manual restart
        if let Some(runtime) = runtime_states.get(id) {
            runtime.restart_count.store(0, Ordering::Relaxed);
            runtime.restart_history.lock().clear();
        }

        drop(runtime_states);
        drop(process_manager);

        // Stop the process first
        if let Err(e) = self.stop_process(id) {
            warn!("Failed to stop process before restart: {}", e);
        }

        // Small delay to ensure clean shutdown
        std::thread::sleep(std::time::Duration::from_millis(500));

        // Start the process
        self.start_process(id)
    }

    pub fn monitor_processes(&mut self) {
        let process_ids: Vec<String> = {
            let process_manager = self.process_manager.inner.lock();
            let processes = process_manager.processes.lock();
            processes.keys().cloned().collect()
        };

        let current_time = get_current_timestamp();

        for id in process_ids {
            let should_check = {
                let process_manager = self.process_manager.inner.lock();
                let processes = process_manager.processes.lock();
                let runtime_states = process_manager.runtime_states.lock();

                if let (Some(config), Some(runtime)) = (processes.get(&id), runtime_states.get(&id)) {
                    if !config.auto_restart {
                        continue;
                    }

                    let pid = runtime.running_pid.load(Ordering::Relaxed);
                    
                    // Check if process is expected to be running but isn't
                    let was_running = runtime.is_running.load(Ordering::Relaxed);
                    let is_actually_running = pid > 0 && is_process_running(pid);

                    if was_running && !is_actually_running {
                        // Process crashed, consider restart
                        Some((config.clone(), pid))
                    } else if !is_actually_running && pid > 0 {
                        // Process stopped unexpectedly
                        Some((config.clone(), pid))
                    } else {
                        None
                    }
                } else {
                    None
                }
            };

            if let Some((config, old_pid)) = should_check {
                info!(
                    "Process {} (PID: {}) is not running, checking restart policy",
                    config.name, old_pid
                );

                let process_manager = self.process_manager.inner.lock();
                let runtime_states = process_manager.runtime_states.lock();

                if let Some(runtime) = runtime_states.get(&id) {
                    // Mark as not running
                    runtime.is_running.store(false, Ordering::Relaxed);

                    if Self::should_restart_process(&config, runtime, current_time) {
                        drop(runtime_states);
                        drop(process_manager);

                        info!("Auto-restarting process: {}", config.name);
                        if let Err(e) = self.attempt_restart(&id) {
                            error!("Failed to auto-restart process {}: {}", config.name, e);
                        }
                    } else {
                        info!(
                            "Process {} will not be restarted (policy check failed)",
                            config.name
                        );
                    }
                }
            }
        }
    }
}
