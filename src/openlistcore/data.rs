use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicI32},
};

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ProcessConfig {
    pub id: String,
    pub name: String,
    pub bin_path: String,
    pub args: Vec<String>,
    pub log_file: String,
    pub working_dir: Option<String>,
    pub env_vars: Option<HashMap<String, String>>,
    pub auto_restart: bool,
    pub auto_start: bool,
    pub run_as_admin: bool,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ProcessStatus {
    pub id: String,
    pub name: String,
    pub is_running: bool,
    pub pid: Option<u32>,
    pub started_at: Option<u64>,
    pub restart_count: u32,
    pub last_exit_code: Option<i32>,
    pub config: ProcessConfig,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CreateProcessRequest {
    pub name: String,
    pub bin_path: String,
    pub args: Option<Vec<String>>,
    pub log_file: Option<String>,
    pub working_dir: Option<String>,
    pub env_vars: Option<HashMap<String, String>>,
    pub auto_restart: Option<bool>,
    pub auto_start: Option<bool>,
    pub run_as_admin: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UpdateProcessRequest {
    pub name: Option<String>,
    pub bin_path: Option<String>,
    pub args: Option<Vec<String>>,
    pub log_file: Option<String>,
    pub working_dir: Option<String>,
    pub env_vars: Option<HashMap<String, String>>,
    pub auto_restart: Option<bool>,
    pub auto_start: Option<bool>,
    pub run_as_admin: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct StartProcessRequest {
    pub id: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct StopProcessRequest {
    pub id: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LogRequest {
    pub id: String,
    pub lines: Option<usize>, // Number of lines to fetch from end
    pub from_timestamp: Option<u64>,
    pub to_timestamp: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct LogResponse {
    pub id: String,
    pub name: String,
    pub log_content: String,
    pub total_lines: usize,
    pub fetched_lines: usize,
}

#[derive(Deserialize, Serialize)]
pub struct JsonResponse<T: Serialize> {
    pub code: u64,
    pub msg: String,
    pub data: Option<T>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct VersionResponse {
    pub service: String,
    pub version: String,
}

#[derive(Debug)]
pub struct ProcessRuntime {
    pub is_running: Arc<AtomicBool>,
    pub running_pid: Arc<AtomicI32>,
    pub started_at: Arc<Mutex<Option<u64>>>,
    pub restart_count: Arc<AtomicI32>,
    pub last_exit_code: Arc<AtomicI32>,
}

impl Default for ProcessRuntime {
    fn default() -> Self {
        Self {
            is_running: Arc::new(AtomicBool::new(false)),
            running_pid: Arc::new(AtomicI32::new(-1)),
            started_at: Arc::new(Mutex::new(None)),
            restart_count: Arc::new(AtomicI32::new(0)),
            last_exit_code: Arc::new(AtomicI32::new(0)),
        }
    }
}

#[derive(Default, Debug)]
pub struct ProcessManager {
    pub processes: Arc<Mutex<HashMap<String, ProcessConfig>>>,
    pub runtime_states: Arc<Mutex<HashMap<String, ProcessRuntime>>>,
}

pub struct CoreManager {
    pub process_manager: StatusInner<ProcessManager>,
}

pub struct StatusInner<T> {
    pub inner: Mutex<T>,
}

impl<T> StatusInner<T> {
    pub fn new(inner: T) -> Self {
        StatusInner {
            inner: Mutex::new(inner),
        }
    }
}
