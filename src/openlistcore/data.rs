use serde::{Deserialize, Serialize};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicI32},
};

#[derive(Default, Debug, Deserialize, Serialize, Clone)]
pub struct StartBody {
    pub bin_path: String,
    pub log_file: String,
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

#[derive(Default, Debug)]
pub struct OpenListStatus {
    pub is_running: Arc<AtomicBool>,
    pub running_pid: Arc<AtomicI32>,
    pub runtime_config: Arc<Mutex<Option<StartBody>>>,
}

pub struct CoreManager {
    pub openlist_status: StatusInner<OpenListStatus>,
}

pub struct StatusInner<T> {
    pub inner: Arc<Mutex<T>>,
}

impl<T> StatusInner<T> {
    pub fn new(inner: T) -> Self {
        StatusInner {
            inner: Arc::new(Mutex::new(inner)),
        }
    }
}
