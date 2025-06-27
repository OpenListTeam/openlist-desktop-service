use crate::openlistcore::core::CORE_MANAGER;
use crate::openlistcore::data::*;
use anyhow::{Context, Result};
use axum::{
    Router,
    extract::{Query, Request, State},
    http::{Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Json},
    routing::{delete, get, post, put},
};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::{
    env,
    time::{SystemTime, UNIX_EPOCH},
};
use tower::ServiceBuilder;
use tower_http::cors::{Any, CorsLayer};

const DEFAULT_HTTP_SERVER_HOST: &str = "127.0.0.1";
const DEFAULT_HTTP_SERVER_PORT: u16 = 53211;

const DEFAULT_API_KEY: &str = "yeM6PCcZGaCpapyBKAbjTp2YAhcku6cUr";

fn get_api_key() -> String {
    env::var("PROCESS_MANAGER_API_KEY").unwrap_or_else(|_| {
        warn!("Environment variable PROCESS_MANAGER_API_KEY not set, using default API key");
        info!("Recommend setting environment variable in production: set PROCESS_MANAGER_API_KEY=your-secure-api-key");
        DEFAULT_API_KEY.to_string()
    })
}

fn get_server_host() -> String {
    env::var("PROCESS_MANAGER_HOST").unwrap_or_else(|_| DEFAULT_HTTP_SERVER_HOST.to_string())
}

fn get_server_port() -> u16 {
    env::var("PROCESS_MANAGER_PORT")
        .ok()
        .and_then(|port_str| port_str.parse().ok())
        .unwrap_or_else(|| {
            info!(
                "Environment variable PROCESS_MANAGER_PORT not set or invalid, using default port: {DEFAULT_HTTP_SERVER_PORT}",
            );
            DEFAULT_HTTP_SERVER_PORT
        })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
    pub timestamp: u64,
}

#[derive(Debug, Deserialize)]
pub struct LogQueryParams {
    pub lines: Option<usize>,
}

#[derive(Clone)]
pub struct AppState {
    pub api_key: String,
}

async fn auth_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, StatusCode> {
    let auth_header = request
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok());

    match auth_header {
        Some(auth_value) => {
            let api_key = if let Some(stripped) = auth_value.strip_prefix("Bearer ") {
                stripped
            } else {
                auth_value
            };

            if api_key == state.api_key {
                Ok(next.run(request).await)
            } else {
                warn!("Invalid API key provided");
                Err(StatusCode::UNAUTHORIZED)
            }
        }
        None => {
            warn!("Missing Authorization header");
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

fn success_response<T: Serialize>(data: T) -> Json<ApiResponse<T>> {
    Json(ApiResponse {
        success: true,
        data: Some(data),
        error: None,
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    })
}

fn error_response(error: String) -> Json<ApiResponse<()>> {
    Json(ApiResponse {
        success: false,
        data: None,
        error: Some(error),
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    })
}

async fn get_status() -> impl IntoResponse {
    info!("Handling GET /api/v1/status request");

    let core_manager = CORE_MANAGER.lock();

    match core_manager.get_openlist_status() {
        Ok(status_data) => {
            debug!("Status retrieved successfully");
            Json(ApiResponse {
                success: true,
                data: Some(status_data),
                error: None,
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            })
            .into_response()
        }
        Err(err) => {
            error!("Failed to get status: {err}");
            error_response(format!("Failed to get status: {err}")).into_response()
        }
    }
}

async fn get_service_version() -> impl IntoResponse {
    info!("Handling GET /api/v1/version request");

    let core_manager = CORE_MANAGER.lock();

    match core_manager.get_version() {
        Ok(version_data) => {
            debug!("Version retrieved successfully");
            success_response(version_data).into_response()
        }
        Err(err) => {
            error!("Failed to get version: {err}");
            error_response(format!("Failed to get version: {err}")).into_response()
        }
    }
}

async fn create_process_api(Json(payload): Json<CreateProcessRequest>) -> impl IntoResponse {
    info!("Handling POST /api/v1/processes request");

    let mut core_manager = CORE_MANAGER.lock();

    match core_manager.create_process(payload) {
        Ok(config) => {
            info!("Process created successfully: {}", config.name);
            success_response(config).into_response()
        }
        Err(err) => {
            error!("Failed to create process: {err}");
            error_response(format!("Failed to create process: {err}")).into_response()
        }
    }
}

async fn list_processes_api() -> impl IntoResponse {
    info!("Handling GET /api/v1/processes request");

    let core_manager = CORE_MANAGER.lock();

    match core_manager.list_processes() {
        Ok(processes) => {
            debug!("Processes retrieved successfully");
            success_response(processes).into_response()
        }
        Err(err) => {
            error!("Failed to list processes: {err}");
            error_response(format!("Failed to list processes: {err}")).into_response()
        }
    }
}

async fn get_process_api(
    axum::extract::Path(id): axum::extract::Path<String>,
) -> impl IntoResponse {
    info!("Handling GET /api/v1/processes/{id} request");
    let core_manager = CORE_MANAGER.lock();

    match core_manager.get_process(&id) {
        Ok(process) => {
            debug!("Process retrieved successfully: {}", process.name);
            success_response(process).into_response()
        }
        Err(err) => {
            error!("Failed to get process {id}: {err}");
            error_response(format!("Failed to get process: {err}")).into_response()
        }
    }
}

async fn update_process_api(
    axum::extract::Path(id): axum::extract::Path<String>,
    Json(payload): Json<UpdateProcessRequest>,
) -> impl IntoResponse {
    info!("Handling PUT /api/v1/processes/{id} request");

    let mut core_manager = CORE_MANAGER.lock();

    match core_manager.update_process(&id, payload) {
        Ok(config) => {
            info!("Process updated successfully: {}", config.name);
            success_response(config).into_response()
        }
        Err(err) => {
            error!("Failed to update process {id}: {err}");
            error_response(format!("Failed to update process: {err}")).into_response()
        }
    }
}

async fn delete_process_api(
    axum::extract::Path(id): axum::extract::Path<String>,
) -> impl IntoResponse {
    info!("Handling DELETE /api/v1/processes/{id} request");

    let mut core_manager = CORE_MANAGER.lock();

    match core_manager.delete_process(&id) {
        Ok(_) => {
            info!("Process deleted successfully: {id}");
            success_response("Process deleted successfully").into_response()
        }
        Err(err) => {
            error!("Failed to delete process {id}: {err}");
            error_response(format!("Failed to delete process: {err}")).into_response()
        }
    }
}

async fn start_process_api(
    axum::extract::Path(id): axum::extract::Path<String>,
) -> impl IntoResponse {
    info!("Handling POST /api/v1/processes/{id}/start request");

    let mut core_manager = CORE_MANAGER.lock();

    match core_manager.start_process(&id) {
        Ok(_) => {
            info!("Process started successfully: {id}");
            success_response("Process started successfully").into_response()
        }
        Err(err) => {
            error!("Failed to start process {id}: {err}");
            error_response(format!("Failed to start process: {err}")).into_response()
        }
    }
}

async fn stop_process_api(
    axum::extract::Path(id): axum::extract::Path<String>,
) -> impl IntoResponse {
    info!("Handling POST /api/v1/processes/{id}/stop request");

    let mut core_manager = CORE_MANAGER.lock();

    match core_manager.stop_process(&id) {
        Ok(_) => {
            info!("Process stopped successfully: {id}");
            success_response("Process stopped successfully").into_response()
        }
        Err(err) => {
            error!("Failed to stop process {id}: {err}");
            error_response(format!("Failed to stop process: {err}")).into_response()
        }
    }
}

async fn get_process_logs_api(
    axum::extract::Path(id): axum::extract::Path<String>,
    Query(params): Query<LogQueryParams>,
) -> impl IntoResponse {
    info!("Handling GET /api/v1/processes/{id}/logs request");

    let core_manager = CORE_MANAGER.lock();

    match core_manager.get_process_logs(&id, params.lines) {
        Ok(logs) => {
            debug!("Process logs retrieved successfully: {}", logs.name);
            success_response(logs).into_response()
        }
        Err(err) => {
            error!("Failed to get logs for process {id}: {err}");
            error_response(format!("Failed to get process logs: {err}")).into_response()
        }
    }
}

async fn stop_service_api() -> impl IntoResponse {
    info!("Handling POST /api/v1/service/stop request - stopping service");

    {
        let mut core_manager = CORE_MANAGER.lock();
        if let Err(err) = core_manager.shutdown_all_processes() {
            warn!("Failed to gracefully stop all processes: {err}");
        }
    }

    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
        info!("Initiating service stop...");

        #[cfg(target_os = "windows")]
        if let Err(err) = crate::openlistcore::stop_service() {
            error!("Failed to stop Windows service: {err}");
            std::process::exit(1);
        }

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if let Err(err) = crate::openlistcore::stop_service() {
            error!("Failed to stop service: {err}");
        }

        std::process::exit(0);
    });

    info!("Service stop initiated successfully");
    success_response("Service stop initiated successfully").into_response()
}

async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "timestamp": SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }))
}

fn create_router(app_state: AppState) -> Router {
    let protected_routes = Router::new()
        .route("/api/v1/status", get(get_status))
        .route("/api/v1/version", get(get_service_version))
        .route("/api/v1/service/stop", post(stop_service_api))
        .route("/api/v1/processes", get(list_processes_api))
        .route("/api/v1/processes", post(create_process_api))
        .route("/api/v1/processes/:id", get(get_process_api))
        .route("/api/v1/processes/:id", put(update_process_api))
        .route("/api/v1/processes/:id", delete(delete_process_api))
        .route("/api/v1/processes/:id/start", post(start_process_api))
        .route("/api/v1/processes/:id/stop", post(stop_process_api))
        .route("/api/v1/processes/:id/logs", get(get_process_logs_api))
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            auth_middleware,
        ));

    let public_routes = Router::new().route("/health", get(health_check));

    Router::new()
        .merge(protected_routes)
        .merge(public_routes)
        .layer(
            ServiceBuilder::new().layer(
                CorsLayer::new()
                    .allow_origin(Any)
                    .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
                    .allow_headers(Any),
            ),
        )
        .with_state(app_state)
}

pub async fn run_ipc_server() -> Result<()> {
    let api_key = get_api_key();
    let host = get_server_host();
    let port = get_server_port();

    let app_state = AppState {
        api_key: api_key.clone(),
    };

    let app = create_router(app_state);

    let addr = format!("{host}:{port}");
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("Failed to bind to {addr}"))?;
    info!("HTTP API server started successfully, listening on: {addr}");
    info!("API Key: {api_key}");
    info!("Environment variables configuration:");
    info!("  PROCESS_MANAGER_HOST={host} (default: {DEFAULT_HTTP_SERVER_HOST})");
    info!("  PROCESS_MANAGER_PORT={port} (default: {DEFAULT_HTTP_SERVER_PORT})");
    info!("  PROCESS_MANAGER_API_KEY=*** (default: use built-in key)");
    info!("");
    info!("API endpoints:");
    info!("  GET  /health - Health check");
    info!("  GET  /api/v1/status - Get service status");
    info!("  GET  /api/v1/version - Get version information");

    info!("");
    info!("Service management endpoints:");
    info!("  POST /api/v1/service/stop - Stop the entire service");
    info!("  POST /api/v1/service/restart - Restart the entire service");

    info!("");
    info!("Process management endpoints:");
    info!("  GET    /api/v1/processes - List all processes");
    info!("  POST   /api/v1/processes - Create new process");
    info!("  GET    /api/v1/processes/:id - Get process details");
    info!("  PUT    /api/v1/processes/:id - Update process");
    info!("  DELETE /api/v1/processes/:id - Delete process");
    info!("  POST   /api/v1/processes/:id/start - Start process");
    info!("  POST   /api/v1/processes/:id/stop - Stop process");
    info!("  GET    /api/v1/processes/:id/logs - Get process logs");
    info!("");
    info!("Usage examples:");
    info!("  curl -H \"Authorization: {api_key}\" http://{addr}/api/v1/processes",);
    info!("  or");
    info!("  curl -H \"Authorization: Bearer {api_key}\" http://{addr}/api/v1/status");

    axum::serve(listener, app)
        .await
        .context("HTTP server failed to run")?;

    Ok(())
}
