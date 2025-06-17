use crate::openlistcore::core::CORE_MANAGER;
use crate::openlistcore::data::*;
use anyhow::{Context, Result};
use axum::{
    Router,
    extract::{Request, State},
    http::{Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Json},
    routing::{get, post},
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
    env::var("OPENLIST_API_KEY").unwrap_or_else(|_| {
        warn!("Environment variable OPENLIST_API_KEY not set, using default API key");
        info!("Recommend setting environment variable in production: set OPENLIST_API_KEY=your-secure-api-key");
        DEFAULT_API_KEY.to_string()
    })
}

fn get_server_host() -> String {
    env::var("OPENLIST_HOST").unwrap_or_else(|_| DEFAULT_HTTP_SERVER_HOST.to_string())
}

fn get_server_port() -> u16 {
    env::var("OPENLIST_PORT")
        .ok()
        .and_then(|port_str| port_str.parse().ok())
        .unwrap_or_else(|| {
            info!(
                "Environment variable OPENLIST_PORT not set or invalid, using default port: {}",
                DEFAULT_HTTP_SERVER_PORT
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

    let core_manager = match CORE_MANAGER.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            error!("CORE_MANAGER mutex is poisoned: {}", poisoned);
            return error_response("Internal server error: mutex poisoned".to_string())
                .into_response();
        }
    };

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
            error!("Failed to get status: {}", err);
            error_response(format!("Failed to get status: {}", err)).into_response()
        }
    }
}

async fn get_service_version() -> impl IntoResponse {
    info!("Handling GET /api/v1/version request");

    let core_manager = match CORE_MANAGER.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            error!("CORE_MANAGER mutex is poisoned: {}", poisoned);
            return error_response("Internal server error: mutex poisoned".to_string())
                .into_response();
        }
    };

    match core_manager.get_version() {
        Ok(version_data) => {
            debug!("Version retrieved successfully");
            success_response(version_data).into_response()
        }
        Err(err) => {
            error!("Failed to get version: {}", err);
            error_response(format!("Failed to get version: {}", err)).into_response()
        }
    }
}

async fn start_core_api(Json(payload): Json<StartBody>) -> impl IntoResponse {
    info!("Handling POST /api/v1/start request");

    let core_manager = match CORE_MANAGER.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            error!("CORE_MANAGER mutex is poisoned: {}", poisoned);
            return error_response("Internal server error: mutex poisoned".to_string())
                .into_response();
        }
    };

    match core_manager.start_openlist_service(payload) {
        Ok(_) => {
            info!("Core application started successfully");
            success_response("Core application started successfully").into_response()
        }
        Err(err) => {
            error!("Failed to start core application: {}", err);
            error_response(format!("Failed to start core application: {}", err)).into_response()
        }
    }
}

async fn stop_core_api() -> impl IntoResponse {
    info!("Handling POST /api/v1/stop request");

    let core_manager = match CORE_MANAGER.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            error!("CORE_MANAGER mutex is poisoned: {}", poisoned);
            return error_response("Internal server error: mutex poisoned".to_string())
                .into_response();
        }
    };

    match core_manager.shutdown_openlist() {
        Ok(_) => {
            info!("Core application stopped successfully");
            success_response("Core application stopped successfully").into_response()
        }
        Err(err) => {
            error!("Failed to stop core application: {}", err);
            error_response(format!("Failed to stop core application: {}", err)).into_response()
        }
    }
}

async fn stop_service() -> impl IntoResponse {
    info!("Handling POST /api/v1/shutdown request - shutting down entire service");

    if let Ok(core_manager) = CORE_MANAGER.lock() {
        if let Err(err) = core_manager.shutdown_openlist() {
            warn!("Failed to gracefully stop core application: {}", err);
        }
    } else {
        warn!("CORE_MANAGER mutex is poisoned during shutdown");
    }

    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        info!("Initiating service shutdown...");

        #[cfg(target_os = "windows")]
        if let Err(err) = crate::openlistcore::stop_service() {
            error!("Failed to stop Windows service: {}", err);
            std::process::exit(1);
        }

        #[cfg(not(target_os = "windows"))]
        if let Err(err) = crate::openlistcore::stop_service() {
            error!("Failed to stop service: {}", err);
        }

        std::process::exit(0);
    });

    info!("Service shutdown initiated successfully");
    success_response("Service shutdown initiated successfully").into_response()
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
        .route("/api/v1/start", post(start_core_api))
        .route("/api/v1/stop", post(stop_core_api))
        .route("/api/v1/shutdown", post(stop_service))
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

    let addr = format!("{}:{}", host, port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("Failed to bind to {}", addr))?;
    info!(
        "HTTP API server started successfully, listening on: {}",
        addr
    );
    info!("API Key: {}", api_key);
    info!("Environment variables configuration:");
    info!(
        "  OPENLIST_HOST={} (default: {})",
        host, DEFAULT_HTTP_SERVER_HOST
    );
    info!(
        "  OPENLIST_PORT={} (default: {})",
        port, DEFAULT_HTTP_SERVER_PORT
    );
    info!("  OPENLIST_API_KEY=*** (default: use built-in key)");
    info!(
        "  OPENLIST_AUTO_START={} (default: true)",
        std::env::var("OPENLIST_AUTO_START").unwrap_or_else(|_| "true".to_string())
    );
    info!("");
    info!("API endpoints:");
    info!("  GET  /health - Health check");
    info!("  GET  /api/v1/status - Get service status");
    info!("  GET  /api/v1/version - Get version information");
    info!("  POST /api/v1/start - Start core application");
    info!("  POST /api/v1/stop - Stop core application");
    info!("  POST /api/v1/shutdown - Shutdown entire service");
    info!("");
    info!("Usage examples:");
    info!(
        "  curl -H \"Authorization: {}\" http://{}/api/v1/status",
        api_key, addr
    );
    info!("  or");
    info!(
        "  curl -H \"Authorization: Bearer {}\" http://{}/api/v1/status",
        api_key, addr
    );

    axum::serve(listener, app)
        .await
        .context("HTTP server failed to run")?;

    Ok(())
}
