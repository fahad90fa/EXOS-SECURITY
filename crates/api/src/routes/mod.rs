use axum::{routing::get, Router};

pub mod scans;
pub mod projects;
pub mod reports;
pub mod mobile;

pub fn api_routes() -> Router {
    Router::new()
        .route("/health", get(health_check))
        .nest("/api/v1/scans", scans::routes())
        .nest("/api/v1/projects", projects::routes())
        .nest("/api/v1/reports", reports::routes())
        .nest("/api/v1/mobile", mobile::routes())
}

async fn health_check() -> &'static str {
    "Nexus Sentinel API is running"
}
