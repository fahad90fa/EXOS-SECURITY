use axum::{routing::get, Json, Router};
use serde_json::json;

pub fn routes() -> Router {
    Router::new()
        .route("/", get(list_reports))
        .route("/:id", get(get_report))
}

async fn list_reports() -> Json<serde_json::Value> {
    Json(json!({
        "reports": [],
        "message": "Report listing not implemented yet"
    }))
}

async fn get_report() -> Json<serde_json::Value> {
    Json(json!({
        "message": "Report retrieval not implemented yet"
    }))
}
