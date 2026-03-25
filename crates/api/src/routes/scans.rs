use axum::{extract::Path, routing::get, Json, Router};
use serde_json::json;

pub fn routes() -> Router {
    Router::new()
        .route("/", get(list_scans))
        .route("/:id", get(get_scan))
        .route("/:id/status", get(get_scan_status))
        .route("/:id/results", get(get_scan_results))
}

async fn list_scans() -> Json<serde_json::Value> {
    Json(json!({
        "scans": [],
        "message": "Scan listing not implemented yet"
    }))
}

async fn get_scan(Path(scan_id): Path<String>) -> Json<serde_json::Value> {
    Json(json!({
        "scan_id": scan_id,
        "message": "Scan retrieval not implemented yet"
    }))
}

async fn get_scan_status(Path(scan_id): Path<String>) -> Json<serde_json::Value> {
    Json(json!({
        "scan_id": scan_id,
        "status": "not_implemented",
        "progress": 0
    }))
}

async fn get_scan_results(Path(scan_id): Path<String>) -> Json<serde_json::Value> {
    Json(json!({
        "scan_id": scan_id,
        "vulnerabilities": [],
        "message": "Scan results not implemented yet"
    }))
}
