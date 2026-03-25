use axum::{routing::get, Json, Router};
use serde_json::json;

pub fn routes() -> Router {
    Router::new()
        .route("/", get(list_projects))
        .route("/:id", get(get_project))
}

async fn list_projects() -> Json<serde_json::Value> {
    Json(json!({
        "projects": [],
        "message": "Project listing not implemented yet"
    }))
}

async fn get_project() -> Json<serde_json::Value> {
    Json(json!({
        "message": "Project retrieval not implemented yet"
    }))
}
