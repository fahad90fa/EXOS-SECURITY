use std::path::PathBuf;

use axum::{
    extract::Multipart,
    http::StatusCode,
    routing::post,
    Json, Router,
};
use nexus_mobile::analyze_apk;
use serde::Serialize;
use tempfile::NamedTempFile;
use std::io::Write;

#[derive(Debug, Serialize)]
struct MobileAnalyzeResponse {
    status: String,
    risk_score: u32,
    report: nexus_mobile::ApkAnalysisReport,
}

pub fn routes() -> Router {
    Router::new().route("/analyze", post(analyze_mobile_apk))
}

async fn analyze_mobile_apk(mut multipart: Multipart) -> Result<Json<MobileAnalyzeResponse>, (StatusCode, String)> {
    let mut apk_bytes: Option<Vec<u8>> = None;
    let mut apk_name: Option<String> = None;

    while let Some(field) = multipart.next_field().await.map_err(internal_error)? {
        let name = field.name().unwrap_or_default().to_string();
        if name != "file" && name != "apk" {
            continue;
        }

        apk_name = field.file_name().map(|v| v.to_string());
        let data = field.bytes().await.map_err(internal_error)?;
        apk_bytes = Some(data.to_vec());
        break;
    }

    let apk_bytes = apk_bytes.ok_or((StatusCode::BAD_REQUEST, "missing APK file field".to_string()))?;
    let mut temp = NamedTempFile::new().map_err(internal_error)?;
    temp.write_all(&apk_bytes).map_err(internal_error)?;

    let path: PathBuf = temp.path().to_path_buf();
    let report = analyze_apk(&path).map_err(internal_error)?;

    Ok(Json(MobileAnalyzeResponse {
        status: format!("analyzed: {}", apk_name.unwrap_or_else(|| "uploaded.apk".to_string())),
        risk_score: report.risk_score(),
        report,
    }))
}

fn internal_error<E: std::fmt::Display>(err: E) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
}
