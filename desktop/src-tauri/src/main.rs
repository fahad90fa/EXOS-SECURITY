// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::HashMap;
use std::sync::Arc;
use tauri::{AppHandle, Manager, State};
use tokio::sync::Mutex;
use serde::{Deserialize, Serialize};

// ─── Shared State ───────────────────────────────────────────────────────────

#[derive(Default)]
struct AppState {
    proxy: Arc<Mutex<Option<nexus_proxy::ProxyServer>>>,
    scans: Arc<Mutex<HashMap<String, nexus_core::models::Scan>>>,
    findings: Arc<Mutex<Vec<nexus_core::models::Vulnerability>>>,
}

// ─── Commands ───────────────────────────────────────────────────────────────

// Proxy commands
#[tauri::command]
async fn start_proxy(
    app: AppHandle,
    state: State<'_, AppState>,
    config: ProxyConfig,
) -> Result<String, String> {
    let proxy_config = nexus_proxy::ProxyConfig {
        host: config.host,
        port: config.port,
        intercept_mode: config.intercept_mode,
        record_traffic: true,
        ..Default::default()
    };

    let server = nexus_proxy::ProxyServer::new(proxy_config)
        .map_err(|e| format!("Failed to create proxy server: {}", e))?;

    let mut proxy_state = state.proxy.lock().await;
    *proxy_state = Some(server);

    Ok(format!("Proxy started on {}:{}", config.host, config.port))
}

#[tauri::command]
async fn stop_proxy(state: State<'_, AppState>) -> Result<String, String> {
    let mut proxy_state = state.proxy.lock().await;
    *proxy_state = None;
    Ok("Proxy stopped".to_string())
}

#[tauri::command]
async fn get_proxy_traffic(state: State<'_, AppState>) -> Result<Vec<TrafficItem>, String> {
    let proxy_state = state.proxy.lock().await;
    if let Some(server) = &*proxy_state {
        let storage = server.storage();
        let requests = storage.all_requests();
        let traffic = requests.into_iter().map(|req| {
            TrafficItem {
                id: req.id.to_string(),
                url: req.url,
                method: req.method,
                status: 0, // Would get from response
                timestamp: req.timestamp.timestamp(),
            }
        }).collect();
        Ok(traffic)
    } else {
        Ok(vec![])
    }
}

// Scan commands
#[tauri::command]
async fn start_scan(
    app: AppHandle,
    state: State<'_, AppState>,
    config: ScanConfig,
) -> Result<String, String> {
    let scan_config = nexus_core::models::ScanConfig {
        scan_type: match config.scan_type.as_str() {
            "full" => nexus_core::models::ScanType::Full,
            "active" => nexus_core::models::ScanType::Active,
            "passive" => nexus_core::models::ScanType::Passive,
            _ => nexus_core::models::ScanType::Full,
        },
        include_sqli: config.include_sqli,
        include_xss: config.include_xss,
        include_ssrf: config.include_ssrf,
        ..Default::default()
    };

    let engine = nexus_scanner::ScanEngine::new(scan_config)
        .map_err(|e| format!("Failed to create scan engine: {}", e))?;

    let scan_id = uuid::Uuid::new_v4().to_string();
    let project_id = uuid::Uuid::new_v4();

    // For demo, scan a single URL
    let urls = vec![config.target_url.clone()];
    let (tx, mut rx) = tokio::sync::mpsc::channel(100);

    let handle = tokio::spawn(async move {
        engine.run(project_id, project_id, urls, tx).await;
    });

    // Store scan info
    let scan = nexus_core::models::Scan::new(
        project_id,
        config.target_url.clone(),
        scan_config,
    );

    let mut scans = state.scans.lock().await;
    scans.insert(scan_id.clone(), scan);

    Ok(format!("Scan started: {}", scan_id))
}

#[tauri::command]
async fn get_scan_results(
    state: State<'_, AppState>,
    scan_id: String,
) -> Result<Vec<FindingItem>, String> {
    let findings = state.findings.lock().await;
    let results = findings.iter()
        .filter(|f| f.scan_id.to_string() == scan_id)
        .map(|f| FindingItem {
            id: f.id.to_string(),
            title: format!("{} in {}", f.class, f.parameter),
            severity: format!("{:?}", f.severity),
            url: f.url.clone(),
            description: f.description.clone(),
        })
        .collect();

    Ok(results)
}

// ─── Data Structures ────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct ProxyConfig {
    host: String,
    port: u16,
    intercept_mode: bool,
}

#[derive(Serialize, Deserialize)]
struct ScanConfig {
    target_url: String,
    scan_type: String,
    include_sqli: bool,
    include_xss: bool,
    include_ssrf: bool,
}

#[derive(Serialize, Deserialize)]
struct TrafficItem {
    id: String,
    url: String,
    method: String,
    status: u16,
    timestamp: i64,
}

#[derive(Serialize, Deserialize)]
struct FindingItem {
    id: String,
    title: String,
    severity: String,
    url: String,
    description: String,
}

fn main() {
    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            start_proxy,
            stop_proxy,
            get_proxy_traffic,
            start_scan,
            get_scan_results
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
