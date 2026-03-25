//! nexus-scanner — Sentinel Core Scanner
//!
//! Exposes the multi-class vulnerability detection engine.

pub mod detectors;
pub mod engine;
pub mod http_client;
pub mod payloads;

pub use engine::{findings_to_vulns, ScanEngine, ScanEvent};
pub use http_client::{HttpClient, HttpClientConfig, ScanRequest, ScanResponse};
