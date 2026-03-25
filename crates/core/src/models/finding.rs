use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::vulnerability::{Severity, VulnerabilityClass};

/// A `Finding` is the raw detector output — one per payload test.
/// Multiple findings can merge into a single `Vulnerability`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id:         Uuid,
    pub scan_id:    Uuid,
    pub class:      VulnerabilityClass,
    pub severity:   Severity,
    pub confidence: f32,
    pub url:        String,
    pub parameter:  String,
    pub payload:    String,
    pub evidence:   String,
    pub request:    String,   // raw HTTP request
    pub response:   String,   // raw HTTP response
    pub timestamp:  DateTime<Utc>,
    pub detector:   String,   // which detector produced this
    pub extra:      serde_json::Value,
}

impl Finding {
    pub fn new(
        scan_id:   Uuid,
        class:     VulnerabilityClass,
        severity:  Severity,
        url:       impl Into<String>,
        parameter: impl Into<String>,
        payload:   impl Into<String>,
        evidence:  impl Into<String>,
        detector:  impl Into<String>,
    ) -> Self {
        Self {
            id:         Uuid::new_v4(),
            scan_id,
            class,
            severity,
            confidence: 0.9,
            url:        url.into(),
            parameter:  parameter.into(),
            payload:    payload.into(),
            evidence:   evidence.into(),
            request:    String::new(),
            response:   String::new(),
            timestamp:  Utc::now(),
            detector:   detector.into(),
            extra:      serde_json::Value::Null,
        }
    }

    pub fn with_traffic(
        mut self,
        request: impl Into<String>,
        response: impl Into<String>,
    ) -> Self {
        self.request  = request.into();
        self.response = response.into();
        self
    }

    pub fn with_confidence(mut self, c: f32) -> Self {
        self.confidence = c.clamp(0.0, 1.0);
        self
    }
}
