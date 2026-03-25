pub mod format;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum StepStatus {
    Planned,
    InProgress,
    Complete,
    Blocked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedTeamStep {
    pub id: String,
    pub title: String,
    pub description: String,
    pub status: StepStatus,
    pub mitre_technique: Option<String>,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedTeamReport {
    pub generated_at: DateTime<Utc>,
    pub risk_score: u32,
    pub summary: String,
    pub steps: Vec<RedTeamStep>,
}

impl RedTeamReport {
    pub fn new(summary: impl Into<String>) -> Self {
        Self {
            generated_at: Utc::now(),
            risk_score: 0,
            summary: summary.into(),
            steps: Vec::new(),
        }
    }

    pub fn push_step(&mut self, step: RedTeamStep) {
        self.steps.push(step);
        self.risk_score = (self.steps.len() as u32 * 10).min(100);
    }
}
