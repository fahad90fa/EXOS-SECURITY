use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id:          Uuid,
    pub name:        String,
    pub description: Option<String>,
    pub target_url:  String,
    pub scope:       Vec<String>,   // regex patterns defining in-scope URLs
    pub tags:        Vec<String>,
    pub created_at:  DateTime<Utc>,
    pub updated_at:  DateTime<Utc>,
    pub owner_id:    Option<Uuid>,
}

impl Project {
    pub fn new(name: impl Into<String>, target_url: impl Into<String>) -> Self {
        let now = Utc::now();
        let url = target_url.into();
        Self {
            id:          Uuid::new_v4(),
            name:        name.into(),
            description: None,
            scope:       vec![url.clone()],
            target_url:  url,
            tags:        Vec::new(),
            created_at:  now,
            updated_at:  now,
            owner_id:    None,
        }
    }

    pub fn is_in_scope(&self, url: &str) -> bool {
        self.scope.iter().any(|pattern| {
            regex::Regex::new(pattern)
                .map(|re| re.is_match(url))
                .unwrap_or(false)
                || url.starts_with(pattern)
        })
    }
}
