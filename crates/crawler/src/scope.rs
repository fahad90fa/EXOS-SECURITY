//! Scope management — determines if a URL is in-scope for crawling.

use url::Url;

#[derive(Debug, Clone)]
pub struct ScopeChecker {
    base_url:      Url,
    /// Additional regex patterns that are in-scope
    scope_patterns: Vec<regex::Regex>,
    /// Explicit out-of-scope patterns
    exclude_patterns: Vec<regex::Regex>,
}

impl ScopeChecker {
    pub fn new(base_url: &str) -> anyhow::Result<Self> {
        let base = Url::parse(base_url)?;
        Ok(Self {
            base_url:         base,
            scope_patterns:   Vec::new(),
            exclude_patterns: Vec::new(),
        })
    }

    pub fn add_scope_pattern(&mut self, pattern: &str) -> anyhow::Result<()> {
        self.scope_patterns.push(regex::Regex::new(pattern)?);
        Ok(())
    }

    pub fn add_exclude_pattern(&mut self, pattern: &str) -> anyhow::Result<()> {
        self.exclude_patterns.push(regex::Regex::new(pattern)?);
        Ok(())
    }

    pub fn is_in_scope(&self, url: &str) -> bool {
        let parsed = match Url::parse(url) {
            Ok(u) => u,
            Err(_) => return false,
        };

        // Must be http or https
        if parsed.scheme() != "http" && parsed.scheme() != "https" {
            return false;
        }

        // Must have same host
        let same_host = parsed.host_str() == self.base_url.host_str();

        // Check explicit exclusions first
        for pat in &self.exclude_patterns {
            if pat.is_match(url) {
                return false;
            }
        }

        // Check additional scope patterns
        if !self.scope_patterns.is_empty() {
            return self.scope_patterns.iter().any(|p| p.is_match(url));
        }

        same_host
    }

    /// Filter a list of URLs to those in scope, deduped.
    pub fn filter_urls(&self, urls: Vec<String>) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        urls.into_iter()
            .filter(|u| self.is_in_scope(u))
            .filter(|u| seen.insert(normalize_url(u)))
            .collect()
    }

    pub fn base_origin(&self) -> String {
        format!("{}://{}", self.base_url.scheme(), self.base_url.host_str().unwrap_or(""))
    }
}

/// Strip fragment and normalize trailing slash for deduplication.
pub fn normalize_url(url: &str) -> String {
    if let Ok(mut parsed) = Url::parse(url) {
        parsed.set_fragment(None);
        let s = parsed.to_string();
        if s.ends_with('/') && parsed.path() == "/" {
            s
        } else {
            s.trim_end_matches('/').to_string()
        }
    } else {
        url.to_string()
    }
}
