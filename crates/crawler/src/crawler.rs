//! Main web crawler engine with configurable depth, concurrency, and scope control.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use dashmap::DashSet;
use nexus_scanner::http_client::{HttpClient, HttpClientConfig, ScanRequest};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::{
    parser::{extract_forms, extract_links, parse_robots, parse_sitemap, DiscoveredForm},
    scope::{normalize_url, ScopeChecker},
};

// ─── CrawlerConfig ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrawlerConfig {
    pub max_depth:       u32,
    pub max_urls:        usize,
    pub concurrency:     usize,
    pub timeout_ms:      u64,
    pub user_agent:      String,
    pub follow_redirects: bool,
    pub respect_robots:  bool,
    pub submit_forms:    bool,
    pub auth_cookie:     Option<String>,
    pub scope_patterns:  Vec<String>,
    pub exclude_patterns: Vec<String>,
}

impl Default for CrawlerConfig {
    fn default() -> Self {
        Self {
            max_depth:       10,
            max_urls:        10_000,
            concurrency:     10,
            timeout_ms:      10_000,
            user_agent:      "NexusSentinel/0.1 Crawler".into(),
            follow_redirects: true,
            respect_robots:  false, // security scanners typically ignore robots
            submit_forms:    true,
            auth_cookie:     None,
            scope_patterns:  Vec::new(),
            exclude_patterns: Vec::new(),
        }
    }
}

// ─── CrawlTarget ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct CrawlTarget {
    url:   String,
    depth: u32,
}

// ─── CrawlResult ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CrawlResult {
    pub urls:   Vec<String>,
    pub forms:  Vec<DiscoveredForm>,
    pub errors: Vec<String>,
}

// ─── Crawler ──────────────────────────────────────────────────────────────────

pub struct Crawler {
    config:  CrawlerConfig,
    client:  HttpClient,
    scope:   ScopeChecker,
}

impl Crawler {
    pub fn new(base_url: &str, config: CrawlerConfig) -> Result<Self> {
        let client_cfg = HttpClientConfig {
            timeout_ms:       config.timeout_ms,
            max_concurrency:  config.concurrency,
            user_agent:       config.user_agent.clone(),
            follow_redirects: config.follow_redirects,
            cookie:           config.auth_cookie.clone(),
            ..Default::default()
        };
        let client = HttpClient::new(&client_cfg)?;

        let mut scope = ScopeChecker::new(base_url)?;
        for pat in &config.scope_patterns {
            scope.add_scope_pattern(pat)?;
        }
        for pat in &config.exclude_patterns {
            scope.add_exclude_pattern(pat)?;
        }

        Ok(Self { config, client, scope })
    }

    /// Run the full crawl and return all discovered URLs + forms.
    pub async fn crawl(&self, target_url: &str) -> CrawlResult {
        let mut visited: HashSet<String> = HashSet::new();
        let mut queue:   VecDeque<CrawlTarget> = VecDeque::new();
        let mut all_forms: Vec<DiscoveredForm> = Vec::new();
        let mut errors: Vec<String> = Vec::new();

        queue.push_back(CrawlTarget { url: target_url.to_string(), depth: 0 });

        // Fetch robots.txt first
        let robots_exclusions = self.fetch_robots(target_url).await;

        while let Some(target) = queue.pop_front() {
            if visited.len() >= self.config.max_urls {
                info!("Max URL limit ({}) reached", self.config.max_urls);
                break;
            }

            let norm = normalize_url(&target.url);
            if visited.contains(&norm) { continue; }
            if !self.scope.is_in_scope(&target.url) { continue; }
            if self.config.respect_robots && robots_exclusions.contains(&norm) { continue; }

            visited.insert(norm.clone());
            debug!("[depth={}] crawling {}", target.depth, target.url);

            match self.fetch_page(&target.url).await {
                Ok(body) => {
                    // Extract links
                    let links = extract_links(&body, &target.url);
                    let in_scope = self.scope.filter_urls(links);

                    if target.depth < self.config.max_depth {
                        for url in in_scope {
                            let n = normalize_url(&url);
                            if !visited.contains(&n) {
                                queue.push_back(CrawlTarget {
                                    url,
                                    depth: target.depth + 1,
                                });
                            }
                        }
                    }

                    // Extract and optionally submit forms
                    let forms = extract_forms(&body, &target.url);
                    if self.config.submit_forms {
                        for form in &forms {
                            if let Some(form_url) = self.build_form_url(form) {
                                let n = normalize_url(&form_url);
                                if !visited.contains(&n) {
                                    queue.push_back(CrawlTarget {
                                        url:   form_url,
                                        depth: target.depth + 1,
                                    });
                                }
                            }
                        }
                    }
                    all_forms.extend(forms);
                }
                Err(e) => {
                    errors.push(format!("{}: {}", target.url, e));
                }
            }
        }

        // Also fetch sitemap.xml
        let sitemap_urls = self.fetch_sitemap(target_url).await;
        let filtered = self.scope.filter_urls(sitemap_urls);
        for url in filtered {
            let n = normalize_url(&url);
            if !visited.contains(&n) {
                visited.insert(n);
            }
        }

        info!("Crawl complete: {} URLs discovered", visited.len());

        CrawlResult {
            urls:   visited.into_iter().collect(),
            forms:  all_forms,
            errors,
        }
    }

    async fn fetch_page(&self, url: &str) -> Result<String> {
        let req = ScanRequest::get(url);
        let resp = self.client.send(req).await?;
        Ok(resp.body)
    }

    async fn fetch_robots(&self, base_url: &str) -> HashSet<String> {
        let robots_url = format!("{}/robots.txt",
            base_url.trim_end_matches('/'));

        if let Ok(resp) = self.client.send(ScanRequest::get(&robots_url)).await {
            let (_, disallowed) = parse_robots(&resp.body, base_url);
            disallowed.into_iter()
                .map(|u| normalize_url(&u))
                .collect()
        } else {
            HashSet::new()
        }
    }

    async fn fetch_sitemap(&self, base_url: &str) -> Vec<String> {
        let sitemap_url = format!("{}/sitemap.xml",
            base_url.trim_end_matches('/'));

        if let Ok(resp) = self.client.send(ScanRequest::get(&sitemap_url)).await {
            if resp.status == 200 {
                return parse_sitemap(&resp.body);
            }
        }
        Vec::new()
    }

    fn build_form_url(&self, form: &DiscoveredForm) -> Option<String> {
        if form.method == "GET" {
            // Build URL with default field values
            let params: Vec<String> = form.fields.iter()
                .map(|f| {
                    let val = if f.default_value.is_empty() { "test" } else { &f.default_value };
                    format!("{}={}", f.name, val)
                })
                .collect();
            let query = params.join("&");
            if query.is_empty() {
                Some(form.action.clone())
            } else {
                Some(format!("{}?{}", form.action, query))
            }
        } else {
            // POST forms — just return the action URL
            Some(form.action.clone())
        }
    }
}
