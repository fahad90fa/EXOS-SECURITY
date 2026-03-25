//! HTML and lightweight JS static analysis for link and endpoint extraction.

use scraper::{Html, Selector};
use url::Url;

/// A discovered form ready for submission.
#[derive(Debug, Clone)]
pub struct DiscoveredForm {
    pub action:  String,
    pub method:  String,
    pub fields:  Vec<FormField>,
    pub enctype: String,
}

#[derive(Debug, Clone)]
pub struct FormField {
    pub name:         String,
    pub field_type:   String,
    pub default_value: String,
}

/// Extract all hyperlinks from an HTML document.
pub fn extract_links(html: &str, base_url: &str) -> Vec<String> {
    let document = Html::parse_document(html);
    let mut links = Vec::new();

    let base = Url::parse(base_url).ok();

    // <a href>, <link href>, <area href>
    for attr in &["a[href]", "link[href]", "area[href]"] {
        if let Ok(sel) = Selector::parse(attr) {
            for el in document.select(&sel) {
                if let Some(href) = el.value().attr("href") {
                    if let Some(abs) = resolve_url(href, base.as_ref()) {
                        links.push(abs);
                    }
                }
            }
        }
    }

    // <script src>, <img src>, <iframe src>, <frame src>
    for attr in &["script[src]", "iframe[src]", "frame[src]"] {
        if let Ok(sel) = Selector::parse(attr) {
            for el in document.select(&sel) {
                if let Some(src) = el.value().attr("src") {
                    if let Some(abs) = resolve_url(src, base.as_ref()) {
                        links.push(abs);
                    }
                }
            }
        }
    }

    // <form action>
    if let Ok(sel) = Selector::parse("form[action]") {
        for el in document.select(&sel) {
            if let Some(action) = el.value().attr("action") {
                if let Some(abs) = resolve_url(action, base.as_ref()) {
                    links.push(abs);
                }
            }
        }
    }

    // Extract URLs from inline JavaScript (simple regex approach)
    let js_links = extract_js_urls(html, base.as_ref());
    links.extend(js_links);

    links
}

/// Extract forms from HTML including input fields.
pub fn extract_forms(html: &str, base_url: &str) -> Vec<DiscoveredForm> {
    let document = Html::parse_document(html);
    let base = Url::parse(base_url).ok();
    let mut forms = Vec::new();

    if let Ok(form_sel) = Selector::parse("form") {
        for form_el in document.select(&form_sel) {
            let action = form_el.value().attr("action")
                .and_then(|a| resolve_url(a, base.as_ref()))
                .unwrap_or_else(|| base_url.to_string());
            let method = form_el.value().attr("method")
                .unwrap_or("GET").to_uppercase();
            let enctype = form_el.value().attr("enctype")
                .unwrap_or("application/x-www-form-urlencoded").to_string();

            let mut fields = Vec::new();

            // input elements
            if let Ok(input_sel) = Selector::parse("input, textarea, select") {
                for input in form_el.select(&input_sel) {
                    let name = input.value().attr("name").unwrap_or("").to_string();
                    if name.is_empty() { continue; }
                    let field_type = input.value().attr("type").unwrap_or("text").to_string();
                    let default_value = input.value().attr("value").unwrap_or("").to_string();
                    fields.push(FormField { name, field_type, default_value });
                }
            }

            if !fields.is_empty() {
                forms.push(DiscoveredForm { action, method, fields, enctype });
            }
        }
    }

    forms
}

/// Simple regex-based JS URL extractor (catches fetch(), XHR, and string literals).
fn extract_js_urls(html: &str, base: Option<&Url>) -> Vec<String> {
    let pattern = regex::Regex::new(
        r#"(?:fetch|xhr\.open|axios\.get|axios\.post|url|href|src)\s*[=(,]\s*['"]([^'"]{3,200})['"]"#
    ).unwrap();

    pattern.captures_iter(html)
        .filter_map(|cap| cap.get(1))
        .filter_map(|m| resolve_url(m.as_str(), base))
        .filter(|u| u.starts_with("http://") || u.starts_with("https://") || u.starts_with('/'))
        .collect()
}

fn resolve_url(href: &str, base: Option<&Url>) -> Option<String> {
    // Skip fragments, javascript:, mailto:, data:
    if href.starts_with('#') || href.starts_with("javascript:") ||
       href.starts_with("mailto:") || href.starts_with("data:") ||
       href.is_empty() {
        return None;
    }

    if href.starts_with("http://") || href.starts_with("https://") {
        return Some(href.to_string());
    }

    base.and_then(|b| b.join(href).ok()).map(|u| u.to_string())
}

/// Parse robots.txt and extract disallowed paths (as full URLs).
pub fn parse_robots(content: &str, base_url: &str) -> (Vec<String>, Vec<String>) {
    let base = Url::parse(base_url).ok();
    let mut allowed   = Vec::new();
    let mut disallowed = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if let Some(path) = line.strip_prefix("Allow: ") {
            if let Some(b) = &base {
                if let Ok(u) = b.join(path) {
                    allowed.push(u.to_string());
                }
            }
        } else if let Some(path) = line.strip_prefix("Disallow: ") {
            if let Some(b) = &base {
                if let Ok(u) = b.join(path) {
                    disallowed.push(u.to_string());
                }
            }
        } else if let Some(sitemap) = line.strip_prefix("Sitemap: ") {
            allowed.push(sitemap.trim().to_string());
        }
    }

    (allowed, disallowed)
}

/// Parse sitemap XML and extract URLs.
pub fn parse_sitemap(xml: &str) -> Vec<String> {
    let re = regex::Regex::new(r#"<loc>\s*(https?://[^\s<]+)\s*</loc>"#).unwrap();
    re.captures_iter(xml)
        .filter_map(|c| c.get(1))
        .map(|m| m.as_str().to_string())
        .collect()
}
