//! nexus-crawler — DeepCrawl AI web crawler

pub mod crawler;
pub mod parser;
pub mod scope;

pub use crawler::{CrawlResult, Crawler, CrawlerConfig};
pub use parser::{DiscoveredForm, FormField};
pub use scope::ScopeChecker;
