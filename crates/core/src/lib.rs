//! nexus-core — shared types, database, configuration, and utilities
//! used by every other crate in the workspace.

pub mod config;
pub mod db;
pub mod error;
pub mod models;
pub mod utils;

pub use config::AppConfig;
pub use db::{Database, RedisPool};
pub use error::{Error, Result};
