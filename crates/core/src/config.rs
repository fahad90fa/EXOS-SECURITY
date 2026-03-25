use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};

static INSTANCE: OnceCell<AppConfig> = OnceCell::new();

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    // ── Server ──────────────────────────────────────────────────────────
    pub api_host:  String,
    pub api_port:  u16,
    pub proxy_host: String,
    pub proxy_port: u16,

    // ── Database ────────────────────────────────────────────────────────
    pub database_url:  String,
    pub redis_url:     String,
    pub db_pool_max:   u32,

    // ── Security ────────────────────────────────────────────────────────
    pub jwt_secret:    String,
    pub jwt_expiry_h:  u64,
    pub ca_cert_path:  Option<String>,
    pub ca_key_path:   Option<String>,

    // ── OAST ────────────────────────────────────────────────────────────
    pub oast_domain:   String,
    pub oast_http_port: u16,
    pub oast_dns_port:  u16,

    // ── AI service ──────────────────────────────────────────────────────
    pub ai_service_url: String,

    // ── Scanning ────────────────────────────────────────────────────────
    pub scan_concurrency: usize,
    pub scan_timeout_ms:  u64,
    pub scan_rate_limit:  u32,   // requests/second

    // ── Notifications ───────────────────────────────────────────────────
    pub slack_webhook:    Option<String>,
    pub discord_webhook:  Option<String>,

    // ── Telemetry ───────────────────────────────────────────────────────
    pub log_level: String,
    pub enable_telemetry: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            api_host:         "0.0.0.0".into(),
            api_port:         8000,
            proxy_host:       "0.0.0.0".into(),
            proxy_port:       8080,
            database_url:     "postgres://nexus:nexus@localhost:5432/nexusdb".into(),
            redis_url:        "redis://localhost:6379".into(),
            db_pool_max:      20,
            jwt_secret:       "CHANGE_ME_IN_PRODUCTION".into(),
            jwt_expiry_h:     24,
            ca_cert_path:     None,
            ca_key_path:      None,
            oast_domain:      "oast.localhost".into(),
            oast_http_port:   4444,
            oast_dns_port:    5353,
            ai_service_url:   "http://localhost:8001".into(),
            scan_concurrency: 20,
            scan_timeout_ms:  10_000,
            scan_rate_limit:  100,
            slack_webhook:    None,
            discord_webhook:  None,
            log_level:        "info".into(),
            enable_telemetry: false,
        }
    }
}

impl AppConfig {
    /// Load configuration from environment variables (with `.env` file support).
    pub fn load() -> anyhow::Result<Self> {
        dotenvy::dotenv().ok();

        let cfg = config::Config::builder()
            .set_default("api_host",        "0.0.0.0")?
            .set_default("api_port",        8000)?
            .set_default("proxy_host",      "0.0.0.0")?
            .set_default("proxy_port",      8080)?
            .set_default("database_url",    "postgres://nexus:nexus@localhost:5432/nexusdb")?
            .set_default("redis_url",       "redis://localhost:6379")?
            .set_default("db_pool_max",     20)?
            .set_default("jwt_secret",      "CHANGE_ME_IN_PRODUCTION")?
            .set_default("jwt_expiry_h",    24)?
            .set_default("oast_domain",     "oast.localhost")?
            .set_default("oast_http_port",  4444)?
            .set_default("oast_dns_port",   5353)?
            .set_default("ai_service_url",  "http://localhost:8001")?
            .set_default("scan_concurrency", 20)?
            .set_default("scan_timeout_ms", 10_000)?
            .set_default("scan_rate_limit", 100)?
            .set_default("log_level",       "info")?
            .set_default("enable_telemetry", false)?
            .add_source(
                config::Environment::default()
                    .prefix("NEXUS")
                    .separator("__"),
            )
            .build()?;

        Ok(cfg.try_deserialize()?)
    }

    /// Returns the global singleton (panics if not yet initialised).
    pub fn global() -> &'static AppConfig {
        INSTANCE.get().expect("AppConfig not initialised — call AppConfig::init() first")
    }

    /// Initialise the global singleton. Should be called once at startup.
    pub fn init() -> anyhow::Result<&'static AppConfig> {
        let cfg = Self::load()?;
        Ok(INSTANCE.get_or_init(|| cfg))
    }
}
