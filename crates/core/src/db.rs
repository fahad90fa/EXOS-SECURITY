use anyhow::Result;
use once_cell::sync::OnceCell;
use redis::aio::ConnectionManager;
use sqlx::{migrate::Migrator, postgres::PgPoolOptions, PgPool};

static DB: OnceCell<Database> = OnceCell::new();
static REDIS: OnceCell<RedisPool> = OnceCell::new();

// ─── Postgres ────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct Database(pub PgPool);

impl Database {
    pub async fn connect(url: &str, max_conn: u32) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(max_conn)
            .connect(url)
            .await?;
        Ok(Self(pool))
    }

    /// Run pending SQLx migrations.
    pub async fn run_migrations(&self) -> Result<()> {
        let migrator = Migrator::new(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../migrations")).await?;
        migrator.run(&self.0).await?;
        Ok(())
    }

    pub fn pool(&self) -> &PgPool {
        &self.0
    }

    /// Initialise global DB singleton.
    pub async fn init(url: &str, max_conn: u32) -> Result<&'static Database> {
        let db = Self::connect(url, max_conn).await?;
        Ok(DB.get_or_init(|| db))
    }

    pub fn global() -> &'static Database {
        DB.get().expect("Database not initialised")
    }
}

impl std::ops::Deref for Database {
    type Target = PgPool;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// ─── Redis ───────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct RedisPool(pub ConnectionManager);

impl RedisPool {
    pub async fn connect(url: &str) -> Result<Self> {
        let client = redis::Client::open(url)?;
        let mgr = ConnectionManager::new(client).await?;
        Ok(Self(mgr))
    }

    /// Initialise global Redis singleton.
    pub async fn init(url: &str) -> Result<&'static RedisPool> {
        let pool = Self::connect(url).await?;
        Ok(REDIS.get_or_init(|| pool))
    }

    pub fn global() -> &'static RedisPool {
        REDIS.get().expect("Redis not initialised")
    }

    pub fn conn(&self) -> ConnectionManager {
        self.0.clone()
    }
}

impl std::ops::Deref for RedisPool {
    type Target = ConnectionManager;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
