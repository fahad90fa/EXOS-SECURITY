//! Built-in wordlists for directory, parameter, and credential fuzzing.

/// Common web directories and files.
pub const COMMON_PATHS: &[&str] = &[
    "admin", "login", "dashboard", "api", "api/v1", "api/v2", "api/v3",
    "wp-admin", "wp-login.php", "phpmyadmin", "phpinfo.php",
    "config", "config.php", "config.json", "config.yml", "settings",
    "backup", "backup.zip", "backup.tar.gz", "db.sql", "database.sql",
    "upload", "uploads", "files", "static", "assets", "media",
    ".env", ".env.local", ".env.production", ".git/config", ".git/HEAD",
    ".htaccess", ".htpasswd", "web.config", "robots.txt", "sitemap.xml",
    "swagger.json", "openapi.json", "swagger-ui", "api-docs",
    "health", "healthz", "status", "metrics", "debug", "test",
    "actuator", "actuator/health", "actuator/env", "actuator/mappings",
    "console", "shell", "cmd", "exec",
    "user", "users", "account", "accounts", "profile", "register",
    "logout", "signout", "reset-password", "forgot-password",
    "search", "ajax", "ajax.php", "process", "handler",
    "include", "includes", "lib", "libs", "vendor",
    "tmp", "temp", "cache", "log", "logs", "error.log", "access.log",
    "old", "bak", "orig", "copy", "1", "2", "new",
];

/// Common GraphQL endpoints.
pub const GRAPHQL_ENDPOINTS: &[&str] = &[
    "graphql", "graphql/v1", "graphql/v2", "api/graphql",
    "query", "gql", "api/query",
];

/// Common API parameter names to fuzz.
pub const COMMON_PARAMS: &[&str] = &[
    "id", "user_id", "uid", "userid", "account_id", "order_id",
    "file", "path", "page", "url", "redirect", "callback",
    "token", "key", "api_key", "secret", "password",
    "q", "query", "search", "s", "term", "keyword",
    "name", "username", "email", "phone",
    "action", "cmd", "command", "exec", "run",
    "format", "output", "lang", "language", "locale",
    "debug", "test", "verbose", "mode",
    "limit", "offset", "page", "size", "count",
    "sort", "order", "orderby", "filter",
    "from", "to", "start", "end", "date",
    "ref", "source", "origin", "host",
];

/// Common username values for credential stuffing probes.
pub const COMMON_USERNAMES: &[&str] = &[
    "admin", "administrator", "root", "superuser", "user", "test",
    "guest", "demo", "operator", "manager", "support", "helpdesk",
    "info", "mail", "webmaster", "postmaster",
];

/// Common weak passwords.
pub const COMMON_PASSWORDS: &[&str] = &[
    "password", "123456", "password123", "admin", "admin123",
    "root", "letmein", "qwerty", "111111", "1234567890",
    "test", "test123", "changeme", "default", "pass",
    "P@ssw0rd", "Passw0rd!", "Welcome1",
];

/// File extension wordlist for backup/source file discovery.
pub const SOURCE_EXTENSIONS: &[&str] = &[
    ".bak", ".old", ".orig", ".copy", ".backup",
    ".php.bak", ".php~", ".php.old",
    ".asp.bak", ".aspx.bak",
    ".js.bak", ".js~",
    ".zip", ".tar.gz", ".tgz", ".7z", ".rar",
    ".sql", ".sql.gz", ".db",
    ".log", ".txt", ".xml", ".json", ".yaml", ".yml", ".env",
    "~", "#",
];

/// Mutation functions for a given input value.
pub fn mutate_value(value: &str) -> Vec<String> {
    let mut mutations = vec![
        // boundary/off-by-one
        "0".to_string(),
        "-1".to_string(),
        "9999999".to_string(),
        // SQL characters
        format!("{}'", value),
        format!("{}\"", value),
        format!("{}--", value),
        // XSS
        format!("{}<", value),
        format!("{}&lt;", value),
        // format string
        format!("{}%s%s%s", value),
        // null byte
        format!("{}\0", value),
        // long string
        "A".repeat(4096),
        // special characters
        format!("{}/../etc/passwd", value),
        format!("{}{{7*7}}", value),
        // empty
        String::new(),
        // whitespace
        "   ".to_string(),
    ];
    // Numeric increment/decrement
    if let Ok(n) = value.parse::<i64>() {
        mutations.push((n + 1).to_string());
        mutations.push((n - 1).to_string());
        mutations.push(0i64.to_string());
    }
    mutations
}
