use regex::Regex;

use crate::report::{finding, SecurityReport, SecuritySeverity};

pub fn analyze_web3_javascript(source: &str) -> SecurityReport {
    let mut report = SecurityReport::new("<memory>", "javascript");
    let key_re = Regex::new(r#"(?i)(private[_-]?key|secret|mnemonic|seed)\s*[:=]\s*['"][^'"]{8,}"#).unwrap();
    let rpc_re = Regex::new(r#"https?://[^"'`\s]+(?:infura|alchemy|quicknode|rpc)[^"'`\s]*"#).unwrap();
    let unsafe_store_re = Regex::new(r"(?i)(localstorage|sessionstorage|asyncstorage)").unwrap();
    let wallet_sign_re = Regex::new(r"(?i)(signmessage|eth_sign|personal_sign|eth_sendtransaction)").unwrap();

    let mut add = |id, title, description, severity, recommendation, evidence: Vec<String>| {
        report.push(finding(id, title, description, severity, None, recommendation, evidence));
    };

    if key_re.is_match(source) {
        add(
            "BC-WEB3-SEC-001",
            "Hardcoded private key pattern",
            "JavaScript source contains a string that resembles a private key or seed.",
            SecuritySeverity::Critical,
            "Remove the secret from frontend code and rotate the credential immediately.",
            vec![key_re.find(source).map(|m| m.as_str().to_string()).unwrap_or_default()],
        );
    }

    if rpc_re.is_match(source) {
        add(
            "BC-WEB3-RPC-001",
            "Embedded RPC endpoint",
            "Potential public or privileged RPC endpoint detected in frontend JavaScript.",
            SecuritySeverity::Medium,
            "Move RPC configuration to runtime environment variables and constrain allowed origins.",
            vec![rpc_re.find(source).map(|m| m.as_str().to_string()).unwrap_or_default()],
        );
    }

    if unsafe_store_re.is_match(source) {
        add(
            "BC-WEB3-STORAGE-001",
            "Browser storage usage detected",
            "Sensitive browser storage APIs were detected; review for token or credential storage.",
            SecuritySeverity::Medium,
            "Prefer secure wallet storage, HTTP-only cookies, or platform key stores over browser-local persistence.",
            vec!["Browser storage APIs".to_string()],
        );
    }

    if wallet_sign_re.is_match(source) {
        add(
            "BC-WEB3-WALLET-001",
            "Wallet signing flow detected",
            "Transaction or message signing is delegated to a wallet integration. Validate the request content carefully.",
            SecuritySeverity::Info,
            "Check chain IDs, destination addresses, and signing payloads before user approval.",
            vec!["Wallet signing API usage".to_string()],
        );
    }

    report
}
