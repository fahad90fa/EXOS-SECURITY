use std::{fs, path::Path};

use anyhow::{Context, Result};
use regex::Regex;
use tracing::debug;

use crate::report::{finding, SecuritySeverity, SecurityReport};

pub fn analyze_solidity_file(path: impl AsRef<Path>) -> Result<SecurityReport> {
    let path = path.as_ref();
    let source = fs::read_to_string(path)
        .with_context(|| format!("failed to read Solidity source: {}", path.display()))?;
    let mut report = analyze_solidity_source(&source);
    report.source_name = path.display().to_string();
    Ok(report)
}

pub fn analyze_solidity_source(source: &str) -> SecurityReport {
    let mut report = SecurityReport::new("<memory>", "solidity");
    let lines: Vec<&str> = source.lines().collect();

    let mut push = |id, title, description, severity, line, recommendation, evidence: Vec<String>| {
        report.push(finding(id, title, description, severity, line, recommendation, evidence));
    };

    let reentrancy_call = Regex::new(r"\.(call|delegatecall|staticcall)\s*(\{|\\()").unwrap();
    let state_write = Regex::new(r"\b(?:balances|owner|totalSupply|state|counter|locked)\b.*=").unwrap();
    let unchecked_call = Regex::new(r"\.(call|send|transfer)\s*(\{|\\()").unwrap();
    let tx_origin = Regex::new(r"\btx\.origin\b").unwrap();
    let block_time = Regex::new(r"\bblock\.(timestamp|difficulty|number)\b").unwrap();
    let loop_re = Regex::new(r"\bfor\s*\(|\bwhile\s*\(").unwrap();
    let safe_math_missing = Regex::new(r"(?i)(\+|\-|\*|/)\s*[^=]").unwrap();
    let hardcoded_secret = Regex::new(r"(?i)(private[_-]?key|secret|seed|mnemonic)\s*[:=]").unwrap();
    let approve_risk = Regex::new(r"\bapprove\s*\(").unwrap();
    let web3_rpc = Regex::new(r#"https?://[^"'\\s]+"#).unwrap();

    let mut saw_external_call = false;
    for (idx, line) in lines.iter().enumerate() {
        let line_no = idx + 1;
        let trimmed = line.trim();

        if reentrancy_call.is_match(trimmed) {
            saw_external_call = true;
            debug!("external call at line {}", line_no);
            push(
                "BC-REENT-001",
                "External call detected",
                "A low-level external call was found, which can become reentrancy-prone if state changes happen afterward.",
                SecuritySeverity::Medium,
                Some(line_no),
                "Move state updates before external calls and consider ReentrancyGuard.",
                vec![trimmed.to_string()],
            );
        }

        if saw_external_call && state_write.is_match(trimmed) {
            push(
                "BC-REENT-002",
                "State write follows external call",
                "State appears to be updated after an external interaction, which is a classic reentrancy pattern.",
                SecuritySeverity::Critical,
                Some(line_no),
                "Apply checks-effects-interactions and protect the function with a reentrancy lock.",
                vec![trimmed.to_string()],
            );
            saw_external_call = false;
        }

        if unchecked_call.is_match(trimmed) {
            push(
                "BC-CALL-001",
                "Unchecked external call",
                "A low-level call/send/transfer was used. The return value should be checked explicitly.",
                SecuritySeverity::High,
                Some(line_no),
                "Capture the success flag and revert on failure.",
                vec![trimmed.to_string()],
            );
        }

        if tx_origin.is_match(trimmed) {
            push(
                "BC-AUTH-001",
                "tx.origin authentication",
                "tx.origin should not be used for authorization checks because it can be phishing-prone.",
                SecuritySeverity::High,
                Some(line_no),
                "Use msg.sender and explicit role-based access control.",
                vec![trimmed.to_string()],
            );
        }

        if block_time.is_match(trimmed) {
            push(
                "BC-CRYPTO-001",
                "Weak randomness source",
                "block.timestamp / block.number style entropy is miner-influenceable and should not be used for security decisions.",
                SecuritySeverity::Medium,
                Some(line_no),
                "Use a verifiable randomness source such as Chainlink VRF or a commit-reveal scheme.",
                vec![trimmed.to_string()],
            );
        }

        if loop_re.is_match(trimmed) {
            push(
                "BC-GAS-001",
                "Loop detected",
                "Loops in smart contracts can become expensive or unbounded and lead to denial-of-service conditions.",
                SecuritySeverity::Low,
                Some(line_no),
                "Keep loops bounded and move heavy work off-chain where possible.",
                vec![trimmed.to_string()],
            );
        }

        if safe_math_missing.is_match(trimmed)
            && trimmed.contains('=')
            && !trimmed.contains("==")
            && !trimmed.contains("!=")
        {
            push(
                "BC-OVER-001",
                "Arithmetic expression detected",
                "Arithmetic in Solidity should be reviewed for overflow safety, especially in older compiler versions.",
                SecuritySeverity::Medium,
                Some(line_no),
                "Use Solidity 0.8+ checked arithmetic or SafeMath-style wrappers for legacy code.",
                vec![trimmed.to_string()],
            );
        }

        if hardcoded_secret.is_match(trimmed) {
            push(
                "BC-SEC-001",
                "Possible hardcoded secret",
                "A secret-like value appears to be hardcoded in source code.",
                SecuritySeverity::High,
                Some(line_no),
                "Move secrets out of source control and into a secure secret manager.",
                vec![trimmed.to_string()],
            );
        }

        if approve_risk.is_match(trimmed) {
            push(
                "BC-TOKEN-001",
                "ERC20 approval flow detected",
                "Approval flows should be reviewed for unlimited allowances and race conditions.",
                SecuritySeverity::Low,
                Some(line_no),
                "Prefer permit-based or bounded approvals and document approval lifecycle expectations.",
                vec![trimmed.to_string()],
            );
        }

        if web3_rpc.is_match(trimmed) {
            push(
                "BC-WEB3-001",
                "RPC endpoint detected",
                "A remote RPC endpoint is embedded in the source. Review for leaked public keys or insecure endpoints.",
                SecuritySeverity::Low,
                Some(line_no),
                "Use environment-driven configuration and avoid shipping privileged RPC endpoints to the browser.",
                vec![trimmed.to_string()],
            );
        }
    }

    report
}

#[cfg(test)]
mod tests {
    use super::analyze_solidity_source;

    #[test]
    fn flags_reentrancy_and_tx_origin_patterns() {
        let source = r#"
        contract Demo {
            mapping(address => uint256) balances;
            function withdraw(uint256 amount) external {
                (bool ok,) = msg.sender.call{value: amount}("");
                balances[msg.sender] = 0;
            }
            function auth() public view returns (bool) {
                return tx.origin == owner;
            }
        }
        "#;

        let report = analyze_solidity_source(source);
        assert!(report.findings.iter().any(|f| f.id == "BC-REENT-002"));
        assert!(report.findings.iter().any(|f| f.id == "BC-AUTH-001"));
    }
}
