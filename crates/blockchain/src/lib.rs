//! Nexus Sentinel blockchain and Web3 security analysis.

pub mod report;
pub mod solidity;
pub mod web3;

pub use report::{SecurityFinding, SecurityReport, SecuritySeverity};
pub use solidity::{analyze_solidity_file, analyze_solidity_source};
pub use web3::analyze_web3_javascript;
