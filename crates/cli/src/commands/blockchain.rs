use std::{fs, path::Path};

use anyhow::Result;
use nexus_blockchain::{analyze_solidity_file, analyze_web3_javascript};

pub async fn analyze(contract: String) -> Result<()> {
    let report = analyze_solidity_file(Path::new(&contract))?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

pub async fn web3(bundle: String) -> Result<()> {
    let source = fs::read_to_string(&bundle)?;
    let report = analyze_web3_javascript(&source);
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
