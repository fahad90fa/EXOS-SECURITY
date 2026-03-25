use std::{
    collections::HashSet,
    fs,
    io::{Cursor, Read},
    path::Path,
    process::Command,
};

use anyhow::{Context, Result};
use regex::Regex;
use tempfile::tempdir;
use zip::ZipArchive;

#[derive(Debug, Clone)]
pub struct ParsedApk {
    pub file_count: usize,
    pub files: Vec<String>,
    pub manifest_text: Option<String>,
    pub extracted_urls: Vec<String>,
    pub api_endpoints: Vec<String>,
    pub secrets: Vec<String>,
    pub raw_bytes: Vec<u8>,
}

impl ParsedApk {
    pub fn from_file(path: &Path) -> Result<Self> {
        let raw_bytes = fs::read(path)
            .with_context(|| format!("failed to read APK bytes: {}", path.display()))?;
        let mut archive = ZipArchive::new(Cursor::new(raw_bytes.as_slice()))
            .with_context(|| format!("failed to parse APK ZIP: {}", path.display()))?;

        let mut files = Vec::new();
        let mut manifest_text = None;
        let mut extracted_urls = HashSet::new();
        let mut api_endpoints = HashSet::new();
        let mut secrets = HashSet::new();

        let url_re = Regex::new(r#"https?://[[:alnum:][:punct:]]+"#)?;
        let api_re = Regex::new(r#"/[a-zA-Z0-9_./-]*(api|graphql|v1|v2)[a-zA-Z0-9_./-]*"#)?;
        let secret_re = Regex::new(
            r#"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][^'\"]{8,}['\"]"#,
        )?;

        for i in 0..archive.len() {
            let mut file = archive.by_index(i)?;
            let name = file.name().to_string();
            files.push(name.clone());

            let mut buf = Vec::new();
            file.read_to_end(&mut buf)?;

            if name == "AndroidManifest.xml" {
                manifest_text = String::from_utf8(buf.clone()).ok();
            }

            if let Ok(text) = std::str::from_utf8(&buf) {
                for m in url_re.find_iter(text) {
                    extracted_urls.insert(m.as_str().trim_end_matches('"').to_string());
                }
                for m in api_re.find_iter(text) {
                    api_endpoints.insert(m.as_str().to_string());
                }
                for m in secret_re.find_iter(text) {
                    secrets.insert(m.as_str().to_string());
                }
            }
        }

        if manifest_text.is_none() {
            manifest_text = try_decode_manifest_with_apktool(path).ok();
        }

        Ok(Self {
            file_count: files.len(),
            files,
            manifest_text,
            extracted_urls: extracted_urls.into_iter().collect(),
            api_endpoints: api_endpoints.into_iter().collect(),
            secrets: secrets.into_iter().collect(),
            raw_bytes,
        })
    }
}

fn try_decode_manifest_with_apktool(path: &Path) -> Result<String> {
    let temp = tempdir()?;
    let output_dir = temp.path().join("decoded");

    let status = Command::new("apktool")
        .arg("d")
        .arg("-f")
        .arg(path)
        .arg("-o")
        .arg(&output_dir)
        .status();

    match status {
        Ok(exit) if exit.success() => {
            let manifest_path = output_dir.join("AndroidManifest.xml");
            let data = fs::read_to_string(&manifest_path)
                .with_context(|| format!("apktool decode succeeded but missing {}", manifest_path.display()))?;
            Ok(data)
        }
        Ok(exit) => anyhow::bail!("apktool failed with status: {}", exit),
        Err(err) => anyhow::bail!("apktool unavailable: {}", err),
    }
}
