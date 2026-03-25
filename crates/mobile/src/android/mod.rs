pub mod apk_parser;
pub mod certificate_analyzer;
pub mod manifest_analyzer;
pub mod permission_auditor;
pub mod resource_extractor;

use std::path::Path;

use anyhow::Result;

use crate::common::ApkAnalysisReport;

pub fn analyze_apk<P: AsRef<Path>>(apk_path: P) -> Result<ApkAnalysisReport> {
    let apk = apk_parser::ParsedApk::from_file(apk_path.as_ref())?;

    let mut report = ApkAnalysisReport {
        file_path: apk_path.as_ref().display().to_string(),
        file_count: apk.file_count,
        urls: apk.extracted_urls,
        api_endpoints: apk.api_endpoints,
        secrets: apk.secrets,
        ..Default::default()
    };

    let (manifest_summary, mut manifest_findings) =
        manifest_analyzer::analyze_manifest(apk.manifest_text.as_deref(), &apk.files)?;
    report.package_name = manifest_summary.package_name.clone();
    report.manifest = manifest_summary;

    let mut permission_findings = permission_auditor::audit_permissions(&report.manifest);
    let signature = certificate_analyzer::analyze_signature_schemes(&apk.raw_bytes, &apk.files);
    let mut cert_findings = certificate_analyzer::build_certificate_findings(&signature);
    report.signature = signature;

    let mut resource_findings = resource_extractor::analyze_resource_indicators(&report);

    report.findings.append(&mut manifest_findings);
    report.findings.append(&mut permission_findings);
    report.findings.append(&mut cert_findings);
    report.findings.append(&mut resource_findings);

    Ok(report)
}
