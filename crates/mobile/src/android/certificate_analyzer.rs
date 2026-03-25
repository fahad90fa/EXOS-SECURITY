use crate::common::{
    finding, AnalysisSeverity, Finding, FindingCategory, SignatureSchemeStatus,
};

pub fn analyze_signature_schemes(raw_bytes: &[u8], files: &[String]) -> SignatureSchemeStatus {
    let mut status = SignatureSchemeStatus::default();

    if files.iter().any(|f| f.starts_with("META-INF/")) {
        status.v1 = true;
    }

    if raw_bytes.windows(8).any(|window| window == b"APK Sig ") || files.iter().any(|f| {
        f.contains("cert") || f.contains("signature") || f.contains("v2") || f.contains("v3")
    }) {
        status.v2_or_higher = true;
    }

    status
}

pub fn build_certificate_findings(signature: &SignatureSchemeStatus) -> Vec<Finding> {
    let mut findings = Vec::new();

    if !signature.v1 {
        findings.push(finding(
            "MOB-CERT-001",
            "Legacy V1 signature not present",
            "The APK does not appear to expose a JAR/V1 signature block. This can be normal for modern packages, but verification should still confirm V2/V3 integrity.",
            AnalysisSeverity::Info,
            FindingCategory::Certificate,
            "Verify the package is signed with V2/V3 and is installable on the target Android versions.",
            Vec::new(),
        ));
    }

    if !signature.v2_or_higher {
        findings.push(finding(
            "MOB-CERT-002",
            "Modern signature scheme not detected",
            "The APK does not appear to contain an APK Signature Scheme v2+ block, which weakens tamper resistance on newer Android releases.",
            AnalysisSeverity::High,
            FindingCategory::Certificate,
            "Re-sign the package with apksigner using V2/V3 schemes enabled.",
            Vec::new(),
        ));
    }

    findings
}
