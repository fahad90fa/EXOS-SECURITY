use std::collections::HashSet;

use crate::common::{
    finding, AnalysisSeverity, AndroidManifestSummary, Finding, FindingCategory,
};

pub fn audit_permissions(manifest: &AndroidManifestSummary) -> Vec<Finding> {
    let mut findings = Vec::new();
    let perms: HashSet<_> = manifest.permissions.iter().map(String::as_str).collect();

    let dangerous_permissions = [
        "android.permission.READ_SMS",
        "android.permission.RECORD_AUDIO",
        "android.permission.READ_CONTACTS",
        "android.permission.READ_CALL_LOG",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.READ_PHONE_STATE",
    ];

    let exposed: Vec<String> = dangerous_permissions
        .iter()
        .filter(|p| perms.contains(**p))
        .map(|p| (*p).to_string())
        .collect();

    if !exposed.is_empty() {
        findings.push(finding(
            "MOB-AND-010",
            "Dangerous permissions requested",
            "Application requests high-risk runtime permissions that increase attack impact and privacy risk.",
            AnalysisSeverity::Medium,
            FindingCategory::Permissions,
            "Enforce least privilege and remove permissions not essential to core functionality.",
            exposed,
        ));
    }

    if perms.contains("android.permission.INTERNET")
        && perms.contains("android.permission.READ_PHONE_STATE")
    {
        findings.push(finding(
            "MOB-AND-011",
            "INTERNET + READ_PHONE_STATE combination",
            "Application can access device identifiers and transmit them over the network.",
            AnalysisSeverity::High,
            FindingCategory::Permissions,
            "Minimize device identifier collection and document explicit user consent and retention controls.",
            vec![
                "android.permission.INTERNET".to_string(),
                "android.permission.READ_PHONE_STATE".to_string(),
            ],
        ));
    }

    if perms.contains("android.permission.RECEIVE_BOOT_COMPLETED")
        && perms.contains("android.permission.INTERNET")
    {
        findings.push(finding(
            "MOB-AND-012",
            "Persistence permission combination",
            "Application can auto-start on boot and communicate outbound, a pattern commonly abused for persistence.",
            AnalysisSeverity::High,
            FindingCategory::Permissions,
            "Validate boot receivers are necessary and restrict network actions to trusted endpoints with strict TLS.",
            vec![
                "android.permission.RECEIVE_BOOT_COMPLETED".to_string(),
                "android.permission.INTERNET".to_string(),
            ],
        ));
    }

    if perms.contains("android.permission.CAMERA") && perms.contains("android.permission.INTERNET") {
        findings.push(finding(
            "MOB-AND-013",
            "Camera data exfiltration risk",
            "Camera access combined with network access requires explicit consent and transparent privacy controls.",
            AnalysisSeverity::Medium,
            FindingCategory::Permissions,
            "Ensure in-app permission rationale, explicit user action gating, and encryption for media uploads.",
            vec![
                "android.permission.CAMERA".to_string(),
                "android.permission.INTERNET".to_string(),
            ],
        ));
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::audit_permissions;
    use crate::common::AndroidManifestSummary;

    #[test]
    fn flags_permission_combinations() {
        let manifest = AndroidManifestSummary {
            permissions: vec![
                "android.permission.INTERNET".to_string(),
                "android.permission.READ_PHONE_STATE".to_string(),
                "android.permission.RECEIVE_BOOT_COMPLETED".to_string(),
            ],
            ..Default::default()
        };

        let findings = audit_permissions(&manifest);
        assert!(findings.iter().any(|f| f.id == "MOB-AND-011"));
        assert!(findings.iter().any(|f| f.id == "MOB-AND-012"));
    }
}
