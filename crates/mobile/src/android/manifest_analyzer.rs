use anyhow::Result;
use quick_xml::{events::Event, Reader};

use crate::common::{
    finding, AnalysisSeverity, AndroidManifestSummary, Finding, FindingCategory,
};

pub fn analyze_manifest(
    manifest_text: Option<&str>,
    files: &[String],
) -> Result<(AndroidManifestSummary, Vec<Finding>)> {
    let mut summary = AndroidManifestSummary::default();
    let mut findings = Vec::new();

    let Some(xml) = manifest_text else {
        findings.push(finding(
            "MOB-AND-001",
            "Manifest could not be decoded",
            "AndroidManifest.xml was not readable from APK directly and apktool fallback failed.",
            AnalysisSeverity::Medium,
            FindingCategory::Manifest,
            "Install apktool on the scanner host to decode binary AndroidManifest.xml reliably.",
            vec!["AndroidManifest.xml unavailable".to_string()],
        ));
        return Ok((summary, findings));
    };

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();

    let mut inside_component = false;
    let mut current_component = String::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();

                if name == "manifest" {
                    for attr in e.attributes().flatten() {
                        if attr.key.as_ref() == b"package" {
                            summary.package_name =
                                Some(String::from_utf8_lossy(attr.value.as_ref()).to_string());
                        }
                    }
                }

                if name == "uses-sdk" {
                    for attr in e.attributes().flatten() {
                        let key = String::from_utf8_lossy(attr.key.as_ref());
                        let value = String::from_utf8_lossy(attr.value.as_ref()).to_string();
                        if key.ends_with("minSdkVersion") {
                            summary.min_sdk = Some(value);
                        }
                        if key.ends_with("targetSdkVersion") {
                            summary.target_sdk = Some(value);
                        }
                    }
                }

                if name == "uses-permission" {
                    for attr in e.attributes().flatten() {
                        let key = String::from_utf8_lossy(attr.key.as_ref());
                        if key.ends_with("name") {
                            summary
                                .permissions
                                .push(String::from_utf8_lossy(attr.value.as_ref()).to_string());
                        }
                    }
                }

                if name == "application" {
                    for attr in e.attributes().flatten() {
                        let key = String::from_utf8_lossy(attr.key.as_ref());
                        let value = String::from_utf8_lossy(attr.value.as_ref()).to_string();
                        if key.ends_with("debuggable") && value == "true" {
                            summary.debuggable = true;
                        }
                        if key.ends_with("allowBackup") && value == "true" {
                            summary.allow_backup = true;
                        }
                        if key.ends_with("usesCleartextTraffic") && value == "true" {
                            summary.uses_cleartext_traffic = true;
                        }
                        if key.ends_with("networkSecurityConfig") {
                            summary.network_security_config = Some(value);
                        }
                    }
                }

                if ["activity", "service", "receiver", "provider"].contains(&name.as_str()) {
                    inside_component = true;
                    current_component = name.clone();
                    let mut comp_name = None;
                    let mut exported = None;
                    for attr in e.attributes().flatten() {
                        let key = String::from_utf8_lossy(attr.key.as_ref());
                        let value = String::from_utf8_lossy(attr.value.as_ref()).to_string();
                        if key.ends_with("name") {
                            comp_name = Some(value.clone());
                        }
                        if key.ends_with("exported") {
                            exported = Some(value);
                        }
                    }

                    if exported.as_deref() == Some("true") {
                        summary.exported_components.push(format!(
                            "{}:{}",
                            current_component,
                            comp_name.unwrap_or_else(|| "<unnamed>".to_string())
                        ));
                    }
                }

                if inside_component && name == "intent-filter" {
                    summary
                        .intent_filters
                        .push(format!("intent-filter on {}", current_component));
                }
            }
            Ok(Event::End(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if ["activity", "service", "receiver", "provider"].contains(&name.as_str()) {
                    inside_component = false;
                    current_component.clear();
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }

        buf.clear();
    }

    if summary.debuggable {
        findings.push(finding(
            "MOB-AND-002",
            "Debuggable build enabled",
            "Application is built with android:debuggable=true, enabling easier runtime inspection and tampering.",
            AnalysisSeverity::High,
            FindingCategory::Manifest,
            "Set android:debuggable to false for production builds and enforce release signing in CI.",
            vec!["android:debuggable=true".to_string()],
        ));
    }

    if summary.allow_backup {
        findings.push(finding(
            "MOB-AND-003",
            "ADB backup allowed",
            "android:allowBackup=true may permit extraction of app data on debug-enabled devices.",
            AnalysisSeverity::Medium,
            FindingCategory::Manifest,
            "Set android:allowBackup=false unless backup data is encrypted and explicitly required.",
            vec!["android:allowBackup=true".to_string()],
        ));
    }

    if summary.uses_cleartext_traffic {
        findings.push(finding(
            "MOB-AND-004",
            "Cleartext network traffic permitted",
            "Application allows cleartext traffic which can expose credentials and session tokens to network attackers.",
            AnalysisSeverity::High,
            FindingCategory::Network,
            "Set android:usesCleartextTraffic=false and enforce TLS-only endpoints.",
            vec!["android:usesCleartextTraffic=true".to_string()],
        ));
    }

    if summary.network_security_config.is_none()
        && files.iter().any(|f| f.contains("res/xml/network_security_config"))
    {
        findings.push(finding(
            "MOB-AND-005",
            "Network security config file present but not referenced",
            "A network_security_config.xml file exists but application manifest does not bind it.",
            AnalysisSeverity::Low,
            FindingCategory::Network,
            "Reference @xml/network_security_config in android:networkSecurityConfig on the <application> tag.",
            vec!["res/xml/network_security_config.xml".to_string()],
        ));
    }

    if !summary.exported_components.is_empty() {
        findings.push(finding(
            "MOB-AND-006",
            "Exported components detected",
            "One or more Android components are exported and may be reachable by untrusted apps.",
            AnalysisSeverity::Medium,
            FindingCategory::Manifest,
            "Review each exported component and protect sensitive entry points with permissions or explicit runtime checks.",
            summary.exported_components.clone(),
        ));
    }

    Ok((summary, findings))
}

#[cfg(test)]
mod tests {
    use super::analyze_manifest;

    #[test]
    fn parses_manifest_and_flags_core_findings() {
        let xml = r#"<?xml version='1.0' encoding='utf-8'?>
            <manifest package='com.example.app' xmlns:android='http://schemas.android.com/apk/res/android'>
              <uses-sdk android:minSdkVersion='24' android:targetSdkVersion='34'/>
              <uses-permission android:name='android.permission.INTERNET'/>
              <application android:debuggable='true' android:allowBackup='true' android:usesCleartextTraffic='true'>
                 <activity android:name='.MainActivity' android:exported='true'>
                    <intent-filter>
                      <action android:name='android.intent.action.VIEW'/>
                    </intent-filter>
                 </activity>
              </application>
            </manifest>"#;

        let (summary, findings) = analyze_manifest(Some(xml), &[]).expect("analysis should work");
        assert_eq!(summary.package_name.as_deref(), Some("com.example.app"));
        assert!(summary.debuggable);
        assert!(summary.allow_backup);
        assert!(summary.uses_cleartext_traffic);
        assert!(!summary.exported_components.is_empty());
        assert!(findings.iter().any(|f| f.id == "MOB-AND-002"));
    }
}
