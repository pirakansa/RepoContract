use crate::required_files::{RequiredFileCheck, Summary};
use crate::Severity;

#[derive(Debug, Clone, serde::Serialize)]
pub struct DiffEntry {
    pub rule: String,
    pub path: String,
    #[serde(rename = "type")]
    pub diff_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub missing: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<Vec<String>>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DiffReport {
    pub diffs: Vec<DiffEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<Summary>,
}

pub fn diff_required_files(checks: &[RequiredFileCheck]) -> DiffReport {
    let mut diffs = Vec::new();
    let mut summary = Summary::default();
    for check in checks {
        if check.exists {
            continue;
        }
        match check.severity {
            Severity::Error => summary.error += 1,
            Severity::Warning => summary.warning += 1,
            Severity::Info => summary.info += 1,
        }
        diffs.push(DiffEntry {
            rule: "required_files".to_string(),
            path: check.path.clone(),
            diff_type: "missing_file".to_string(),
            severity: Some(check.severity),
            target: None,
            expected: None,
            actual: None,
            missing: None,
            extra: None,
        });
    }

    DiffReport {
        diffs,
        summary: Some(summary),
    }
}
