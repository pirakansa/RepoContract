use crate::{
    BranchProtection, BranchProtectionRules, ContractError, ContractResult, DiffEntry,
    RequiredPullRequestReviews, RequiredStatusChecks, StatusCheck, Summary,
};
use globset::{GlobBuilder, GlobSetBuilder};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize)]
pub struct BranchProtectionCheck {
    pub path: String,
    pub expected: Value,
    pub actual: Value,
    pub severity: crate::Severity,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct BranchProtectionDetail {
    pub path: String,
    pub expected: Value,
    pub actual: Value,
    pub missing: Option<Vec<String>>,
    pub extra: Option<Vec<String>>,
    pub passed: bool,
    pub severity: crate::Severity,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BranchProtectionReport {
    pub target: String,
    pub checks: Vec<BranchProtectionCheck>,
    #[serde(skip_serializing)]
    pub details: Vec<BranchProtectionDetail>,
}

pub struct GithubClient {
    base_url: String,
    token: Option<String>,
}

impl GithubClient {
    pub fn new(token: Option<String>) -> Self {
        Self {
            base_url: "https://api.github.com".to_string(),
            token,
        }
    }

    pub fn with_base_url(token: Option<String>, base_url: String) -> Self {
        Self { base_url, token }
    }

    pub fn list_branches(&self, repo: &str) -> ContractResult<Vec<String>> {
        let path = format!("/repos/{repo}/branches?per_page=100");
        let branches: Vec<GithubBranch> = self.get_json(&path)?;
        Ok(branches.into_iter().map(|branch| branch.name).collect())
    }

    pub fn get_branch_protection(
        &self,
        repo: &str,
        branch: &str,
    ) -> ContractResult<Option<BranchProtectionRules>> {
        let path = format!("/repos/{repo}/branches/{branch}/protection");
        let response: Option<GithubBranchProtection> = self.get_optional_json(&path)?;
        Ok(response.map(convert_protection_rules))
    }

    fn get_optional_json<T: DeserializeOwned>(&self, path: &str) -> ContractResult<Option<T>> {
        let url = format!(
            "{}/{}",
            self.base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        );
        let mut request = ureq::get(&url)
            .header("User-Agent", "contract")
            .header("Accept", "application/vnd.github+json");
        if let Some(token) = &self.token {
            request = request.header("Authorization", &format!("Bearer {token}"));
        }
        let mut response = match request.call() {
            Ok(response) => response,
            Err(ureq::Error::StatusCode(404)) => return Ok(None),
            Err(ureq::Error::StatusCode(status)) => {
                return Err(ContractError::GitHubApi(format!("status code {status}")));
            }
            Err(error) => return Err(ContractError::GitHubApi(error.to_string())),
        };
        let parsed = response
            .body_mut()
            .read_json::<T>()
            .map_err(|error| ContractError::GitHubApi(error.to_string()))?;
        Ok(Some(parsed))
    }

    fn get_json<T: DeserializeOwned>(&self, path: &str) -> ContractResult<T> {
        self.get_optional_json(path)?
            .ok_or_else(|| ContractError::GitHubApi("GitHub API returned 404".to_string()))
    }
}

#[derive(Debug, Deserialize)]
struct GithubBranch {
    name: String,
}

#[derive(Debug, Deserialize)]
struct GithubBranchProtection {
    required_pull_request_reviews: Option<GithubPullRequestReviews>,
    required_status_checks: Option<GithubStatusChecks>,
    enforce_admins: Option<GithubEnabled>,
    required_linear_history: Option<GithubEnabled>,
    allow_force_pushes: Option<GithubEnabled>,
    allow_deletions: Option<GithubEnabled>,
    required_conversation_resolution: Option<GithubEnabled>,
    required_signatures: Option<GithubEnabled>,
}

#[derive(Debug, Deserialize)]
struct GithubPullRequestReviews {
    required_approving_review_count: u8,
    dismiss_stale_reviews: bool,
    require_code_owner_reviews: bool,
    require_last_push_approval: bool,
}

#[derive(Debug, Deserialize)]
struct GithubStatusChecks {
    strict: bool,
    #[serde(default)]
    contexts: Vec<String>,
    #[serde(default)]
    checks: Vec<GithubStatusCheck>,
}

#[derive(Debug, Deserialize)]
struct GithubStatusCheck {
    context: String,
    #[serde(default)]
    app_id: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct GithubEnabled {
    enabled: bool,
}

pub fn check_branch_protection(
    client: &GithubClient,
    repo: &str,
    config: &BranchProtection,
) -> ContractResult<Vec<BranchProtectionReport>> {
    let branches = client.list_branches(repo)?;
    let targets = match_branch_patterns(&config.branches, &branches)?;
    let mut reports = Vec::new();
    for target in targets {
        let protection = client.get_branch_protection(repo, &target)?;
        let details = if let Some(protection) = protection {
            evaluate_branch_protection(&config.rules, &protection)
        } else {
            vec![missing_branch_protection_detail()]
        };
        let checks = details
            .iter()
            .filter(|detail| !detail.passed)
            .map(detail_to_check)
            .collect();
        reports.push(BranchProtectionReport {
            target,
            checks,
            details,
        });
    }
    Ok(reports)
}

pub fn summarize_branch_protection(reports: &[BranchProtectionReport]) -> Summary {
    let mut summary = Summary::default();
    for report in reports {
        for detail in &report.details {
            if detail.passed {
                continue;
            }
            match detail.severity {
                crate::Severity::Error => summary.error += 1,
                crate::Severity::Warning => summary.warning += 1,
                crate::Severity::Info => summary.info += 1,
            }
        }
    }
    summary
}

pub fn diff_branch_protection(reports: &[BranchProtectionReport]) -> Vec<DiffEntry> {
    let mut diffs = Vec::new();
    for report in reports {
        for detail in &report.details {
            if detail.passed {
                continue;
            }
            let diff_type = if detail.missing.is_some() || detail.extra.is_some() {
                "array_diff"
            } else {
                "value_mismatch"
            };
            diffs.push(DiffEntry {
                rule: "branch_protection".to_string(),
                path: detail.path.clone(),
                diff_type: diff_type.to_string(),
                severity: None,
                target: Some(report.target.clone()),
                expected: Some(detail.expected.clone()),
                actual: Some(detail.actual.clone()),
                missing: detail.missing.clone(),
                extra: detail.extra.clone(),
            });
        }
    }
    diffs
}

fn missing_branch_protection_detail() -> BranchProtectionDetail {
    BranchProtectionDetail {
        path: "branch_protection".to_string(),
        expected: Value::Bool(true),
        actual: Value::Bool(false),
        missing: None,
        extra: None,
        passed: false,
        severity: crate::Severity::Error,
        message: "Branch protection is not enabled".to_string(),
    }
}

fn detail_to_check(detail: &BranchProtectionDetail) -> BranchProtectionCheck {
    BranchProtectionCheck {
        path: detail.path.clone(),
        expected: detail.expected.clone(),
        actual: detail.actual.clone(),
        severity: detail.severity,
        message: detail.message.clone(),
    }
}

fn match_branch_patterns(patterns: &[String], branches: &[String]) -> ContractResult<Vec<String>> {
    if patterns.is_empty() {
        return Ok(Vec::new());
    }
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        let glob = GlobBuilder::new(pattern)
            .literal_separator(true)
            .build()
            .map_err(|error| ContractError::InvalidConfig(error.to_string()))?;
        builder.add(glob);
    }
    let glob_set = builder
        .build()
        .map_err(|error| ContractError::InvalidConfig(error.to_string()))?;
    Ok(branches
        .iter()
        .filter(|branch| glob_set.is_match(branch))
        .cloned()
        .collect())
}

fn convert_protection_rules(protection: GithubBranchProtection) -> BranchProtectionRules {
    BranchProtectionRules {
        required_pull_request_reviews: convert_pull_request_reviews(
            protection.required_pull_request_reviews,
        ),
        required_status_checks: convert_status_checks(protection.required_status_checks),
        enforce_admins: protection
            .enforce_admins
            .map(|value| value.enabled)
            .unwrap_or(false),
        required_linear_history: protection
            .required_linear_history
            .map(|value| value.enabled)
            .unwrap_or(false),
        allow_force_pushes: protection
            .allow_force_pushes
            .map(|value| value.enabled)
            .unwrap_or(false),
        allow_deletions: protection
            .allow_deletions
            .map(|value| value.enabled)
            .unwrap_or(false),
        required_conversation_resolution: protection
            .required_conversation_resolution
            .map(|value| value.enabled)
            .unwrap_or(false),
        required_signatures: protection
            .required_signatures
            .map(|value| value.enabled)
            .unwrap_or(false),
    }
}

fn convert_pull_request_reviews(
    reviews: Option<GithubPullRequestReviews>,
) -> RequiredPullRequestReviews {
    if let Some(reviews) = reviews {
        RequiredPullRequestReviews {
            enabled: true,
            required_approving_review_count: reviews.required_approving_review_count,
            dismiss_stale_reviews: reviews.dismiss_stale_reviews,
            require_code_owner_reviews: reviews.require_code_owner_reviews,
            require_last_push_approval: reviews.require_last_push_approval,
        }
    } else {
        RequiredPullRequestReviews {
            enabled: false,
            required_approving_review_count: 0,
            dismiss_stale_reviews: false,
            require_code_owner_reviews: false,
            require_last_push_approval: false,
        }
    }
}

fn convert_status_checks(checks: Option<GithubStatusChecks>) -> RequiredStatusChecks {
    if let Some(checks) = checks {
        let mut result = Vec::new();
        for context in checks.contexts {
            result.push(StatusCheck {
                context,
                app_id: None,
            });
        }
        for check in checks.checks {
            result.push(StatusCheck {
                context: check.context,
                app_id: check.app_id,
            });
        }
        RequiredStatusChecks {
            enabled: true,
            strict: checks.strict,
            checks: result,
        }
    } else {
        RequiredStatusChecks {
            enabled: false,
            strict: false,
            checks: Vec::new(),
        }
    }
}

fn evaluate_branch_protection(
    expected: &BranchProtectionRules,
    actual: &BranchProtectionRules,
) -> Vec<BranchProtectionDetail> {
    let mut details = Vec::new();

    let reviews_expected = &expected.required_pull_request_reviews;
    let reviews_actual = &actual.required_pull_request_reviews;
    let review_enabled_passed = reviews_expected.enabled == reviews_actual.enabled;
    let review_enabled_severity = if reviews_expected.enabled && !reviews_actual.enabled {
        crate::Severity::Error
    } else {
        crate::Severity::Warning
    };
    push_detail(
        &mut details,
        "required_pull_request_reviews.enabled",
        Value::Bool(reviews_expected.enabled),
        Value::Bool(reviews_actual.enabled),
        review_enabled_passed,
        review_enabled_severity,
        format!(
            "required_pull_request_reviews.enabled: expected {}, got {}",
            reviews_expected.enabled, reviews_actual.enabled
        ),
    );
    if reviews_expected.enabled {
        let review_count_passed = reviews_actual.required_approving_review_count
            >= reviews_expected.required_approving_review_count;
        push_detail(
            &mut details,
            "required_pull_request_reviews.required_approving_review_count",
            Value::Number(serde_json::Number::from(
                reviews_expected.required_approving_review_count,
            )),
            Value::Number(serde_json::Number::from(
                reviews_actual.required_approving_review_count,
            )),
            review_count_passed,
            crate::Severity::Error,
            format!(
                "required_approving_review_count: expected {}, got {}",
                reviews_expected.required_approving_review_count,
                reviews_actual.required_approving_review_count
            ),
        );
        push_detail(
            &mut details,
            "required_pull_request_reviews.dismiss_stale_reviews",
            Value::Bool(reviews_expected.dismiss_stale_reviews),
            Value::Bool(reviews_actual.dismiss_stale_reviews),
            reviews_expected.dismiss_stale_reviews == reviews_actual.dismiss_stale_reviews,
            crate::Severity::Warning,
            format!(
                "dismiss_stale_reviews: expected {}, got {}",
                reviews_expected.dismiss_stale_reviews, reviews_actual.dismiss_stale_reviews
            ),
        );
        push_detail(
            &mut details,
            "required_pull_request_reviews.require_code_owner_reviews",
            Value::Bool(reviews_expected.require_code_owner_reviews),
            Value::Bool(reviews_actual.require_code_owner_reviews),
            reviews_expected.require_code_owner_reviews
                == reviews_actual.require_code_owner_reviews,
            crate::Severity::Warning,
            format!(
                "require_code_owner_reviews: expected {}, got {}",
                reviews_expected.require_code_owner_reviews,
                reviews_actual.require_code_owner_reviews
            ),
        );
        push_detail(
            &mut details,
            "required_pull_request_reviews.require_last_push_approval",
            Value::Bool(reviews_expected.require_last_push_approval),
            Value::Bool(reviews_actual.require_last_push_approval),
            reviews_expected.require_last_push_approval
                == reviews_actual.require_last_push_approval,
            crate::Severity::Warning,
            format!(
                "require_last_push_approval: expected {}, got {}",
                reviews_expected.require_last_push_approval,
                reviews_actual.require_last_push_approval
            ),
        );
    }

    let status_expected = &expected.required_status_checks;
    let status_actual = &actual.required_status_checks;
    let status_enabled_passed = status_expected.enabled == status_actual.enabled;
    let status_enabled_severity = if status_expected.enabled && !status_actual.enabled {
        crate::Severity::Error
    } else {
        crate::Severity::Warning
    };
    push_detail(
        &mut details,
        "required_status_checks.enabled",
        Value::Bool(status_expected.enabled),
        Value::Bool(status_actual.enabled),
        status_enabled_passed,
        status_enabled_severity,
        format!(
            "required_status_checks.enabled: expected {}, got {}",
            status_expected.enabled, status_actual.enabled
        ),
    );
    if status_expected.enabled {
        push_detail(
            &mut details,
            "required_status_checks.strict",
            Value::Bool(status_expected.strict),
            Value::Bool(status_actual.strict),
            status_expected.strict == status_actual.strict,
            crate::Severity::Warning,
            format!(
                "required_status_checks.strict: expected {}, got {}",
                status_expected.strict, status_actual.strict
            ),
        );
        let expected_checks = &status_expected.checks;
        let actual_checks = &status_actual.checks;
        if !expected_checks.is_empty() {
            let missing = missing_status_checks(expected_checks, actual_checks);
            let extra = extra_status_checks(expected_checks, actual_checks);
            let expected_value = Value::Array(
                expected_checks
                    .iter()
                    .map(|check| Value::String(check.context.clone()))
                    .collect(),
            );
            let actual_value = Value::Array(
                actual_checks
                    .iter()
                    .map(|check| Value::String(check.context.clone()))
                    .collect(),
            );
            let passed = missing.is_empty() && extra.is_empty();
            let severity = if missing.is_empty() {
                crate::Severity::Warning
            } else {
                crate::Severity::Error
            };
            let message = if passed {
                "".to_string()
            } else if !missing.is_empty() {
                if extra.is_empty() {
                    format!("Missing required status check: {}", missing.join(", "))
                } else {
                    format!(
                        "Missing required status check: {} (extra: {})",
                        missing.join(", "),
                        extra.join(", ")
                    )
                }
            } else {
                format!("Unexpected status checks: {}", extra.join(", "))
            };
            details.push(BranchProtectionDetail {
                path: "required_status_checks.checks".to_string(),
                expected: expected_value,
                actual: actual_value,
                missing: Some(missing),
                extra: Some(extra),
                passed,
                severity,
                message,
            });
        }
    }

    push_detail(
        &mut details,
        "enforce_admins",
        Value::Bool(expected.enforce_admins),
        Value::Bool(actual.enforce_admins),
        expected.enforce_admins == actual.enforce_admins,
        crate::Severity::Warning,
        format!(
            "enforce_admins: expected {}, got {}",
            expected.enforce_admins, actual.enforce_admins
        ),
    );
    push_detail(
        &mut details,
        "required_linear_history",
        Value::Bool(expected.required_linear_history),
        Value::Bool(actual.required_linear_history),
        expected.required_linear_history == actual.required_linear_history,
        crate::Severity::Warning,
        format!(
            "required_linear_history: expected {}, got {}",
            expected.required_linear_history, actual.required_linear_history
        ),
    );
    push_detail(
        &mut details,
        "allow_force_pushes",
        Value::Bool(expected.allow_force_pushes),
        Value::Bool(actual.allow_force_pushes),
        expected.allow_force_pushes == actual.allow_force_pushes,
        crate::Severity::Warning,
        format!(
            "allow_force_pushes: expected {}, got {}",
            expected.allow_force_pushes, actual.allow_force_pushes
        ),
    );
    push_detail(
        &mut details,
        "allow_deletions",
        Value::Bool(expected.allow_deletions),
        Value::Bool(actual.allow_deletions),
        expected.allow_deletions == actual.allow_deletions,
        crate::Severity::Warning,
        format!(
            "allow_deletions: expected {}, got {}",
            expected.allow_deletions, actual.allow_deletions
        ),
    );
    push_detail(
        &mut details,
        "required_conversation_resolution",
        Value::Bool(expected.required_conversation_resolution),
        Value::Bool(actual.required_conversation_resolution),
        expected.required_conversation_resolution == actual.required_conversation_resolution,
        crate::Severity::Warning,
        format!(
            "required_conversation_resolution: expected {}, got {}",
            expected.required_conversation_resolution, actual.required_conversation_resolution
        ),
    );
    push_detail(
        &mut details,
        "required_signatures",
        Value::Bool(expected.required_signatures),
        Value::Bool(actual.required_signatures),
        expected.required_signatures == actual.required_signatures,
        crate::Severity::Warning,
        format!(
            "required_signatures: expected {}, got {}",
            expected.required_signatures, actual.required_signatures
        ),
    );

    details
}

fn push_detail(
    details: &mut Vec<BranchProtectionDetail>,
    path: &str,
    expected: Value,
    actual: Value,
    passed: bool,
    severity: crate::Severity,
    message: String,
) {
    details.push(BranchProtectionDetail {
        path: path.to_string(),
        expected,
        actual,
        missing: None,
        extra: None,
        passed,
        severity,
        message: if passed { String::new() } else { message },
    });
}

fn missing_status_checks(expected: &[StatusCheck], actual: &[StatusCheck]) -> Vec<String> {
    expected
        .iter()
        .filter(|expected_check| !has_status_check(expected_check, actual))
        .map(|check| check.context.clone())
        .collect()
}

fn extra_status_checks(expected: &[StatusCheck], actual: &[StatusCheck]) -> Vec<String> {
    let expected_contexts: HashSet<&str> = expected
        .iter()
        .map(|check| check.context.as_str())
        .collect();
    actual
        .iter()
        .filter(|check| !expected_contexts.contains(check.context.as_str()))
        .map(|check| check.context.clone())
        .collect()
}

fn has_status_check(expected: &StatusCheck, actual: &[StatusCheck]) -> bool {
    actual.iter().any(|check| {
        check.context == expected.context
            && expected
                .app_id
                .map(|app_id| check.app_id == Some(app_id))
                .unwrap_or(true)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status_check(context: &str) -> StatusCheck {
        StatusCheck {
            context: context.to_string(),
            app_id: None,
        }
    }

    #[test]
    fn reports_missing_status_checks() {
        let expected = BranchProtectionRules {
            required_status_checks: RequiredStatusChecks {
                enabled: true,
                strict: true,
                checks: vec![status_check("ci"), status_check("lint")],
            },
            ..BranchProtectionRules::default()
        };
        let actual = BranchProtectionRules {
            required_status_checks: RequiredStatusChecks {
                enabled: true,
                strict: true,
                checks: vec![status_check("ci")],
            },
            ..BranchProtectionRules::default()
        };

        let details = evaluate_branch_protection(&expected, &actual);
        let report = BranchProtectionReport {
            target: "main".to_string(),
            checks: details
                .iter()
                .filter(|detail| !detail.passed)
                .map(detail_to_check)
                .collect(),
            details,
        };
        let diffs = diff_branch_protection(&[report]);
        assert!(diffs.iter().any(|diff| {
            diff.path == "required_status_checks.checks"
                && diff
                    .missing
                    .as_ref()
                    .map(|missing| missing.contains(&"lint".to_string()))
                    .unwrap_or(false)
        }));
    }

    #[test]
    fn reports_insufficient_review_count() {
        let mut expected = BranchProtectionRules::default();
        expected
            .required_pull_request_reviews
            .required_approving_review_count = 2;
        let mut actual = BranchProtectionRules::default();
        actual
            .required_pull_request_reviews
            .required_approving_review_count = 1;

        let details = evaluate_branch_protection(&expected, &actual);
        assert!(details.iter().any(|detail| {
            detail.path == "required_pull_request_reviews.required_approving_review_count"
                && !detail.passed
        }));
    }
}
