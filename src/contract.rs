use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct Contract {
    pub version: String,
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub language: Option<String>,
    #[serde(default)]
    pub branch_protection: Option<BranchProtection>,
    #[serde(default)]
    pub required_files: Vec<RequiredFile>,
    #[serde(default)]
    pub metadata: Option<serde_yaml::Value>,
}

impl Contract {
    pub fn merge_profile(&self, profile: Contract) -> Contract {
        let mut merged = self.clone();
        merged.required_files.extend(profile.required_files);
        if profile.branch_protection.is_some() {
            merged.branch_protection = profile.branch_protection;
        }
        if profile.metadata.is_some() {
            merged.metadata = profile.metadata;
        }
        merged
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BranchProtection {
    #[serde(default = "default_branches")]
    pub branches: Vec<String>,
    #[serde(default)]
    pub rules: BranchProtectionRules,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct BranchProtectionRules {
    pub required_pull_request_reviews: RequiredPullRequestReviews,
    pub required_status_checks: RequiredStatusChecks,
    pub enforce_admins: bool,
    pub required_linear_history: bool,
    pub allow_force_pushes: bool,
    pub allow_deletions: bool,
    pub required_conversation_resolution: bool,
    pub required_signatures: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct RequiredPullRequestReviews {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_review_count")]
    pub required_approving_review_count: u8,
    #[serde(default = "default_true")]
    pub dismiss_stale_reviews: bool,
    #[serde(default)]
    pub require_code_owner_reviews: bool,
    #[serde(default)]
    pub require_last_push_approval: bool,
}

impl Default for RequiredPullRequestReviews {
    fn default() -> Self {
        Self {
            enabled: true,
            required_approving_review_count: 1,
            dismiss_stale_reviews: true,
            require_code_owner_reviews: false,
            require_last_push_approval: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct RequiredStatusChecks {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub strict: bool,
    #[serde(default)]
    pub checks: Vec<StatusCheck>,
}

impl Default for RequiredStatusChecks {
    fn default() -> Self {
        Self {
            enabled: true,
            strict: true,
            checks: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StatusCheck {
    pub context: String,
    #[serde(default)]
    pub app_id: Option<u64>,
}

fn default_true() -> bool {
    true
}

fn default_review_count() -> u8 {
    1
}

fn default_branches() -> Vec<String> {
    vec!["main".to_string()]
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RequiredFile {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub alternatives: Vec<String>,
    #[serde(default)]
    pub severity: Severity,
    #[serde(default)]
    pub case_insensitive: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    #[default]
    Error,
    Warning,
    Info,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Info => "info",
        }
    }
}
