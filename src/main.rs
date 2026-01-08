use anyhow::{anyhow, Context};
use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use std::path::{Path, PathBuf};
use std::process::Command;

use contract::{
    check_branch_protection, check_required_files, diff_branch_protection, diff_required_files,
    init_contract_files, load_config_file, load_contract, resolve_cli_config, schema_json,
    summarize_branch_protection, validate_contract_file, BranchProtectionReport, CliConfig,
    ContractError, GithubClient, LoadOptions, RequiredFilesReport, Summary,
};

#[derive(Parser)]
#[command(name = "contract", version, about = "Repo Contract CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    #[arg(short = 'v', long = "verbose", action = ArgAction::Count)]
    verbose: u8,
    #[arg(long = "no-color", default_value_t = false)]
    no_color: bool,
}

#[derive(Subcommand)]
enum Commands {
    Validate(ValidateArgs),
    Check(CheckArgs),
    Diff(DiffArgs),
    Apply(ApplyArgs),
    Init(InitArgs),
    Schema,
}

#[derive(clap::Args)]
struct ValidateArgs {
    #[arg(value_name = "PATH")]
    path: Option<PathBuf>,
    #[arg(short = 'c', long = "config")]
    config: Option<PathBuf>,
    #[arg(short = 'p', long = "with-profile", default_value_t = false)]
    with_profile: bool,
    #[arg(short = 'f', long = "format")]
    format: Option<ValidateFormat>,
    #[arg(short = 'q', long = "quiet", default_value_t = false)]
    quiet: bool,
}

#[derive(clap::Args)]
struct CheckArgs {
    #[arg(short = 'c', long = "config")]
    config: Option<PathBuf>,
    #[arg(short = 'r', long = "remote")]
    remote: Option<String>,
    #[arg(long = "rules")]
    rules: Option<String>,
    #[arg(short = 'f', long = "format")]
    format: Option<CheckFormat>,
    #[arg(short = 's', long = "strict", action = ArgAction::SetTrue)]
    strict: Option<bool>,
    #[arg(short = 'q', long = "quiet", default_value_t = false)]
    quiet: bool,
}

#[derive(clap::Args)]
struct DiffArgs {
    #[arg(short = 'c', long = "config")]
    config: Option<PathBuf>,
    #[arg(short = 'r', long = "remote")]
    remote: Option<String>,
    #[arg(long = "rules")]
    rules: Option<String>,
    #[arg(short = 'f', long = "format")]
    format: Option<DiffFormat>,
}

#[derive(clap::Args)]
struct ApplyArgs {
    #[arg(short = 'c', long = "config")]
    config: Option<PathBuf>,
}

#[derive(clap::Args)]
struct InitArgs {
    #[arg(short = 'o', long = "output", default_value = "contract.yml")]
    output: PathBuf,
    #[arg(short = 'p', long = "profile")]
    profile: Option<String>,
    #[arg(long = "from-repo", default_value_t = false)]
    from_repo: bool,
    #[arg(short = 'r', long = "remote")]
    remote: Option<String>,
    #[arg(short = 'f', long = "force", default_value_t = false)]
    force: bool,
}

#[derive(Clone, Debug, ValueEnum)]
enum ValidateFormat {
    Human,
    Json,
}

#[derive(Clone, Debug, ValueEnum)]
enum CheckFormat {
    Human,
    Json,
}

#[derive(Clone, Debug, ValueEnum)]
enum DiffFormat {
    Human,
    Json,
    Yaml,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rule {
    RequiredFiles,
    BranchProtection,
}

fn main() {
    let cli = Cli::parse();
    let exit_code = match run(cli) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error}");
            2
        }
    };
    std::process::exit(exit_code);
}

fn run(cli: Cli) -> anyhow::Result<i32> {
    let config_file = load_config_file(Path::new(".contract.toml"))?;
    let cli_config = resolve_cli_config(config_file);
    match cli.command {
        Commands::Validate(args) => run_validate(args, &cli_config),
        Commands::Check(args) => run_check(args, &cli_config),
        Commands::Diff(args) => run_diff(args, &cli_config),
        Commands::Apply(_args) => {
            eprintln!("apply は Phase 2 で対応予定です。");
            Ok(2)
        }
        Commands::Init(args) => run_init(args),
        Commands::Schema => {
            println!("{}", schema_json());
            Ok(0)
        }
    }
}

fn run_validate(args: ValidateArgs, cli_config: &CliConfig) -> anyhow::Result<i32> {
    let config_path = resolve_config_path(args.path, args.config, cli_config);
    let format = args
        .format
        .or_else(|| cli_config.format.as_deref().and_then(parse_validate_format))
        .unwrap_or(ValidateFormat::Human);
    let mut reports = Vec::new();

    if !config_path.exists() {
        eprintln!(
            "contract ファイルが見つかりません: {}",
            config_path.display()
        );
        return Ok(2);
    }
    let report = validate_contract_file(&config_path)
        .with_context(|| format!("{config_path:?} の検証に失敗しました"))?;
    reports.push(report);

    if args.with_profile {
        let profile_name = report_profile_name(&config_path)?;
        if let Some(profile_name) = profile_name {
            let profile_path = profile_path_for(&config_path, &profile_name);
            if !profile_path.exists() {
                eprintln!("profile が見つかりません: {}", profile_path.display());
                return Ok(2);
            }
            let profile_report = validate_contract_file(&profile_path)?;
            reports.push(profile_report);
        }
    }

    let valid = reports.iter().all(|report| report.valid);
    if args.quiet && valid {
        return Ok(0);
    }

    match format {
        ValidateFormat::Human => print_validate_human(&reports),
        ValidateFormat::Json => print_validate_json(&reports)?,
    }

    Ok(if valid { 0 } else { 1 })
}

fn run_check(args: CheckArgs, cli_config: &CliConfig) -> anyhow::Result<i32> {
    let rules = parse_rules(args.rules, cli_config.check_rules.clone())?;
    if args.remote.is_some() && rules.contains(&Rule::RequiredFiles) {
        eprintln!("remote の required_files チェックは未対応です。");
        return Ok(2);
    }
    let config_path = resolve_config_path(None, args.config, cli_config);
    if !config_path.exists() {
        eprintln!(
            "contract ファイルが見つかりません: {}",
            config_path.display()
        );
        return Ok(2);
    }
    let strict = resolve_strict(args.strict, cli_config.strict);
    let format = args
        .format
        .or_else(|| cli_config.format.as_deref().and_then(parse_check_format))
        .unwrap_or(CheckFormat::Human);

    let loaded = load_contract(LoadOptions {
        config_path: config_path.clone(),
        include_profile: true,
    })?;
    let root = config_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));

    let branch_reports = if rules.contains(&Rule::BranchProtection) {
        if let Some(branch_protection) = loaded.contract.branch_protection.as_ref() {
            let repo = resolve_repository(args.remote.as_deref())
                .context("GitHub リポジトリの解決に失敗しました")?;
            let token = resolve_github_token(cli_config);
            let client = GithubClient::new(token);
            check_branch_protection(&client, &repo, branch_protection)?
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };

    let report = if rules.contains(&Rule::RequiredFiles) {
        Some(check_required_files(
            &root,
            &loaded.contract.required_files,
        )?)
    } else {
        None
    };

    let mut summary = summarize_required_files(&report);
    let branch_summary = summarize_branch_protection(&branch_reports);
    add_summary(&mut summary, &branch_summary);
    let has_error = summary.error > 0 || (strict && summary.warning > 0);
    if args.quiet && summary.error == 0 && summary.warning == 0 {
        return Ok(0);
    }

    match format {
        CheckFormat::Human => print_check_human(&branch_reports, report.as_ref(), &summary),
        CheckFormat::Json => {
            print_check_json(&branch_reports, report.as_ref(), &summary, !has_error)?
        }
    }

    Ok(if has_error { 1 } else { 0 })
}

fn run_diff(args: DiffArgs, cli_config: &CliConfig) -> anyhow::Result<i32> {
    let rules = parse_rules(args.rules, cli_config.check_rules.clone())?;
    if args.remote.is_some() && rules.contains(&Rule::RequiredFiles) {
        eprintln!("remote の required_files diff は未対応です。");
        return Ok(2);
    }
    let config_path = resolve_config_path(None, args.config, cli_config);
    if !config_path.exists() {
        eprintln!(
            "contract ファイルが見つかりません: {}",
            config_path.display()
        );
        return Ok(2);
    }
    let format = args
        .format
        .or_else(|| cli_config.format.as_deref().and_then(parse_diff_format))
        .unwrap_or(DiffFormat::Human);

    let loaded = load_contract(LoadOptions {
        config_path: config_path.clone(),
        include_profile: true,
    })?;
    let root = config_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));

    let mut diffs = Vec::new();
    let summary = if rules.contains(&Rule::RequiredFiles) {
        let required_report = check_required_files(&root, &loaded.contract.required_files)?;
        diffs.extend(diff_required_files(&required_report.checks).diffs);
        Some(required_report.summary)
    } else {
        None
    };

    if rules.contains(&Rule::BranchProtection) {
        if let Some(branch_protection) = loaded.contract.branch_protection.as_ref() {
            let repo = resolve_repository(args.remote.as_deref())
                .context("GitHub リポジトリの解決に失敗しました")?;
            let token = resolve_github_token(cli_config);
            let client = GithubClient::new(token);
            let reports = check_branch_protection(&client, &repo, branch_protection)?;
            diffs.extend(diff_branch_protection(&reports));
        }
    }

    let report = contract::DiffReport { diffs, summary };

    let has_diff = !report.diffs.is_empty();
    match format {
        DiffFormat::Human => print_diff_human(Some(&report)),
        DiffFormat::Json => print_diff_json(Some(&report))?,
        DiffFormat::Yaml => print_diff_yaml(Some(&report))?,
    }

    Ok(if has_diff { 1 } else { 0 })
}

fn run_init(args: InitArgs) -> anyhow::Result<i32> {
    if args.remote.is_some() {
        eprintln!("remote からの init は未対応です。");
        return Ok(2);
    }
    let root = std::env::current_dir()?;
    match init_contract_files(
        &root,
        contract::InitOptions {
            output_path: args.output,
            profile: args.profile,
            from_repo: args.from_repo,
            force: args.force,
        },
    ) {
        Ok(outcome) => {
            for path in outcome.created {
                println!("Created: {}", path.display());
            }
            Ok(0)
        }
        Err(ContractError::AlreadyExists(path)) => {
            eprintln!("ファイルが既に存在します: {path}");
            Ok(1)
        }
        Err(error) => Err(error.into()),
    }
}

fn resolve_config_path(
    path: Option<PathBuf>,
    config: Option<PathBuf>,
    cli_config: &CliConfig,
) -> PathBuf {
    path.or(config)
        .or_else(|| cli_config.config_path.clone())
        .unwrap_or_else(|| PathBuf::from("contract.yml"))
}

fn resolve_strict(flag: Option<bool>, config_strict: Option<bool>) -> bool {
    let mut strict = flag.or(config_strict).unwrap_or(false);
    if env_true("CONTRACT_STRICT") {
        strict = true;
    }
    strict
}

fn env_true(key: &str) -> bool {
    std::env::var(key)
        .ok()
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn resolve_github_token(cli_config: &CliConfig) -> Option<String> {
    std::env::var("GITHUB_TOKEN")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| cli_config.github_token.clone())
}

fn resolve_repository(remote: Option<&str>) -> anyhow::Result<String> {
    if let Some(remote) = remote {
        return normalize_repository(remote)
            .ok_or_else(|| anyhow!("invalid remote repository: {remote}"));
    }
    if let Ok(repo) = std::env::var("GITHUB_REPOSITORY") {
        if !repo.trim().is_empty() {
            return Ok(repo);
        }
    }
    let output = Command::new("git")
        .args(["config", "--get", "remote.origin.url"])
        .output()
        .context("git remote.origin.url の取得に失敗しました")?;
    if !output.status.success() {
        return Err(anyhow!("git remote.origin.url が見つかりません"));
    }
    let url = String::from_utf8_lossy(&output.stdout).trim().to_string();
    normalize_repository(&url).ok_or_else(|| anyhow!("invalid remote repository: {url}"))
}

fn normalize_repository(value: &str) -> Option<String> {
    let trimmed = value.trim().trim_end_matches(".git");
    if let Some(rest) = trimmed.strip_prefix("git@github.com:") {
        return take_owner_repo(rest);
    }
    if let Some(rest) = trimmed.strip_prefix("ssh://git@github.com/") {
        return take_owner_repo(rest);
    }
    if let Some(index) = trimmed.find("github.com/") {
        let rest = &trimmed[index + "github.com/".len()..];
        return take_owner_repo(rest);
    }
    take_owner_repo(trimmed)
}

fn take_owner_repo(value: &str) -> Option<String> {
    let mut parts = value.split('/');
    let owner = parts.next()?;
    let repo = parts.next()?;
    if owner.is_empty() || repo.is_empty() {
        return None;
    }
    Some(format!("{owner}/{repo}"))
}

fn report_profile_name(config_path: &Path) -> anyhow::Result<Option<String>> {
    let content = std::fs::read_to_string(config_path)?;
    let contract: serde_yaml::Value = serde_yaml::from_str(&content)?;
    if let Some(profile) = contract.get("profile") {
        Ok(profile.as_str().map(|value| value.to_string()))
    } else {
        Ok(None)
    }
}

fn profile_path_for(config_path: &Path, profile: &str) -> PathBuf {
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(format!("contract.{profile}.yml"))
}

fn parse_rules(
    rules: Option<String>,
    config_rules: Option<Vec<String>>,
) -> anyhow::Result<Vec<Rule>> {
    let list = if let Some(rules) = rules {
        rules
            .split(',')
            .map(|item| item.trim().to_string())
            .collect::<Vec<_>>()
    } else if let Some(config_rules) = config_rules {
        config_rules
            .into_iter()
            .map(|item| item.trim().to_string())
            .collect::<Vec<_>>()
    } else {
        vec![
            "required_files".to_string(),
            "branch_protection".to_string(),
        ]
    };
    let mut parsed = Vec::new();
    for rule in list {
        match rule.as_str() {
            "required_files" => parsed.push(Rule::RequiredFiles),
            "branch_protection" => parsed.push(Rule::BranchProtection),
            other => {
                return Err(ContractError::InvalidConfig(format!(
                    "unknown rule: {other}"
                )))
                .context("rules の解決に失敗しました")
            }
        }
    }
    Ok(parsed)
}

fn parse_validate_format(value: &str) -> Option<ValidateFormat> {
    match value {
        "human" => Some(ValidateFormat::Human),
        "json" => Some(ValidateFormat::Json),
        _ => None,
    }
}

fn parse_check_format(value: &str) -> Option<CheckFormat> {
    match value {
        "human" => Some(CheckFormat::Human),
        "json" => Some(CheckFormat::Json),
        _ => None,
    }
}

fn parse_diff_format(value: &str) -> Option<DiffFormat> {
    match value {
        "human" => Some(DiffFormat::Human),
        "json" => Some(DiffFormat::Json),
        "yaml" => Some(DiffFormat::Yaml),
        _ => None,
    }
}

fn print_validate_human(reports: &[contract::ValidationReport]) {
    let mut errors = 0;
    for report in reports {
        if report.valid {
            println!("✓ {}: Valid", report.path);
        } else {
            println!("✗ {}: Invalid", report.path);
            for issue in &report.errors {
                println!("  - {}", issue.message);
            }
            errors += report.errors.len();
        }
    }
    println!("Validated {} files, {} errors", reports.len(), errors);
}

fn print_validate_json(reports: &[contract::ValidationReport]) -> anyhow::Result<()> {
    let output = serde_json::json!({
        "valid": reports.iter().all(|report| report.valid),
        "files": reports
    });
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn print_check_human(
    branch_reports: &[BranchProtectionReport],
    report: Option<&RequiredFilesReport>,
    summary: &Summary,
) {
    for report in branch_reports {
        println!("Branch Protection [{}]", report.target);
        if report.details.is_empty() {
            println!("  ✓ No checks configured");
            continue;
        }
        for detail in &report.details {
            if detail.passed {
                println!(
                    "  ✓ {}: {}",
                    detail.path,
                    format_check_value(&detail.expected)
                );
            } else {
                let icon = match detail.severity {
                    contract::Severity::Error => "✗",
                    contract::Severity::Warning => "⚠",
                    contract::Severity::Info => "ℹ",
                };
                println!("  {icon} {}: {}", detail.path, detail.message);
            }
        }
        println!();
    }
    if let Some(report) = report {
        println!("Required Files");
        for check in &report.checks {
            let (icon, message) = if check.exists {
                ("✓", "Found")
            } else {
                match check.severity {
                    contract::Severity::Error => ("✗", "Not found (error)"),
                    contract::Severity::Warning => ("⚠", "Not found (warning)"),
                    contract::Severity::Info => ("ℹ", "Not found (info)"),
                }
            };
            println!("  {icon} {}: {message}", check.path);
        }
    }
    println!(
        "Summary: {} error, {} warning, {} info",
        summary.error, summary.warning, summary.info
    );
}

fn print_check_json(
    branch_reports: &[BranchProtectionReport],
    report: Option<&RequiredFilesReport>,
    summary: &Summary,
    valid: bool,
) -> anyhow::Result<()> {
    let mut results = Vec::new();
    for report in branch_reports {
        results.push(serde_json::json!({
            "rule": "branch_protection",
            "target": report.target,
            "checks": report.checks,
        }));
    }
    if let Some(report) = report {
        results.push(serde_json::json!({
            "rule": "required_files",
            "checks": report.checks,
        }));
    }
    let output = serde_json::json!({
        "valid": valid,
        "results": results,
        "summary": summary,
    });
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn print_diff_human(report: Option<&contract::DiffReport>) {
    if let Some(report) = report {
        if report.diffs.is_empty() {
            println!("No differences found.");
            return;
        }
        let mut branch_groups: Vec<(String, Vec<&contract::DiffEntry>)> = Vec::new();
        let mut required_diffs = Vec::new();
        for diff in &report.diffs {
            if diff.rule == "branch_protection" {
                let target = diff.target.clone().unwrap_or_else(|| "unknown".to_string());
                if let Some((_, entries)) = branch_groups.iter_mut().find(|(key, _)| key == &target)
                {
                    entries.push(diff);
                } else {
                    branch_groups.push((target, vec![diff]));
                }
            } else if diff.rule == "required_files" {
                required_diffs.push(diff);
            }
        }

        for (target, diffs) in branch_groups {
            println!("Branch Protection [{target}]");
            for diff in diffs {
                if diff.diff_type == "array_diff" {
                    println!("  {}:", diff.path);
                    if let Some(missing) = &diff.missing {
                        for value in missing {
                            println!("    + {value} (missing)");
                        }
                    }
                    if let Some(extra) = &diff.extra {
                        for value in extra {
                            println!("    - {value} (extra)");
                        }
                    }
                } else {
                    println!(
                        "  {}: expected {}, got {}",
                        diff.path,
                        format_diff_value(diff.expected.as_ref()),
                        format_diff_value(diff.actual.as_ref())
                    );
                }
            }
            println!();
        }

        if !required_diffs.is_empty() {
            println!("Required Files:");
            for diff in required_diffs {
                let severity = diff.severity.map(|value| value.as_str()).unwrap_or("error");
                println!("  + {} (missing, severity: {severity})", diff.path);
            }
        }
    } else {
        println!("No differences found.");
    }
}

fn print_diff_json(report: Option<&contract::DiffReport>) -> anyhow::Result<()> {
    let output = serde_json::json!({
        "diffs": report.map(|report| report.diffs.clone()).unwrap_or_default(),
    });
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn print_diff_yaml(report: Option<&contract::DiffReport>) -> anyhow::Result<()> {
    let output = serde_yaml::to_string(
        &report
            .map(|report| report.diffs.clone())
            .unwrap_or_default(),
    )?;
    println!("{output}");
    Ok(())
}

fn summarize_required_files(report: &Option<RequiredFilesReport>) -> Summary {
    report
        .as_ref()
        .map(|report| report.summary.clone())
        .unwrap_or_default()
}

fn add_summary(summary: &mut Summary, other: &Summary) {
    summary.error += other.error;
    summary.warning += other.warning;
    summary.info += other.info;
}

fn format_check_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => text.clone(),
        _ => value.to_string(),
    }
}

fn format_diff_value(value: Option<&serde_json::Value>) -> String {
    value
        .map(format_check_value)
        .unwrap_or_else(|| "-".to_string())
}
