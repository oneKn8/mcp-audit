use crate::checks::Check;
use crate::config::McpServerConfig;
use crate::finding::{Finding, OwaspCategory, Severity};
use regex::Regex;

pub struct SupplyChainCheck;

impl Check for SupplyChainCheck {
    fn run(&self, config: &McpServerConfig) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check command for package execution patterns (npx, pip, etc.)
        if let Some(ref cmd) = config.command {
            check_package_execution(config, cmd, &config.args, &mut findings);
        }

        // Check for known vulnerable or suspicious package patterns
        check_known_risks(config, &mut findings);

        // Check for unsigned/unverified remote code execution
        check_remote_code(config, &mut findings);

        // Check for rug pull indicators (tool hash pinning absence)
        check_rug_pull_risk(config, &mut findings);

        findings
    }
}

fn check_package_execution(
    config: &McpServerConfig,
    cmd: &str,
    args: &[String],
    findings: &mut Vec<Finding>,
) {
    let cmd_base = cmd.rsplit('/').next().unwrap_or(cmd);

    // npx runs packages without explicit install -- supply chain risk
    if cmd_base == "npx" {
        let package = args.first().map(|a| a.as_str()).unwrap_or("unknown");
        findings.push(Finding {
            server_name: config.name.clone(),
            severity: Severity::Medium,
            category: OwaspCategory::MCP04,
            message: format!(
                "Server runs via npx ('{}') -- package fetched at runtime without lockfile verification",
                package
            ),
            location: Some("command".to_string()),
            remediation: Some(
                "Pin the package version explicitly (e.g., npx package@1.2.3). Better: install locally and run directly."
                    .to_string(),
            ),
        });

        // Check if the npx package has a version pin
        if let Some(pkg) = args.first() {
            if !pkg.contains('@') || pkg.ends_with("@latest") {
                findings.push(Finding {
                    server_name: config.name.clone(),
                    severity: Severity::High,
                    category: OwaspCategory::MCP04,
                    message: format!(
                        "Package '{}' has no version pin -- vulnerable to supply chain substitution",
                        pkg
                    ),
                    location: Some("args[0]".to_string()),
                    remediation: Some(
                        "Pin to exact version: npx package@1.2.3".to_string(),
                    ),
                });
            }
        }
    }

    // pip/pipx install at runtime
    if cmd_base == "pipx" || cmd_base == "pip" || cmd_base == "pip3" {
        findings.push(Finding {
            server_name: config.name.clone(),
            severity: Severity::Medium,
            category: OwaspCategory::MCP04,
            message: "Server installs Python package at runtime -- verify package integrity"
                .to_string(),
            location: Some("command".to_string()),
            remediation: Some(
                "Install packages in advance with pinned versions and hash verification (pip install --require-hashes)."
                    .to_string(),
            ),
        });
    }

    // Docker with :latest tag
    if cmd_base == "docker" {
        let full_args = args.join(" ");
        if full_args.contains(":latest") || (!full_args.contains(':') && full_args.contains("run")) {
            findings.push(Finding {
                server_name: config.name.clone(),
                severity: Severity::Medium,
                category: OwaspCategory::MCP04,
                message: "Docker image uses :latest tag or no tag -- unpinned image version"
                    .to_string(),
                location: Some("args".to_string()),
                remediation: Some(
                    "Pin Docker images to specific SHA256 digests or version tags".to_string(),
                ),
            });
        }
    }
}

fn check_known_risks(config: &McpServerConfig, findings: &mut Vec<Finding>) {
    let raw = config.raw_json.to_string().to_lowercase();

    // Check for known problematic patterns
    let risky_patterns: Vec<(Regex, &str, Severity)> = vec![
        (
            Regex::new(r"(?i)curl\s+.*\|\s*(sh|bash|python)").unwrap(),
            "Pipe-to-shell installation pattern (curl | sh)",
            Severity::Critical,
        ),
        (
            Regex::new(r"(?i)wget\s+.*\|\s*(sh|bash|python)").unwrap(),
            "Pipe-to-shell installation pattern (wget | sh)",
            Severity::Critical,
        ),
        (
            Regex::new(r"(?i)eval\s*\(.*https?://").unwrap(),
            "Remote code evaluation from URL",
            Severity::Critical,
        ),
    ];

    for (pattern, message, severity) in &risky_patterns {
        if pattern.is_match(&raw) {
            findings.push(Finding {
                server_name: config.name.clone(),
                severity: *severity,
                category: OwaspCategory::MCP04,
                message: message.to_string(),
                location: Some("config".to_string()),
                remediation: Some(
                    "Never pipe remote scripts directly to shell. Download, verify hash, then execute."
                        .to_string(),
                ),
            });
        }
    }
}

fn check_remote_code(config: &McpServerConfig, findings: &mut Vec<Finding>) {
    let all_args = config.args.join(" ");
    let raw = config.raw_json.to_string();

    // Check for GitHub raw URLs (unsigned, mutable)
    let github_raw = Regex::new(r"https?://raw\.githubusercontent\.com/").unwrap();
    if github_raw.is_match(&all_args) || github_raw.is_match(&raw) {
        findings.push(Finding {
            server_name: config.name.clone(),
            severity: Severity::High,
            category: OwaspCategory::MCP04,
            message: "References raw GitHub content -- mutable, unsigned, can be changed by repo owner"
                .to_string(),
            location: Some("args/config".to_string()),
            remediation: Some(
                "Pin to specific commit SHA instead of branch references. Verify content hash."
                    .to_string(),
            ),
        });
    }

    // Check for remote URLs in args that might download code
    let remote_url = Regex::new(r"https?://[^\s]+\.(js|py|sh|ts|rb|exe|bin)").unwrap();
    if remote_url.is_match(&all_args) {
        findings.push(Finding {
            server_name: config.name.clone(),
            severity: Severity::High,
            category: OwaspCategory::MCP04,
            message: "Arguments reference remote executable/script URL".to_string(),
            location: Some("args".to_string()),
            remediation: Some(
                "Download scripts in advance, verify integrity, and reference local copies"
                    .to_string(),
            ),
        });
    }
}

fn check_rug_pull_risk(config: &McpServerConfig, findings: &mut Vec<Finding>) {
    // Check if tools have any hash/integrity pinning
    if !config.tools.is_empty() {
        let raw = config.raw_json.to_string().to_lowercase();
        let has_pinning = raw.contains("hash") || raw.contains("integrity") || raw.contains("checksum") || raw.contains("pin");

        if !has_pinning {
            findings.push(Finding {
                server_name: config.name.clone(),
                severity: Severity::Low,
                category: OwaspCategory::MCP04,
                message: "No tool definition pinning detected -- server could change tool behavior silently"
                    .to_string(),
                location: Some("tools".to_string()),
                remediation: Some(
                    "Consider using tool definition hashing (e.g., Invariant's tool pinning) to detect silent changes to tool descriptions."
                        .to_string(),
                ),
            });
        }
    }
}
