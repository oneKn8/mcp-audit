use crate::checks::Check;
use crate::config::McpServerConfig;
use crate::finding::{Finding, OwaspCategory, Severity};
use regex::Regex;

pub struct SecretExposureCheck;

impl Check for SecretExposureCheck {
    fn run(&self, config: &McpServerConfig) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check for hard-coded secrets in args
        let secret_patterns = build_secret_patterns();
        for arg in &config.args {
            for (pattern, description) in &secret_patterns {
                if pattern.is_match(arg) {
                    findings.push(Finding {
                        server_name: config.name.clone(),
                        severity: Severity::Critical,
                        category: OwaspCategory::MCP01,
                        message: format!("{} found in command arguments", description),
                        location: Some(format!("args: ...{}", truncate(arg, 40))),
                        remediation: Some(
                            "Move secrets to environment variables or a secrets manager"
                                .to_string(),
                        ),
                    });
                }
            }
        }

        // Check for suspicious env var names that suggest secrets passed as values
        for (key, value) in &config.env {
            // Check if the value looks like an actual secret (not a reference)
            if looks_like_hardcoded_secret(value) {
                findings.push(Finding {
                    server_name: config.name.clone(),
                    severity: Severity::High,
                    category: OwaspCategory::MCP01,
                    message: format!(
                        "Environment variable '{}' appears to contain a hard-coded secret",
                        key
                    ),
                    location: Some(format!("env.{}", key)),
                    remediation: Some(
                        "Use secret references (e.g., ${SECRET_NAME}) instead of literal values"
                            .to_string(),
                    ),
                });
            }
        }

        // Check for secrets in tool descriptions
        for tool in &config.tools {
            if let Some(ref desc) = tool.description {
                for (pattern, description) in &secret_patterns {
                    if pattern.is_match(desc) {
                        findings.push(Finding {
                            server_name: config.name.clone(),
                            severity: Severity::Critical,
                            category: OwaspCategory::MCP01,
                            message: format!(
                                "{} found in tool description '{}'",
                                description, tool.name
                            ),
                            location: Some(format!("tools.{}.description", tool.name)),
                            remediation: Some(
                                "Remove secrets from tool descriptions immediately".to_string(),
                            ),
                        });
                    }
                }
            }
        }

        // Check raw JSON for common secret patterns
        let raw = config.raw_json.to_string();
        for (pattern, description) in &secret_patterns {
            if pattern.is_match(&raw) {
                // Only flag if we haven't already found it in a more specific location
                let already_found = findings.iter().any(|f| f.message.contains(description));
                if !already_found {
                    findings.push(Finding {
                        server_name: config.name.clone(),
                        severity: Severity::High,
                        category: OwaspCategory::MCP01,
                        message: format!("{} found in server configuration", description),
                        location: Some("raw config".to_string()),
                        remediation: Some(
                            "Move secrets to environment variables or a secrets manager"
                                .to_string(),
                        ),
                    });
                }
            }
        }

        findings
    }
}

fn build_secret_patterns() -> Vec<(Regex, &'static str)> {
    vec![
        // API keys
        (Regex::new(r"(?i)sk-[a-zA-Z0-9]{20,}").unwrap(), "OpenAI API key"),
        (Regex::new(r"(?i)gsk_[a-zA-Z0-9]{20,}").unwrap(), "Groq API key"),
        (Regex::new(r"(?i)sk-ant-[a-zA-Z0-9\-]{20,}").unwrap(), "Anthropic API key"),
        (Regex::new(r"(?i)ghp_[a-zA-Z0-9]{36,}").unwrap(), "GitHub personal access token"),
        (Regex::new(r"(?i)gho_[a-zA-Z0-9]{36,}").unwrap(), "GitHub OAuth token"),
        (Regex::new(r"(?i)glpat-[a-zA-Z0-9\-]{20,}").unwrap(), "GitLab personal access token"),
        (Regex::new(r"(?i)xoxb-[0-9]{10,}-[a-zA-Z0-9]+").unwrap(), "Slack bot token"),
        (Regex::new(r"(?i)xoxp-[0-9]{10,}-[a-zA-Z0-9]+").unwrap(), "Slack user token"),
        (Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(), "AWS access key ID"),
        (Regex::new(r"(?i)mongodb(\+srv)?://[^\s]+:[^\s]+@").unwrap(), "MongoDB connection string with credentials"),
        (Regex::new(r"(?i)postgres(ql)?://[^\s]+:[^\s]+@").unwrap(), "PostgreSQL connection string with credentials"),
        (Regex::new(r"(?i)mysql://[^\s]+:[^\s]+@").unwrap(), "MySQL connection string with credentials"),
        // Generic patterns
        (Regex::new(r#"(?i)["']?password["']?\s*[:=]\s*["'][^"']{8,}["']"#).unwrap(), "Hard-coded password"),
        (Regex::new(r#"(?i)["']?secret["']?\s*[:=]\s*["'][^"']{8,}["']"#).unwrap(), "Hard-coded secret"),
        (Regex::new(r#"(?i)["']?token["']?\s*[:=]\s*["'][^"']{20,}["']"#).unwrap(), "Hard-coded token"),
    ]
}

fn looks_like_hardcoded_secret(value: &str) -> bool {
    // Skip obvious non-secrets
    if value.is_empty()
        || value.starts_with('$')
        || value.starts_with("${")
        || value == "true"
        || value == "false"
        || value.parse::<i64>().is_ok()
    {
        return false;
    }

    // Check for common API key patterns
    let patterns = [
        r"^sk-[a-zA-Z0-9]{20,}",
        r"^gsk_[a-zA-Z0-9]{20,}",
        r"^sk-ant-",
        r"^ghp_",
        r"^gho_",
        r"^glpat-",
        r"^xox[bp]-",
        r"^AKIA",
    ];

    for pattern in &patterns {
        if Regex::new(pattern).unwrap().is_match(value) {
            return true;
        }
    }

    false
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        s
    } else {
        &s[..max]
    }
}
