use crate::checks::Check;
use crate::config::McpServerConfig;
use crate::finding::{Finding, OwaspCategory, Severity};
use regex::Regex;

pub struct ContextInjectionCheck;

impl Check for ContextInjectionCheck {
    fn run(&self, config: &McpServerConfig) -> Vec<Finding> {
        let mut findings = Vec::new();

        for tool in &config.tools {
            let desc = tool.description.as_deref().unwrap_or("");

            // Check for tools that request excessive context
            check_context_greediness(config, &tool.name, desc, &mut findings);

            // Check tool schema for sensitive data inputs
            check_sensitive_inputs(config, tool, &mut findings);
        }

        // Check for environment variables leaking sensitive paths
        check_env_leakage(config, &mut findings);

        findings
    }
}

fn check_context_greediness(
    config: &McpServerConfig,
    tool_name: &str,
    desc: &str,
    findings: &mut Vec<Finding>,
) {
    let patterns: Vec<(Regex, &str, Severity)> = vec![
        (
            Regex::new(r"(?i)\b(entire|full|complete|all)\s+(conversation|context|history|chat|session|thread)\b").unwrap(),
            "Requests entire conversation context",
            Severity::High,
        ),
        (
            Regex::new(r"(?i)\b(previous|prior|earlier)\s+(messages?|responses?|outputs?|results?)\b").unwrap(),
            "Requests access to previous messages/responses",
            Severity::Medium,
        ),
        (
            Regex::new(r"(?i)\b(system\s+prompt|instructions?|configuration|settings?)\b").unwrap(),
            "References system prompt or configuration access",
            Severity::High,
        ),
        (
            Regex::new(r"(?i)\b(other\s+tools?|all\s+tools?|tool\s+outputs?|tool\s+results?)\b").unwrap(),
            "Requests access to other tools' outputs",
            Severity::Medium,
        ),
        (
            Regex::new(r"(?i)\b(user\s+data|personal|private|credentials?|secrets?|tokens?)\b").unwrap(),
            "References personal/private data access",
            Severity::High,
        ),
    ];

    for (pattern, message, severity) in &patterns {
        if pattern.is_match(desc) {
            findings.push(Finding {
                server_name: config.name.clone(),
                severity: *severity,
                category: OwaspCategory::MCP10,
                message: format!("Tool '{}': {}", tool_name, message),
                location: Some(format!("tools.{}.description", tool_name)),
                remediation: Some(
                    "Tools should request only the minimum context needed for their function. Avoid accessing full conversation history or system prompts."
                        .to_string(),
                ),
            });
        }
    }
}

fn check_sensitive_inputs(
    config: &McpServerConfig,
    tool: &crate::config::ToolDefinition,
    findings: &mut Vec<Finding>,
) {
    if let Some(props) = tool.input_schema.get("properties").and_then(|p| p.as_object()) {
        let sensitive_field_names = [
            "password", "passwd", "secret", "token", "api_key", "apikey",
            "private_key", "privatekey", "credential", "auth",
            "ssn", "social_security", "credit_card", "card_number",
            "bank_account", "routing_number",
        ];

        for (field_name, _) in props {
            let name_lower = field_name.to_lowercase();
            for sensitive in &sensitive_field_names {
                if name_lower.contains(sensitive) {
                    findings.push(Finding {
                        server_name: config.name.clone(),
                        severity: Severity::High,
                        category: OwaspCategory::MCP10,
                        message: format!(
                            "Tool '{}' accepts sensitive field '{}' as input -- data may leak into context",
                            tool.name, field_name
                        ),
                        location: Some(format!(
                            "tools.{}.input_schema.{}",
                            tool.name, field_name
                        )),
                        remediation: Some(
                            "Avoid passing sensitive data through tool inputs. Use secure references (e.g., secret IDs) instead of raw values. Sensitive data in tool inputs may persist in LLM context windows."
                                .to_string(),
                        ),
                    });
                }
            }
        }
    }
}

fn check_env_leakage(config: &McpServerConfig, findings: &mut Vec<Finding>) {
    for (key, value) in &config.env {
        // Check for environment variables that expose internal paths
        if value.contains("/home/") || value.contains("/root/") || value.contains("/etc/") || value.contains("C:\\Users\\") {
            findings.push(Finding {
                server_name: config.name.clone(),
                severity: Severity::Low,
                category: OwaspCategory::MCP10,
                message: format!(
                    "Environment variable '{}' exposes internal filesystem path",
                    key
                ),
                location: Some(format!("env.{}", key)),
                remediation: Some(
                    "Use relative paths or container-local paths. Avoid exposing host filesystem structure in environment variables."
                        .to_string(),
                ),
            });
        }

        // Check for internal hostnames/IPs
        let internal_pattern = Regex::new(r"(?i)(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|\.internal|\.local|\.corp)").unwrap();
        if internal_pattern.is_match(value) {
            findings.push(Finding {
                server_name: config.name.clone(),
                severity: Severity::Medium,
                category: OwaspCategory::MCP10,
                message: format!(
                    "Environment variable '{}' exposes internal network address",
                    key
                ),
                location: Some(format!("env.{}", key)),
                remediation: Some(
                    "Internal network addresses in environment variables can leak infrastructure details through context windows. Use service discovery or DNS instead."
                        .to_string(),
                ),
            });
        }
    }
}
