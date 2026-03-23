use crate::checks::Check;
use crate::config::McpServerConfig;
use crate::finding::{Finding, OwaspCategory, Severity};

pub struct PrivilegeEscalationCheck;

impl Check for PrivilegeEscalationCheck {
    fn run(&self, config: &McpServerConfig) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Count total tool capabilities
        let tool_count = config.tools.len();
        let dangerous_capabilities = count_dangerous_capabilities(config);

        // Flag servers with excessive tool count (scope creep indicator)
        if tool_count > 20 {
            findings.push(Finding {
                server_name: config.name.clone(),
                severity: Severity::Medium,
                category: OwaspCategory::MCP02,
                message: format!(
                    "Server exposes {} tools -- large attack surface, review for least privilege",
                    tool_count
                ),
                location: Some("tools".to_string()),
                remediation: Some(
                    "Reduce tool count to only what is necessary. Split into multiple focused servers if needed."
                        .to_string(),
                ),
            });
        }

        // Flag servers with mixed read/write/exec capabilities
        if dangerous_capabilities.has_read && dangerous_capabilities.has_write && dangerous_capabilities.has_exec {
            findings.push(Finding {
                server_name: config.name.clone(),
                severity: Severity::High,
                category: OwaspCategory::MCP02,
                message: "Server has read + write + execute capabilities -- full system access"
                    .to_string(),
                location: Some("tools".to_string()),
                remediation: Some(
                    "Separate read, write, and execute capabilities into distinct servers with independent permissions."
                        .to_string(),
                ),
            });
        }

        // Check for wildcard or overly broad file access patterns
        for tool in &config.tools {
            let tool_json = serde_json::to_string(&tool.input_schema).unwrap_or_default().to_lowercase();
            let desc = tool.description.as_deref().unwrap_or("").to_lowercase();
            let combined = format!("{} {}", desc, tool_json);

            // Check for root/home directory access
            if combined.contains("root") || combined.contains("/home") || combined.contains("/**") || combined.contains("any directory") || combined.contains("any file") || combined.contains("entire filesystem") {
                findings.push(Finding {
                    server_name: config.name.clone(),
                    severity: Severity::High,
                    category: OwaspCategory::MCP02,
                    message: format!(
                        "Tool '{}' appears to have unrestricted filesystem access",
                        tool.name
                    ),
                    location: Some(format!("tools.{}", tool.name)),
                    remediation: Some(
                        "Restrict file access to specific directories using an allowlist. Never allow access to /, /home, or /etc."
                            .to_string(),
                    ),
                });
            }

            // Check for admin/sudo capabilities
            if combined.contains("admin") || combined.contains("sudo") || combined.contains("superuser") || combined.contains("root access") {
                findings.push(Finding {
                    server_name: config.name.clone(),
                    severity: Severity::Critical,
                    category: OwaspCategory::MCP02,
                    message: format!(
                        "Tool '{}' references elevated/admin privileges",
                        tool.name
                    ),
                    location: Some(format!("tools.{}", tool.name)),
                    remediation: Some(
                        "MCP servers should never run with elevated privileges. Use least-privilege service accounts."
                            .to_string(),
                    ),
                });
            }
        }

        // Check env vars for elevated privilege indicators
        for (key, value) in &config.env {
            let k = key.to_lowercase();
            let v = value.to_lowercase();
            if k.contains("sudo") || v.contains("root") || k == "user" && v == "root" {
                findings.push(Finding {
                    server_name: config.name.clone(),
                    severity: Severity::Critical,
                    category: OwaspCategory::MCP02,
                    message: format!(
                        "Environment variable '{}' suggests elevated privileges",
                        key
                    ),
                    location: Some(format!("env.{}", key)),
                    remediation: Some(
                        "Run MCP servers as non-root user with minimal permissions".to_string(),
                    ),
                });
            }
        }

        findings
    }
}

struct Capabilities {
    has_read: bool,
    has_write: bool,
    has_exec: bool,
}

fn count_dangerous_capabilities(config: &McpServerConfig) -> Capabilities {
    let mut caps = Capabilities {
        has_read: false,
        has_write: false,
        has_exec: false,
    };

    let read_keywords = ["read", "get", "fetch", "list", "search", "query", "find", "view"];
    let write_keywords = ["write", "create", "update", "delete", "put", "set", "modify", "insert", "remove", "drop"];
    let exec_keywords = ["execute", "run", "exec", "shell", "command", "spawn", "eval", "script"];

    for tool in &config.tools {
        let name_lower = tool.name.to_lowercase();
        let desc_lower = tool.description.as_deref().unwrap_or("").to_lowercase();
        let combined = format!("{} {}", name_lower, desc_lower);

        if read_keywords.iter().any(|k| combined.contains(k)) {
            caps.has_read = true;
        }
        if write_keywords.iter().any(|k| combined.contains(k)) {
            caps.has_write = true;
        }
        if exec_keywords.iter().any(|k| combined.contains(k)) {
            caps.has_exec = true;
        }
    }

    caps
}
