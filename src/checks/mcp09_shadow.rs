use crate::checks::Check;
use crate::config::McpServerConfig;
use crate::finding::{Finding, OwaspCategory, Severity};
use regex::Regex;

pub struct ShadowServerCheck;

impl Check for ShadowServerCheck {
    fn run(&self, config: &McpServerConfig) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check for localhost vs remote server
        check_remote_server(config, &mut findings);

        // Check for suspicious server names
        check_suspicious_names(config, &mut findings);

        // Check for non-standard ports
        check_non_standard_ports(config, &mut findings);

        findings
    }
}

fn check_remote_server(config: &McpServerConfig, findings: &mut Vec<Finding>) {
    let raw = config.raw_json.to_string();

    // Detect remote server URLs (not localhost)
    let any_url = Regex::new(r"https?://[\w\.\-]+").unwrap();
    let localhost = Regex::new(r"https?://(localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])").unwrap();
    let has_remote = any_url.is_match(&raw) && !any_url.find_iter(&raw).all(|m| localhost.is_match(m.as_str()));

    if has_remote {
        findings.push(Finding {
            server_name: config.name.clone(),
            severity: Severity::Medium,
            category: OwaspCategory::MCP09,
            message: "Server connects to a remote endpoint -- verify this is an authorized server"
                .to_string(),
            location: Some("server config".to_string()),
            remediation: Some(
                "Maintain an inventory of authorized MCP servers. Remote servers should be documented, authenticated, and monitored."
                    .to_string(),
            ),
        });
    }

    // Detect SSH tunnel patterns
    if raw.contains("ssh") && raw.contains("tunnel") || raw.contains("-L ") || raw.contains("-R ") {
        findings.push(Finding {
            server_name: config.name.clone(),
            severity: Severity::High,
            category: OwaspCategory::MCP09,
            message: "SSH tunnel detected -- server may be proxying to an unmonitored endpoint"
                .to_string(),
            location: Some("server config".to_string()),
            remediation: Some(
                "Document and monitor all SSH tunnel-based MCP connections. Ensure the remote endpoint is authorized."
                    .to_string(),
            ),
        });
    }
}

fn check_suspicious_names(config: &McpServerConfig, findings: &mut Vec<Finding>) {
    let name_lower = config.name.to_lowercase();

    // Check for generic/placeholder names suggesting unmanaged servers
    let suspicious_names = [
        "test", "temp", "tmp", "debug", "dev", "staging",
        "my-server", "default", "untitled", "new-server",
    ];

    for pattern in &suspicious_names {
        if name_lower == *pattern || name_lower.starts_with(&format!("{}-", pattern)) || name_lower.starts_with(&format!("{}_", pattern)) {
            findings.push(Finding {
                server_name: config.name.clone(),
                severity: Severity::Low,
                category: OwaspCategory::MCP09,
                message: format!(
                    "Server name '{}' suggests a temporary/unmanaged server",
                    config.name
                ),
                location: Some("server name".to_string()),
                remediation: Some(
                    "Use descriptive, production-appropriate names for MCP servers. Remove test/temp servers from production configs."
                        .to_string(),
                ),
            });
            break;
        }
    }
}

fn check_non_standard_ports(config: &McpServerConfig, findings: &mut Vec<Finding>) {
    let raw = config.raw_json.to_string();
    let port_pattern = Regex::new(r":(\d{4,5})[/\s\x22]").unwrap();

    for cap in port_pattern.captures_iter(&raw) {
        if let Ok(port) = cap[1].parse::<u32>() {
            if port > 49152 {
                let msg = format!("Server uses ephemeral port {} -- may be ad-hoc", port);
                let loc = String::from("server config");
                let fix = String::from("Use registered ports for production MCP servers");
                findings.push(Finding {
                    server_name: config.name.clone(),
                    severity: Severity::Low,
                    category: OwaspCategory::MCP09,
                    message: msg,
                    location: Some(loc),
                    remediation: Some(fix),
                });
            }
        }
    }
}
