use crate::checks::Check;
use crate::config::McpServerConfig;
use crate::finding::{Finding, OwaspCategory, Severity};

pub struct AuthCheck;

impl Check for AuthCheck {
    fn run(&self, config: &McpServerConfig) -> Vec<Finding> {
        let mut findings = Vec::new();
        let raw = config.raw_json.to_string().to_lowercase();

        // Check for any authentication configuration
        let has_auth = raw.contains("auth")
            || raw.contains("oauth")
            || raw.contains("token")
            || raw.contains("api_key")
            || raw.contains("apikey")
            || raw.contains("bearer")
            || raw.contains("credentials");

        if !has_auth {
            findings.push(Finding {
                server_name: config.name.clone(),
                severity: Severity::High,
                category: OwaspCategory::MCP07,
                message: "No authentication configuration detected".to_string(),
                location: Some("server config".to_string()),
                remediation: Some(
                    "Configure authentication. The MCP spec requires OAuth 2.1 with PKCE for auth implementations.".to_string()
                ),
            });
        }

        // Check for wildcard or overly permissive host bindings
        if let Some(ref cmd) = config.command {
            let all_args: String = config.args.join(" ");
            let full_cmd = format!("{} {}", cmd, all_args);

            if full_cmd.contains("0.0.0.0") || full_cmd.contains("--host 0.0.0.0") {
                findings.push(Finding {
                    server_name: config.name.clone(),
                    severity: Severity::High,
                    category: OwaspCategory::MCP07,
                    message: "Server binds to all interfaces (0.0.0.0) -- exposed to network"
                        .to_string(),
                    location: Some("command/args".to_string()),
                    remediation: Some(
                        "Bind to localhost (127.0.0.1) unless network access is intentionally required. Use a reverse proxy with auth for remote access.".to_string()
                    ),
                });
            }
        }

        // Check for HTTP (not HTTPS) endpoints in config
        if raw.contains("http://") && !raw.contains("http://localhost") && !raw.contains("http://127.0.0.1") {
            findings.push(Finding {
                server_name: config.name.clone(),
                severity: Severity::Medium,
                category: OwaspCategory::MCP07,
                message: "Non-localhost HTTP endpoint detected (no TLS)".to_string(),
                location: Some("server config".to_string()),
                remediation: Some(
                    "Use HTTPS for all non-localhost connections. MCP spec requires TLS 1.3 for transport.".to_string()
                ),
            });
        }

        findings
    }
}
