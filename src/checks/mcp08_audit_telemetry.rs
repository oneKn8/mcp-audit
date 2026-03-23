use crate::checks::Check;
use crate::config::McpServerConfig;
use crate::finding::{Finding, OwaspCategory, Severity};

pub struct AuditTelemetryCheck;

impl Check for AuditTelemetryCheck {
    fn run(&self, config: &McpServerConfig) -> Vec<Finding> {
        let mut findings = Vec::new();
        let raw = config.raw_json.to_string().to_lowercase();

        // Check for logging configuration
        let has_logging = raw.contains("log")
            || raw.contains("logging")
            || raw.contains("logger")
            || raw.contains("syslog")
            || raw.contains("winston")
            || raw.contains("pino")
            || raw.contains("bunyan");

        // Check for telemetry/monitoring
        let has_telemetry = raw.contains("telemetry")
            || raw.contains("opentelemetry")
            || raw.contains("otel")
            || raw.contains("prometheus")
            || raw.contains("datadog")
            || raw.contains("sentry")
            || raw.contains("metrics")
            || raw.contains("tracing");

        // Check for audit trail
        let has_audit = raw.contains("audit")
            || raw.contains("trail")
            || raw.contains("history")
            || raw.contains("event_log");

        if !has_logging && !has_telemetry {
            findings.push(Finding {
                server_name: config.name.clone(),
                severity: Severity::Medium,
                category: OwaspCategory::MCP08,
                message: "No logging or telemetry configuration detected".to_string(),
                location: Some("server config".to_string()),
                remediation: Some(
                    "Add structured logging (e.g., JSON logs to stdout). For production: integrate OpenTelemetry for distributed tracing of tool calls."
                        .to_string(),
                ),
            });
        }

        if !has_audit {
            // Only flag for servers with write/execute capabilities
            let has_dangerous_tools = config.tools.iter().any(|t| {
                let name = t.name.to_lowercase();
                let desc = t.description.as_deref().unwrap_or("").to_lowercase();
                let combined = format!("{} {}", name, desc);
                combined.contains("write")
                    || combined.contains("delete")
                    || combined.contains("execute")
                    || combined.contains("create")
                    || combined.contains("modify")
                    || combined.contains("send")
            });

            if has_dangerous_tools {
                findings.push(Finding {
                    server_name: config.name.clone(),
                    severity: Severity::Medium,
                    category: OwaspCategory::MCP08,
                    message:
                        "Server has write/execute tools but no audit trail configuration detected"
                            .to_string(),
                    location: Some("server config".to_string()),
                    remediation: Some(
                        "Implement an audit log for all state-changing operations. Record: timestamp, tool name, input parameters (sanitized), caller identity, outcome."
                            .to_string(),
                    ),
                });
            }
        }

        // Check for error reporting
        let has_error_reporting = raw.contains("sentry")
            || raw.contains("bugsnag")
            || raw.contains("rollbar")
            || raw.contains("error_reporting")
            || raw.contains("on_error");

        if !has_error_reporting && config.tools.len() > 5 {
            findings.push(Finding {
                server_name: config.name.clone(),
                severity: Severity::Low,
                category: OwaspCategory::MCP08,
                message: "No error reporting service detected for server with 5+ tools"
                    .to_string(),
                location: Some("server config".to_string()),
                remediation: Some(
                    "Consider adding error reporting (Sentry, Bugsnag) to catch silent failures in production."
                        .to_string(),
                ),
            });
        }

        findings
    }
}
