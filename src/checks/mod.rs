pub mod mcp01_secrets;
pub mod mcp03_tool_poisoning;
pub mod mcp05_command_injection;
pub mod mcp07_auth;

use crate::config::McpServerConfig;
use crate::finding::Finding;

/// A security check that produces zero or more findings.
pub trait Check {
    fn run(&self, config: &McpServerConfig) -> Vec<Finding>;
}

/// Run all registered checks against a server config.
pub fn run_all_checks(config: &McpServerConfig) -> Vec<Finding> {
    let checks: Vec<Box<dyn Check>> = vec![
        Box::new(mcp01_secrets::SecretExposureCheck),
        Box::new(mcp03_tool_poisoning::ToolPoisoningCheck),
        Box::new(mcp05_command_injection::CommandInjectionCheck),
        Box::new(mcp07_auth::AuthCheck),
    ];

    let mut findings = Vec::new();
    for check in &checks {
        findings.extend(check.run(config));
    }
    findings
}
