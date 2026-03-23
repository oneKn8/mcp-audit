pub mod mcp01_secrets;
pub mod mcp02_privilege;
pub mod mcp03_tool_poisoning;
pub mod mcp04_supply_chain;
pub mod mcp05_command_injection;
pub mod mcp06_intent;
pub mod mcp07_auth;
pub mod mcp08_audit_telemetry;
pub mod mcp09_shadow;
pub mod mcp10_context;

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
        Box::new(mcp02_privilege::PrivilegeEscalationCheck),
        Box::new(mcp03_tool_poisoning::ToolPoisoningCheck),
        Box::new(mcp04_supply_chain::SupplyChainCheck),
        Box::new(mcp05_command_injection::CommandInjectionCheck),
        Box::new(mcp06_intent::IntentSubversionCheck),
        Box::new(mcp07_auth::AuthCheck),
        Box::new(mcp08_audit_telemetry::AuditTelemetryCheck),
        Box::new(mcp09_shadow::ShadowServerCheck),
        Box::new(mcp10_context::ContextInjectionCheck),
    ];

    let mut findings = Vec::new();
    for check in &checks {
        findings.extend(check.run(config));
    }
    findings
}
