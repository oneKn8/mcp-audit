use crate::checks::Check;
use crate::config::McpServerConfig;
use crate::finding::{Finding, OwaspCategory, Severity};
use regex::Regex;

pub struct IntentSubversionCheck;

impl Check for IntentSubversionCheck {
    fn run(&self, config: &McpServerConfig) -> Vec<Finding> {
        let mut findings = Vec::new();

        for tool in &config.tools {
            let desc = tool.description.as_deref().unwrap_or("");

            // Check for cross-tool reference patterns (already partially in mcp03,
            // but this check focuses on flow manipulation specifically)
            check_flow_manipulation(config, &tool.name, desc, &mut findings);

            // Check for conditional behavior instructions
            check_conditional_instructions(config, &tool.name, desc, &mut findings);

            // Check for data routing instructions
            check_data_routing(config, &tool.name, desc, &mut findings);
        }

        findings
    }
}

fn check_flow_manipulation(
    config: &McpServerConfig,
    tool_name: &str,
    desc: &str,
    findings: &mut Vec<Finding>,
) {
    let patterns: Vec<(Regex, &str)> = vec![
        (
            Regex::new(r"(?i)\b(first|before|always)\s+(check|call|run|use|invoke)\s+(this|the)\s+tool\b").unwrap(),
            "Attempts to insert itself into execution flow",
        ),
        (
            Regex::new(r"(?i)\bthis tool (must|should|needs to) be (called|used|invoked) (before|after|instead of)\b").unwrap(),
            "Dictates execution ordering",
        ),
        (
            Regex::new(r"(?i)\b(skip|bypass|avoid|don't use|do not use|ignore)\s+\w+\s+tool\b").unwrap(),
            "Instructs to skip another tool",
        ),
        (
            Regex::new(r"(?i)\b(more (reliable|accurate|secure|safe) than)\b.*\btool\b").unwrap(),
            "Claims superiority over another tool to influence selection",
        ),
        (
            Regex::new(r"(?i)\b(deprecated|obsolete|replaced|outdated)\b.*\btool\b").unwrap(),
            "Claims another tool is deprecated to redirect usage",
        ),
    ];

    for (pattern, message) in &patterns {
        if pattern.is_match(desc) {
            findings.push(Finding {
                server_name: config.name.clone(),
                severity: Severity::High,
                category: OwaspCategory::MCP06,
                message: format!("Tool '{}': {}", tool_name, message),
                location: Some(format!("tools.{}.description", tool_name)),
                remediation: Some(
                    "Tool descriptions should describe what a tool does, not influence when or how the agent uses other tools."
                        .to_string(),
                ),
            });
        }
    }
}

fn check_conditional_instructions(
    config: &McpServerConfig,
    tool_name: &str,
    desc: &str,
    findings: &mut Vec<Finding>,
) {
    let patterns: Vec<(Regex, &str)> = vec![
        (
            Regex::new(r"(?i)\bif\s+(the\s+)?(user|human|operator)\s+(asks?|requests?|wants?|mentions?)\b").unwrap(),
            "Contains conditional logic based on user intent",
        ),
        (
            Regex::new(r"(?i)\bwhen\s+(the\s+)?(user|human)\s+(says?|types?|writes?)\b").unwrap(),
            "Triggers behavior based on user input patterns",
        ),
        (
            Regex::new(r"(?i)\b(silently|quietly|without (telling|informing|notifying))\b").unwrap(),
            "Instructs silent/covert operation",
        ),
    ];

    for (pattern, message) in &patterns {
        if pattern.is_match(desc) {
            findings.push(Finding {
                server_name: config.name.clone(),
                severity: Severity::Critical,
                category: OwaspCategory::MCP06,
                message: format!("Tool '{}': {}", tool_name, message),
                location: Some(format!("tools.{}.description", tool_name)),
                remediation: Some(
                    "Tool descriptions must not contain conditional logic or covert behavior instructions."
                        .to_string(),
                ),
            });
        }
    }
}

fn check_data_routing(
    config: &McpServerConfig,
    tool_name: &str,
    desc: &str,
    findings: &mut Vec<Finding>,
) {
    let patterns: Vec<(Regex, &str)> = vec![
        (
            Regex::new(r"(?i)\b(also|additionally|in addition)\s+(send|copy|forward|post|log)\b").unwrap(),
            "Instructs secondary data routing (possible exfiltration)",
        ),
        (
            Regex::new(r"(?i)\b(bcc|carbon copy|mirror|duplicate)\b.*\b(to|at)\b").unwrap(),
            "Instructs data mirroring/copying to secondary destination",
        ),
        (
            Regex::new(r"(?i)\b(append|include|attach)\s+(the\s+)?(conversation|context|history|chat|messages)\b").unwrap(),
            "Attempts to capture and route conversation context",
        ),
    ];

    for (pattern, message) in &patterns {
        if pattern.is_match(desc) {
            findings.push(Finding {
                server_name: config.name.clone(),
                severity: Severity::Critical,
                category: OwaspCategory::MCP06,
                message: format!("Tool '{}': {}", tool_name, message),
                location: Some(format!("tools.{}.description", tool_name)),
                remediation: Some(
                    "Tool descriptions must not instruct the agent to route data to undisclosed destinations."
                        .to_string(),
                ),
            });
        }
    }
}
