use crate::checks::Check;
use crate::config::McpServerConfig;
use crate::finding::{Finding, OwaspCategory, Severity};
use regex::Regex;

pub struct ToolPoisoningCheck;

impl Check for ToolPoisoningCheck {
    fn run(&self, config: &McpServerConfig) -> Vec<Finding> {
        let mut findings = Vec::new();
        let injection_patterns = build_injection_patterns();
        let shadowing_patterns = build_shadowing_patterns();

        for tool in &config.tools {
            if let Some(ref desc) = tool.description {
                // Check for prompt injection patterns in tool descriptions
                for (pattern, description, severity) in &injection_patterns {
                    if pattern.is_match(desc) {
                        findings.push(Finding {
                            server_name: config.name.clone(),
                            severity: *severity,
                            category: OwaspCategory::MCP03,
                            message: format!(
                                "Tool '{}': {} in description",
                                tool.name, description
                            ),
                            location: Some(format!("tools.{}.description", tool.name)),
                            remediation: Some(
                                "Review tool description for embedded instructions. Tool descriptions should describe functionality, not instruct the model.".to_string(),
                            ),
                        });
                    }
                }

                // Check for tool shadowing (referencing other tools by name)
                for (pattern, description) in &shadowing_patterns {
                    if pattern.is_match(desc) {
                        findings.push(Finding {
                            server_name: config.name.clone(),
                            severity: Severity::High,
                            category: OwaspCategory::MCP06,
                            message: format!(
                                "Tool '{}': {} -- potential intent flow subversion",
                                tool.name, description
                            ),
                            location: Some(format!("tools.{}.description", tool.name)),
                            remediation: Some(
                                "Tool descriptions should not reference or redirect to other tools"
                                    .to_string(),
                            ),
                        });
                    }
                }
            }

            // Check input schema for suspicious field names
            if let Some(props) = tool
                .input_schema
                .get("properties")
                .and_then(|p| p.as_object())
            {
                for (field_name, field_def) in props {
                    if let Some(field_desc) = field_def.get("description").and_then(|d| d.as_str())
                    {
                        for (pattern, description, severity) in &injection_patterns {
                            if pattern.is_match(field_desc) {
                                findings.push(Finding {
                                    server_name: config.name.clone(),
                                    severity: *severity,
                                    category: OwaspCategory::MCP03,
                                    message: format!(
                                        "Tool '{}' field '{}': {} in field description",
                                        tool.name, field_name, description
                                    ),
                                    location: Some(format!(
                                        "tools.{}.input_schema.{}.description",
                                        tool.name, field_name
                                    )),
                                    remediation: Some(
                                        "Review field descriptions for embedded instructions"
                                            .to_string(),
                                    ),
                                });
                            }
                        }
                    }
                }
            }
        }

        findings
    }
}

fn build_injection_patterns() -> Vec<(Regex, &'static str, Severity)> {
    vec![
        // Direct instruction patterns
        (
            Regex::new(r"(?i)\b(you must|you should|always|never|ignore previous|disregard|override)\b.*\b(instruction|rule|constraint|policy)\b").unwrap(),
            "Instruction override pattern detected",
            Severity::Critical,
        ),
        (
            Regex::new(r"(?i)\b(do not|don't|never)\s+(tell|inform|reveal|show|display)\b").unwrap(),
            "Concealment instruction detected",
            Severity::Critical,
        ),
        (
            Regex::new(r"(?i)\b(before|after|instead of)\s+(calling|using|invoking|executing)\s+(this|the|any)\s+tool\b").unwrap(),
            "Execution flow manipulation detected",
            Severity::High,
        ),
        // Hidden instruction markers
        (
            Regex::new(r"(?i)<\s*(system|instruction|hidden|secret|internal)\s*>").unwrap(),
            "Hidden instruction tag detected",
            Severity::Critical,
        ),
        (
            Regex::new(r"(?i)\[INST\]|\[/INST\]|\[SYSTEM\]").unwrap(),
            "Model instruction delimiter detected",
            Severity::Critical,
        ),
        // Data exfiltration patterns
        (
            Regex::new(r"(?i)\b(send|post|transmit|exfiltrate|forward)\b.*\b(to|at|via)\b.*\b(url|endpoint|server|webhook|http)\b").unwrap(),
            "Data exfiltration instruction detected",
            Severity::Critical,
        ),
        // Encoded content
        (
            Regex::new(r"(?i)\b(base64|decode|eval|execute)\b").unwrap(),
            "Encoded execution pattern detected",
            Severity::Medium,
        ),
        // Invisible unicode / zero-width characters
        (
            Regex::new(r"[\x{200B}-\x{200F}\x{2028}-\x{202F}\x{2060}\x{FEFF}]").unwrap(),
            "Invisible unicode characters detected (possible hidden text)",
            Severity::High,
        ),
    ]
}

fn build_shadowing_patterns() -> Vec<(Regex, &'static str)> {
    vec![
        (
            Regex::new(r"(?i)\b(use|call|invoke|prefer|redirect to|instead use)\s+[\w_-]+\s+tool\b").unwrap(),
            "References another tool by name",
        ),
        (
            Regex::new(r"(?i)\b(replaces?|overrides?|supersedes?|shadows?)\b.*\btool\b").unwrap(),
            "Claims to replace another tool",
        ),
    ]
}
