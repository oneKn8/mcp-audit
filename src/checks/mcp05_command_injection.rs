use crate::checks::Check;
use crate::config::McpServerConfig;
use crate::finding::{Finding, OwaspCategory, Severity};
use regex::Regex;

pub struct CommandInjectionCheck;

impl Check for CommandInjectionCheck {
    fn run(&self, config: &McpServerConfig) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check command for dangerous patterns
        if let Some(ref cmd) = config.command {
            check_command_safety(config, cmd, &mut findings);
        }

        // Check args for shell injection indicators
        for (i, arg) in config.args.iter().enumerate() {
            if contains_shell_metacharacters(arg) {
                findings.push(Finding {
                    server_name: config.name.clone(),
                    severity: Severity::High,
                    category: OwaspCategory::MCP05,
                    message: format!("Shell metacharacters in argument {}", i),
                    location: Some(format!("args[{}]", i)),
                    remediation: Some(
                        "Avoid shell metacharacters in arguments. Use array-based execution instead of shell strings.".to_string()
                    ),
                });
            }
        }

        // Check tool definitions for command execution patterns
        for tool in &config.tools {
            if let Some(ref desc) = tool.description {
                let exec_patterns = build_exec_patterns();
                for (pattern, description) in &exec_patterns {
                    if pattern.is_match(desc) {
                        findings.push(Finding {
                            server_name: config.name.clone(),
                            severity: Severity::High,
                            category: OwaspCategory::MCP05,
                            message: format!(
                                "Tool '{}': {} -- potential command injection vector",
                                tool.name, description
                            ),
                            location: Some(format!("tools.{}", tool.name)),
                            remediation: Some(
                                "Ensure all user input is sanitized before passing to shell commands. Use allowlists for permitted commands.".to_string()
                            ),
                        });
                    }
                }
            }

            // Check if tool accepts path or command-like inputs
            if let Some(props) = tool
                .input_schema
                .get("properties")
                .and_then(|p| p.as_object())
            {
                for (field_name, _) in props {
                    let name_lower = field_name.to_lowercase();
                    if name_lower.contains("command")
                        || name_lower.contains("cmd")
                        || name_lower.contains("exec")
                        || name_lower.contains("shell")
                        || name_lower.contains("script")
                    {
                        findings.push(Finding {
                            server_name: config.name.clone(),
                            severity: Severity::High,
                            category: OwaspCategory::MCP05,
                            message: format!(
                                "Tool '{}' accepts '{}' as input -- potential command execution",
                                tool.name, field_name
                            ),
                            location: Some(format!(
                                "tools.{}.input_schema.{}",
                                tool.name, field_name
                            )),
                            remediation: Some(
                                "Validate and sanitize command inputs. Use allowlists for permitted operations.".to_string()
                            ),
                        });
                    }

                    // Path traversal check
                    if name_lower.contains("path")
                        || name_lower.contains("file")
                        || name_lower.contains("dir")
                    {
                        findings.push(Finding {
                            server_name: config.name.clone(),
                            severity: Severity::Medium,
                            category: OwaspCategory::MCP05,
                            message: format!(
                                "Tool '{}' accepts '{}' as input -- verify path traversal protection",
                                tool.name, field_name
                            ),
                            location: Some(format!(
                                "tools.{}.input_schema.{}",
                                tool.name, field_name
                            )),
                            remediation: Some(
                                "Ensure file paths are validated against an allowlist of permitted directories. Reject paths containing '..' or absolute paths outside the sandbox.".to_string()
                            ),
                        });
                    }
                }
            }
        }

        findings
    }
}

fn check_command_safety(config: &McpServerConfig, cmd: &str, findings: &mut Vec<Finding>) {
    // Check for shell invocation
    let shell_commands = ["sh", "bash", "zsh", "cmd", "powershell", "pwsh"];
    let cmd_basename = cmd.rsplit('/').next().unwrap_or(cmd);

    if shell_commands.contains(&cmd_basename) {
        // If the command IS a shell, check if args contain -c (inline execution)
        if config.args.iter().any(|a| a == "-c" || a == "/c") {
            findings.push(Finding {
                server_name: config.name.clone(),
                severity: Severity::High,
                category: OwaspCategory::MCP05,
                message: format!(
                    "Server runs through shell ({} -c) -- high injection risk",
                    cmd_basename
                ),
                location: Some("command".to_string()),
                remediation: Some(
                    "Avoid shell invocation. Execute binaries directly with array arguments."
                        .to_string(),
                ),
            });
        }
    }

    // Check for common dangerous commands
    let dangerous = ["eval", "exec", "system", "popen", "subprocess"];
    for d in &dangerous {
        if cmd.contains(d) {
            findings.push(Finding {
                server_name: config.name.clone(),
                severity: Severity::Medium,
                category: OwaspCategory::MCP05,
                message: format!("Command contains '{}' -- potential code execution", d),
                location: Some("command".to_string()),
                remediation: Some("Review command for injection risks".to_string()),
            });
        }
    }
}

fn contains_shell_metacharacters(s: &str) -> bool {
    let metacharacters = ['|', ';', '&', '$', '`', '(', ')', '{', '}', '<', '>'];
    // Allow common safe patterns like ${VAR}
    let cleaned = Regex::new(r"\$\{[A-Z_]+\}").unwrap().replace_all(s, "");
    cleaned.chars().any(|c| metacharacters.contains(&c))
}

fn build_exec_patterns() -> Vec<(Regex, &'static str)> {
    vec![
        (
            Regex::new(r"(?i)\b(execute|run|spawn|fork)\s+(command|shell|script|process)\b")
                .unwrap(),
            "Describes command execution capability",
        ),
        (
            Regex::new(r"(?i)\b(arbitrary|any|user-provided)\s+(command|code|script)\b").unwrap(),
            "Accepts arbitrary command execution",
        ),
        (
            Regex::new(r"(?i)\bsudo\b").unwrap(),
            "References privileged execution (sudo)",
        ),
        (
            Regex::new(r"(?i)\b(rm\s+-rf|chmod\s+777|curl\s+.*\|\s*sh)\b").unwrap(),
            "Contains dangerous shell pattern",
        ),
    ]
}
