use serde::Serialize;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            _ => Severity::Low,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum OwaspCategory {
    MCP01,
    MCP02,
    MCP03,
    MCP04,
    MCP05,
    MCP06,
    MCP07,
    MCP08,
    MCP09,
    MCP10,
}

impl fmt::Display for OwaspCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            OwaspCategory::MCP01 => "MCP01",
            OwaspCategory::MCP02 => "MCP02",
            OwaspCategory::MCP03 => "MCP03",
            OwaspCategory::MCP04 => "MCP04",
            OwaspCategory::MCP05 => "MCP05",
            OwaspCategory::MCP06 => "MCP06",
            OwaspCategory::MCP07 => "MCP07",
            OwaspCategory::MCP08 => "MCP08",
            OwaspCategory::MCP09 => "MCP09",
            OwaspCategory::MCP10 => "MCP10",
        };
        write!(f, "{}", s)
    }
}

impl OwaspCategory {
    pub fn title(&self) -> &'static str {
        match self {
            OwaspCategory::MCP01 => "Token Mismanagement & Secret Exposure",
            OwaspCategory::MCP02 => "Privilege Escalation via Scope Creep",
            OwaspCategory::MCP03 => "Tool Poisoning",
            OwaspCategory::MCP04 => "Supply Chain Attacks",
            OwaspCategory::MCP05 => "Command Injection",
            OwaspCategory::MCP06 => "Intent Flow Subversion",
            OwaspCategory::MCP07 => "Insufficient Authentication",
            OwaspCategory::MCP08 => "Lack of Audit & Telemetry",
            OwaspCategory::MCP09 => "Shadow MCP Servers",
            OwaspCategory::MCP10 => "Context Injection & Over-Sharing",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub server_name: String,
    pub severity: Severity,
    pub category: OwaspCategory,
    pub message: String,
    pub location: Option<String>,
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub server_name: String,
    pub findings: Vec<Finding>,
}

impl ScanResult {
    pub fn max_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }
}
