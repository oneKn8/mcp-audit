use crate::finding::{ScanResult, Severity};
use colored::*;

pub fn print_terminal(results: &[ScanResult]) -> i32 {
    println!();
    println!(
        "  {}  v{}",
        "mcp-audit".bold(),
        env!("CARGO_PKG_VERSION")
    );
    println!();

    let total_servers = results.len();
    println!(
        "  Scanning {} configured MCP server{}...",
        total_servers,
        if total_servers == 1 { "" } else { "s" }
    );
    println!();

    let mut total_findings = 0;
    let mut critical = 0;
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;
    let mut pass = 0;

    for result in results {
        if result.findings.is_empty() {
            println!("  {} {}", "[PASS]".green().bold(), result.server_name.bold());
            println!("    No findings");
            println!();
            pass += 1;
        } else {
            let severity_label = match result.max_severity() {
                Some(Severity::Critical) => "[CRITICAL]".red().bold(),
                Some(Severity::High) => "[HIGH]".yellow().bold(),
                Some(Severity::Medium) => "[MEDIUM]".blue().bold(),
                Some(Severity::Low) => "[LOW]".dimmed().bold(),
                None => "[PASS]".green().bold(),
            };

            println!("  {} {}", severity_label, result.server_name.bold());

            for finding in &result.findings {
                let cat = format!("{}", finding.category).dimmed();
                let msg = &finding.message;
                let severity_color = match finding.severity {
                    Severity::Critical => msg.red(),
                    Severity::High => msg.yellow(),
                    Severity::Medium => msg.blue(),
                    Severity::Low => msg.dimmed(),
                };
                println!("    {}  {}", cat, severity_color);

                if let Some(ref loc) = finding.location {
                    println!("         {}", loc.dimmed());
                }

                match finding.severity {
                    Severity::Critical => critical += 1,
                    Severity::High => high += 1,
                    Severity::Medium => medium += 1,
                    Severity::Low => low += 1,
                }
                total_findings += 1;
            }
            println!();
        }
    }

    // Summary
    println!("  {}", "---".dimmed());
    println!(
        "  Summary: {} server{} scanned",
        total_servers,
        if total_servers == 1 { "" } else { "s" }
    );

    let mut parts = Vec::new();
    if critical > 0 {
        parts.push(format!("{} critical", critical).red().to_string());
    }
    if high > 0 {
        parts.push(format!("{} high", high).yellow().to_string());
    }
    if medium > 0 {
        parts.push(format!("{} medium", medium).blue().to_string());
    }
    if low > 0 {
        parts.push(format!("{} low", low).to_string());
    }
    if pass > 0 {
        parts.push(format!("{} pass", pass).green().to_string());
    }

    println!("    {}", parts.join(" | "));
    println!("    {} total findings", total_findings);
    println!();

    0
}

pub fn print_json(results: &[ScanResult]) -> i32 {
    let json = serde_json::to_string_pretty(results).unwrap_or_else(|_| "[]".to_string());
    println!("{}", json);
    0
}

pub fn print_no_configs(path: &str) {
    eprintln!();
    eprintln!(
        "  {} No MCP server configurations found in: {}",
        "warning:".yellow().bold(),
        path
    );
    eprintln!();
    eprintln!("  Supported formats:");
    eprintln!("    - Claude Code: ~/.claude/settings.json");
    eprintln!("    - Cursor:      ~/.cursor/mcp.json");
    eprintln!("    - Standalone:   server.json / server.yaml");
    eprintln!("    - Directory:    ./mcp-servers/");
    eprintln!();
}
