use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "mcp-audit",
    version,
    about = "Fast, local security scanner for MCP servers. Maps findings to OWASP MCP Top 10."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Scan MCP server configurations and source code for security issues
    Scan {
        /// Path to MCP config file, server directory, or IDE settings
        path: String,

        /// Output format: "terminal" (default) or "json"
        #[arg(short, long, default_value = "terminal")]
        format: String,

        /// Exit with code 1 if any finding meets this severity: critical, high, medium, low
        #[arg(long)]
        fail_on: Option<String>,
    },
}
