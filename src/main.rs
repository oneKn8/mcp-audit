mod cli;
mod config;
mod finding;
mod output;
mod scanner;
mod checks;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands};

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            path,
            format,
            fail_on,
        } => {
            let configs = config::load_configs(&path)?;

            if configs.is_empty() {
                output::print_no_configs(&path);
                return Ok(());
            }

            let findings = scanner::scan_all(&configs);

            match format.as_str() {
                "json" => output::print_json(&findings),
                _ => output::print_terminal(&findings),
            };

            if let Some(ref severity) = fail_on {
                let threshold = finding::Severity::from_str(severity);
                let has_violation = findings
                    .iter()
                    .flat_map(|r| &r.findings)
                    .any(|f| f.severity >= threshold);
                if has_violation {
                    std::process::exit(1);
                }
            }
        }
    }

    Ok(())
}
