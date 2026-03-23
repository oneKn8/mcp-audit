use crate::checks;
use crate::config::McpServerConfig;
use crate::finding::ScanResult;

pub fn scan_all(configs: &[McpServerConfig]) -> Vec<ScanResult> {
    configs
        .iter()
        .map(|config| {
            let findings = checks::run_all_checks(config);
            ScanResult {
                server_name: config.name.clone(),
                findings,
            }
        })
        .collect()
}
