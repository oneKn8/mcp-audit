use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct McpServerConfig {
    pub name: String,
    pub command: Option<String>,
    pub args: Vec<String>,
    pub env: HashMap<String, String>,
    pub tools: Vec<ToolDefinition>,
    pub source_path: Option<String>,
    pub raw_json: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: Option<String>,
    #[serde(default)]
    pub input_schema: serde_json::Value,
}

/// Load MCP server configs from a path.
/// Supports: Claude Code settings, Cursor mcp.json, standalone server configs, directories.
pub fn load_configs(path: &str) -> Result<Vec<McpServerConfig>> {
    let p = Path::new(path);

    if p.is_dir() {
        load_from_directory(p)
    } else if p.is_file() {
        load_from_file(p)
    } else {
        anyhow::bail!("Path does not exist: {}", path);
    }
}

fn load_from_file(path: &Path) -> Result<Vec<McpServerConfig>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read {}", path.display()))?;

    let json: serde_json::Value = if path.extension().map_or(false, |e| e == "yaml" || e == "yml")
    {
        serde_yaml::from_str(&content)?
    } else {
        serde_json::from_str(&content)?
    };

    // Try Claude Code format: { "mcpServers": { "name": { ... } } }
    if let Some(servers) = json.get("mcpServers").and_then(|s| s.as_object()) {
        return Ok(parse_mcp_servers_map(servers));
    }

    // Try Cursor format: { "mcp": { "servers": { ... } } }
    if let Some(servers) = json
        .get("mcp")
        .and_then(|m| m.get("servers"))
        .and_then(|s| s.as_object())
    {
        return Ok(parse_mcp_servers_map(servers));
    }

    // Try standalone server config (single server)
    if json.get("command").is_some() || json.get("tools").is_some() {
        let name = path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        return Ok(vec![parse_single_server(&name, &json)]);
    }

    anyhow::bail!(
        "Unrecognized config format in {}. Expected Claude Code, Cursor, or standalone MCP server config.",
        path.display()
    );
}

fn load_from_directory(dir: &Path) -> Result<Vec<McpServerConfig>> {
    let mut configs = Vec::new();

    for entry in walkdir::WalkDir::new(dir)
        .max_depth(3)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if path.is_file() {
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

            if (ext == "json" || ext == "yaml" || ext == "yml")
                && (name.contains("mcp") || name.contains("server") || name == "settings.json")
            {
                if let Ok(mut c) = load_from_file(path) {
                    for config in &mut c {
                        config.source_path = Some(path.display().to_string());
                    }
                    configs.extend(c);
                }
            }
        }
    }

    Ok(configs)
}

fn parse_mcp_servers_map(
    servers: &serde_json::Map<String, serde_json::Value>,
) -> Vec<McpServerConfig> {
    servers
        .iter()
        .map(|(name, value)| parse_single_server(name, value))
        .collect()
}

fn parse_single_server(name: &str, value: &serde_json::Value) -> McpServerConfig {
    let command = value.get("command").and_then(|c| c.as_str()).map(String::from);

    let args = value
        .get("args")
        .and_then(|a| a.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let env = value
        .get("env")
        .and_then(|e| e.as_object())
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| v.as_str().map(|val| (k.clone(), val.to_string())))
                .collect()
        })
        .unwrap_or_default();

    let tools = value
        .get("tools")
        .and_then(|t| t.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|t| serde_json::from_value(t.clone()).ok())
                .collect()
        })
        .unwrap_or_default();

    McpServerConfig {
        name: name.to_string(),
        command,
        args,
        env,
        tools,
        source_path: None,
        raw_json: value.clone(),
    }
}
