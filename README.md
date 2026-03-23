# mcp-audit

**90% of MCP servers fail basic security checks. This tool finds out why.**

A fast, local, zero-dependency security scanner for MCP (Model Context Protocol) servers. Maps every finding to the [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/). No cloud APIs. No LLM calls. Just static analysis that runs in seconds.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Rust](https://img.shields.io/badge/Rust-000000?style=flat&logo=rust&logoColor=white)

---

## Why

Every developer using Claude Code, Cursor, or Windsurf with MCP servers is running unaudited code with filesystem, database, and cloud access. The ecosystem has 19,000+ servers, 30 CVEs filed in 60 days, and only 2.5% pass basic security review.

Existing scanners require cloud API calls or LLM backends. mcp-audit runs entirely locally in milliseconds.

## Install

```bash
cargo install mcp-audit
```

## Usage

```bash
# Scan a single MCP server config
mcp-audit scan server.json

# Scan your Claude Code MCP config
mcp-audit scan ~/.claude/settings.json

# Scan a Cursor MCP config
mcp-audit scan ~/.cursor/mcp.json

# Scan an MCP server's source code directory
mcp-audit scan ./my-mcp-server/

# JSON output for CI pipelines
mcp-audit scan server.json --format json

# Scan and fail CI if any critical/high findings
mcp-audit scan server.json --fail-on high
```

## What It Checks

Every finding maps to the [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/):

| Check | OWASP | What it detects |
|-------|-------|----------------|
| Secret exposure | MCP01 | Hard-coded API keys, tokens, credentials in configs and source |
| Privilege escalation | MCP02 | Overly broad tool permissions, missing scope constraints |
| Tool poisoning | MCP03 | Prompt injection patterns in tool descriptions and metadata |
| Supply chain | MCP04 | Known vulnerable dependencies, unsigned packages, rug pull indicators |
| Command injection | MCP05 | Unsanitized input in shell commands, exec calls, eval patterns |
| Intent subversion | MCP06 | Tool descriptions that reference or shadow other tools |
| Missing auth | MCP07 | No authentication, weak auth patterns, missing OAuth config |
| No audit trail | MCP08 | Missing logging, no telemetry, no request tracking |
| Shadow servers | MCP09 | Unregistered or undocumented server configurations |
| Context leakage | MCP10 | Sensitive data patterns in context windows, over-permissive reads |

## Output

```
$ mcp-audit scan ~/.claude/settings.json

  mcp-audit v0.1.0

  Scanning 4 configured MCP servers...

  [CRITICAL] my-db-server
    MCP01  Hard-coded database password in config
    MCP05  Shell command constructed from user input (tools/run_query)
    MCP07  No authentication configured

  [HIGH] file-manager
    MCP05  Path traversal possible in tools/read_file (no sanitization)
    MCP01  API key in environment variable name suggests secret exposure

  [MEDIUM] web-fetcher
    MCP03  Tool description contains instruction-like text
    MCP08  No request logging configured

  [PASS] approved-server
    No findings

  Summary: 4 servers scanned
    1 critical | 1 high | 1 medium | 1 pass
    7 findings mapped to 4 OWASP categories
```

## CI Integration

```yaml
# GitHub Actions
- name: Audit MCP servers
  run: |
    cargo install mcp-audit
    mcp-audit scan .mcp/ --format json --fail-on high
```

## How It Works

mcp-audit is pure static analysis. It:

1. Parses MCP server configurations (JSON/YAML) from Claude Code, Cursor, Windsurf, or standalone files
2. Reads tool definitions, descriptions, and metadata
3. Optionally scans server source code directories for vulnerable patterns
4. Applies regex-based and AST-level checks mapped to OWASP MCP Top 10
5. Reports findings with severity, OWASP category, and remediation guidance

No network calls. No AI. No cloud backend. Runs in milliseconds on thousands of servers.

## Compared to Existing Tools

| | mcp-audit | Snyk Agent Scan | Cisco MCP Scanner |
|---|-----------|-----------------|-------------------|
| Fully local | Yes | No (cloud API) | No (LLM API) |
| OWASP mapping | MCP01-10 | Partial | No |
| Source code scan | Yes | No | No |
| CI integration | Native | Yes | No |
| Language | Rust | Python | Python |
| Speed | Milliseconds | Seconds | Seconds |
| Pre-install scan | Yes | Post-install | Post-install |

## License

MIT
