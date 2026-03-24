# Tyr

**Security, Validation & Standards Layer for AI Development**

<p align="center>
<em>Package Validation, SAST, Audit, and Quality Standards</em>
</p>

Tyr provides security scanning, package validation, and quality standards enforcement.

```
OpenCode / Claude Code / Cursor / ...
    ↓ MCP stdio
Tyr (single Go binary)
    ↓
SQLite + Security Results
```

## Features

- **Package Validation** - CVE checks, license analysis, typosquatting detection
- **SAST Analysis** - Static application security testing with Semgrep
- **Audit Trail** - Complete action logging with risk assessment
- **Standards Enforcement** - Quality gates and compliance checks
- **Scope Enforcement** - Detect and prevent unauthorized file access

## Quick Start

### Install (One-liner)

**macOS / Linux:**
```bash
curl -fsSL https://raw.githubusercontent.com/andragon31/Tyr/main/install.sh | sh
```

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/andragon31/Tyr/main/install.ps1 | iex
```

### Setup Your Agent

| Agent | Command |
|-------|---------|
| OpenCode | `tyr setup opencode` |
| Claude Code | `tyr setup claude-code` |
| Cursor | `tyr setup cursor` |
| Windsurf | `tyr setup windsurf` |

## MCP Tools (22 total)

### Validator Module
| Tool | Description |
|------|-------------|
| `pkg_check` | Validate package existence and CVEs before install |
| `pkg_license` | Check package license and policy compliance |
| `pkg_audit` | Full audit of dependencies for CVEs and licenses |
| `pkg_audit_snapshot` | Get snapshot of current vulnerabilities |
| `pkg_audit_continuous` | Check for new CVEs in existing deps |

### SAST Module
| Tool | Description |
|------|-------------|
| `sast_run` | Run SAST analysis with Semgrep |
| `sast_findings` | List active SAST findings with filters |
| `sast_resolve` | Mark SAST finding as resolved |

### Audit Module
| Tool | Description |
|------|-------------|
| `audit_log` | Log agent action to audit trail |
| `session_audit` | Get complete audit log for session |
| `inject_guard` | Check content for prompt injection patterns |
| `proactive_scan` | Proactively scan files for injections |
| `sanitize` | Strip secrets and private tags from content |

### Standards Module
| Tool | Description |
|------|-------------|
| `standard_run` | Run a specific standard |
| `standard_run_all` | Run all standards, return Quality Snapshot |
| `standard_list` | List configured standards with last result |

### Quality & Scope
| Tool | Description |
|------|-------------|
| `quality_snapshot` | Get most recent Quality Snapshot |
| `scope_violations` | List detected scope violations |

### System
| Tool | Description |
|------|-------------|
| `tyr_stats` | System statistics and health |

## CLI Reference

```bash
tyr setup [agent]   # Setup for an AI agent
tyr init           # Initialize in project
tyr mcp            # Start MCP server
tyr serve [port]   # Start HTTP API
tyr version        # Show version
```

## Usage Examples

### Validate a package before installing
```json
{
  "name": "lodash",
  "ecosystem": "npm"
}
```

### Run security scan
```bash
tyr sast_run --target ./src --rulesets "security"
```

### Check audit log
```bash
tyr session_audit --session_id "ses-123"
```

## Architecture

```
┌─────────────────────────────────────────────┐
│                 OpenCode                     │
│              Claude Code                     │
│                Cursor                        │
└─────────────────┬───────────────────────────┘
                  │ MCP stdio
                  ▼
┌─────────────────────────────────────────────┐
│                   Tyr                        │
├─────────────────────────────────────────────┤
│  Validator │  SAST   │  Audit  │ Standards │
└─────────────────┬───────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────┐
│              SQLite Database                 │
│        (.tyr/tyr.db)                        │
├─────────────────────────────────────────────┤
│  pkg_cache │ sast_findings │ audit_log    │
│  standards_results │ scope_violations     │
└─────────────────────────────────────────────┘
```

## Quality Snapshot

Tyr generates quality snapshots that include:
- Unit test results
- E2E test results
- SAST findings
- Security checks
- Overall quality score (0.0 - 1.0)

This is consumed by **Hati** for checkpoint approvals.

## License

MIT
