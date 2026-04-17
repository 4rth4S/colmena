# Security Policy

Colmena is a security tool. We take vulnerabilities in it seriously.

## Supported Versions

Only the latest release is supported. Colmena is pre-1.0 (semver `0.x`) — fixes land on `main` and flow into the next tagged release (M0 through M7.2 are considered current).

| Version | Supported |
|---------|-----------|
| latest  | yes       |
| older   | no        |

## Reporting a Vulnerability

**Do not file security reports as public GitHub issues.**

Use GitHub Private Vulnerability Reporting:

1. Go to the repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Provide reproduction steps, affected versions, and impact.

This creates a private advisory visible only to maintainers.

## Response Timeline

- **Acknowledge:** within 72 hours of report.
- **Triage + plan or fix:** within 14 days.
- **Disclosure:** coordinated with reporter, after a fix is available.

## Scope

In scope:
- `colmena-cli` hook path (PreToolUse, PostToolUse, PermissionRequest, SubagentStop).
- `colmena-mcp` server and exposed MCP tools.
- Firewall rule evaluation, delegation handling, review/ELO logic.
- Config file loading and validation.

Out of scope:
- User-authored scripts, custom roles, or custom patterns.
- Third-party MCP servers integrated alongside Colmena.
- Vulnerabilities in Claude Code itself — report those upstream.

built with ❤️‍🔥 by AppSec
