# Getting Started with Colmena

From zero to a working trust firewall in 5 minutes.

## Prerequisites

- **Rust toolchain** (stable). Install via [rustup](https://rustup.rs/) if you don't have it.
- **Claude Code** installed and working (`claude` command available).

## Installation

### 1. Build

```bash
git clone https://github.com/4rth4S/colmena.git
cd colmena
cargo build --workspace --release
```

This produces two binaries:
- `target/release/colmena` -- the hook binary + CLI
- `target/release/colmena-mcp` -- the MCP server

### 2. Setup

```bash
./target/release/colmena setup
```

This single command does everything:

1. **Detects mode.** If it finds a workspace `Cargo.toml` with `colmena-core`, it runs in repo mode (config at `<project>/config/`). Otherwise, standalone mode (config at `~/.colmena/config/`).

2. **Creates config directories.** Sets up `library/roles`, `library/patterns`, `library/prompts`, `queue/pending`, `queue/decided`.

3. **Writes default config files.** All defaults are embedded in the binary -- no downloads needed. Key files created:

   | File | Purpose |
   |------|---------|
   | `trust-firewall.yaml` | Firewall rules (what to allow, ask, block) |
   | `filter-config.yaml` | Output filter settings (line limits, truncation) |
   | `review-config.yaml` | Peer review thresholds |
   | `library/roles/*.yaml` | 10 built-in role definitions |
   | `library/patterns/*.yaml` | 10 orchestration patterns |
   | `library/prompts/*.md` | System prompts for each role |

4. **Registers hooks.** Adds four hook entries to `~/.claude/settings.json`:
   - **PreToolUse** -- evaluates every tool call against the firewall
   - **PostToolUse** -- filters noisy Bash output
   - **PermissionRequest** -- auto-approves role-scoped tools
   - **SubagentStop** -- enforces peer review before agents stop

5. **Registers MCP server.** Writes `~/.mcp.json` so Claude Code can call Colmena's 27 tools natively.

If you've customized any config files, setup preserves your changes and saves the new defaults to a `.defaults/` directory for reference. Use `--force` to overwrite, or `--dry-run` to preview.

### 3. Verify

```bash
./target/release/colmena doctor
```

Doctor runs a full health check across 7 categories: config validity, hook registration, MCP registration, library integrity, runtime state, file permissions, and version consistency.

## Your First Run

Start a Claude Code session. The firewall is now active. Here's what happens when Claude calls different tools:

### A Read call (auto-approved)

Claude invokes `Read` on a file. Colmena evaluates it:

1. CC sends JSON to `colmena hook` via stdin
2. Firewall checks rules in precedence order: blocked → delegations → agent overrides → restricted → trust circle → defaults (simplified — the [full 8-step chain](../dev/architecture.md#pretooluse-tool-call-evaluation) also includes ELO overrides, chain guard, and mission revocation)
3. `Read` matches the first trust_circle rule (safe read operations)
4. Colmena returns `allow` -- CC proceeds without prompting you
5. Decision logged to `config/audit.log`

You never see a prompt. The file just loads.

### A Bash build command (auto-approved)

Claude runs `cargo test --workspace`. Colmena recognizes it from the trust_circle rule for build tools and auto-approves. No prompt.

### A destructive command (asks you)

Claude tries `rm -rf target/`. Colmena matches the restricted rule for destructive commands. You see:

```
[tool_use] Bash: rm -rf target/
ASK: Potentially destructive system command
Allow? [y/n]
```

### A force push (blocked)

Claude tries `git push --force origin main`. Colmena matches the blocked rule. The tool call is denied immediately -- no prompt, no override.

## Customizing the Firewall

The firewall lives at `config/trust-firewall.yaml`. It has three sections, evaluated in order:

```yaml
# Highest priority -- always denied
blocked:
  - tools: [Bash]
    conditions:
      bash_pattern: '^git push.*--force'
    action: block
    reason: 'Destructive operation'

# Middle priority -- human confirms
restricted:
  - tools: [Agent]
    action: ask
    reason: 'Agent spawning requires human review'

# Lowest priority -- auto-approved
trust_circle:
  - tools: [Read, Glob, Grep]
    action: auto-approve
    reason: 'Read-only operations'
```

### Adding a rule

To auto-approve `npm install` (currently caught by the defaults `ask`):

```yaml
trust_circle:
  # ... existing rules ...

  # Auto-approve npm install
  - tools: [Bash]
    conditions:
      bash_pattern: '^npm install\b'
    action: auto-approve
    reason: 'Package installation in project context'
```

### Tightening a rule

To block all `curl` commands instead of just asking:

```yaml
blocked:
  # ... existing rules ...

  - tools: [Bash]
    conditions:
      bash_pattern: '^curl\b'
    action: block
    reason: 'No network requests allowed'
```

### Path-based rules

Restrict writes to specific directories:

```yaml
trust_circle:
  - tools: [Write, Edit]
    conditions:
      path_within: ['${PROJECT_DIR}/src']
      path_not_match: ['*.env', '*secret*']
    action: auto-approve
    reason: 'Source code writes only'
```

`${PROJECT_DIR}` resolves to your current working directory at runtime.

After editing, validate your config:

```bash
./target/release/colmena config check
```

## Delegating Tools

Delegations let you temporarily expand permissions without editing the YAML. Every delegation has a mandatory TTL (max 24 hours).

### Grant a tool to all agents for 4 hours

```bash
colmena delegate add --tool WebFetch --ttl 4
```

### Grant to a specific agent

```bash
colmena delegate add --tool Write --agent developer --ttl 8
```

### Scope to the current session

```bash
colmena delegate add --tool Write --session sess_abc123 --ttl 2
```

### View and revoke

```bash
colmena delegate list          # Show all active delegations
colmena delegate revoke --tool WebFetch  # Revoke
```

Key details:
- Delegations **cannot override blocked rules**. Blocked is always blocked.
- Bash delegations are blocked via the CLI -- use `trust-firewall.yaml` agent_overrides or role-based missions for scoped Bash access.
- Expired delegations are automatically pruned on next load and logged as audit events.

## Checking the Audit Log

Every firewall decision is appended to `config/audit.log`:

```
[2026-04-15T10:30:00Z] ALLOW session=sess_abc agent=* tool=Read key="src/main.rs" rule=trust_circle
[2026-04-15T10:30:01Z] ALLOW session=sess_abc agent=* tool=Bash key="cargo test --workspace" rule=trust_circle
[2026-04-15T10:30:05Z] ASK   session=sess_abc agent=pentester tool=Bash key="rm -rf target/" rule=restricted
[2026-04-15T10:30:10Z] BLOCK session=sess_abc agent=* tool=Bash key="git push --force origin main" rule=blocked
```

The log auto-rotates at 10MB.

To see aggregated stats for a session:

```bash
colmena stats
colmena stats --session <session-id>
```

## What's Next

- [Use Cases](use-cases.md) -- concrete workflows for security audits, code review, pentesting, and documentation
- [User Guide](../guide.md) -- detailed walkthrough with a payments API audit example
- [Architecture](../dev/architecture.md) -- how the four crates work together
- [Internals](../dev/internals.md) -- edge cases, safety contracts, and implementation details
