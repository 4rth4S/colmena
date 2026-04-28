# Getting Started

Zero to a working trust firewall in 5 minutes, then your first multi-agent mission.

## Prerequisites

- **Claude Code** installed and working (`claude` command available).
- **Rust toolchain** (stable) via [rustup](https://rustup.rs/) — only if you build from source. If you use the pre-built binary or `cargo install`, skip this.
- A real `$HOME`. Colmena refuses to fall back to `/tmp` on purpose.

## Install

Pick one path. Both end at `colmena doctor` green.

### Option A: from source (fastest while v0.12 is in flight)

```bash
git clone https://github.com/4rth4S/colmena.git
cd colmena
cargo build --workspace --release
./target/release/colmena setup
./target/release/colmena doctor
```

### Option B: pre-built binary

```bash
curl -LO https://github.com/4rth4S/colmena/releases/download/vX.Y.Z/colmena-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz
curl -LO https://github.com/4rth4S/colmena/releases/download/vX.Y.Z/SHA256SUMS.txt
sha256sum -c SHA256SUMS.txt --ignore-missing
tar xzf colmena-vX.Y.Z-*.tar.gz
./colmena setup
./colmena doctor
```

### Option C: crates.io (post v0.12.0)

```bash
cargo install colmena-cli colmena-mcp
colmena setup
colmena doctor
```

### Option D: let your CC do it for you

Point your Claude Code at this repo and ask it to install Colmena. See [Install Mode B](../install-mode-b.md).

## What `colmena setup` actually does

One idempotent command. You can re-run it safely — your edits are preserved, new defaults land in `.defaults/` for reference.

1. **Detects mode.** Repo mode if a workspace `Cargo.toml` with `colmena-core` is nearby (config at `<project>/config/`), otherwise standalone (`~/.colmena/config/`).
2. **Creates config directories:** `library/roles`, `library/patterns`, `library/prompts`, `queue/pending`, `queue/decided`.
3. **Writes default config files.** All defaults embedded in the binary — no downloads.

   | File | Purpose |
   |---|---|
   | `trust-firewall.yaml` | What to allow, ask, block |
   | `filter-config.yaml` | Output filter settings |
   | `review-config.yaml` | Auditor review thresholds |
   | `library/roles/*.yaml` | 15 built-in roles |
   | `library/patterns/*.yaml` | 11 orchestration patterns |
   | `library/prompts/*.md` | System prompts per role |

4. **Registers hooks** in `~/.claude/settings.json`:
   - `PreToolUse` — evaluates every tool call
   - `PostToolUse` — filters noisy Bash output
   - `PermissionRequest` — auto-approves role-scoped tools
   - `SubagentStop` — enforces auditor review before agents stop
5. **Registers MCP** in `~/.mcp.json` so CC sees the 27 Colmena tools natively.

`--force` overwrites custom files. `--dry-run` previews without writing.

## Verify

```bash
./target/release/colmena doctor
```

Seven categories: config validity, hook registration, MCP registration, library integrity, runtime state, file permissions, version consistency. All should be green before you proceed.

## First run — what the firewall feels like

Open a Claude Code session in any project. The firewall is live.

**Read call** — auto-approved. No prompt. File loads.

**`cargo test --workspace`** — auto-approved by the `build tools` rule in `trust_circle`.

**`rm -rf target/`** — Colmena matches a `restricted` rule:

```
[tool_use] Bash: rm -rf target/
ASK: Potentially destructive system command
Allow? [y/n]
```

**`git push --force origin main`** — blocked outright, no prompt, no override:

```
BLOCK: Destructive operation
```

Every decision appends a line to `config/audit.log`.

## First mission — what multi-agent feels like

From inside Claude Code, paste:

```
mcp__colmena__mission_suggest("review the auth module, improve test coverage, and have a reviewer check it")
```

Colmena will estimate complexity and tell you whether to use it at all. If `recommended_agents >= 3`, spawn the squad:

```
mcp__colmena__mission_spawn(mission="review the auth module, improve test coverage, and have a reviewer check it")
```

You get back:

- A pattern selected (e.g. `code-review-cycle` or `plan-then-execute`)
- Topology slots mapped to real roles (architect, developer, code_reviewer, auditor)
- A generated `CLAUDE.md` per agent with role prompt, scope, mission marker, and the exact `review_submit` call the agent will use
- Scoped delegations (8-hour TTL by default) bundled for each role
- The reviewer lead assigned by ELO (highest-rated eligible role wins)

Paste the generated prompts into CC `Agent` tool calls. Each agent:

- Carries a mission marker `<!-- colmena:mission_id=... -->`
- Has its role's tools auto-approved via the `PermissionRequest` hook
- Cannot `Stop` until it calls `mcp__colmena__review_submit` (the `SubagentStop` hook blocks Stops otherwise)

When the auditor evaluates with `mcp__colmena__review_evaluate`, QPC scores feed the ELO log, alerts fire if scores are low, and your findings accumulate.

## Customize the firewall

`config/trust-firewall.yaml` has three tiers evaluated in order:

```yaml
blocked:      # Highest priority — always denied
  - tools: [Bash]
    conditions:
      bash_pattern: '^git push.*--force'
    action: block
    reason: 'Destructive operation'

restricted:   # Middle — human confirms
  - tools: [Agent]
    action: ask
    reason: 'Agent spawning requires human review'

trust_circle: # Lowest — auto-approved
  - tools: [Read, Glob, Grep]
    action: auto-approve
    reason: 'Read-only operations'
```

Precedence is actually 8 steps: `blocked > delegations > agent_overrides (YAML) > ELO overrides > restricted > chain_guard > mission_revocation > trust_circle > defaults`. Full chain in [../dev/architecture.md](../dev/architecture.md#precedence-chain-pretooluse).

### Add a rule

Auto-approve `npm install` (currently routed to `ask` by defaults):

```yaml
trust_circle:
  # ... existing rules ...
  - tools: [Bash]
    conditions:
      bash_pattern: '^npm install\b'
    action: auto-approve
    reason: 'Package installation in project context'
```

### Tighten a rule

Block `curl` outright:

```yaml
blocked:
  - tools: [Bash]
    conditions:
      bash_pattern: '^curl\b'
    action: block
    reason: 'No network requests allowed'
```

### Path-based rules

```yaml
trust_circle:
  - tools: [Write, Edit]
    conditions:
      path_within: ['${PROJECT_DIR}/src']
      path_not_match: ['*.env', '*secret*']
    action: auto-approve
    reason: 'Source code writes only'
```

`${PROJECT_DIR}` resolves to the CC working directory.

### Validate

```bash
./target/release/colmena config check
```

## Delegate temporarily

Delegations expand permissions without editing YAML. Every delegation has a mandatory TTL (max 24h) and cannot override `blocked` rules.

```bash
# All agents, 4 hours
colmena delegate add --tool WebFetch --ttl 4

# One agent, 8 hours
colmena delegate add --tool Write --agent developer --ttl 8

# Only this CC session
colmena delegate add --tool Write --session sess_abc123 --ttl 2

# List and revoke
colmena delegate list
colmena delegate revoke --tool WebFetch
```

Bash delegations require a mandatory condition (`bash_pattern` or `path_within`). Expired delegations prune on load and emit `DELEGATE_EXPIRE` audit events.

## The audit log

Every firewall decision:

```
[2026-04-15T10:30:00Z] ALLOW session=sess_abc agent=* tool=Read key="src/main.rs" rule=trust_circle
[2026-04-15T10:30:01Z] ALLOW session=sess_abc agent=* tool=Bash key="cargo test --workspace" rule=trust_circle
[2026-04-15T10:30:05Z] ASK   session=sess_abc agent=pentester tool=Bash key="rm -rf target/" rule=restricted
[2026-04-15T10:30:10Z] BLOCK session=sess_abc agent=* tool=Bash key="git push --force origin main" rule=blocked
```

Rotates at 10MB.

Aggregate stats:

```bash
colmena stats
colmena stats --session <session-id>
```

Before ending a session, ask your CC to call `mcp__colmena__session_stats` to print the value summary (prompts saved + tokens saved).

## Where to go next

- [Use Cases](use-cases.md) — full tutorials: pentest, dev review, devops, SRE, refactor, docs-from-code
- [Install Mode B](../install-mode-b.md) — let your CC bootstrap Colmena
- [User Guide](../guide.md) — detailed walkthrough with a payments API audit
- [Architecture](../dev/architecture.md) — how the four crates fit together
- [Internals](../dev/internals.md) — edge cases, safety contracts, gotchas
