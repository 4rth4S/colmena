# Colmena

<p align="center">
  <img src="docs/colmena-banner.png" alt="Colmena — the hive defends the colony" width="400">
</p>

Multi-agent orchestration layer for Claude Code. Trust firewall, wisdom library, peer review, and performance scoring — all through native hook and MCP integration.

## Problem

Running multiple AI agents in parallel generates ~100 permission prompts per session. The human acts as relay between agents. Orchestration decisions are ad-hoc every time. Agent quality is invisible — no scores, no accountability, no institutional memory.

Colmena eliminates the noise, coordinates the swarm, and tracks who delivers.

## How It Works

Two integration points with Claude Code:

**1. Hook (reactive)** — registered as `PreToolUse` hook. Every tool call is evaluated against declarative YAML rules. Auto-approves ~70%, blocks destructive ops, asks for the rest. Every decision is logged.

```
CC tool call --> colmena hook (stdin JSON)
                    |
                    |-- blocked?    --> deny  (force push, rm -rf)
                    |-- delegated?  --> allow (human expanded trust)
                    |-- restricted? --> ask   (rm, docker, external comms)
                    |-- trusted?    --> allow (reads, greps, project writes)
                    +-- default     --> ask
```

**2. MCP Server (proactive)** — CC calls colmena tools natively to manage trust, select orchestration patterns, coordinate agents, submit reviews, and query findings.

```
CC: "use colmena to select a pattern for auditing the payments API"
 --> mcp__colmena__library_select(mission: "audit payments API")
 --> returns pattern recommendations with role assignments

CC: "submit this review with scores and findings"
 --> mcp__colmena__review_submit(...)
 --> ELO updates, findings stored, trust gate evaluated
```

## Quick Start

```bash
# Build all binaries
cargo build --release

# Register the PreToolUse hook
./target/release/colmena install

# Verify
./target/release/colmena config check
```

The MCP server is auto-discovered via `.mcp.json` in the project root.

## Features

### Trust Firewall (M0)

Declarative YAML rules evaluated in <15ms. Rule precedence:

```
blocked > runtime delegations > agent overrides > restricted > trust circle > defaults
```

- Auto-approves reads, greps, web searches, project writes
- Blocks force pushes, `rm -rf`, hard resets
- Asks for everything else — you only see what needs judgment
- Sound notifications: silence (auto-approved), Glass (low ask), Hero (high ask), Basso (blocked)

### Approval Queue (M0)

Every `ask` and `deny` decision is queued with priority and timestamp. Review what happened, prune old entries.

### Runtime Delegations (M0)

Expand trust mid-session without editing YAML. TTL-capped (max 24h), auditable, revocable.

```bash
colmena delegate add --tool Bash --agent pentester --ttl 4
colmena delegate list
colmena delegate revoke --tool Bash
```

MCP `delegate` tool is read-only — it returns the CLI command for the human to run.

### Audit Log (M0)

Every firewall decision is logged to `config/audit.log`:

```
[2026-03-30T05:00:05Z] ALLOW session=abc agent=* tool=Read key="/src/auth.rs" rule=trust_circle[0]
[2026-03-30T05:00:05Z] DENY  session=abc agent=* tool=Bash key="git push --force" rule=blocked[0]
```

### Wisdom Library (M1)

Curated role definitions and orchestration patterns for multi-agent missions.

- **4 roles:** security_architect, pentester, auditor, researcher — each with system prompt, tools, and trust config
- **6 patterns:** pipeline, oracle-workers, debate, plan-then-execute, mentored-execution, swarm-consensus
- **Pattern selector:** keyword scoring recommends the right pattern for your mission
- **Mission generator:** produces per-agent CLAUDE.md files with role-specific instructions

### Peer Review Protocol (M2)

Structured review between agents with security invariants:

- No self-review (agents cannot review their own work)
- No reciprocal review (A reviews B, B cannot review A in same mission)
- Artifact hash verification (content integrity)
- Minimum 2 scoring dimensions required
- Trust gate: auto-approve if average score >= 7.0 and no critical findings

### ELO Engine (M2)

Append-only performance log with temporal decay:

| Age | Weight |
|-----|--------|
| < 7 days | 1.0 |
| 7-30 days | 0.7 |
| 30-90 days | 0.4 |
| > 90 days | 0.1 |

Ratings start at 1500. The leaderboard shows who delivers consistently.

### Findings Store (M2)

Persistent knowledge base from reviews. Query by role, category, severity, date range, or mission. Findings accumulate across sessions — institutional memory for the swarm.

## CLI Reference

```
colmena hook                              # Hot path: CC hook (stdin JSON)
colmena config check                      # Validate trust-firewall.yaml
colmena install                           # Register hook in ~/.claude/settings.json

colmena queue list                        # Pending approval items
colmena queue prune --older-than 7        # Prune entries older than N days

colmena delegate add --tool X [--agent Y] [--ttl 4]  # Add delegation (max 24h)
colmena delegate list                     # List active delegations
colmena delegate revoke --tool X          # Revoke delegation

colmena library list                      # List roles + patterns
colmena library show <id>                 # Role/pattern details
colmena library select --mission "..."    # Pattern selector + mission generator
colmena library create-role --id X        # Scaffold new role template

colmena review list [--state pending]     # List peer reviews
colmena review show <review-id>           # Review detail

colmena elo show                          # ELO leaderboard
```

## MCP Tools Reference

### Trust Firewall (M0.5) — 6 tools

| Tool | Description |
|------|-------------|
| `config_check` | Validate firewall config |
| `queue_list` | List pending approvals |
| `delegate` | Show delegation CLI command (read-only) |
| `delegate_list` | List active delegations |
| `delegate_revoke` | Show revoke CLI command (read-only) |
| `evaluate` | Evaluate a tool call against firewall |

### Wisdom Library (M1) — 5 tools

| Tool | Description |
|------|-------------|
| `library_list` | List roles and patterns |
| `library_show` | Show role/pattern details |
| `library_select` | Recommend patterns for a mission |
| `library_generate` | Generate per-agent CLAUDE.md for a mission |
| `library_create_role` | Scaffold a new role template |

### Peer Review + ELO (M2) — 6 tools

| Tool | Description |
|------|-------------|
| `review_submit` | Submit a peer review with scores |
| `review_list` | List reviews (filter by state) |
| `review_evaluate` | Evaluate review against trust gate |
| `elo_ratings` | Get ELO leaderboard |
| `findings_query` | Query findings by criteria |
| `findings_list` | List all findings |

**20 tools total** across all milestones.

## Configuration

### trust-firewall.yaml

The main firewall rules file. Defines blocked, restricted, trust_circle, and agent_overrides sections. Run `colmena config check` after any change.

### review-config.yaml

Peer review thresholds and reviewer assignment strategy:

```yaml
thresholds:
  auto_approve: 7.0    # Average score >= this → auto-complete
  floor: 5.0           # Hardcoded floor — never auto-approve below this

reviewer_assignment:
  strategy: role_rotation  # Pick different role, avoid reciprocal
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `COLMENA_HOME` | Override project root (default: auto-detected from binary location) |
| `COLMENA_CONFIG` | Override config file path |

## Architecture

Rust workspace with 3 crates. The core library has zero platform dependencies. CLI and MCP are thin adapters.

```
colmena/
├── colmena-core/              # Shared library — all business logic
│   └── src/
│       ├── lib.rs             # Public API surface
│       ├── config.rs          # Firewall config loading + regex compilation
│       ├── firewall.rs        # Core rule evaluation engine
│       ├── delegate.rs        # Runtime trust delegations (TTL, list, revoke)
│       ├── queue.rs           # Approval queue file I/O
│       ├── audit.rs           # Append-only audit log
│       ├── models.rs          # Protocol-agnostic types (EvaluationInput)
│       ├── paths.rs           # Path resolution utilities
│       ├── library.rs         # Wisdom Library — roles + patterns
│       ├── selector.rs        # Pattern selector + mission generator
│       ├── review.rs          # Peer Review Protocol
│       ├── elo.rs             # ELO Engine — ratings, decay, leaderboard
│       └── findings.rs        # Findings Store — persistent knowledge base
├── colmena-cli/               # CLI binary — hook handler + subcommands
│   └── src/
│       ├── main.rs            # Clap CLI, hook hot path, review/elo/library cmds
│       ├── hook.rs            # CC hook payload/response types
│       ├── notify.rs          # Notification hook (no-op placeholder)
│       └── install.rs         # Hook registration
├── colmena-mcp/               # MCP server — CC native integration
│   └── src/
│       └── main.rs            # rmcp server, stdio transport, 20 tools
├── config/
│   ├── trust-firewall.yaml    # Firewall rules
│   ├── review-config.yaml     # Review thresholds
│   ├── runtime-delegations.json
│   ├── audit.log              # Append-only decision log
│   ├── queue/
│   │   ├── pending/           # Approval items awaiting decision
│   │   └── decided/           # Resolved items
│   └── library/
│       ├── roles/             # Role definitions (YAML)
│       ├── patterns/          # Orchestration patterns (YAML)
│       └── prompts/           # System prompts per role (Markdown)
├── .mcp.json                  # MCP server registration for CC
└── docs/
```

## Design Principles

- **< 15ms** hook latency — Rust, pre-compiled regexes, no network calls
- **Safe fallback** — any hook failure returns `ask`, never `deny` or crash
- **Files over databases** — YAML config, JSON queue, JSONL logs, git-versionable
- **Build on CC, not around it** — hooks + MCP + Agent Teams, no hacks
- **Domain-agnostic** — the engine is generic, the domain is in YAML templates
- **6 security invariants** — no self-review, no reciprocal, artifact hash, min 2 scores, append-only ELO, trust gate floor

## Roadmap

| Milestone | Status | Description |
|-----------|--------|-------------|
| M0 | Done | Trust Firewall + Approval Hub |
| M0.5 | Done | Workspace refactor + MCP server |
| M1 | Done | Wisdom Library + Pattern Selector + RRA security hardening |
| M2 | Done | Peer Review Protocol + ELO Engine + Findings Store |
| M3 | Next | Dynamic trust calibration — ELO-driven auto-delegation, mentoring, demotion |

## Docs

- [User Guide](docs/guide.md) — setup, daily workflow, payments API audit walkthrough, M1 + M2 features
- [Design Spec](docs/specs/2026-03-29-hivemind-design.md) — full M0-M3 design
- [Dark Corners](docs/dark-corners.md) — M0 edge case analysis
- [Dark Corners M1](docs/dark-corners-m1.md) — M1 edge case analysis
- [Full Roadmap](docs/plans/2026-03-29-full-roadmap.md) — roadmap with MCP integration
- [Presentation](docs/presentation.html) — overview deck (open in browser)

## License

Private — not yet licensed for distribution.

---

<p align="center">built with ❤️‍🔥 by AppSec</p>
