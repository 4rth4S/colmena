# Colmena

<p align="center">
  <img src="docs/colmena-banner.png" alt="Colmena — the hive defends the colony" width="400">
</p>

Multi-agent orchestration layer for Claude Code. Trust firewall, wisdom library, peer review, and performance scoring — all through native hook and MCP integration.

## Problem

Running multiple AI agents in parallel generates ~100 permission prompts per session. The human acts as relay between agents. Orchestration decisions are ad-hoc every time. Agent quality is invisible — no scores, no accountability, no institutional memory.

Colmena eliminates the noise, coordinates the swarm, and tracks who delivers.

## How It Works

Five integration points with Claude Code:

**1. PreToolUse Hook (reactive — before execution)** — Every tool call is evaluated against declarative YAML rules. Auto-approves ~70%, blocks destructive ops, asks for the rest. Includes mission revocation kill switch. Every decision is logged.

```
CC tool call --> colmena hook (stdin JSON)
                    |
                    |-- blocked?           --> deny  (force push, rm -rf)
                    |-- delegated?         --> allow (human or role-bound trust)
                    |-- agent override     --> allow/ask/block (YAML then ELO)
                    |-- restricted?        --> ask   (rm, docker, external comms)
                    |-- mission revoked?   --> deny  (kill switch for deactivated missions)
                    |-- trusted?           --> allow (reads, greps, project writes)
                    +-- default            --> ask
```

**2. PostToolUse Hook (reactive — after execution)** — Filters Bash tool outputs before CC processes them. Strips ANSI, deduplicates repeated lines, extracts only stderr on failures, and applies smart truncation. Saves 30-50% tokens per output.

```
CC executes Bash --> colmena PostToolUse hook
                        |
                        |-- ANSI strip     (clean escape sequences)
                        |-- stderr-only    (discard stdout on failure)
                        |-- dedup          (collapse repeated lines)
                        |-- truncate       (keep start + end, respect 30K limit)
                        +-- return via updatedMCPToolOutput
```

**3. PermissionRequest Hook (reactive — when CC asks user)** — Intercepts CC's permission prompts for mission agents. If the agent's role allows the tool, auto-approves and teaches CC session rules so subsequent calls skip all hooks.

```
CC about to prompt user --> colmena PermissionRequest hook
                              |
                              |-- agent has role delegation?  (source="role")
                              |-- tool in role's tools_allowed?
                              |     --> allow + teach CC session rules
                              |     --> CC auto-approves future calls (no hooks)
                              +-- otherwise --> no output (CC prompts user)
```

**4. SubagentStop Hook (reactive — when agent stops)** — Blocks mission workers from stopping until they've called `review_submit`. The centralized auditor role is exempt. Any error approves (safe fallback — never traps an agent).

```
Agent attempts to stop --> colmena SubagentStop hook
                              |
                              |-- has delegation with source="role"?
                              |     --> No: approve (not a mission worker)
                              |     --> Yes: role_type is "auditor"?
                              |       --> Yes: approve (auditor exempt)
                              |       --> No: has submitted review?
                              |         --> Yes: approve
                              |         --> No: block + "Call review_submit before stopping"
```

**5. MCP Server (proactive)** — CC calls colmena tools natively to manage trust, select orchestration patterns, coordinate agents, submit reviews, and query findings.

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

# One-command setup: hooks + MCP + config verification
./target/release/colmena setup
```

That's it. `setup` registers the PreToolUse + PostToolUse + PermissionRequest + SubagentStop hooks in `~/.claude/settings.json`, registers the MCP server in `~/.mcp.json`, validates config and library, and prints a checklist. Restart Claude Code to pick up the MCP server.

For standalone installs (release binary, no repo), `setup` embeds all default config and library files — the binary is self-contained.

## Features

### Trust Firewall (M0)

Declarative YAML rules evaluated in <15ms. Rule precedence:

```
blocked > delegations > agent_overrides > ELO overrides > restricted > chain_guard > mission_revocation > trust_circle > defaults
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

- **10 roles:** security_architect, pentester, auditor, researcher, web_pentester, api_pentester, developer, code_reviewer, tester, architect — each with system prompt, scoped permissions, and trust config
- **10 patterns:** pipeline, oracle-workers, debate, plan-then-execute, mentored-execution, swarm-consensus, caido-pentest, code-review-cycle, docs-from-code, refactor-safe
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

### Output Filtering (M2.5)

PostToolUse hook intercepts Bash outputs and applies a filter pipeline before CC's brute 50K truncation:

- **ANSI strip** — removes escape sequences (color codes, cursor movement)
- **Stderr-only** — on failure (exit != 0), discards stdout noise, keeps only errors
- **Dedup** — collapses 3+ consecutive identical lines to first + count + last
- **Smart truncation** — preserves start + end of output, inserts marker in the middle

Token savings tracked in JSONL log. View with `colmena stats`.

```yaml
# config/filter-config.yaml
max_output_lines: 150
max_output_chars: 30000    # < CC's 50K limit
dedup_threshold: 3
error_only_on_failure: true
strip_ansi: true
enabled: true
```

### Dynamic Trust Calibration (M3 + M6.3)

Three mechanisms that eliminate approval fatigue for multi-agent missions:

**Role tools_allowed auto-approve (M6.3)** -- When a mission agent's tool call would prompt the user, Colmena's PermissionRequest hook checks the role's `tools_allowed`. If the tool matches (exact or glob like `mcp__caido__*`), it auto-approves and teaches CC session rules. Subsequent calls for that role's tools skip all hooks entirely. Activation requires a human-approved mission (delegation with `source: "role"`).

**Role-bound mission delegations (temporary)** -- When `library_generate` creates a mission, it auto-generates scoped delegations from each agent's role permissions. The human approves once at mission creation; agents run without repeated prompts.

```yaml
# config/library/roles/pentester.yaml (optional permissions block)
permissions:
  bash_patterns:
    - '^nmap\b'
    - '^nikto\b'
    - '^python\b'
  path_within:
    - '${MISSION_DIR}'
  path_not_match:
    - '*.env'
    - '*credentials*'
```

Delegations are agent-scoped, session-bound, and time-limited (8h default, 24h max). Blocked rules always win.

**ELO-driven trust tiers (persistent)** -- After enough peer reviews, agent ELO scores determine their trust level. Running `colmena calibrate run` converts scores into firewall overrides.

| Tier | ELO | Effect |
|------|-----|--------|
| Uncalibrated | < 3 reviews | Default rules (warm-up) |
| Elevated | >= 1600 | Auto-approve role's tools |
| Standard | 1300-1599 | Default rules |
| Restricted | 1100-1299 | Ask for everything |
| Probation | < 1100 | Block dangerous tools |

ELO overrides are stored separately in `config/elo-overrides.json`. YAML agent_overrides always take precedence (human wins). `colmena calibrate reset` instantly revokes all ELO-based trust.

### Mission Lifecycle (M3 + M6.3)

Missions are a first-class concept with full lifecycle management and mid-session kill switch:

```
library_generate   --> creates CLAUDE.md + role-bound delegations
agents work        --> PermissionRequest auto-approves role tools via CC session rules
                       (first call teaches CC; subsequent calls skip all hooks)
mission complete   --> colmena mission deactivate --id X
                       --> marks agents in revoked-missions.json
                       --> PreToolUse DENY overrides CC session rules (kill switch)
over time          --> colmena calibrate run (ELO-based trust persists)
```

## CLI Reference

```
colmena hook                              # Hot path: CC hook (stdin JSON)
colmena config check                      # Validate trust-firewall.yaml
colmena install                           # Register hooks in ~/.claude/settings.json
colmena setup [--dry-run] [--force]       # One-command onboarding: config + hooks + MCP

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

colmena mission list                      # Active missions with delegation counts
colmena mission deactivate --id X         # Revoke all mission delegations

colmena calibrate run                     # Apply ELO-based trust tiers
colmena calibrate show                    # Show trust tier per agent
colmena calibrate reset                   # Clear all ELO overrides

colmena doctor                            # Full health check: config, hooks, MCP, runtime
colmena stats                             # Filter token savings summary
colmena stats --session <id>              # Stats for a specific session
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

### Wisdom Library (M1) — 6 tools

| Tool | Description |
|------|-------------|
| `library_list` | List roles and patterns |
| `library_show` | Show role/pattern details |
| `library_select` | Recommend patterns for a mission |
| `library_generate` | Generate per-agent CLAUDE.md for a mission |
| `library_create_role` | Create role with intelligent defaults (8 categories) |
| `library_create_pattern` | Create pattern with topology detection (7 topologies) |

### Peer Review + ELO (M2) — 6 tools

| Tool | Description |
|------|-------------|
| `review_submit` | Submit a peer review with scores |
| `review_list` | List reviews (filter by state) |
| `review_evaluate` | Evaluate review against trust gate |
| `elo_ratings` | Get ELO leaderboard |
| `findings_query` | Query findings by criteria |
| `findings_list` | List all findings |

### Alerts & Auditor Calibration (M6.4) — 4 tools

| Tool | Description |
|------|-------------|
| `alerts_list` | List alerts (filter by severity/acknowledged) |
| `alerts_ack` | Acknowledge alert(s) by ID or "all" |
| `calibrate_auditor` | Present auditor evaluations for human calibration (bilingual en/es) |
| `calibrate_auditor_feedback` | Submit calibration feedback (adjusts auditor ELO) |

### Dynamic Trust (M3) — 3 tools

| Tool | Description |
|------|-------------|
| `mission_deactivate` | Show deactivation CLI command (read-only) |
| `calibrate` | Show calibration state and recommend actions |
| `session_stats` | Show prompts saved + tokens saved + alert count (call before ending session) |

**27 tools total** across all milestones (26 MCP + PermissionRequest hook + SubagentStop hook).

## Configuration

### trust-firewall.yaml

The main firewall rules file. Defines blocked, restricted, trust_circle, and agent_overrides sections. Run `colmena config check` after any change.

### filter-config.yaml

Output filter settings for the PostToolUse pipeline. Controls max output size, dedup threshold, and which filters are active. Falls back to sensible defaults if file is missing.

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

Rust workspace with 4 crates. The core library has zero platform dependencies. CLI, MCP, and filter are thin adapters.

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
│       ├── review.rs          # Peer Review Protocol + has_submitted_review()
│       ├── elo.rs             # ELO Engine — ratings, decay, leaderboard
│       ├── findings.rs        # Findings Store — persistent knowledge base
│       └── alerts.rs          # Alerts — low-score review warnings (append-only)
├── colmena-cli/               # CLI binary — hook handler + subcommands
│   └── src/
│       ├── main.rs            # Clap CLI, Pre/Post/PermissionRequest/SubagentStop hooks, all cmds
│       ├── hook.rs            # CC hook payload/response types (Pre + Post + PermissionRequest + SubagentStop)
│       ├── notify.rs          # Notification hook (no-op placeholder)
│       └── install.rs         # Hook registration (4 hooks: Pre/Post/PermissionRequest/SubagentStop)
├── colmena-filter/            # Output filtering pipeline
│   └── src/
│       ├── lib.rs             # Public API surface
│       ├── config.rs          # FilterConfig loading (YAML)
│       ├── pipeline.rs        # FilterPipeline — chains filters with catch_unwind
│       ├── stats.rs           # JSONL token savings log + summary
│       └── filters/
│           ├── mod.rs         # OutputFilter trait + FilterResult
│           ├── ansi.rs        # ANSI escape sequence stripping
│           ├── dedup.rs       # Consecutive duplicate line collapsing
│           ├── truncate.rs    # Smart truncation (preserve start + end)
│           └── stderr_only.rs # Discard stdout on command failure
├── colmena-mcp/               # MCP server — CC native integration
│   └── src/
│       └── main.rs            # rmcp server, stdio transport, 27 tools
├── config/
│   ├── trust-firewall.yaml    # Firewall rules
│   ├── filter-config.yaml     # Output filter settings
│   ├── review-config.yaml     # Review thresholds
│   ├── runtime-delegations.json  # Active trust delegations
│   ├── revoked-missions.json    # Agent IDs from deactivated missions (kill switch)
│   ├── alerts.json              # Low-score review alerts (append-only, human-ack only)
│   ├── elo-overrides.json       # ELO-calibrated agent overrides (auto-generated)
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
- **7 security invariants** — no self-review, no reciprocal, artifact hash, min 2 scores, append-only ELO, trust gate floor, mandatory review before stop

## Roadmap

| Milestone | Status | Description |
|-----------|--------|-------------|
| M0 | Done | Trust Firewall + Approval Hub |
| M0.5 | Done | Workspace refactor + MCP server |
| M1 | Done | Wisdom Library + Pattern Selector + RRA security hardening |
| M2 | Done | Peer Review Protocol + ELO Engine + Findings Store |
| M2.5 | Done | Output Filtering — PostToolUse hook + colmena-filter pipeline |
| M3 | Done | Dynamic trust calibration — role-bound permissions, ELO-driven firewall rules, mission lifecycle |
| M3.5 | Done | Security hardening + Mission bridge — STRIDE/DREAD fixes, session stats, ELO reviewer lead |
| M4 | Done | Mentor prompt refinement — debate pattern for prompt improvement suggestions |
| M4.1 | Done | Caido-native pentester roles — web_pentester + api_pentester for bug bounty with Caido MCP |
| M5 | Done | Plug-and-play onboarding — `colmena setup` (config, hooks, MCP in one command) |
| M6 | Done | Intelligent role & pattern creation — 8 categories, 7 topologies, pattern suggestion |
| M6.1 | Done | Security hardening — error sanitization, rate limiting, log rotation, permissions checks |
| M6.2 | Done | P0+P1 hardening — MCP precision, collusion prevention, delegate scoping |
| M6.3 | Done | Role tools_allowed firewall — PermissionRequest auto-approve + mission revocation kill switch |
| M6.4 | Done | Enforced Peer Review — SubagentStop hook, centralized auditor, alerts, auditor calibration |

## Docs

- [Changelog](CHANGELOG.md) — version history and upgrade notes
- [Contributing](CONTRIBUTING.md) — branching, PRs, versioning, releasing
- [User Guide](docs/guide.md) — setup, upgrading, daily workflow, all features M0-M6.4
- [Design Spec](docs/specs/2026-03-29-hivemind-design.md) — full M0-M3 design
- [Dark Corners](docs/dark-corners.md) — M0 edge case analysis
- [Dark Corners M1](docs/dark-corners-m1.md) — M1 edge case analysis
- [Full Roadmap](docs/plans/2026-03-29-full-roadmap.md) — roadmap with MCP integration
- [Presentation](docs/presentation.html) — overview deck (open in browser)

## License

Private — not yet licensed for distribution.

---

<p align="center">built with ❤️‍🔥 by AppSec</p>
