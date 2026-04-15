# Colmena

<p align="center">
  <img src="docs/colmena-banner.png" alt="Colmena — the hive defends the colony" width="400">
</p>

<p align="center"><strong>Be the sharpest knife.</strong></p>

<p align="center">Force multiplier for solo-operators who orchestrate AI agents with trust and accountability.<br>Designed for the one-person-army.</p>

---

Colmena intercepts every tool call your agents make and evaluates it against your rules — auto-approve the safe stuff, ask about the risky stuff, block the dangerous stuff. No more babysitting agents. No more 100 permission prompts per session.

```
                       ┌──────────────────┐
                       │   Claude Code     │
                       │   (tool call)     │
                       └────────┬─────────┘
                                │ stdin JSON
                                v
                       ┌──────────────────┐
                       │     Colmena      │
                       │  Trust Firewall  │
                       └──┬─────┬──────┬──┘
                          │     │      │
                     ┌────┘     │      └────┐
                     v          v           v
                  ALLOW       ASK        BLOCK
               (proceed)  (human ok?)  (denied)
```

## What It Does

- **Auto-approves safe operations.** File reads, `git log`, `cargo test`, `grep` — they just work. No permission prompts for things that can't break anything.

- **Asks about risky ones.** `rm`, `curl -X POST`, `git push`, agent spawning — Colmena pauses and asks you. One keypress to approve or deny.

- **Blocks the truly dangerous.** `git push --force`, `rm -rf /` — blocked outright. No agent can execute these, even with delegation.

- **Orchestrates multi-agent missions.** Spawn a documentation squad, a code review cycle, or a refactoring team. Each agent gets scoped permissions, peer review enforcement, and ELO-based trust that evolves over time.

## Quick Start

```bash
# Build
cargo build --workspace --release

# Set up everything (config, hooks, MCP server)
./target/release/colmena setup

# Verify installation
./target/release/colmena doctor
```

Two commands after the build. The firewall is now active for every Claude Code session.

## What a Session Looks Like

```
# Agent reads a file → auto-approved
[tool_use] Read: src/main.rs
  → ALLOW: Read-only local operations

# Agent runs tests → auto-approved
[tool_use] Bash: cargo test --workspace
  → ALLOW: Build tools

# Agent tries to push → Colmena asks you
[tool_use] Bash: git push origin feature-branch
  → ASK: Push requires human confirmation
  [y/n?]

# Agent tries force push → blocked, no question asked
[tool_use] Bash: git push --force origin main
  → BLOCK: Destructive operation
```

Every decision logged to `config/audit.log`.

## Key Features

**Runtime Delegations.** Temporarily expand agent permissions without editing config. All delegations have mandatory TTL (max 24h) and optional agent/session scoping.

```bash
colmena delegate add --tool WebFetch --agent architect --ttl 4
```

**Multi-Agent Missions.** Spawn coordinated agent squads with one command. Colmena selects the right pattern, maps roles, generates scoped prompts, creates time-limited delegations, and assigns a reviewer lead.

```bash
colmena suggest "refactor the auth module with tests and review"
# → complexity=medium, recommended_agents=3+, use Colmena

colmena library select --mission "refactor the auth module with tests and review"
# → ranked pattern recommendations
```

**ELO-Based Trust.** Agents earn trust through peer review. Five tiers: Uncalibrated → Standard → Elevated (auto-approve role tools) / Restricted / Probation. Trust calibrates automatically — good agents earn autonomy, bad ones get restricted.

**Output Filtering.** Bash output passes through a 4-stage pipeline (ANSI strip → stderr-only → dedup → truncate) before Claude processes it. Saves 30-50% tokens from noisy commands.

**Extensible Library.** 10 built-in roles and 10 orchestration patterns ship out of the box, but Colmena is designed to be extended. Create roles and patterns that match your domain — the engine is generic, the specialization is yours.

## Make It Yours

Colmena's built-in library is a starting point. The real value comes when you create roles and patterns that fit your workflow.

**Create a custom role:**

```bash
colmena library create-role --id data_engineer --description "ETL pipeline development and data quality validation" --category development
```

This generates a complete role definition — YAML config with scoped tool permissions, a system prompt, and trust configuration. You get:

```
config/library/roles/data_engineer.yaml    # tools_allowed, trust level, specializations
config/library/prompts/data_engineer.md    # system prompt with methodology
```

Edit the YAML to scope exactly what the role can do:

```yaml
# config/library/roles/data_engineer.yaml
tools_allowed: [Read, Write, Edit, Bash, Glob, Grep]
permissions:
  bash_patterns:
    - '^python\b'
    - '^dbt\b'
    - '^sql\b'
  path_within:
    - '${MISSION_DIR}'
    - 'pipelines/'
```

**Create a custom pattern:**

```bash
colmena library create-pattern --id etl-review --description "ETL pipeline development with data quality review" --topology sequential
```

Generates a pattern definition with topology slots that you can map to your roles.

**Use it immediately:**

```bash
colmena suggest "build the user analytics ETL pipeline with validation"
# → recommends your custom pattern if it matches

colmena library select --mission "build the user analytics ETL pipeline"
# → your etl-review pattern appears in recommendations
```

Your custom roles and patterns work with the full Colmena stack — trust firewall, scoped delegations, peer review, ELO ratings. The same guarantees that apply to built-in roles apply to yours.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Workspace                         │
│                                                      │
│  ┌──────────────┐   ┌──────────────┐                │
│  │ colmena-core │   │colmena-filter│                │
│  │  (library)   │   │  (pipeline)  │                │
│  │              │   │              │                │
│  │ • firewall   │   │ • ANSI strip │                │
│  │ • config     │   │ • dedup      │                │
│  │ • delegate   │   │ • truncate   │                │
│  │ • ELO        │   │ • stats      │                │
│  │ • review     │   └──────┬───────┘                │
│  │ • library    │          │                         │
│  │ • missions   │          │                         │
│  └──────┬───────┘          │                         │
│         │                  │                         │
│  ┌──────┴──────────────────┴───┐  ┌──────────────┐  │
│  │      colmena-cli            │  │ colmena-mcp  │  │
│  │      (hook binary)          │  │ (MCP server) │  │
│  │                             │  │              │  │
│  │ • PreToolUse (evaluate)     │  │ • 27 tools   │  │
│  │ • PostToolUse (filter)      │  │ • stdio      │  │
│  │ • PermissionRequest (auto)  │  │ • rate limit │  │
│  │ • SubagentStop (review)     │  │              │  │
│  └─────────────────────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────┘
```

**colmena-core** — all business logic. Protocol-agnostic, zero platform deps.

**colmena-cli** — hook binary invoked by Claude Code on every tool call.

**colmena-filter** — output filtering pipeline. Saves tokens.

**colmena-mcp** — 27 tools exposed as native Claude Code tools via MCP.

## CLI Commands

```
colmena setup                         # One-command onboarding
colmena doctor                        # Health check
colmena delegate add/list/revoke      # Manage trust delegations
colmena library list/show/select      # Browse roles and patterns
colmena library create-role/create-pattern  # Create your own
colmena review list/show              # Peer reviews
colmena elo show                      # ELO leaderboard
colmena calibrate run/show/reset      # Trust calibration
colmena mission list/deactivate       # Mission lifecycle
colmena suggest "<mission>"           # Complexity analysis
colmena stats                         # Session statistics
```

## Documentation

**For users:**
- [Getting Started](docs/user/getting-started.md) — from zero to working in 5 minutes
- [Use Cases](docs/user/use-cases.md) — real workflows: code review, documentation, refactoring
- [User Guide](docs/guide.md) — detailed walkthrough

**For contributors:**
- [Architecture](docs/dev/architecture.md) — crates, data flows, trust model, MCP internals
- [Contributing](docs/dev/contributing.md) — dev setup, how to add rules/tools/roles, PR workflow
- [Internals](docs/dev/internals.md) — edge cases, dark corners, safety contracts

## Design Principles

- **< 15ms** hook latency — Rust, pre-compiled regexes, no network calls
- **Safe fallback** — any hook failure returns `ask`, never `deny` or crash
- **Files over databases** — YAML config, JSON queue, JSONL logs, git-versionable
- **Build on CC, not around it** — hooks + MCP, no hacks
- **Domain-agnostic** — the engine is generic, the domain is in your templates
- **Extensible** — create roles, patterns, and prompts that match your workflow

## License

Private — not yet licensed for distribution.

---

<p align="center">built with ❤️‍🔥 by AppSec</p>
