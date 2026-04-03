# Colmena

Multi-agent orchestration layer for Claude Code. Rust workspace with hook binary + MCP server. Auto-approves routine operations, exposes trust management as native CC tools.

## Session Protocol

- **Before ending a session:** Always call `mcp__colmena__session_stats` to show the value summary (prompts saved + tokens saved). This helps the user understand Colmena's impact.
- **Before spawning agents:** Call `mcp__colmena__library_select` to check if there's an appropriate role. If there is, use the Colmena-generated prompt for the agent.

## Quick Reference

- **Build:** `cargo build --workspace --release`
- **Test:** `cargo test --workspace` (single crate: `cargo test -p colmena-core`)
- **Lint:** `cargo clippy --workspace -- -W warnings`
- **CLI binary:** `target/release/colmena`
- **MCP binary:** `target/release/colmena-mcp`
- **Version:** 0.6.1 (semver, single workspace version)
- **Config:** `config/trust-firewall.yaml`, `config/filter-config.yaml`
- **MCP registration:** `.mcp.json`
- **CI:** GitHub Actions — `ci.yml` (test+clippy+build on PRs), `release.yml` (tag-triggered releases)
- **Repo:** `git@github.com:4rth4S/colmena.git`

## Architecture

Rust workspace with 4 crates:

- **colmena-core** — shared library: config, firewall, delegate, calibrate, queue, models, paths. Zero platform deps.
- **colmena-cli** — CLI binary: Pre/PostToolUse hooks, clap subcommands, notifications (no-op placeholder), install
- **colmena-filter** — output filtering pipeline: OutputFilter trait, 4 base filters, FilterPipeline with catch_unwind, JSONL stats
- **colmena-mcp** — MCP server: rmcp, stdio transport, exposes core functions as CC tools

Three CC integration points:
1. **PreToolUse Hook (reactive):** evaluates every tool call against YAML firewall rules
2. **PostToolUse Hook (reactive):** filters Bash outputs via colmena-filter pipeline before CC processes them
3. **MCP (proactive):** CC calls 21 colmena tools natively — firewall, library, review, ELO, findings, calibration, stats

Rule precedence: `blocked > delegations > agent_overrides (YAML) > ELO overrides > restricted > trust_circle > defaults`

## Tech Stack

- **Language:** Rust (edition 2021, workspace)
- **Core deps:** serde, serde_json, serde_yml, regex, anyhow, chrono
- **CLI deps:** clap (derive)
- **MCP deps:** rmcp (server, transport-io, macros), tokio
- **Config format:** YAML (firewall rules), JSON (queue, delegations, MCP)
- **No external services** — everything is filesystem-based

## Conventions

- Git: always use branches (feature/, fix/, chore/, docs/). Never commit to main. MR workflow.
- Signature: "built with ❤️‍🔥 by AppSec" on all public-facing docs and commit trailers
- Error handling: `anyhow::Result` everywhere. Never panic in the hook path.
- Hook path must complete in <100ms — no network calls, no heavy I/O
- Any hook failure returns `ask` (safe fallback), never `deny` or exit 2
- YAML regex patterns use single-quoted strings to avoid `\b` → backspace escaping issues
- Queue filenames use millisecond timestamps + tool_use_id for uniqueness
- Firewall `bash_pattern` conditions only apply when tool is `Bash` — skip for other tools
- Glob matching in `path_not_match` operates on **filename only** (last path component)
- Path comparison uses component-based normalization (not `canonicalize()`)
- Regex patterns compiled once at config load time (`compile_config`)
- Atomic file writes (temp + rename) for concurrent CC instances
- Integration tests spawn the CLI binary as subprocess and pipe JSON via stdin
- Core library tests use `env!("CARGO_MANIFEST_DIR")` + `../config/` to reach workspace root
- Run clippy before release — must be clean
- CC hooks format: `{ "matcher": "", "hooks": [{ "type": "command", "command": "..." }] }`
- MCP delegate/revoke tools are read-only: return CLI commands for human confirmation, never execute directly
- Delegations always have a TTL (max 24h), `--permanent` removed. Validate with `validate_ttl()`
- All firewall decisions logged to `config/audit.log` (append-only, one line per decision)
- Agent tool is in `restricted` (ask), not `trust_circle` (auto-approve)
- Queue entries truncate tool_input: commands to 200 chars, Write content redacted
- HOME fallback to /tmp is banned — fail explicitly if HOME is not set
- PostToolUse hook must be as fast as PreToolUse (<100ms) — no network calls
- PostToolUse safe fallback: any error → passthrough (return original output unchanged), never "ask" or "deny"
- Filter pipeline order: ANSI strip → stderr-only → dedup → truncate (clean first, hard cap last)
- Each filter wrapped in catch_unwind — a buggy filter never crashes the hook
- FilterConfig max_output_chars (30K) must be < CC's internal limit (50K)
- Filters only apply to Bash tool outputs (Read/Write/Edit don't need filtering)
- Token savings logged to JSONL at `<colmena_home>/config/filter-stats.jsonl` (10MB rotation)
- MCP error messages sanitized via `colmena_core::sanitize::sanitize_error` — no filesystem paths leak to agents
- MCP generative tools rate-limited: 30 calls/min per tool (library_generate, review_submit, review_evaluate, library_create_role/pattern, mission_deactivate)
- `library_create_role` and `library_create_pattern` are in `restricted` — require human review (prevent library poisoning)
- Delegations without `--session` warn about global scope (applies to ALL CC sessions)
- Watchdog timeout (5s) logged as TIMEOUT event in audit.log before exit
- `load_findings()` hard cap: 5000 records max to prevent OOM
- `calibrate run` cleans orphan ELO overrides (agent_ids with no matching role in library)
- Review IDs include random component: `r_{timestamp}_{hex4}` to prevent collisions
- Config file permissions checked on load: warns if critical files are world-writable (Unix only)
- Review invariants are hardcoded in review.rs, not configurable: author!=reviewer, no reciprocal, min 2 scores, hash verification
- ELO is append-only JSONL log with 10MB rotation — never mutable state. Rating calculated at read time with temporal decay
- Review MCP tools (submit, evaluate) are in `restricted` — require human oversight
- Trust gate floor (5.0) is hardcoded — config can raise threshold but never below floor
- rmcp MCP server: uses `#[tool_router]` on impl + `#[tool_handler(router = self.tool_router)]` on ServerHandler
- CLI maps `HookPayload` → `colmena_core::models::EvaluationInput` before calling core (protocol-agnostic boundary)
- Integration test paths: use `Path::parent()` for workspace root, never string concat with `..`
- Role `permissions` block is optional — existing roles without it parse fine (backward compatible)
- RuntimeDelegation has optional `source`, `mission_id`, `conditions` fields (serde(default))
- Mission delegations are session-bound when session_id is provided at generate_mission()
- ELO overrides stored separately in `config/elo-overrides.json`, never pollute trust-firewall.yaml
- YAML agent_overrides take precedence over ELO overrides (human always wins)
- Calibration warm-up: agents need min_reviews_to_calibrate (default 3) before ELO trust applies
- TrustTier: Uncalibrated → Standard → Elevated/Restricted/Probation
- `colmena calibrate reset` instantly revokes all ELO-based trust
- Mission delegation TTL default: 8h (DEFAULT_MISSION_TTL_HOURS), max 24h
- Bash delegations require mandatory conditions (bash_pattern or path_within) — enforced in save_delegations and CLI
- Delegations without `expires_at` are skipped on load with warning (no permanent delegations via JSON injection)
- Finding severity validated against closed enum: `["critical", "high", "medium", "low"]`
- `library_generate` MCP is read-only — returns CLI commands for delegations, never persists directly
- `generate_mission()` accepts ELO ratings to assign reviewer lead (highest ELO in squad)
- CC PostToolUse sends `tool_response` (not `tool_output`) and `interrupted` (not `exitCode`)
- Config files protected in trust_circle Write rule via path_not_match (trust-firewall.yaml, runtime-delegations.json, audit.log, elo-overrides.json, filter-config/stats, settings.json)
- `gh pr merge` is blocked in firewall — PRs are merged by human only, never by Claude or agents
- `generate_mission()` accepts optional `config_dir` for M4 prompt review detection — `None` skips detection (backward compatible)
- Prompt review detection uses compound keyword matching: prefix ("review", "improve", "refine") + role name/id + suffix ("prompt", "instructions", "approach") — all three required to avoid false positives
- Findings with `category: "prompt_improvement"` are suggestions from debate/mentor agents about role prompts — queryable via `findings_query`, human decides what to apply
- Wisdom Library has 6 built-in roles + 7 built-in patterns. New roles/patterns created via `library_create_role`/`library_create_pattern`
- RoleCategory: 8 categories (offensive, defensive, compliance, architecture, research, development, operations, creative) — each with distinct trust level, tools, methodology, safety rails
- PatternTopology: 7 topologies (hierarchical, sequential, adversarial, peer, fan-out-merge, recursive, iterative) — aligned with agentic-patterns.com
- `library_select` suggests creating a pattern when no existing one matches the mission
- Generated role prompts have 5 sections: Core Responsibilities, Methodology (5 phases), Escalation, Output Format, Boundaries
- Generated roles/patterns are starting points — human/CC customizes after creation
- Caido pentester roles (web_pentester, api_pentester) are Caido-native — every methodology step references specific Caido MCP tools, designed for bug bounty missions
- `colmena setup` embeds all 22 default config + library files via `include_str!()` (~46KB) — binary is self-contained
- Setup detects repo mode (Cargo.toml nearby) vs standalone mode (release binary) automatically
- Setup merge strategy: new defaults copied, custom files preserved (new defaults saved to `.defaults/` for reference)
- `~/.mcp.json` is the global MCP registration target — setup writes absolute path to colmena-mcp binary

## CLI Subcommands

```
colmena hook                          # Hot path: stdin JSON → evaluate → stdout JSON (CC hook)
colmena queue list                    # List pending approval items
colmena queue prune --older-than 7    # Prune entries older than N days
colmena delegate add --tool X [--agent Y] [--ttl 4]  # Add delegation (max 24h)
colmena delegate list                 # List active delegations
colmena delegate revoke --tool X      # Revoke a delegation
colmena config check                  # Validate trust-firewall.yaml
colmena install                       # Register hook in ~/.claude/settings.json
colmena setup [--dry-run] [--force]   # One-command onboarding: config + hooks + MCP
colmena library list                  # List roles + patterns
colmena library show <id>             # Show role or pattern details
colmena library select --mission "…"  # Pattern selector + mission generator
colmena library create-role --id X --description "Y" [--category Z]  # Intelligent role creation
colmena library create-pattern --id X --description "Y" [--topology Z]  # Pattern scaffolding
colmena review list [--state pending]  # List peer reviews
colmena review show <review-id>        # Review detail
colmena elo show                       # ELO leaderboard
colmena mission list                   # List active missions with delegation counts
colmena mission deactivate --id X      # Revoke all delegations for a mission
colmena calibrate run                  # Run ELO-based trust calibration
colmena calibrate show                 # Show current trust tiers per agent
colmena calibrate reset                # Clear all ELO-based overrides
colmena stats                          # Combined firewall + filter savings summary
colmena stats --session <id>           # Stats for a specific session
```

## MCP Tools (M0.5)

```
config_check       — validate firewall config
queue_list         — list pending approvals
delegate           — request delegation (returns CLI command, read-only)
delegate_list      — list active delegations
delegate_revoke    — request revocation (returns CLI command, read-only)
evaluate           — evaluate a tool call against firewall
```

## MCP Tools (M1)

```
library_list       — list roles + patterns
library_show       — show role/pattern details
library_select     — recommend patterns for a mission
library_generate   — generate CLAUDE.md per agent for a mission
library_create_role — create role with intelligent defaults (8 categories)
library_create_pattern — create pattern with topology detection (7 topologies)
```

## MCP Tools (M2)

```
review_submit      — submit artifact for peer review (assigns reviewer)
review_list        — list peer reviews (pending/completed)
review_evaluate    — submit scores + findings as reviewer (triggers ELO + trust gate)
elo_ratings        — ELO leaderboard with temporal decay
findings_query     — search findings by role/category/severity/date/mission
findings_list      — list recent findings
```

## MCP Tools (M3)

```
mission_deactivate — request mission deactivation (returns CLI command, read-only)
calibrate          — show ELO-based trust calibration state + recommend CLI commands
session_stats      — show prompts saved + tokens saved (call before ending session)
```

## Environment Variables

- `COLMENA_HOME` — Override project root (default: auto-detected from binary)
- `COLMENA_CONFIG` — Override config file path

## Roadmap

- **M0** Trust Firewall + Approval Hub (done)
- **M0.5** Workspace refactor + MCP server (done)
- **M1** Wisdom Library + Pattern Selector + RRA hardening (done)
- **M2** Peer Review Protocol + ELO Engine + Findings Store (done)
- **M2.5** Output Filtering — PostToolUse hook + colmena-filter pipeline (done)
- **M3** Dynamic trust calibration — role-bound permissions + ELO → firewall rules (done)
- **M3.5** Security hardening + Mission bridge — STRIDE/DREAD fixes, session stats, ELO reviewer lead (done)
- **M4** Mentor prompt refinement — debate pattern for prompt improvement suggestions (done)
- **M4.1** Caido-native pentester roles — web_pentester + api_pentester + caido-pentest pattern (done)
- **M5** Plug-and-play onboarding — `colmena setup` command (done)
- **M6** Intelligent role & pattern creation — 8 role categories, 7 pattern topologies, pattern suggestion (done)
- **M6.1** Security hardening — STRIDE/DREAD threat model fixes: error sanitization, rate limiting, log rotation, orphan cleanup, permissions checks (done)
- **M7** Library Guardian — prompt validation, file integrity, trust elevation (planned)

## Current State (2026-04-03)

**Branch:** `main` (v0.6.1)
**Done:** M0, M0.5, M1, RRA hardening, M2, M2.5, M3, M3.5, M3.6 (security hardening), M4, M4.1, M5, M6 (intelligent role creation), M6.1 (security hardening — STRIDE/DREAD fixes)
**Next:** M7 (Library Guardian — prompt validation, integrity checks)

## Key Docs

- `docs/specs/2026-03-29-hivemind-design.md` — Full design spec (M0-M3)
- `docs/plans/2026-03-29-full-roadmap.md` — Full roadmap with MCP integration
- `docs/dark-corners.md` — M0 edge case analysis
- `docs/dark-corners-m1.md` — M1 edge case analysis
- `docs/security/` — STRIDE+DREAD threat model reports (gitignored, local reference only)
- `docs/guide.md` — User guide with payments API audit walkthrough
- `docs/presentation.html` — Overview deck (open in browser)
- `docs/superpowers/specs/2026-04-02-mission-bridge-design.md` — Mission bridge spec (agent spawn → review → ELO)
- `docs/superpowers/specs/2026-04-02-mentor-prompt-refinement-design.md` — M4 spec (debate pattern for prompt improvement)
- `docs/caido-pentester-roles-plan.md` — M4.1 plan (Caido-native web_pentester + api_pentester roles)
- `docs/superpowers/specs/2026-04-02-colmena-setup-design.md` — M5 spec (colmena setup onboarding command)
- `docs/superpowers/specs/2026-04-02-intelligent-role-creation-design.md` — M6 spec (intelligent role + pattern creation)
