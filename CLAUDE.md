# Colmena

Multi-agent orchestration layer for Claude Code. Rust workspace with hook binary + MCP server. Auto-approves routine operations, exposes trust management as native CC tools.

## Quick Reference

- **Build:** `cargo build --workspace --release`
- **Test:** `cargo test --workspace`
- **Lint:** `cargo clippy --workspace -- -W warnings`
- **CLI binary:** `target/release/colmena`
- **MCP binary:** `target/release/colmena-mcp`
- **Config:** `config/trust-firewall.yaml`, `config/filter-config.yaml`
- **MCP registration:** `.mcp.json`
- **Repo:** `git@git.in.ripio.com:nicobrambilla/colmena.git`

## Architecture

Rust workspace with 4 crates:

- **colmena-core** — shared library: config, firewall, delegate, queue, models, paths. Zero platform deps.
- **colmena-cli** — CLI binary: Pre/PostToolUse hooks, clap subcommands, notifications (no-op placeholder), install
- **colmena-filter** — output filtering pipeline: OutputFilter trait, 4 base filters, FilterPipeline with catch_unwind, JSONL stats
- **colmena-mcp** — MCP server: rmcp, stdio transport, exposes core functions as CC tools

Three CC integration points:
1. **PreToolUse Hook (reactive):** evaluates every tool call against YAML firewall rules
2. **PostToolUse Hook (reactive):** filters Bash outputs via colmena-filter pipeline before CC processes them
3. **MCP (proactive):** CC calls colmena tools natively (config_check, queue_list, delegate, evaluate)

Rule precedence: `blocked > delegations > agent_overrides > restricted > trust_circle > defaults`

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
- Token savings logged to JSONL at `<colmena_home>/config/filter-stats.jsonl`
- Review invariants are hardcoded in review.rs, not configurable: author!=reviewer, no reciprocal, min 2 scores, hash verification
- ELO is append-only JSONL log — never mutable state. Rating calculated at read time with temporal decay
- Review MCP tools (submit, evaluate) are in `restricted` — require human oversight
- Trust gate floor (5.0) is hardcoded — config can raise threshold but never below floor
- rmcp MCP server: uses `#[tool_router]` on impl + `#[tool_handler(router = self.tool_router)]` on ServerHandler
- CLI maps `HookPayload` → `colmena_core::models::EvaluationInput` before calling core (protocol-agnostic boundary)
- Integration test paths: use `Path::parent()` for workspace root, never string concat with `..`

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
colmena library list                  # List roles + patterns
colmena library show <id>             # Show role or pattern details
colmena library select --mission "…"  # Pattern selector + mission generator
colmena library create-role --id X    # Scaffold new role template
colmena review list [--state pending]  # List peer reviews
colmena review show <review-id>        # Review detail
colmena elo show                       # ELO leaderboard
colmena stats                          # Filter token savings summary
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
library_create_role — scaffold new role
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

## Environment Variables

- `COLMENA_HOME` — Override project root (default: auto-detected from binary)
- `COLMENA_CONFIG` — Override config file path

## Roadmap

- **M0** Trust Firewall + Approval Hub (done)
- **M0.5** Workspace refactor + MCP server (done)
- **M1** Wisdom Library + Pattern Selector + RRA hardening (done)
- **M2** Peer Review Protocol + ELO Engine + Findings Store (done)
- **M2.5** Output Filtering — PostToolUse hook + colmena-filter pipeline (done)
- **M3** Dynamic trust calibration (ELO → firewall rules)

## Current State (2026-04-01)

**Branch:** `feature/colmena-filter-post-tool-use`
**Done:** M0, M0.5, M1, RRA hardening, M2, M2.5 (output filtering)
**In progress:** Documentation updates for M2.5
**Next:** M3 (dynamic trust calibration — ELO → firewall rules)

## Key Docs

- `docs/specs/2026-03-29-hivemind-design.md` — Full design spec (M0-M3)
- `docs/plans/2026-03-29-full-roadmap.md` — Full roadmap with MCP integration
- `docs/dark-corners.md` — M0 edge case analysis
- `docs/dark-corners-m1.md` — M1 edge case analysis
- `docs/security/RRA_Summary_JIRA_colmena.md` — STRIDE+DREAD threat model (NOT committed, gitignored)
- `docs/guide.md` — User guide with payments API audit walkthrough
- `docs/presentation.html` — Overview deck (open in browser)
