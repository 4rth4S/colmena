# Changelog

All notable changes to Colmena are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/).
Versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.5.0] - 2026-04-02

### Added
- **Plug-and-play onboarding (M5):** `colmena setup` replaces 4 manual steps with one command
  - Auto-detects repo mode (developer clone) vs standalone mode (release binary)
  - Embeds all 22 default config + library files (~46KB) in binary via `include_str!()`
  - Merge inteligente: copies new defaults, preserves custom files (saves new defaults to `.defaults/`)
  - Registers Pre/PostToolUse hooks (delegates to `install`)
  - Registers MCP server globally in `~/.mcp.json` with absolute path
  - Verifies config, library, hooks, and MCP binary with formatted checklist
  - `--dry-run` previews all actions without modifying, `--force` overwrites everything
  - New files: `colmena-cli/src/setup.rs`, `colmena-cli/src/defaults.rs`

### Changed
- `install.rs`: `colmena_binary_path()` and `settings_json_path()` now `pub(crate)` for setup reuse
- Tests: 202 (was 193), 9 new tests for setup merge logic and MCP registration

## [0.4.0] - 2026-04-02

### Added
- **Caido-native pentester roles (M4.1):** two new specialized roles for bug bounty missions using Caido MCP tools
  - `web_pentester`: XSS, CSRF, CORS, IDOR, session management, clickjacking, open redirect — Caido-native methodology with HTTPQL examples
  - `api_pentester`: BOLA, broken auth, injection, mass assignment, business logic, rate limiting, GraphQL — OWASP API Security Top 10 coverage
  - `caido-pentest` pattern: connects new roles to the pattern selector (`library_select` recommends it for web/API/bug bounty missions)
  - Both roles include mission setup protocol, safety rails, scope enforcement, and finding output format mapped to `caido_create_finding()`
- **Mentor prompt refinement (M4):** debate pattern for prompt improvement suggestions
  - `generate_prompt_review_context()` loads target role's prompt, ELO performance, and recent findings
  - Compound keyword detection: triggers only when mission text contains prefix + role name + suffix (e.g., "review pentester prompt")
  - Context injected into debate/mentor agents' CLAUDE.md for structured analysis
  - Suggestions stored as findings with `category: "prompt_improvement"` — human decides what to apply
- **Firewall hardening:** `gh pr merge` blocked — PRs are merged by human only

### Changed
- `generate_mission()` now accepts optional `config_dir: Option<&Path>` for prompt review detection (backward compatible — `None` skips detection)
- Wisdom Library: 6 roles (was 4), 7 patterns (was 6)
- Tests: 193 (was 184), 9 new tests for prompt review keyword detection and context generation

## [0.3.0] - 2026-04-02

### Added
- **Security hardening sprint:** 8 STRIDE/DREAD fixes resolving all Critical and High findings
  - Removed `curl -s` from pipe auto-approve pattern (DREAD 9.4 → 2.0)
  - `library_generate` MCP now read-only — returns CLI commands, never persists delegations
  - Config files protected via `path_not_match` (trust-firewall.yaml, runtime-delegations.json, audit.log, etc.)
  - Bash delegations require mandatory scope conditions (bash_pattern or path_within)
  - ELO override regex patterns now compiled in evaluation flow
  - Finding severity validated against closed enum [critical, high, medium, low]
  - Delegations without `expires_at` skipped on load with warning
- **PostToolUse filter fix:** aligned payload with CC actual format (`tool_response` not `tool_output`, `interrupted` not `exitCode`). Output filtering now works.
- **Session stats:** `colmena stats` shows combined firewall + filter savings. `colmena stats --session <id>` for per-session view.
- **`session_stats` MCP tool:** on-demand access to prompts saved + tokens saved summary (20 MCP tools total)
- **Mission bridge:** `library_generate` now queries ELO ratings to assign reviewer lead (highest ELO). Generated CLAUDE.md files include post-work review protocol for workers and review responsibility for the lead.
- **Review instruction templates:** `config/library/prompts/review-worker-instructions.md` and `review-lead-instructions.md`
- **Session protocol in CLAUDE.md:** instructions to call `session_stats` before ending and `library_select` before spawning agents

### Changed
- `generate_mission()` now accepts `elo_ratings` parameter for reviewer lead assignment
- `MissionConfig` includes `reviewer_lead: Option<ReviewerLead>` field
- Security reports (`docs/security/`) removed from git tracking, gitignored

### Fixed
- PostToolUse hook silently passed through all outputs since M2.5 due to payload field mismatch
- `config/trust-firewall.yaml` Write auto-approve exposed Colmena's own config files to agent modification

## [0.2.0] - 2026-04-01

### Added
- **Dynamic trust calibration (M3):** ELO scores now drive firewall rules automatically
  - `colmena calibrate run` -- applies ELO-based trust tiers as agent overrides
  - `colmena calibrate show` -- displays current trust tier per agent
  - `colmena calibrate reset` -- clears all ELO-based overrides instantly
  - Trust tiers: Uncalibrated, Elevated, Standard, Restricted, Probation
  - Warm-up period: agents need 3+ peer reviews before calibration applies
  - ELO overrides stored in `config/elo-overrides.json` (separate from YAML)
- **Mission lifecycle management:**
  - `colmena mission list` -- shows active missions with delegation counts
  - `colmena mission deactivate --id X` -- revokes all delegations for a mission
- **Role-bound permissions:** roles can define `permissions` block with `bash_patterns`, `path_within`, `path_not_match` for scoped auto-approve rules
- **Mission delegations:** `library_generate` now creates scoped delegations from role permissions, with optional session binding and 8h default TTL
- **Delegation conditions:** `RuntimeDelegation` supports `conditions` field for fine-grained matching (bash_pattern, path_within, path_not_match)
- **Delegation provenance:** `RuntimeDelegation.source` tracks origin ("human", "role", "elo") and `mission_id` links to missions for bulk revocation
- **Pre-Approved Operations section** in generated CLAUDE.md files -- agents know what they can do without asking
- **2 new MCP tools:** `mission_deactivate`, `calibrate` (19 tools total)
- **3 new audit events:** MISSION_ACTIVATE, MISSION_DEACTIVATE, CALIBRATION
- **New crate module:** `colmena-core/src/calibrate.rs` -- TrustThresholds, TrustTier, calibrate(), save/load overrides

### Changed
- Firewall evaluation precedence now includes ELO overrides: blocked > delegations > agent_overrides (YAML) > ELO overrides > restricted > trust_circle > defaults
- `evaluate()` has a new `evaluate_with_elo()` companion that accepts ELO-calibrated overrides
- Hook now loads `elo-overrides.json` at evaluation time (safe fallback: empty if missing)
- Role scaffold template includes documented `permissions` section (commented out)
- Prompt scaffold template includes "Tools Available" section

### Upgrade notes
- **Zero migration required.** Rebuild and the new features are available.
- Config `trust-firewall.yaml` (version: 1) unchanged -- no schema changes.
- `runtime-delegations.json` has new optional fields (`source`, `mission_id`, `conditions`) -- backward compatible via serde defaults.
- No need to re-run `colmena install` -- hook registration unchanged.

## [0.1.0] - 2026-03-30

### Added
- **Trust Firewall (M0):** declarative YAML rules with precedence (blocked > delegations > agent_overrides > restricted > trust_circle > defaults)
- **Approval Queue (M0):** pending items with priority, timestamps, and truncated inputs
- **Runtime Delegations (M0):** time-limited trust expansion with TTL (max 24h), per-agent and per-session scoping
- **Audit Log (M0):** append-only log for every firewall decision
- **Sound Notifications (M0):** macOS sound cues for different decision types
- **MCP Server (M0.5):** 6 trust management tools via rmcp + stdio transport
- **Wisdom Library (M1):** 4 security roles (pentester, auditor, researcher, security_architect) with ELO config and mentoring
- **Orchestration Patterns (M1):** 6 patterns (oracle-workers, plan-then-execute, debate, mentored-execution, pipeline, swarm-consensus)
- **Pattern Selector (M1):** keyword-based scoring with when_to_use/when_not_to_use/specializations matching
- **Mission Generator (M1):** creates per-agent CLAUDE.md files from role prompts + mission context
- **Role Scaffold (M1):** `library create-role` generates role YAML + prompt template
- **RRA Security Hardening (M1):** path traversal prevention, role ID validation, prompt containment
- **Peer Review Protocol (M2):** submit/assign/evaluate flow with 6 security invariants
- **ELO Engine (M2):** append-only JSONL event log, temporal decay (1.0/0.7/0.4/0.1), leaderboard
- **Trust Gate (M2):** auto-approve at score >= 7.0 with no critical findings, hardcoded floor at 5.0
- **Findings Store (M2):** persistent findings from reviews, queryable by role/category/severity/date/mission
- **Output Filtering (M2.5):** PostToolUse hook with 4-stage pipeline (ANSI strip, stderr-only, dedup, smart truncation)
- **Filter Statistics (M2.5):** JSONL token savings log with `colmena stats` summary
- **20 MCP tools** across M0.5, M1, M2
- **CLI** with hook, queue, delegate, config, install, library, review, elo, stats subcommands

---

built with love by AppSec
