# Changelog

All notable changes to Colmena are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/).
Versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.10.0] - 2026-04-14

### Added
- **Mission Spawn (M7.1):** one-step mission creation via `mission_spawn` MCP tool
  - `spawn_mission()` core function: select pattern → auto-create if no match → map roles → generate mission with markers
  - `SpawnResult`, `AgentPrompt` structs — returns ready-to-paste prompts + delegation CLI commands
  - `MISSION_MARKER_PREFIX` (`<!-- colmena:mission_id=...-->`) embedded in agent prompts
  - Auto-creates patterns via `scaffold_pattern()` when no existing pattern matches
  - Uses `map_topology_roles()` (from M7) to assign real roles to auto-created pattern slots
- **Mission Gate:** opt-in enforcement for Agent tool calls
  - `enforce_missions: bool` on `FirewallConfig` (default false, zero impact on existing installs)
  - PreToolUse step 4c: checks Agent calls for `MISSION_MARKER_PREFIX` when enforced
  - "ask" not "deny" — human can always override and proceed without mission binding
  - Only applies to Agent tool — other tools pass through normally
- **2 new audit events:** `MissionSpawn` (mission_id, pattern_id, auto_created, agent_count) + `MissionGate` (session_id, agent_id)
- **`mission_spawn` MCP tool (25→26):** rate-limited, restricted, returns formatted output with agent prompts + delegation commands + role gap warnings

### Changed
- trust-firewall.yaml: `enforce_missions: false` field, `mission_spawn` in restricted rules
- Tests: 328 (was 314), 14 new tests (5 selector + 3 config + 2 audit + 4 integration)

## [0.9.0] - 2026-04-14

### Added
- **Generic development roles (M7):** 4 new roles for general software engineering workflows
  - `developer` — feature implementation, code writing, build/test execution (includes Agent in tools_allowed)
  - `code_reviewer` — code quality reviews, bug detection, style/performance analysis (read-only Bash)
  - `tester` — test writing, test execution, coverage analysis, regression detection
  - `architect` — system design, tradeoff analysis, technical documentation (Write scoped to docs/)
  - All start at trust level "ask" — ELO calibration elevates over time
  - Each role has scoped `bash_patterns` and `path_not_match` for credentials/secrets
- **3 dev workflow patterns:** purpose-built for software engineering tasks
  - `code-review-cycle` (iterative) — developer implements → auditor reviews → feedback loop
  - `docs-from-code` (sequential) — architect reads → developer generates docs → auditor validates
  - `refactor-safe` (sequential) — developer refactors → tester validates → auditor approves
- **`map_topology_roles()`** — topology-aware role-to-slot mapping with mission keyword scoring
  - `SlotRoleType` enum: Lead, Offensive, Defensive, Research, Worker, Judge
  - Preferred role lists per slot type with specialization-based tie-breaking
  - No-duplicate invariant: each role assigned to at most one slot
  - Topology slot layouts for all 7 topologies
- **Auditor QPC evaluation framework:** formalized 3-dimension scoring
  - Quality (1-10), Precision (1-10), Comprehensiveness (1-10)
  - Role-agnostic evaluation — same dimensions for developers, researchers, pentesters
  - Integrated into auditor.md system prompt
- **Inter-agent token efficiency directive:** injected into multi-agent missions
  - "Facts only" communication protocol for agent-to-agent messages
  - Code/commands/configs never compressed — only prose communication
  - Automatic injection via `generate_mission()` for missions with 2+ agents

### Changed
- Library grows from 6→10 roles, 7→10 patterns
- `defaults.rs` embeds 11 new files (4 roles + 3 patterns + 4 prompts)
- `selector.rs` re-exports `map_topology_roles`, `SlotRoleType`, `SlotDesc`
- Tests: 314 (was 303), 11 new tests

## [0.8.0] - 2026-04-14

### Added
- **Enforced Peer Review (M6.4):** SubagentStop hook blocks mission workers from stopping without calling `review_submit`
  - `SubagentStopPayload` + `SubagentStopResponse` — separate lifecycle event types (no tool_name/tool_input)
  - Hook routing refactored: peek `hook_event_name` from raw JSON, then deserialize to correct type
  - `run_subagent_stop_hook()`: check delegation → role_type → review existence → approve/block
  - Safe fallback: any error → approve (never trap an agent)
- **Centralized auditor model:** replaces cross-review with one dedicated evaluator role
  - `role_type: Option<String>` on Role struct — auditor.yaml has `role_type: auditor`
  - Auditor exempt from review enforcement via role_type check (human-controlled)
  - `evaluation_narrative: Option<String>` on ReviewEntry for auditor reasoning
  - Auditor CLAUDE.md includes full evaluation protocol (score dimensions, narrative, 3 alternatives)
- **Alerts system:** `colmena-core/src/alerts.rs` — surfaces low-score reviews without blocking
  - `Alert` struct with severity (critical/warning), append-only JSON, atomic writes
  - `create_alert()` triggered by `review_evaluate` when trust_gate returns NeedsHumanReview
  - `alerts.json` protected in trust-firewall.yaml path_not_match
- **4 new MCP tools (21→25):**
  - `alerts_list` — read-only, lists alerts with optional severity/acknowledged filters
  - `alerts_ack` — restricted, acknowledges alert(s) by ID or "all"
  - `calibrate_auditor` — read-only, presents last N auditor evaluations with narrative + alternatives (bilingual en/es)
  - `calibrate_auditor_feedback` — restricted, adjusts auditor ELO (+10/−5/−10), saves corrections as findings
- **`session_stats` enriched:** shows unacknowledged alert count warning
- **`has_submitted_review()`** in review.rs — check if agent submitted review for mission

### Changed
- SubagentStop registered as 4th hook in install.rs + setup.rs (was 3 hooks)
- `alerts.json` added to RUNTIME_FILES in setup.rs
- trust-firewall.yaml: restricted rules for `alerts_ack` and `calibrate_auditor_feedback`, path_not_match for alerts.json
- Tests: 303 (was 281), 22 new tests (5 integration + 17 unit)

## [0.7.0] - 2026-04-13

### Added
- **Role tools_allowed firewall (M6.3):** PermissionRequest hook auto-approves role tools via CC session rules, mission revocation kill switch

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
