# Colmena

Multi-agent orchestration layer for Claude Code. Rust workspace with hook binary + MCP server. Auto-approves routine operations, exposes trust management as native CC tools.

## Session Protocol

- **Before ending a session:** Always call `mcp__colmena__session_stats` to show the value summary (prompts saved + tokens saved). This helps the user understand Colmena's impact.
- **Before spawning agents:** Call `mcp__colmena__library_select` to check if there's an appropriate role. If there is, use the Colmena-generated prompt for the agent.

## Quick Reference

- **Build:** `cargo build --workspace --release`
- **Test:** `cargo test --workspace` (single crate: `cargo test -p colmena-core`)
- **Lint:** `cargo clippy --workspace -- -D warnings` (CI enforces `-D` since PR #25)
- **Fmt:** `cargo fmt --all --check` (CI-enforced)
- **CLI binary:** `target/release/colmena`
- **MCP binary:** `target/release/colmena-mcp`
- **Version:** 0.13.0 (semver, single workspace version)
- **Config:** `config/trust-firewall.yaml`, `config/filter-config.yaml`
- **MCP registration:** `.mcp.json`
- **CI:** GitHub Actions — `ci.yml` (fmt + test + clippy `-D warnings` + build + audit + deny on PRs), `release.yml` (tag-triggered releases), dependabot weekly for cargo + github-actions
- **Repo:** `git@github.com:4rth4S/colmena.git`

## Positioning

**Who it's for (ICP).** Pentesters, dev teams, devops, and SRE working in contexts where compliance and auditability matter, or where running many parallel sub-agents requires governance. Validated (2026-04-16) with 4 power users across these profiles.

**Three differentiators.**

1. **Deterministic governance.** Every tool call is evaluated against YAML rules with compiled regexes. Zero LLM calls in the hot path, zero per-call cost, `<15ms` hook latency. Every decision is written to `config/audit.log` with the matching rule ID — any auditor can replay the log and explain why a call was allowed, asked, or blocked.
2. **Multi-agent governance with peer review.** Missions spawn agents with mission markers (`<!-- colmena:mission_id=... -->`); workers submit artifacts through `review_submit`, a centralized auditor evaluates with the QPC framework (Quality + Precision + Comprehensiveness, 1–10 each), and `SubagentStop` gates block workers and reviewers from stopping until the cycle closes. Accountability is per-agent and per-role, not per-call.
3. **ELO-calibrated trust progression.** Role trust is not declared — it's earned. Review outcomes feed a per-role ELO log with temporal decay. Roles climb from Uncalibrated → Standard → Elevated (auto-approve role-scoped tools) or drop to Restricted / Probation. ELO overrides live in a separate file so config stays human-readable, and YAML overrides always win (human authority > ELO).

**Relationship to Claude Code auto-mode.** Anthropic's `--enable-auto-mode` (research preview, 2026-03-24) does semantic intent detection with an LLM classifier — it catches things a rule can't, like prompt injection attempts or context the agent didn't have. Colmena does deterministic rule-based governance plus multi-agent accountability and a local, tamper-evident audit trail. They solve different layers of the same problem and are intended to be used together, not as alternatives. Auto-mode handles "is this request aligned with user intent?", Colmena handles "is this action allowed by the policy I wrote, and who on my team is accountable for the outcome?".

## Architecture

Rust workspace with 4 crates:

- **colmena-core** — shared library: config, firewall, delegate, calibrate, queue, models, paths. Zero platform deps.
- **colmena-cli** — CLI binary: Pre/PostToolUse/PermissionRequest/SubagentStop hooks, clap subcommands, notifications (no-op placeholder), install
- **colmena-filter** — output filtering pipeline: OutputFilter trait, 4 base filters, FilterPipeline with catch_unwind, JSONL stats
- **colmena-mcp** — MCP server: rmcp, stdio transport, exposes core functions as CC tools

Five CC integration points:
1. **PreToolUse Hook (reactive):** evaluates every tool call against YAML firewall rules + mission revocation kill switch
2. **PostToolUse Hook (reactive):** filters Bash outputs via colmena-filter pipeline before CC processes them
3. **PermissionRequest Hook (reactive):** intercepts CC permission prompts, auto-approves tools in role's `tools_allowed` via session rules
4. **SubagentStop Hook (reactive):** blocks mission workers from stopping without calling `review_submit` — auditor role exempt
5. **MCP (proactive):** CC calls 27 colmena tools natively — firewall, library, review, ELO, findings, alerts, calibration, stats

PreToolUse precedence: `blocked > delegations > agent_overrides (YAML) > ELO overrides > restricted > chain_guard > mission_revocation > trust_circle > defaults`
PermissionRequest precedence: `role delegation exists + tool in tools_allowed → allow + teach CC session rules`

## Tech Stack

- **Language:** Rust (edition 2021, workspace, stable toolchain — no nightly features)
- **Core deps:** serde, serde_json, serde_yml, regex, anyhow, chrono
- **CLI deps:** clap (derive)
- **MCP deps:** rmcp (server, transport-io, macros), tokio
- **Config format:** YAML (firewall rules), JSON (queue, delegations, MCP)
- **No external services** — everything is filesystem-based

## Conventions

### General

- Git: always use branches (feature/, fix/, chore/, docs/). Never commit to main. MR workflow.
- Signature: "built with ❤️‍🔥 by AppSec" on all public-facing docs and commit trailers
- Error handling: `anyhow::Result` everywhere. Never panic in the hook path.
- HOME fallback to /tmp is banned — fail explicitly if HOME is not set
- Run clippy before release — must be clean

### Hooks (PreToolUse / PostToolUse / PermissionRequest / SubagentStop)

- Hook path must complete in <100ms — no network calls, no heavy I/O
- PreToolUse safe fallback: any error → `ask`, never `deny` or exit 2
- PostToolUse safe fallback: any error → passthrough (return original unchanged), never "ask" or "deny"
- PermissionRequest safe fallback: any error → no output (CC continues to prompt user)
- PermissionRequest only activates for agents with `source: "role"` delegation (human-approved mission)
- PermissionRequest teaches CC session rules via `updatedPermissions` — subsequent calls auto-approved by CC without hooks
- Mission revocation (`revoked-missions.json`) overrides CC session rules — PreToolUse deny fires before CC checks learned rules
- CC hooks JSON format: `{ "matcher": "", "hooks": [{ "type": "command", "command": "..." }] }`
- CLI maps `HookPayload` → `colmena_core::models::EvaluationInput` before calling core (protocol-agnostic boundary)
- Watchdog timeout (5s) logged as TIMEOUT event in audit.log before exit
- CC PostToolUse sends `tool_response` (not `tool_output`) and `interrupted` (not `exitCode`)
- SubagentStop safe fallback: any error → approve (never trap an agent)
- SubagentStop checks: delegation with `source: "role"` → role_type != "auditor" → has_pending_evaluations() → has_submitted_review() → approve/block
- SubagentStop reviewer gate: agents with pending reviews as reviewer_role are blocked until they call review_evaluate (checked before review_submit gate)
- SubagentStop uses separate `SubagentStopPayload` (lifecycle event, no tool_name/tool_input)
- Auditor role exempt from review check via `role_type: auditor` in YAML (human-controlled)

### Delegations

- Delegations always have a TTL (max 24h), `--permanent` removed. Validate with `validate_ttl()`
- Mission delegation TTL default: 8h (DEFAULT_MISSION_TTL_HOURS), max 24h
- Bash delegations require mandatory conditions (bash_pattern or path_within) — enforced in save_delegations and CLI
- Bash delegation bash_pattern validated as compilable regex before persisting
- Delegations without `expires_at` are skipped on load with warning (no permanent delegations via JSON injection)
- Expired delegations logged as DELEGATE_EXPIRE audit events on load
- CLI `delegate add` supports `--session <id>` to limit delegation scope to one CC session
- Delegations without `--session` warn about global scope (applies to ALL CC sessions)
- `revoked-missions.json` is a runtime file — tracks agent IDs whose missions were deactivated mid-session

### MCP Server

- MCP delegate/revoke tools are read-only: return CLI commands for human confirmation, never execute directly
- `library_generate` MCP is read-only — returns CLI commands for delegations, never persists directly
- MCP error messages sanitized via `colmena_core::sanitize::sanitize_error` — no filesystem paths leak to agents
- MCP generative tools rate-limited: 30 calls/min per tool (library_generate, review_submit, review_evaluate, library_create_role/pattern, mission_deactivate, mission_spawn, alerts_ack, calibrate_auditor_feedback)
- MCP evaluate uses evaluate_with_elo() — includes ELO overrides so probation agents show correct restrictions
- rmcp: uses `#[tool_router]` on impl + `#[tool_handler(router = self.tool_router)]` on ServerHandler

### Security & Trust

- Agent tool is in `restricted` (ask), not `trust_circle` (auto-approve)
- `library_create_role` and `library_create_pattern` are in `restricted` — require human review (prevent library poisoning)
- Review MCP tools (submit, evaluate) are in `restricted` — require human oversight
- `gh pr merge` is blocked in firewall — PRs are merged by human only, never by Claude or agents
- Elevated trust without bash_patterns generates "ask" (not auto-approve) for Bash — forces pattern definition
- Reviewer selection randomized via rand::seq::SliceRandom — prevents deterministic assignment and collusion
- Review invariants are hardcoded in review.rs: author!=reviewer, no reciprocal, min 2 scores, hash verification
- Stale review auto-invalidation: `review_submit` invalidates prior pending reviews for same artifact+mission+author with hash mismatch (state → `Invalidated`, moved to `completed/`)
- Cross-agent invalidation blocked: only the original author can trigger invalidation of their own reviews (STRIDE TM P0)
- `ReviewState::Invalidated` reviews are excluded from anti-reciprocal pairing so freed reviewer slots can be reused
- Trust gate floor (5.0) is hardcoded — config can raise threshold but never below floor
- YAML agent_overrides take precedence over ELO overrides (human always wins)
- Config file permissions checked on load: warns if critical files are world-writable (Unix only)
- Config files protected in trust_circle Write rule via path_not_match (trust-firewall.yaml, runtime-delegations.json, audit.log, elo-overrides.json, filter-config/stats, settings.json, revoked-missions.json, alerts.json, reviews/, findings/)
- Alerts are append-only — agents can't acknowledge or delete alerts
- `alerts_ack` and `calibrate_auditor_feedback` in restricted (ELO/alert modification needs human oversight)

### Config & Data

- YAML regex patterns use single-quoted strings to avoid `\b` → backspace escaping issues
- Firewall `bash_pattern` conditions only apply when tool is `Bash` — skip for other tools
- Glob matching in `path_not_match` operates on **filename only** (last path component)
- Path comparison uses component-based normalization (not `canonicalize()`)
- Regex patterns compiled once at config load time (`compile_config`)
- Atomic file writes (temp + rename) for concurrent CC instances
- All firewall decisions logged to `config/audit.log` (append-only, one line per decision)
- Queue filenames use millisecond timestamps + tool_use_id for uniqueness
- Queue entries truncate tool_input: commands to 200 chars, Write content redacted
- ELO is append-only JSONL log with 10MB rotation — never mutable state. Rating calculated at read time with temporal decay
- ELO overrides stored separately in `config/elo-overrides.json`, never pollute trust-firewall.yaml
- `load_findings()` hard cap: 5000 records max to prevent OOM
- Finding severity validated against closed enum: `["critical", "high", "medium", "low"]`
- Role `tools_allowed` supports glob patterns: `mcp__caido__*` matches all Caido MCP tools
- Token savings logged to JSONL at `<colmena_home>/config/filter-stats.jsonl` (10MB rotation)

### Output Filtering (PostToolUse)

- Filter pipeline order: ANSI strip → stderr-only → dedup → prompt_injection → truncate (clean first, hard cap last)
- Each filter wrapped in catch_unwind — a buggy filter never crashes the hook
- FilterConfig max_output_chars (30K) must be < CC's internal limit (50K)
- Filters only apply to Bash tool outputs (Read/Write/Edit don't need filtering)
- Prompt injection static detection (`prompt_injection.rs`): 10 pattern IDs (OWASP LLM-01 canonical + tag injection + exfiltration) prepend a warning banner to outputs without mutating content. Configurable via `[prompt_injection]` with `enabled` + `patterns_custom`. Complements Claude Code auto-mode's LLM probe (different layers; use together). Does NOT catch: semantic/obfuscated injections, multi-step chains, non-English rephrasings, image/pdf payloads — those need the LLM probe.

### ELO & Calibration

- Calibration warm-up: agents need min_reviews_to_calibrate (default 3) before ELO trust applies
- TrustTier: Uncalibrated → Standard → Elevated/Restricted/Probation
- `calibrate run` cleans orphan ELO overrides (agent_ids with no matching role in library)
- `colmena calibrate reset` instantly revokes all ELO-based trust
- Review IDs include random component: `r_{timestamp}_{hex4}` to prevent collisions
- `generate_mission()` accepts ELO ratings to assign reviewer lead (highest ELO in squad)

### Wisdom Library

- **Private library overlay:** Roles and patterns can be split across two dirs: public `config/library/` (version-controlled) and a private dir (`$COLMENA_PRIVATE_LIBRARY` if set, else `~/.colmena-private/library/`). Private entries with the same `id` override public ones. The loader is additive — if the private dir doesn't exist, behaviour is unchanged. Use this for experimental or personal roles/patterns that must not ship in the public repo.
- **Deterministic loaders:** production code uses `load_roles(dir)` / `load_patterns(dir)` which discover the private dir via env/HOME. Tests and tooling that need determinism go through `load_roles_with_private(dir, Option<&Path>)` / `load_patterns_with_private(dir, Option<&Path>)`.
- **Role model binding (`model: Option<String>`):** roles can declare a preferred model (e.g. `claude-sonnet-4-7`, `claude-opus-4-7`). Colmena does not invoke models — the field is surfaced in the `mission_spawn` output header (`### role (Name) [model: ...]`) so the operator picks the right model when pasting into the Agent tool. Optional.
- **Pattern `workspace_scope: repo-wide`:** patterns can override the default mission-dir scope. When set, `spawn_mission` rewrites file-tool `path_within` to the Colmena repo root and merges default secret exclusions (`*.env`, `*credentials*`, `*secret*`, `*.key`, `*.pem`). Use for missions that must touch production code; leave unset for anything confined to `config/missions/<id>/`.
- 10 built-in roles (6 security + 4 dev) + 10 built-in patterns (7 security + 3 dev). New roles/patterns created via `library_create_role`/`library_create_pattern`
- RoleCategory: 8 categories (offensive, defensive, compliance, architecture, research, development, operations, creative)
- PatternTopology: 7 topologies (hierarchical, sequential, adversarial, peer, fan-out-merge, recursive, iterative)
- `library_select` suggests creating a pattern when no existing one matches the mission
- Generated role prompts have 5 sections: Core Responsibilities, Methodology (5 phases), Escalation, Output Format, Boundaries
- Caido pentester roles (web_pentester, api_pentester) are Caido-native — every methodology step references specific Caido MCP tools
- Prompt review detection uses compound keyword matching: prefix + role name/id + suffix — all three required to avoid false positives
- Findings with `category: "prompt_improvement"` are suggestions about role prompts — queryable via `findings_query`, human decides
- Dev roles (developer, code_reviewer, tester, architect) all start at "ask" trust level — ELO calibration needed before elevation
- Developer has `Agent` in tools_allowed (can spawn sub-agents); code_reviewer is read-only (no Write/Edit)
- Architect Write scoped to `${MISSION_DIR}` + `docs/` — cannot modify production code
- `map_topology_roles()` maps real roles to topology slots by SlotRoleType preference + mission keyword scoring. No duplicates.
- SlotRoleType: Lead, Offensive, Defensive, Research, Worker, Judge — each with preferred role list
- Auditor QPC framework: Quality + Precision + Comprehensiveness (1-10 each) — role-agnostic evaluation
- Inter-agent directive (`INTER_AGENT_DIRECTIVE`, `selector.rs:42`) injected into multi-agent missions (2+ agents) by `generate_mission()`
- Inter-agent protocol: facts only, path:line references, no prose — code/commands never compressed
- Inspired by [caveman](https://github.com/JuliusBrussee/caveman) (OSS, token-saving compressed communication between agents). Colmena's adaptation is narrower: only inter-agent prose is compressed; code and commands stay verbatim to avoid correctness drift.
- Future CLI: `colmena prompt-inject --mode terse` to emit the directive as a standalone block the user can paste into any Agent spawn outside of `mission_spawn` (planned in M7.3 scope).
- `spawn_mission()` is the one-step pipeline: select → auto-create → map_topology_roles → generate_mission with markers
- `MISSION_MARKER_PREFIX` (`<!-- colmena:mission_id=...-->`) embedded in agent prompts for Mission Gate validation
- Mission Gate (`enforce_missions: bool`): opt-in, default false, "ask" not "deny" — human always overrides
- Mission Gate only checks Agent tool — fires after trust rules (step 4c in PreToolUse), never on blocked tools
- `mission_spawn` MCP is rate-limited (generative) + restricted (creates patterns/delegations)
- `suggest_mission_size()` uses 7 domain categories + risk bumpers + simplicity reducers for complexity scoring
- `needs_colmena` threshold: 3+ recommended agents. Below that, Colmena says "use CC directly"
- `mission_suggest` MCP is NOT rate-limited, NOT restricted (read-only informational)
- All patterns enforce minimum 3 agents (2 workers + auditor). No 2-agent patterns allowed.
- All topologies generate 3+ slots in `topology_slots()` — Iterative and Recursive include evaluator/Judge

### Setup & Install

- `colmena setup` embeds all default config + library files via `include_str!()` — binary is self-contained
- Setup detects repo mode (Cargo.toml nearby) vs standalone mode (release binary) automatically
- Setup merge strategy: new defaults copied, custom files preserved (new defaults saved to `.defaults/` for reference)
- `~/.mcp.json` is the global MCP registration target — setup writes absolute path to colmena-mcp binary
- **Install Mode B** (validated with 4 power users, 2026-04-16): a user can point their own CC at this repo (SSH or clone) and let it bootstrap everything — `colmena setup`, MCP registration, first delegations — without reading CLAUDE.md directly. CLAUDE.md + library YAMLs + prompts are structured for agent consumption, so an oriented CC bootstraps the user. M7.6 will promote Mode B to first-class in README alongside the binary install (Mode A).

### Missions & Agent Identity (the ELO recipe)

Every active mission must feed per-agent ELO. Six mechanisms keep the cycle closed end-to-end:

1. **Subagent file name = delegation agent_id**: every role used in a mission must have `~/.claude/agents/<role_id>.md` with `name: <role_id>` in frontmatter. CC propagates `name` as the subagent identity to Colmena hooks. Without this match, ELO tracks a random session ID instead of the role.
2. **Review MCP tools in `tools:` frontmatter AND delegated**: the subagent `.md` must list `mcp__colmena__review_submit` (workers) / `mcp__colmena__review_evaluate` (reviewers), and a matching delegation must exist. Review tools live in `restricted` tier — without both, CC asks the human each call and the cycle breaks.
3. **Mission marker in every spawn prompt**: every Agent spawn in a mission must start with `<!-- colmena:mission_id=<id> -->`. Mission Gate validates it; ELO events tag reviews with this mission for later analysis.
4. **SubagentStop + reviewer gates active**: with `enforce_missions: true`, workers cannot Stop without `review_submit`, reviewers cannot Stop without `review_evaluate`. ELO cannot escape being updated.
5. **Auditor `role_type: auditor` exempt from worker review**: centralized auditor evaluates others without submitting its own work review. Must be set in library YAML, not inferred.
6. **Scope-explicit prompts with `review_submit` pre-filled**: each squad prompt states the files it owns + the exact `review_submit` call (mission_id, artifact_paths, reviewer_role, role) to issue before Stop. Agents do not improvise the protocol.

**Pitfall from prior missions:** if an agent spawns with an ad-hoc `name` like `squad-a` not matching any delegation, or the role YAML's `tools_allowed` omits review MCP tools, ELO stays flat. See memory: `project_elo_success_recipe.md` (working case) vs `project_tm_pattern_learnings.md` (failing case).

**Reviewer pool selection:** `submit_review` picks randomly from `available_roles` passed by the caller, filtered by author != reviewer and no reciprocal pairs (`review.rs`). To force a centralized auditor today, pass `available_roles: ["auditor"]`. Ad-hoc broad pools land on whichever non-author role is alive — not always what the mission intended.

**Future (M7.3):** `mission_spawn` will auto-generate subagent files, bundle review delegations, pre-fill prompt protocol blocks, auto-activate Mission Gate when `source: role` delegations are present, and expose `colmena prompt-inject --mode terse` to emit `INTER_AGENT_DIRECTIVE` standalone.

**Future (M7.7):** multi-perspective reviewer diversification — as more Researcher and Reviewer roles with distinct viewpoints (software engineering, security architect, project manager, SRE, compliance) coexist, reviewer selection will favor complementary `EloConfig.categories` instead of pure random. Every ELO event should reflect a cross-viewpoint judgement, not same-tribe approval.

### Testing

- Integration tests spawn the CLI binary as subprocess and pipe JSON via stdin
- Core library tests use `env!("CARGO_MANIFEST_DIR")` + `../config/` to reach workspace root
- Integration test paths: use `Path::parent()` for workspace root, never string concat with `..`

## CLI Subcommands

```
colmena hook                          # Hot path: stdin JSON → evaluate → stdout JSON (CC hook)
colmena queue list                    # List pending approval items
colmena queue prune --older-than 7    # Prune entries older than N days
colmena delegate add --tool X [--agent Y] [--ttl 4] [--session S]  # Add delegation (max 24h)
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
colmena doctor                         # Full health check: config, hooks, MCP, library, runtime, permissions
colmena suggest "<mission>"            # Analyze mission complexity, recommend Colmena vs vanilla CC
colmena stats                          # Combined firewall + filter savings summary
colmena stats --session <id>           # Stats for a specific session
```

## MCP Tools (27 total)

```
Firewall & Delegations:
  config_check       — validate firewall config
  evaluate           — evaluate a tool call against firewall
  queue_list         — list pending approvals
  delegate           — request delegation (returns CLI command, read-only)
  delegate_list      — list active delegations
  delegate_revoke    — request revocation (returns CLI command, read-only)

Wisdom Library:
  library_list       — list roles + patterns
  library_show       — show role/pattern details
  library_select     — recommend patterns for a mission
  library_generate   — generate CLAUDE.md per agent for a mission
  library_create_role — create role with intelligent defaults (8 categories)
  library_create_pattern — create pattern with topology detection (7 topologies)

Peer Review & Findings:
  review_submit      — submit artifact for peer review (assigns reviewer)
  review_list        — list peer reviews (pending/completed)
  review_evaluate    — submit scores + findings as reviewer (triggers ELO + trust gate + alerts)
  elo_ratings        — ELO leaderboard with temporal decay
  findings_query     — search findings by role/category/severity/date/mission
  findings_list      — list recent findings

Alerts & Calibration:
  alerts_list        — list alerts (filter by severity/acknowledged)
  alerts_ack         — acknowledge alert(s) by ID or "all"
  calibrate_auditor  — present auditor evaluations for human calibration (bilingual en/es)
  calibrate_auditor_feedback — submit calibration feedback (adjusts auditor ELO)

Operations:
  mission_spawn      — one-step mission creation (select→map→generate→markers)
  mission_suggest    — analyze mission complexity, recommend Colmena vs vanilla CC (read-only)
  mission_deactivate — request mission deactivation (returns CLI command, read-only)
  calibrate          — show ELO-based trust calibration state + recommend CLI commands
  session_stats      — show prompts saved + tokens saved + alert count (call before ending session)
```

## Environment Variables

- `COLMENA_HOME` — Override project root (default: auto-detected from binary)
- `COLMENA_CONFIG` — Override config file path
- `COLMENA_PRIVATE_LIBRARY` — Private library dir for roles/patterns that must stay out of the public repo (default: `~/.colmena-private/library/`). Private entries override public ones by `id`.

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
- **M6.2** P0+P1 hardening — MCP calibrate/evaluate precision, reviewer randomization, Elevated Bash guard, --session delegations, regex validation, expire audit trail (done)
- **M6.3** Role tools_allowed firewall — PermissionRequest hook auto-approves role tools via CC session rules, mission revocation kill switch (done)
- **M6.4** Enforced Peer Review — SubagentStop hook blocks workers without review, centralized auditor, alerts system, auditor calibration (done)
- **M7** Generic roles + patterns + topology mapping — 4 dev roles, 3 dev patterns, map_topology_roles, QPC auditor framework, inter-agent directive (done)
- **M7.1** Mission Spawn + Mission Gate — one-step mission creation, enforce_missions opt-in gate (done)
- **M7.2** Mission Sizing / colmena suggest — complexity analysis, recommends Colmena vs vanilla CC, min 3-agent enforcement (done)
- **M7.3** ELO cycle auto-closure — formalize the 6 mechanisms that closed the ELO loop in the public-release-prep mission. Primary goal: every active mission must feed ELO, no more manual workarounds. Scope: (a) `mission_spawn` auto-generates `~/.claude/agents/<role_id>.md` with name matching agent_id; (b) mission delegations include `review_submit`/`review_evaluate`/`findings_query` + role-specific Bash patterns bundled; (c) generated prompts include mission marker + scope block + review_submit params pre-filled + "don't Stop if review_submit fails"; (d) Mission Gate auto-activates when `source: role` delegations exist in session; (e) `colmena prompt-inject --mode terse` CLI to emit the `INTER_AGENT_DIRECTIVE` standalone for Agent spawns outside `mission_spawn`. See `project_elo_success_recipe.md` in memory for the full recipe and contrast with the TM pattern failure case. Reviewer diversification is intentionally scoped out — tracked separately in M7.7.
- **M7.4** Role creation ergonomics — lower the one friction point reported by the 4 validated users. Scope: `colmena role clone <existing> --as <new_id>` (copy-as-template), `colmena role inherit --from <base> --specializations X,Y --name <new>` (seeded scaffolding), `colmena role doctor <id>` (validate YAML + suggest categoria/bash_patterns/tools_allowed per specialization), editable prompt templates with role-category hints.
- **M7.5** DevOps/SRE role expansion — explicit user ask from the 4 validated power users. Scope: create `devops_engineer`, `sre`, `platform_engineer` roles with bash_patterns for `kubectl`, `helm`, `terraform`, `aws/gcloud`, `docker`, `ansible`; include matching prompts; add `ops-runbook` and `incident-response` patterns if the topology makes sense.
- **M7.6** Install Mode B as first-class — document and polish the onboarding path where the user's own CC reads the Colmena repo (SSH or clone) and self-configures. Validated with the 4 power users. Scope: README section at top level, CLAUDE.md structured for agent consumption, copy-pasteable commands, explicit naming conventions. Do not replace Mode A, add B alongside it.
- **M7.3.1** Anti-reciprocal invariant scope fix (discovered during Wave A parallel spawn 2026-04-17) — `submit_review` in `review.rs:141-147` currently filters reviewer candidates against the full reviews store (all missions), blocking legitimate cross-mission reviewer reuse. Scope the filter to `existing.mission == current.mission` so reciprocity is a per-collaboration property, not career-long exclusion. Audit other cross-mission leaks (e.g. stale-review auto-invalidation) for the same assumption. See memory: `project_review_reciprocal_cross_mission_bug.md`. Belongs folded into M7.3 as a required sub-task.
- **M7.7** Multi-perspective reviewer diversification — near-future need flagged explicitly by Coco. As Colmena grows, many Researcher and Reviewer roles will coexist with distinct viewpoints (software engineering, security architect, project manager, SRE, compliance, etc.). Reviewer selection must reflect that diversity instead of pure random from the pool. Scope: (a) `submit_review` accepts an optional `preferred_categories` hint from callers; (b) when unhinted, reviewer selection scores candidates by complementarity — if author's strongest `EloConfig.categories` is X, prefer a reviewer whose strongest category is *not* X; (c) track "perspective balance" per mission — avoid the same reviewer category evaluating N consecutive artifacts; (d) expose `colmena review perspectives <mission>` showing which viewpoints reviewed what; (e) when a mission spawns many Researchers, pair each with a reviewer from a contrasting category (pentester ↔ software_engineer, developer ↔ security_architect, devops ↔ architect). Goal: every ELO event reflects a genuinely cross-viewpoint judgement, not same-tribe approval.
- **M7.12** Library extension mechanism — foundation for "colmena codee colmena" missions. Three opt-in additions: (a) private library overlay via `$COLMENA_PRIVATE_LIBRARY` (default `~/.colmena-private/library/`), loaded by `load_roles`/`load_patterns` and merged over public entries by id; `load_*_with_private(dir, Option<&Path>)` pure variants for tests; (b) `Role.model: Option<String>` surfaced in `mission_spawn` output header `### role (Name) [model: X]` so the operator selects the right model when pasting the prompt into the Agent tool; (c) `Pattern.workspace_scope: Option<String>` — when set to `"repo-wide"`, `spawn_mission` rewrites file-tool `path_within` to the Colmena repo root and merges default secret exclusions (`*.env`, `*credentials*`, `*secret*`, `*.key`, `*.pem`), closing the mission_spawn scope gap for refactor missions. Zero behavior change when fields are absent. Docs in CLAUDE.md §Wisdom Library + §Environment Variables. Follow-up `load_prompt` + `validate_library` fall through to the private dir so private-library roles do not emit false-positive missing-prompt warnings. Env var is authoritative — invalid value disables the private merge (explicit opt-out). (done)

## Current State (2026-04-22)

**Branch:** `feat/library-ext-model-binding` — M7.12 (library extension mechanism) ready for PR.
**Done:** M0–M7.2 + v0.11.1 (review cycle hardening) + public-release-prep (PR #25) + Wave A 2026-04-17 (PRs #28–#31) + M7.3/M7.3.1/M7.5/M7.6/M7.8/M7.9 + M7.12 library extension (v0.13.0) — pending merge.
**Validated users (2026-04-16):** 4 active power users (pentester, developer, devops, SRE).
**ELO milestone:** First mission where per-agent ELO moved end-to-end (public-release-prep 2026-04-16). M7.3 dogfood (2026-04-21) closed the full ELO cycle with centralized auditor + 14 ELO events.
**Next:** merge M7.12 → dogfood warmup via `colmena-self-dev` private pattern (ReviewerLead cleanup re-spawn) → M7.4 (role ergonomics CLI, bundles the 4 M7.4-candidate gaps surfaced 2026-04-22: suggest matcher inflation, library select destructive default, delegate add condition flags, mission_spawn --code-paths) → M7.7 (multi-perspective reviewers). Post-launch: `serde_yml → serde_yaml_ng` migration, RUSTSEC-2026-0097 rand upgrade when patched.

## Key Docs

- `docs/user/getting-started.md` — Zero-to-running in 5 minutes
- `docs/user/use-cases.md` — Concrete workflows Colmena enables
- `docs/dev/architecture.md` — Full system walkthrough for contributors
- `docs/dev/contributing.md` — How to set up, build, test, submit changes
- `docs/dev/internals.md` — Edge cases, safety contracts, gotchas
- `docs/guide.md` — User guide with payments API audit walkthrough
- `docs/install-mode-b.md` — "Point your Claude Code at this repo" onboarding
- `docs/presentation.html` — Overview deck (open in browser)
- `docs/security/` — STRIDE+DREAD threat model reports (gitignored, local reference only)
