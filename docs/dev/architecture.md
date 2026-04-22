# Colmena Architecture

A contributor's walkthrough of the full system: four crates, five Claude Code
integration points, the trust model, the MCP server, and the mission lifecycle
as of M7.12 (v0.13.0).

If you want the *why* at feature level, read the [README](../../README.md).
This document is the *how*: where the code lives, how data flows, and which
invariants you must preserve when you extend it.

---

## 1. System Overview

Colmena is a Rust workspace (edition 2021, stable toolchain). Four crates, two
binaries:

```
colmena/
  Cargo.toml              # Workspace root, single version (0.13.0)
  colmena-core/           # Shared library — all business logic, zero platform deps
  colmena-cli/            # CLI binary: `colmena` (hooks + subcommands)
  colmena-filter/         # Output-filtering pipeline (used by CLI PostToolUse)
  colmena-mcp/            # MCP server binary: `colmena-mcp`
  config/                 # Default YAML/JSON config + library files (embedded via include_str!)
```

### Dependency Graph

```
colmena-cli ──┐
              ├──> colmena-core  (all business logic)
colmena-mcp ──┘          ^
      │                  │
      └──> colmena-filter ┘  (depends only on serde/regex)
```

- `colmena-core` has no platform dependencies. It owns config parsing, the
  firewall evaluator, delegations, the ELO engine, reviews, calibration, the
  wisdom library, the mission manifest, and the emitter helpers.
- `colmena-cli` depends on `colmena-core` for logic and `colmena-filter` for
  PostToolUse output cleanup. Uses `clap` (derive).
- `colmena-mcp` depends on `colmena-core` and `colmena-filter`. Uses `rmcp` +
  `tokio` for stdio JSON-RPC.
- `colmena-filter` is the only crate that produces no public types — it's a
  consumer of `serde`/`regex` with a trait + four filters.

### The Five CC Integration Points

Four reactive hooks plus one proactive server. All five are registered by
`colmena setup`.

| Integration       | Direction | Trigger                                             | Role                                                                                  |
|-------------------|-----------|-----------------------------------------------------|---------------------------------------------------------------------------------------|
| PreToolUse        | Reactive  | Before every tool call                              | Evaluates the call against the firewall (rules + delegations + ELO + mission gate)    |
| PostToolUse       | Reactive  | After Bash completes                                | Runs the filter pipeline on output (ANSI strip, stderr-only, dedup, truncate)         |
| PermissionRequest | Reactive  | When CC would prompt the user                       | Auto-approves role-scoped tools via CC session rules (only for `source: "role"`)      |
| SubagentStop      | Reactive  | When a subagent finishes                            | Blocks mission workers from stopping without `review_submit` (reviewer gate as well)  |
| MCP Server        | Proactive | When CC calls `mcp__colmena__*`                     | 27 tools: firewall, library, review, ELO, findings, alerts, mission spawn, stats      |

**PreToolUse** is the hot path. It runs synchronously with a 5-second watchdog
and must complete in under 100ms. Any error returns `ask` — never `deny`,
never crashes — because a broken hook must not trap the user.

**PostToolUse** only fires on Bash. Other tools (Read/Write/Edit/Glob/Grep)
pass through untouched. Each filter is wrapped in `catch_unwind`, so a
panicking filter is skipped with a note and the prior output is preserved.

**PermissionRequest** only fires for agents with a `source: "role"` delegation
(i.e., actual mission workers). On first allow, it writes CC session rules for
*all* tools in that role's `tools_allowed`, so subsequent calls are
auto-approved by CC itself without hitting the hook.

**SubagentStop** is a lifecycle event, not a tool event — it receives a
different payload (`SubagentStopPayload`, no `tool_name`/`tool_input`). It
checks the role delegation, exempts `role_type: auditor`, and otherwise
requires either `review_submit` (worker) or `review_evaluate` (reviewer)
before approving the stop.

**MCP Server** is a separate binary using `rmcp` with `#[tool_router]` +
`#[tool_handler]`. Transport is stdio; runtime is `tokio`. Each generative
tool is rate-limited to 30 calls/min; error responses are sanitized to hide
filesystem paths.

Hooks are registered in `~/.claude/settings.json`. The MCP server is
registered globally in `~/.mcp.json`. Both happen during `colmena setup`.

---

## 2. Mission Spawn → Review Cycle (the end-to-end flow)

The whole system is built to close the ELO cycle automatically. As of M7.3,
`colmena mission spawn --from manifest.yaml` is the single entry point.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     colmena mission spawn --from manifest.yaml          │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                  ┌─────────────────┴──────────────────┐
                  │  1. MissionManifest::from_path     │
                  │     validates id, pattern, TTL,    │
                  │     roles, ownership.              │
                  └─────────────────┬──────────────────┘
                                    │
                  ┌─────────────────┴──────────────────┐
                  │  2. Border case check               │
                  │  enforce_missions: false explicit  │
                  │  + ≥3 roles → abort with 3         │
                  │  explicit options. Operator wins.  │
                  └─────────────────┬──────────────────┘
                                    │
                  ┌─────────────────┴──────────────────┐
                  │  3. spawn_mission() (selector.rs)  │
                  │  • Resolve pattern (manifest.id)   │
                  │  • Map manifest.roles to slots     │
                  │  • Per role:                       │
                  │    - Compose CLAUDE.md (scope,     │
                  │      task, review protocol,        │
                  │      inter-agent directive)        │
                  │    - Write subagent .md to         │
                  │      ~/.claude/agents/<role>.md    │
                  │    - Build RuntimeDelegations      │
                  │      (tools_allowed + bash_patterns│
                  │       + path_within)               │
                  │  • decide_merge each delegation    │
                  │  • Persist runtime-delegations.json│
                  └─────────────────┬──────────────────┘
                                    │
                  ┌─────────────────┴──────────────────┐
                  │  4. Mission Gate state computed    │
                  │  • explicit true/false honored     │
                  │  • unset + ≥1 source:"role"        │
                  │    delegation → auto-activate      │
                  │  • --session-gate writes sentinel  │
                  └─────────────────┬──────────────────┘
                                    │
                        ┌───────────┴────────────┐
                        │                        │
                        ▼                        ▼
               Operator spawns             Operator runs
               agents via Agent            `delegate_list`,
               tool using written           inspects new
               prompts                      delegations
                        │
                        │ (agents now run)
                        ▼
┌─────────────────────────────────────────────────────────────────────────┐
│              Agent tool call → PreToolUse hook (hot path)               │
│  8-step precedence: blocked → delegations → YAML overrides →            │
│  ELO overrides → restricted → chain guard → mission revocation →        │
│  trust circle → defaults. Then Mission Gate (Agent tool only).          │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
         Worker finishes work →  review_submit (MCP)
                                    │
                                    ▼
                    Worker attempts Stop → SubagentStop hook
                    blocks unless review_submit has run.
                                    │
                                    ▼
         Reviewer (auditor) spawned → review_evaluate (MCP)
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│  review_evaluate writes:                                                │
│  • reviews/completed/<id>.json                                          │
│  • elo-events.jsonl (append-only, both reviewer & author)               │
│  • findings/<mission>/*.json (per finding)                              │
│  • alerts.json (if score < 5.0 or critical finding)                     │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
                    colmena calibrate run
                    → ELO → trust tier → elo-overrides.json
                    → next mission auto-approves Elevated agents
                                    │
                                    ▼
                    colmena mission deactivate --id <mission>
                    • revoke_by_mission (delegations)
                    • mark_mission_agents_revoked (kill switch)
                    • delete auto-generated subagent .md files
                    • clear session-gate sentinel
```

The invariant: **every mission `spawn`ed this way closes the ELO cycle by
construction**. No manual subagent file creation, no manual delegation
`colmena delegate add`, no manually activating the Mission Gate. The six
mechanisms from the M7.3 success recipe are baked into `spawn_mission`.

Source: `colmena-core/src/selector.rs:1347` (`spawn_mission`),
`colmena-cli/src/main.rs:1987` (`run_mission_spawn`),
`colmena-core/src/mission_manifest.rs` (manifest type + validation),
`colmena-core/src/emitters/claude_code.rs` (subagent file + prompt helpers).

---

## 3. Core Crate Internals (`colmena-core/`)

### Module Map

| Module             | File                     | Purpose                                                               | Key Public Types                                      |
|--------------------|--------------------------|-----------------------------------------------------------------------|-------------------------------------------------------|
| `config`           | `config.rs`              | YAML firewall loading, regex compilation, session-gate sentinel       | `FirewallConfig`, `Action`, `Rule`, `CompiledPatterns`|
| `firewall`         | `firewall.rs`            | Evaluation engine with 8-step precedence + mission gate               | `Decision`, `Priority`, `evaluate_with_elo()`         |
| `models`           | `models.rs`              | Protocol-agnostic evaluation input (CLI + MCP share it)               | `EvaluationInput`                                     |
| `paths`            | `paths.rs`               | Home + agents-dir resolution; `HOME` unset is fatal (no /tmp fallback)| `colmena_home()`, `default_agents_dir()`              |
| `delegate`         | `delegate.rs`            | Runtime delegations CRUD, TTL validation, mission revocation, merge   | `RuntimeDelegation`, `MergeDecision`, `decide_merge`  |
| `queue`            | `queue.rs`               | Filesystem approval queue (ms timestamp + tool_use_id filenames)      | `QueueEntry`                                          |
| `audit`            | `audit.rs`               | Append-only audit log with 10MB rotation                              | `AuditEvent`, `log_event()`                           |
| `elo`              | `elo.rs`                 | Append-only JSONL rating engine with temporal decay                   | `AgentRating`, `EloEvent`                             |
| `review`           | `review.rs`              | Peer review lifecycle + per-mission anti-reciprocal filter (M7.3.1)   | `ReviewEntry`, `ReviewState`                          |
| `calibrate`        | `calibrate.rs`           | ELO → firewall rule mapper (5 trust tiers), Elevated Bash guard       | `TrustTier`, `TrustThresholds`                        |
| `library`          | `library.rs`             | Role/pattern YAML loading, glob-aware `tools_allowed` matching        | `Role`, `Pattern`, `RoleToolsAllowed`                 |
| `selector`         | `selector.rs`            | Pattern selection, mission generation, `spawn_mission`, sizing        | `SpawnResult`, `MissionSuggestion`                    |
| `templates`        | `templates.rs`           | Role category system (8 categories), YAML/prompt generation           | `RoleCategory`                                        |
| `pattern_scaffold` | `pattern_scaffold.rs`    | Pattern topology system (7 topologies), slot generation               | `PatternTopology`, `SlotRoleType`                     |
| `findings`         | `findings.rs`            | Finding records (5000 hard cap, closed severity enum)                 | `Finding`, `FindingRecord`, `FindingsFilter`          |
| `alerts`           | `alerts.rs`              | Append-only alerts for low scores / critical findings                 | `Alert`                                               |
| `sanitize`         | `sanitize.rs`            | Filesystem-path redaction for MCP error messages                      | `sanitize_error()`                                    |
| `mission_manifest` | `mission_manifest.rs`    | `MissionManifest` YAML parser + validator (M7.3)                      | `MissionManifest`, `ManifestRole`, `ManifestScope`    |
| `emitters::claude_code` | `emitters/claude_code.rs` | Subagent `.md` writer + prompt composition helpers (M7.3)         | `write_subagent_file`, `scope_block`, `task_block`    |

### Key Data Structures

**EvaluationInput** — the protocol-agnostic boundary. Both the CLI hook
(`colmena-cli/src/hook.rs`) and the MCP server map their transport-specific
payloads into this type before calling any core function.

```rust
// colmena-core/src/models.rs
pub struct EvaluationInput {
    pub session_id: String,
    pub tool_name: String,
    pub tool_input: Value,    // serde_json::Value — tool-specific params
    pub tool_use_id: String,
    pub agent_id: Option<String>,
    pub cwd: String,
}
```

**FirewallConfig** — top-level YAML structure. Note `enforce_missions` is now
`Option<bool>` (M7.3 change) — `None` means "auto-activate when role
delegations live", `Some(true)`/`Some(false)` means honor literally.

```rust
// colmena-core/src/config.rs
pub struct FirewallConfig {
    pub version: u32,
    pub defaults: Defaults,
    pub trust_circle: Vec<Rule>,
    pub restricted: Vec<Rule>,
    pub blocked: Vec<Rule>,
    pub agent_overrides: HashMap<String, Vec<Rule>>,
    pub notifications: Option<NotificationsConfig>,
    pub enforce_missions: Option<bool>,  // M7.3: 3-state
}
```

**MissionManifest** (M7.3) — the input to `mission spawn`. Validates `id`,
`pattern`, `mission_ttl_hours` (1-24h), and at least one role with a non-empty
name.

```rust
// colmena-core/src/mission_manifest.rs
pub struct MissionManifest {
    pub id: String,
    pub pattern: String,
    pub mission_ttl_hours: i64,   // default 8
    pub roles: Vec<ManifestRole>,
}

pub struct ManifestRole {
    pub name: String,
    pub scope: ManifestScope,     // owns + forbidden file lists
    pub task: String,
}
```

**MergeDecision** (M7.3) — encodes the idempotency contract for mission
spawns. When `mission spawn` re-runs, each candidate delegation is checked:

```rust
// colmena-core/src/delegate.rs
pub enum MergeDecision {
    Insert,                                            // no match, safe to add
    SkipRespected { existing_expires_at: DateTime<Utc> },  // existing covers mission_end
    TtlTooShort  { existing_expires_at: DateTime<Utc>, needed_until: DateTime<Utc> },
}
```

`SkipRespected` means an operator or prior spawn already authorized this
tool/agent through the mission window — the caller respects it. `TtlTooShort`
aborts unless `--extend-existing` is passed, so mission spawns never silently
narrow a previously-granted TTL.

**Decision** — firewall output: `action` (AutoApprove/Ask/Block), `reason`,
`matched_rule`, `priority` (Low/Medium/High).

### File-Based State

No databases, no servers. All state is on disk.

| File                                     | Write strategy            | Purpose                                                          |
|------------------------------------------|---------------------------|------------------------------------------------------------------|
| `runtime-delegations.json`               | atomic temp+rename + lock | Live role/human delegations                                      |
| `elo-overrides.json`                     | atomic temp+rename        | Calibration-produced agent-scoped rule overrides                 |
| `alerts.json`                            | atomic temp+rename        | Append-only alert list (agents cannot modify)                    |
| `revoked-missions.json`                  | read-modify-write         | Agent IDs whose missions were deactivated mid-session            |
| `session-gate.json`                      | atomic temp+rename        | M7.3 `--session-gate` sentinel (expires with mission TTL)        |
| `audit.log`                              | append, 10MB rotation     | Every firewall decision + lifecycle events                       |
| `elo-events.jsonl`                       | append, 10MB rotation     | Every ELO delta (append-only; rating calculated at read time)    |
| `filter-stats.jsonl`                     | append, 10MB rotation     | Token-saved stats from PostToolUse filtering                     |
| `missions/<mission>/mission.yaml`        | write-once                | Mission config (pattern, roles, TTL)                             |
| `missions/<mission>/agents/<role>/CLAUDE.md` | write-once            | Per-agent prompt (includes scope, task, review protocol)         |
| `queue/pending/*.json`                   | per-entry (30-day prune)  | Pending approval requests (ms timestamp + tool_use_id filenames) |
| `reviews/pending/*.json` → `completed/`  | per-entry, moved on finish| Peer review lifecycle                                            |
| `findings/<mission>/*.json`              | per-entry, 5000 hard cap  | Findings extracted from reviews                                  |
| `~/.claude/agents/<role>.md`             | atomic temp+rename + .md.colmena-backup on overwrite | Subagent files (M7.3, outside config_dir)     |

---

## 4. Trust Model

### Firewall Rule Structure

A rule in `trust-firewall.yaml` has four fields. `conditions` are optional
but ALL must match when present.

```yaml
- tools: [Bash, Write]
  conditions:
    bash_pattern: '^ls\b'               # single-quoted — double quotes turn \b into backspace
    path_within: ['${PROJECT_DIR}']      # component-based, not string prefix
    path_not_match: ['*.env', '*secret*']# glob on filename only (last path component)
  action: auto-approve                   # auto-approve | ask | block (kebab-case)
  reason: 'Safe operations'
```

Source: `colmena-core/src/config.rs`.

### Precedence Chain (PreToolUse)

`firewall.rs:evaluate_with_elo()` follows this exact order. Stop at the first
match.

1. **Blocked** — non-overridable. No delegation can override a blocked rule.
2. **Runtime delegations** — check `tool`, `agent_id` scope, `session_id`
   scope, and conditions (`bash_pattern`, `path_within`, `path_not_match`).
3. **Agent overrides — YAML first** (`agent_overrides` in `trust-firewall.yaml`).
   **Human always wins over ELO.**
4. **Agent overrides — ELO** (from `elo-overrides.json`, regex compiled at
   evaluation time because they come from JSON, not the YAML compile pass).
5. **Restricted** → Ask.
6. **Shell chain guard** — Bash commands with `&&`, `||`, `;`, `$(`, or
   backtick fall through to defaults (Ask). Plain pipes `|` are intentionally
   excluded.
7. **Mission revocation** — if `agent_id` is in `revoked-missions.json` →
   Block. Fires before CC's learned session rules, so deactivation is
   immediate and complete.
8. **Trust circle** → AutoApprove.
9. **Defaults** → `defaults.action` (typically Ask).

**Mission Gate** fires after the chain, only for the `Agent` tool, and only
when active. Missing `<!-- colmena:mission_id=... -->` marker in the prompt →
Ask. It never elevates a tool that was already blocked.

### Mission Gate Activation (M7.3)

`FirewallConfig::is_mission_gate_active(delegations, session_override) -> bool`
encapsulates the 3-state decision:

```rust
if session_override {            // --session-gate sentinel present & unexpired
    return true;
}
match self.enforce_missions {
    Some(v) => v,                // explicit wins — operator always authoritative
    None    => delegations.iter().any(|d| d.source.as_deref() == Some("role")),
}
```

Three meaningful states:

- `Some(true)`: gate always on. Agent tool without marker → Ask.
- `Some(false)`: gate off. Operator has consciously opted out — respected even
  when mission delegations are live.
- `None` (unset): gate auto-activates as soon as any `source: "role"`
  delegation exists, deactivates when the last one expires.

The `--session-gate` flag on `mission spawn` writes a sentinel at
`config/session-gate.json` with an `expires_at` matching the mission TTL.
This overrides explicit `false` for that one session without mutating YAML.
`mission deactivate` clears the sentinel.

### Delegation Lifecycle

1. **Create** — `colmena delegate add` (human) or `mission spawn` (role-based).
   TTL is mandatory: 1-24h, default 4h for humans, 8h for missions. Bash
   delegations require `bash_pattern` or `path_within`. Regex validated as
   compilable before persisting. Written atomically.
2. **Use** — loaded on every PreToolUse. Expired entries pruned at load time
   and logged as `DELEGATE_EXPIRE`. Delegations without `expires_at` are
   silently skipped (prevents permanent grants via JSON injection).
3. **Merge on re-spawn (M7.3)** — `decide_merge` on every candidate. `Insert`
   if absent, `SkipRespected` if existing TTL ≥ mission end, `TtlTooShort` if
   existing TTL < mission end (abort unless `--extend-existing`).
4. **Revoke** — `colmena delegate revoke` (single) or `mission deactivate`
   (bulk by mission_id). Deactivation also marks agent IDs in
   `revoked-missions.json` (kill switch, step 7 in the precedence chain) and
   deletes auto-generated subagent `.md` files.

### ELO System

- **Rating = f(events, age)**: rating is not stored, it is recalculated from
  all events on every read, with per-event temporal decay
  (`<7d: 1.0`, `7-30d: 0.7`, `30-90d: 0.4`, `>90d: 0.1`). Source:
  `elo.rs:decay_factor`.
- **Author delta** from average review score: `≥8.0: +(score-7)*3`; `5.0-7.0:
  0`; `<5.0: -(6-score)*4`.
- **Reviewer reward**: `+5` per finding.
- **Finding delta against author**: `critical: -10`, `high: -5`,
  `medium/low: 0`.
- **Storage**: JSONL append-only log (`elo-events.jsonl`), 10MB rotation
  (old log renamed to `.jsonl.1`, next append creates a fresh file — old
  history effectively forgotten after rotation).

### Calibration: ELO → Firewall Rules

`colmena calibrate run` maps each role's ELO to a trust tier and writes
`elo-overrides.json`. Defaults (`calibrate.rs`):

| Tier          | ELO         | Min reviews | Effect                                                         |
|---------------|-------------|-------------|----------------------------------------------------------------|
| Uncalibrated  | any         | < 3         | Default rules (warm-up; no trust change)                       |
| Elevated      | ≥ 1600      | ≥ 3         | Auto-approve role's `tools_allowed`                            |
| Standard      | 1300–1599   | ≥ 3         | Default rules                                                  |
| Restricted    | 1100–1299   | ≥ 3         | Ask for everything                                             |
| Probation     | < 1100      | ≥ 3         | Bash + WebFetch blocked, others Ask                            |

The **Elevated Bash guard** (`calibrate.rs`): even Elevated agents get Ask
for Bash unless the role defines explicit `bash_patterns`. This prevents an
unscoped Bash auto-approve.

`calibrate run` also cleans orphan overrides (agent_ids with no matching role
in the library). `calibrate reset` instantly clears all ELO-derived
overrides.

---

## 5. MCP Server Internals

Source: `colmena-mcp/src/main.rs`.

The server uses `rmcp` with two macros:
- `#[tool_router]` on `impl ColmenaServer` registers all 27 tools.
- `#[tool_handler(router = self.tool_router)]` on the `ServerHandler` trait
  impl dispatches them.

Transport: stdio (stdin/stdout JSON-RPC). Runtime: `tokio`.

```rust
fn new(config_dir: PathBuf) -> Self {
    Self {
        config_dir,
        tool_router: Self::tool_router(),
        rate_limiter: Arc::new(RateLimiter::new(30, 60)),  // 30 calls / 60s
    }
}
```

Registration: `~/.mcp.json` points to the `colmena-mcp` binary with no
arguments. The binary resolves `config_dir` from `colmena_home()` at startup.

### Tool Groups (27 total)

- **Firewall & Delegations (6):** `config_check`, `evaluate`, `queue_list`,
  `delegate`, `delegate_list`, `delegate_revoke`.
- **Wisdom Library (6):** `library_list`, `library_show`, `library_select`,
  `library_generate`, `library_create_role`, `library_create_pattern`.
- **Peer Review & Findings (6):** `review_submit`, `review_list`,
  `review_evaluate`, `elo_ratings`, `findings_query`, `findings_list`.
- **Alerts & Calibration (4):** `alerts_list`, `alerts_ack`,
  `calibrate_auditor`, `calibrate_auditor_feedback`.
- **Operations (5):** `mission_spawn`, `mission_suggest`, `mission_deactivate`,
  `calibrate`, `session_stats`.

**Rate-limited (30/min):** generative or state-modifying tools
(`library_generate`, `library_create_*`, `review_submit`, `review_evaluate`,
`alerts_ack`, `calibrate_auditor_feedback`, `mission_spawn`,
`mission_deactivate`).

**Read-only command-returning:** `delegate`, `delegate_revoke`,
`mission_deactivate`. They never execute — they return the CLI command for
the operator to run. Arguments are escaped via `safe_cli_arg()` to prevent
command injection.

### Error Sanitization

All MCP error responses pass through `sanitize_error()`
(`colmena-core/src/sanitize.rs`). It replaces absolute filesystem paths with
the placeholder `<path>`. Agents cannot learn internal directory structure
through error messages.

---

## 6. Mission System (M7.3)

`spawn_mission()` (`selector.rs`) is the one-step pipeline:

```
manifest → resolve pattern → map roles to slots → for each role:
    compose CLAUDE.md (scope + task + review protocol + inter-agent directive)
    + embed MISSION_MARKER_PREFIX (<!-- colmena:mission_id=... -->)
    + write ~/.claude/agents/<role>.md (respect operator-authored files)
    + generate RuntimeDelegations (tools_allowed + bash_patterns + path_within)
  → decide_merge each delegation
  → persist runtime-delegations.json (atomic)
  → return SpawnResult {
      mission_name, agent_prompts, delegations_created,
      delegations_skipped, delegations_aborted,
      subagent_files_written, subagent_files_respected, role_gaps
    }
```

### Subagent Files

Each role gets `~/.claude/agents/<role_id>.md` with:

```yaml
---
name: <role_id>                       # MUST match delegation agent_id for ELO to track
colmena_auto_generated: true          # M7.3 marker — allows safe delete on deactivate
tools:
  - <tool 1>
  - <tool 2>
  - mcp__colmena__review_submit       # or review_evaluate for reviewers
  - mcp__colmena__findings_query
---

<role prompt + mission scope + task + review protocol + inter-agent directive>
```

If the file already exists, `check_subagent_minimums` validates the name matches
the role_id, the auto-generated marker is present, and the required review tool
is listed. On `Pass` → respect it. On `Fail` → abort with an actionable message
unless `--overwrite` is passed; overwrite backs up the prior file as
`.md.colmena-backup`. On `Absent` → write fresh.

This is why the ELO cycle closes: CC propagates the `name` field as the agent
identity in hook payloads, and the delegation is keyed on that same string.
No naming drift, no random session IDs.

### Topology and Roles

7 topologies (`pattern_scaffold.rs`): `hierarchical`, `sequential`,
`adversarial`, `peer`, `fan-out-merge`, `recursive`, `iterative`.

6 slot types (`SlotRoleType`): `Lead`, `Offensive`, `Defensive`, `Research`,
`Worker`, `Judge`. Each has a preferred role list; `map_topology_roles()`
assigns real roles to slots by preference + mission-keyword scoring, no
duplicates.

All topologies generate ≥3 slots. Minimum 3 agents per pattern (2 workers +
auditor). No 2-agent patterns allowed. `Iterative` and `Recursive` topologies
automatically include an evaluator/Judge slot.

### Inter-Agent Directive

`INTER_AGENT_DIRECTIVE` (`selector.rs`) is embedded in every multi-agent
mission's prompts. It enforces a terse protocol: facts only, `path:line`
references, no prose, no pleasantries — but *never* compresses code,
commands, or error messages (correctness must not drift).

For manual Agent spawns outside `mission_spawn`, emit the directive
standalone with `colmena mission prompt-inject --mode terse` and paste it
into the subagent prompt.

### Mission Sizing (`colmena suggest`)

`suggest_mission_size()` analyzes the mission description and returns a
`MissionSuggestion` with `needs_colmena` flag. Uses 7 domain keyword
categories + complexity bumpers + simplicity reducers.

Threshold: 3+ recommended agents. Below that, Colmena recommends "use CC
directly." Honesty over hype — Colmena tells you when it is not the right
tool.

---

## 7. CLI Binary Structure

Source: `colmena-cli/src/main.rs`, `clap` derive.

Subcommand tree:

```
colmena
├── hook            hot path: stdin → evaluate → stdout (<100ms, sync, no tokio)
├── queue {list,prune}
├── delegate {add,list,revoke}
├── config {check}
├── install         register hooks in ~/.claude/settings.json
├── setup [--dry-run] [--force]   one-command onboarding
├── library {list,show,select,create-role,create-pattern}
├── review {list,show}
├── elo {show}
├── mission {list,deactivate,spawn,prompt-inject}
├── calibrate {run,show,reset}
├── stats [--session <id>]
├── doctor          full health check
└── suggest "<mission>"    mission sizing, recommends Colmena vs vanilla CC
```

The **hook** subcommand is synchronous. No async, no network calls. A 5-second
watchdog (`main.rs`) guarantees stdout is always written and the process
exits cleanly even if stdin blocks. Only the MCP server uses `tokio`.

Key internal modules:
- `hook.rs` — payload/response types for all 4 hooks. Includes
  `SubagentStopPayload` (distinct struct, lifecycle event has no tool fields).
- `install.rs` — register hooks in `settings.json`.
- `setup.rs` — one-command onboarding; embeds all default files via
  `include_str!()` so the binary is self-contained.
- `doctor.rs` — end-to-end health check (config, hooks, MCP, library,
  runtime, permissions).
- `defaults.rs` — embeds every default config, library role, pattern, and
  prompt. Add new defaults here or `setup` won't install them.

---

## 8. Output Filter Pipeline

Source: `colmena-filter/src/`.

```
OutputFilter trait
    ├── AnsiStripFilter     (filters/ansi.rs)       regex-based, OnceLock cached
    ├── StderrOnlyFilter    (filters/stderr_only.rs) conditional on exit != 0
    ├── DedupFilter         (filters/dedup.rs)       configurable threshold
    └── TruncateFilter      (filters/truncate.rs)    max_lines + max_chars

FilterPipeline (pipeline.rs) — chains filters, catch_unwind per filter
FilterConfig   (config.rs)   — YAML, sensible defaults
Stats          (stats.rs)    — JSONL with 10MB rotation
```

### Pipeline Order (intentional: clean first, hard cap last)

1. **ANSI strip** — remove escape sequences so subsequent filters operate on
   clean text.
2. **Stderr-only** — if exit code ≠ 0 and stderr has content, discard stdout
   (noisy build output) and keep stderr (errors).
3. **Dedup** — collapse N+ consecutive identical lines (e.g. "Downloading
   crate..." × 50 → 1 line + count).
4. **Truncate** — hard cap at 150 lines / 30K chars (below CC's 50K internal
   limit). Preserves head + tail, cuts from the middle.

Each filter runs inside `catch_unwind`. A panicking filter is skipped with a
`"filter_name:PANICKED"` note in the pipeline log; the prior output is
preserved. A broken filter cannot crash the hook.

### Config Defaults

```rust
// colmena-filter/src/config.rs
max_output_lines: 150
max_output_chars: 30_000      // MUST stay below CC's 50K internal limit
dedup_threshold:  3
error_only_on_failure: true
strip_ansi: true
enabled: true
```

If the YAML file is missing, defaults apply. Partial YAML is valid (missing
fields filled in).

---

## 9. Prompt Injection Defense (M7.8)

Source: `colmena-filter/src/prompt_injection.rs`.

10 canonical pattern IDs (OWASP LLM-01 + tag injection + exfiltration)
prepend a warning banner to matching outputs without mutating the payload.
Configurable via `[prompt_injection]` in `filter-config.yaml` with `enabled`
+ `patterns_custom`.

Intentional limits: this is a static detector. It does NOT catch
semantic/obfuscated injections, multi-step chains, non-English rephrasings,
or image/PDF payloads. For those you need Claude Code's LLM-based probe
(`--enable-auto-mode`). The two layers complement each other — Colmena
handles the deterministic rule-based layer, CC's probe handles the semantic
layer. Use them together.

---

## See Also

- [Contributing](contributing.md) — dev setup, test commands, PR workflow, TL;DR first PR.
- [Internals](internals.md) — edge cases, safety contracts, gotchas that aren't obvious from the code.
- [User Guide](../guide.md) — walking example: payments API audit via `colmena mission spawn`.
- [Getting Started](../user/getting-started.md) — user-facing setup.
- [README](../../README.md) — project overview, value prop, persona hooks.

<p align="center">built with ❤️‍🔥 by AppSec</p>
