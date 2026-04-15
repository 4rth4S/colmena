# Colmena Architecture Deep Dive

A contributor's guide to the full system: crates, data flow, trust model, MCP server, and mission system.

---

## 1. System Overview

Colmena is a Rust workspace with four crates and two output binaries:

```
colmena/
  Cargo.toml              # Workspace root: 4 members, version 0.11.0
  colmena-core/           # Shared library — all business logic
  colmena-cli/            # CLI binary: "colmena" (hooks + subcommands)
  colmena-filter/         # Output filtering pipeline
  colmena-mcp/            # MCP server binary: "colmena-mcp"
  config/                 # Default YAML/JSON config and library files
```

### Dependency Graph

```
colmena-cli ──────┐
                   ├──> colmena-core (shared library)
colmena-mcp ──────┘         |
     |                      |
     └──> colmena-filter <──┘ (used by both CLI and MCP)
```

- **colmena-core** has zero platform dependencies. It owns config parsing, firewall evaluation, delegations, ELO, reviews, calibration, the wisdom library, and the mission system.
- **colmena-cli** depends on colmena-core for all business logic and colmena-filter for PostToolUse output processing. Uses `clap` for CLI parsing.
- **colmena-mcp** depends on colmena-core and colmena-filter. Uses `rmcp` + `tokio` for async MCP transport.
- **colmena-filter** depends only on `serde`/`regex`. Provides the `OutputFilter` trait and a 4-stage pipeline.

### Integration with Claude Code

Five integration points:

| Hook / Interface | Direction | Purpose |
|-----------------|-----------|---------|
| PreToolUse | Reactive | Evaluates every tool call against the firewall before execution |
| PostToolUse | Reactive | Filters Bash output (ANSI strip, dedup, truncate) before CC processes it |
| PermissionRequest | Reactive | Auto-approves role tools via CC session rules |
| SubagentStop | Reactive | Blocks mission workers from stopping without submitting peer review |
| MCP Server | Proactive | CC calls 27 Colmena tools natively via JSON-RPC over stdio |

Hooks are registered in `~/.claude/settings.json`. The MCP server is registered in `~/.mcp.json`. Both registrations are handled by `colmena setup`.

---

## 2. Data Flow Diagrams

### PreToolUse: Tool Call Evaluation

```
CC Tool Call → colmena hook (stdin, 10MB limit, 5s watchdog)
  → load config + delegations + ELO overrides + revoked missions
  → evaluate_with_elo():
      1. Blocked (non-overridable)
      2. Runtime delegations (tool + agent + session + conditions)
      3a. YAML agent_overrides (human, always wins)
      3b. ELO overrides (calibration-generated)
      4. Restricted (→ Ask)
      5. Shell chain guard (&&, ||, ;, $(), ` → defaults/Ask)
      6. Mission revocation (→ Block)
      7. Trust circle (→ AutoApprove)
      8. Defaults (fallback → Ask)
  → Decision { action, reason, matched_rule, priority }
  → audit log → queue (if Ask) → stdout JSON
```
Source: `firewall.rs:53-161`, `main.rs:435-552`

### PostToolUse: Output Filtering

```
CC Bash output → colmena hook (non-Bash tools pass through)
  → FilterPipeline: ANSI strip → stderr-only → dedup → truncate
  → modified? return filtered output : passthrough
  → stats logged to filter-stats.jsonl
```
Source: `pipeline.rs:30-113`, `main.rs:554-640`

### PermissionRequest: Role Tool Auto-Approval

```
CC permission prompt → colmena hook
  → no agent_id? → no output (CC prompts user)
  → find delegation with agent_id + source:"role" → load role
  → tool in role's tools_allowed? → allow + teach ALL role tools as session rules
  → subsequent calls auto-approved by CC without hitting the hook
```
Source: `main.rs:646-733`

### SubagentStop: Peer Review Enforcement

```
Subagent stopping → colmena hook (SubagentStopPayload, no tool_name)
  → no agent_id? → approve (main agent)
  → no role delegation? → approve (not mission worker)
  → role_type:"auditor"? → approve (exempt)
  → has_submitted_review()? → approve : block
```
Source: `main.rs:735-818`

---

## 3. Core Crate Internals (`colmena-core/`)

### Module Map

| Module | File | Purpose | Key Public Types |
|--------|------|---------|-----------------|
| `config` | `config.rs` | YAML firewall loading, regex compilation, `${PROJECT_DIR}` expansion | `FirewallConfig`, `Action`, `Rule`, `Conditions`, `CompiledPatterns` |
| `firewall` | `firewall.rs` | Evaluation engine with 8-step precedence chain | `Decision`, `Priority`, `evaluate()`, `evaluate_with_elo()` |
| `models` | `models.rs` | Protocol-agnostic evaluation input | `EvaluationInput` |
| `paths` | `paths.rs` | Home directory resolution | `colmena_home()`, `default_config_dir()` |
| `delegate` | `delegate.rs` | Runtime delegation CRUD + mission revocation | `RuntimeDelegation`, `DelegationConditions` |
| `queue` | `queue.rs` | Filesystem-based pending approval queue | `QueueEntry` |
| `audit` | `audit.rs` | Append-only audit log with 10MB rotation | `AuditEvent`, `log_event()` |
| `elo` | `elo.rs` | ELO rating engine with temporal decay | `AgentRating`, `EloEvent`, `StoredEloEvent` |
| `review` | `review.rs` | Peer review lifecycle (submit, evaluate, trust gate) | `ReviewEntry`, `ReviewState` |
| `calibrate` | `calibrate.rs` | ELO-to-firewall-rules mapper (5 trust tiers) | `TrustTier`, `TrustThresholds` |
| `library` | `library.rs` | Role/pattern YAML loading, tools_allowed matching | `Role`, `Pattern`, `RoleToolsAllowed` |
| `selector` | `selector.rs` | Pattern selection, mission generation, mission sizing | `SpawnResult`, `MissionSuggestion` |
| `templates` | `templates.rs` | Role category system (8 categories), YAML/prompt generation | `RoleCategory` |
| `pattern_scaffold` | `pattern_scaffold.rs` | Pattern topology system (7 topologies), scaffold generation | `PatternTopology`, `SlotRoleType` |
| `findings` | `findings.rs` | Finding records from reviews | `Finding`, `FindingRecord`, `FindingsFilter` |
| `alerts` | `alerts.rs` | Alert system for low review scores | `Alert` |
| `sanitize` | `sanitize.rs` | Error message path sanitization | `sanitize_error()` |

Source: `colmena-core/src/lib.rs`

### Key Data Structures

**EvaluationInput** — the protocol-agnostic boundary between CLI/MCP and core logic:

```rust
// colmena-core/src/models.rs:7-14
pub struct EvaluationInput {
    pub session_id: String,
    pub tool_name: String,
    pub tool_input: Value,       // serde_json::Value — tool-specific parameters
    pub tool_use_id: String,
    pub agent_id: Option<String>,
    pub cwd: String,
}
```

Both the CLI (`HookPayload::to_evaluation_input()` in `colmena-cli/src/hook.rs:25-34`) and MCP server map their inputs to this type before calling any core function.

**FirewallConfig** — the top-level YAML structure:

```rust
// colmena-core/src/config.rs:50-67
pub struct FirewallConfig {
    pub version: u32,
    pub defaults: Defaults,
    pub trust_circle: Vec<Rule>,
    pub restricted: Vec<Rule>,
    pub blocked: Vec<Rule>,
    pub agent_overrides: HashMap<String, Vec<Rule>>,
    pub notifications: Option<NotificationsConfig>,
    pub enforce_missions: bool,  // default false, opt-in Mission Gate
}
```

**RuntimeDelegation** (`delegate.rs:32-48`) — runtime trust expansion. Key fields: `tool`, `agent_id` (optional scope), `expires_at` (mandatory TTL), `session_id` (optional scope), `source` ("human"/"role"/"elo"), `mission_id`, `conditions` (bash_pattern, path_within, path_not_match).

**Decision** (`firewall.rs:18-24`) — evaluation output: `action` (AutoApprove/Ask/Block), `reason`, `matched_rule`, `priority` (Low/Medium/High).

### File-Based State

All runtime state is filesystem-based. No databases, no external services.

**Atomic write (temp+rename):** `runtime-delegations.json`, `elo-overrides.json`, `alerts.json`
**Append-only with 10MB rotation:** `audit.log`, `elo-events.jsonl`, `filter-stats.jsonl`
**Append-update:** `revoked-missions.json` (read-modify-write, agents added on mission deactivation)
**Write-once:** `missions/<name>/mission.yaml`, `missions/<name>/agents/<role>/CLAUDE.md`
**Per-entry files:** `queue/pending/*.json` (30-day prune), `queue/decided/*.json`, `reviews/pending/*.json` (moved to `completed/`), `findings/<mission>/*.json` (5000 hard cap)

---

## 4. Trust Model

### Firewall Rule Structure

A rule in `trust-firewall.yaml` has four fields:

```yaml
- tools: [Bash, Write]      # Which tools this rule applies to
  conditions:                # Optional — ALL conditions must match
    bash_pattern: '^ls\b'    # Regex for Bash command (single-quoted in YAML)
    path_within: ['${PROJECT_DIR}']    # Component-based directory check
    path_not_match: ['*.env', '*secret*']  # Glob on filename only
  action: auto-approve       # auto-approve | ask | block
  reason: 'Safe operations'  # Human-readable explanation
```

Source: `colmena-core/src/config.rs:17-35`

### Precedence Chain (Full)

The evaluation in `firewall.rs:62-161` follows this exact order:

1. **Blocked** (line 83) — Non-overridable. Even delegations cannot override blocked rules.
2. **Runtime delegations** (line 89) — Checks tool match, agent_id scope, session_id scope, and conditions (bash_pattern, path_within, path_not_match).
3. **Agent overrides**:
   - 3a. YAML `agent_overrides` (line 96) — human-defined in trust-firewall.yaml. Always wins over ELO.
   - 3b. ELO-calibrated overrides (line 103) — generated by `calibrate run`. Their regex patterns are compiled at evaluation time, not at config load.
4. **Restricted** (line 112) — Returns Ask.
5. **Shell chain guard** (line 122) — Bash commands with `&&`, `||`, `;`, `$(`, or backtick fall through to defaults (Ask). Plain pipes (`|`) are intentionally excluded.
6. **Mission revocation** (line 138) — If agent_id is in `revoked-missions.json`, returns Block. Overrides CC session rules.
7. **Trust circle** (line 150) — Returns AutoApprove.
8. **Defaults** (line 155) — Falls back to `defaults.action` (typically Ask).

After evaluation, if `enforce_missions: true` and the tool is `Agent` and it was not blocked, the Mission Gate checks for the `<!-- colmena:mission_id=... -->` marker in the agent prompt. Missing marker triggers Ask.

### Delegation Lifecycle

1. **Create**: Via `colmena delegate add` (CLI) or mission generation (role-based).
   - TTL validated: 1-24h. Constants in `delegate.rs:10-12`: `MAX_TTL_HOURS = 24`, `DEFAULT_TTL_HOURS = 4`.
   - Bash delegations require `bash_pattern` or `path_within` — unscoped Bash is rejected.
   - Regex patterns validated as compilable before persisting.
   - Written atomically: temp file in same directory + rename.

2. **Use**: Loaded on every PreToolUse evaluation. Expired entries pruned at load time.
   - Delegations without `expires_at` are silently skipped (prevents permanent delegations via JSON injection).
   - Matching checks: tool name → agent_id (if scoped) → session_id (if scoped) → conditions.

3. **Expire**: Pruned on load. Expired delegations logged as `DELEGATE_EXPIRE` audit events.

4. **Revoke**: Manually via CLI, or bulk via `revoke_by_mission()` during mission deactivation.

Source: `colmena-core/src/delegate.rs`

### ELO System

**Rating calculation** (`elo.rs:181-219`):
- Baseline ELO: 1500 (configured per role via `elo.initial`; agents not in baselines default to 1000).
- Each stored event's delta is multiplied by a temporal decay factor:
  - Event < 7 days old: factor 1.0
  - 7-30 days: 0.7
  - 30-90 days: 0.4
  - > 90 days: 0.1
- `trend_7d`: sum of deltas from events in the last 7 days (no decay applied).
- Rating is recalculated from all events on every read. There is no stored "current rating."

**Author delta** (from average review score, `elo.rs:59-67`):
- score >= 8.0: `+(score - 7) * 3` (positive)
- score 5.0-7.0: 0 (neutral)
- score < 5.0: `-(6 - score) * 4` (negative)

**Finding delta against author** (`elo.rs:74-80`):
- critical: -10
- high: -5
- medium/low: 0

**Reviewer reward**: +5 per finding (`REVIEWER_FINDING_DELTA`, `elo.rs:52`).

**Storage**: JSONL append-only log (`elo-events.jsonl`). 10MB rotation: current log renamed to `.jsonl.1`. Source: `elo.rs:101-113`.

### Calibration: ELO to Firewall Rules

Source: `colmena-core/src/calibrate.rs`

Default thresholds (`calibrate.rs:27-36`):

| Tier | ELO Requirement | Reviews Required | Effect |
|------|----------------|-----------------|--------|
| Elevated | >= 1600 | >= 3 | Auto-approve role's tools_allowed |
| Standard | >= 1300 | >= 3 | No overrides, default rules |
| Restricted | >= 1100 | >= 3 | Ask for everything |
| Probation | < 1100 | >= 3 | Bash + WebFetch blocked, others Ask |
| Uncalibrated | any | < 3 | Default rules (warm-up period) |

The Elevated Bash guard (`calibrate.rs:212-245`): even elevated agents get Ask for Bash unless the role has explicit `bash_patterns` in its `permissions`. This prevents unscoped Bash auto-approve.

`calibrate run` also cleans orphan ELO overrides (agent_ids with no matching role in the library).

---

## 5. MCP Server Internals

### How rmcp Is Used

Source: `colmena-mcp/src/main.rs`

The server uses the `rmcp` crate with two macros:
- `#[tool_router]` on `impl ColmenaServer` — registers all 27 tools as routable handlers.
- `#[tool_handler(router = self.tool_router)]` on the `ServerHandler` trait implementation.

Transport: stdio (stdin/stdout JSON-RPC). Runtime: `tokio` async.

Server initialization:

```rust
fn new(config_dir: PathBuf) -> Self {
    Self {
        config_dir,
        tool_router: Self::tool_router(),
        rate_limiter: Arc::new(RateLimiter::new(30, 60)), // 30 calls per 60 seconds
    }
}
```

Registration: `~/.mcp.json` points to the `colmena-mcp` binary with no arguments:

```json
{"mcpServers":{"colmena":{"args":[],"command":"<path>/colmena-mcp","type":"stdio"}}}
```

The binary resolves `config_dir` from `colmena_home()` at startup.

### Tool Categorization (27 Tools)

The 27 tools fall into 5 groups: Firewall & Delegations (6), Wisdom Library (6), Peer Review & Findings (6), Alerts & Calibration (4), Operations (5).

**Rate-limited tools** (30 calls/min, most also restricted — state-modifying or generative):
`library_generate`, `library_create_role`, `library_create_pattern`, `review_submit`, `review_evaluate`, `alerts_ack`, `calibrate_auditor_feedback`, `mission_spawn`, `mission_deactivate`

**Read-only tools that return CLI commands** (never execute):
`delegate`, `delegate_revoke`, `mission_deactivate`. Arguments escaped via `safe_cli_arg()` (`main.rs:19-25`) to prevent command injection.

**All other tools** are read-only with no rate limiting or restrictions:
`config_check`, `evaluate`, `queue_list`, `delegate_list`, `library_list`, `library_show`, `library_select`, `review_list`, `elo_ratings`, `findings_query`, `findings_list`, `alerts_list`, `calibrate_auditor`, `mission_suggest`, `calibrate`, `session_stats`

"Restricted" = listed in the `restricted` section of `trust-firewall.yaml`, requiring human confirmation through the firewall. Applies to: `library_create_role`, `library_create_pattern`, `review_submit`, `review_evaluate`, `alerts_ack`, `calibrate_auditor_feedback`, `mission_spawn`.

### Error Sanitization

All MCP error responses pass through `sanitize_error()` (`colmena-core/src/sanitize.rs:3-6`). This function replaces absolute filesystem paths matching `(/[A-Za-z][A-Za-z0-9._/-]+)` with the placeholder `<path>`. This prevents agents from learning internal directory structure through error messages.

---

## 6. Mission System

### Full Pipeline: spawn_mission()

Source: `colmena-core/src/selector.rs`

```
Mission description
    |
    v
1. select_patterns() → ranked pattern matches
    |
    v
[No match? → scaffold_pattern() + suggest_pattern_for_mission() → auto-create]
    |
    v
2. map_topology_roles() → maps real roles to topology slots
   (SlotRoleType preferences + mission keyword scoring, no duplicates)
    |
    v
3. generate_mission() →
   +── Create config/missions/<date>-<slug>/ directory
   +── Write mission.yaml config
   +── For each agent:
   |     +── Load role's system prompt (prompts/<role>.md)
   |     +── Build CLAUDE.md with: mission context, trust level,
   |     |   pre-approved tools, review instructions, inter-agent directive
   |     +── Embed MISSION_MARKER_PREFIX: <!-- colmena:mission_id=... -->
   |     +── Assign reviewer lead (highest ELO in squad)
   +── Create role-bound delegations (source: "role", TTL: 8h default)
   +── Return SpawnResult with per-agent prompts + delegation commands
```

### Topology and Roles

7 topologies (`pattern_scaffold.rs`): hierarchical, sequential, adversarial, peer, fan-out-merge, recursive, iterative.

6 slot types (`SlotRoleType`): Lead, Offensive, Defensive, Research, Worker, Judge. Each has a preferred role list used by `map_topology_roles()`.

All topologies generate 3+ slots. Minimum 3 agents per pattern (2 workers + auditor). No 2-agent patterns allowed. Source: `pattern_scaffold.rs:96-106`.

### Mission Gate

Opt-in enforcement (`enforce_missions: false` by default in `trust-firewall.yaml`).

When enabled, Agent tool calls without a `<!-- colmena:mission_id=... -->` marker trigger Ask. The gate fires after the 8-step evaluation chain in the CLI hook handler (after trust rules, never on already-blocked tools).

### Mission Revocation

`mission deactivate` triggers:
1. `revoke_by_mission()` — removes all delegations for the mission from `runtime-delegations.json`.
2. `mark_mission_agents_revoked()` — adds agent IDs to `revoked-missions.json`.

The PreToolUse hook checks `revoked-missions.json` at step 6 (mission revocation). Revoked agents are blocked regardless of any CC session rules learned earlier via PermissionRequest. This ensures mission deactivation is immediate and complete.

### Mission Sizing

`suggest_mission_size()` (`selector.rs:983`) analyzes the mission description using:
- 7 domain keyword categories
- Complexity bumpers (increase agent count)
- Simplicity reducers (decrease agent count)

Returns a `MissionSuggestion` with `needs_colmena` flag. Threshold: 3+ recommended agents. Below that, Colmena recommends "use CC directly."

---

## 7. CLI Binary Structure

Source: `colmena-cli/src/main.rs`. Uses `clap` derive with a `Commands` enum. 14 top-level commands (see `docs/contributing.md` for the full list).

Key modules: `hook.rs` (payload/response types for all 4 hooks), `install.rs` (register hooks in settings.json), `setup.rs` (one-command onboarding), `doctor.rs` (health check), `defaults.rs` (all default files embedded via `include_str!()`).

The `hook` subcommand is the hot path. It must complete in <100ms. No async, no network calls.

---

## 8. Output Filter Pipeline

Source: `colmena-filter/src/`

### Architecture

```
OutputFilter trait
    |
    +── AnsiStripFilter    (filters/ansi.rs)     — regex-based, OnceLock cached
    +── StderrOnlyFilter   (filters/stderr_only.rs) — conditional on failure
    +── DedupFilter        (filters/dedup.rs)    — configurable threshold
    +── TruncateFilter     (filters/truncate.rs) — max_lines + max_chars

FilterPipeline (pipeline.rs) — chains filters with catch_unwind per filter
FilterConfig   (config.rs)   — YAML config with sensible defaults
Stats          (stats.rs)    — JSONL logging with 10MB rotation
```

### Pipeline Order

Order is intentional: clean first, hard cap last.

1. **ANSI strip** — remove escape sequences so subsequent filters work on clean text.
2. **Stderr-only** — on failure (exit != 0), discard stdout (build output), keep stderr (errors). Conditional filter.
3. **Dedup** — collapse N+ consecutive identical lines into one + count. Reduces noisy build output.
4. **Truncate** — hard cap at `max_output_lines` (150) and `max_output_chars` (30K). Preserves start + end of output.

Each filter is wrapped in `catch_unwind` (`pipeline.rs:75-91`). A panicking filter is skipped with a note `"filter_name:PANICKED"` — it never crashes the hook process.

### Config Defaults

```rust
// colmena-filter/src/config.rs
max_output_lines: 150
max_output_chars: 30_000   // Must be < CC's internal 50K limit
dedup_threshold: 3
error_only_on_failure: true
strip_ansi: true
enabled: true
```

If the config file is missing, defaults are used. Partial YAML is valid (missing fields get defaults).

---

## See Also

- [Contributing](contributing.md) -- dev setup, how to add rules/tools/roles, PR workflow
- [Internals](internals.md) -- hook protocol details, safety contracts, gotchas
- [Getting Started](../user/getting-started.md) -- user-facing setup and first run
- [Use Cases](../user/use-cases.md) -- real workflows using the architecture described here
