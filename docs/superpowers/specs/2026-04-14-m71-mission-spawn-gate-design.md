# M7.1: Mission Spawn + Mission Gate — v0.10.0

**Status:** Planned (2026-04-14)
**Depends on:** M7 (v0.9.0) — generic roles + patterns + map_topology_roles

## Context

Colmena's mission creation is a multi-step manual process: `library_select` → `library_generate` → copy prompts into Agent calls → manually delegate. CLAUDE.md says "Before spawning agents: Call library_select" — but this is a suggestion, not enforcement. An agent spawned without a Colmena mission has:

- No role → no `tools_allowed` → no PermissionRequest auto-approve
- No mission → SubagentStop doesn't gate it (no delegation with `source: "role"`)
- No peer review → ELO doesn't accumulate data
- Only the generic firewall applies (Agent in restricted → "ask")

The brainstorm session (2026-04-13) identified this as the fundamental gap: *"Hooks are reactive (always work), but missions are proactive (depend on CC choosing to use them)."*

**Goal:** Close the loop with carrot (mission_spawn — one-step mission creation) + stick (Mission Gate — enforce mission binding for Agent calls).

**User story:**
> CC wants to spawn agents → calls Agent directly → PreToolUse BLOCK
> → "Use mission_spawn to create a mission first"
> → CC calls `mcp__colmena__mission_spawn("audit PCI-DSS compliance")` 
> → Returns ready-to-paste agent prompts with mission markers + delegation commands
> → CC calls Agent with enriched prompt → PreToolUse sees mission marker → "ask" (normal)
> → Human approves → agent works with full Colmena stack (firewall + ELO + review + SubagentStop)

## Design Decisions

### 1. `spawn_mission()` Core Function

New public function in `selector.rs`:

```rust
pub const MISSION_MARKER_PREFIX: &str = "<!-- colmena:mission_id=";

pub struct SpawnResult {
    pub mission_name: String,
    pub pattern_id: String,
    pub pattern_auto_created: bool,
    pub agent_prompts: Vec<AgentPrompt>,
    pub delegation_commands: Vec<String>,
    pub role_gaps: Vec<String>,
    pub mission_config: MissionConfig,
}

pub struct AgentPrompt {
    pub role_id: String,
    pub role_name: String,
    pub prompt: String,       // Contains MISSION_MARKER_PREFIX
    pub claude_md_path: PathBuf,
}

pub fn spawn_mission(
    mission: &str,
    roles: &[Role],
    patterns: &[Pattern],
    library_dir: &Path,
    missions_dir: &Path,
    session_id: Option<&str>,
    elo_ratings: &[AgentRating],
    config_dir: Option<&Path>,
) -> Result<SpawnResult>
```

**Pipeline:**
1. `select_patterns(mission, patterns)` — find best matching pattern
2. If no match: `suggest_pattern_for_mission(mission)` → `scaffold_pattern()` — auto-create
3. `map_topology_roles(topology, mission, roles)` — assign real roles to pattern slots (from M7)
4. `generate_mission(...)` — create CLAUDE.md files with mission markers + inter-agent directive
5. Return `SpawnResult` with everything ready to use

**Mission marker format:**
```html
<!-- colmena:mission_id=2026-04-14-jwt-authentication-audit -->
```
Embedded at the top of each agent's prompt. PreToolUse searches for this prefix to validate mission binding.

### 2. `mission_spawn` MCP Tool

```rust
#[derive(Debug, Deserialize, JsonSchema)]
struct MissionSpawnInput {
    /// Mission description
    mission: String,
    /// Optional pattern ID override — skip auto-selection
    pattern_id: Option<String>,
}
```

- **Rate-limited:** Yes (generative tool, 30 calls/min)
- **Restricted:** Yes (requires human review — creates patterns, delegations, missions)
- **Output:** Formatted with mission metadata + agent prompts (ready to paste) + delegation CLI commands + role gap warnings
- **Audit event:** `MissionSpawn { mission_id, pattern_id, pattern_auto_created, agent_count }`

**library_select + library_generate remain available** as lower-level tools:
- `library_select` = exploration ("what patterns exist for this?")
- `library_generate` = execution with known pattern ("generate this specific mission")
- `mission_spawn` = full pipeline ("handle everything for this mission")

### 3. Mission Gate (PreToolUse Enhancement)

New config field in `trust-firewall.yaml`:
```yaml
enforce_missions: false  # opt-in, off by default
```

**Implementation in `run_pre_tool_use_hook()`:**

After trust rules evaluation (step 4b), before response formatting (step 5):

```
4c. Mission Gate:
    IF tool_name == "Agent" 
       AND config.enforce_missions == true
       AND decision.action != Block (already blocked by other rules):
        
        Check tool_input.prompt for MISSION_MARKER_PREFIX
        
        IF no marker found:
            → "ask" with systemMessage:
              "Mission gate: this Agent call has no Colmena mission binding.
               Use mcp__colmena__mission_spawn to create a mission first,
               then paste the generated agent prompts into Agent calls.
               Approve manually to proceed without mission binding."
            → Log AuditEvent::MissionGate
```

**Key design choices:**
- **"ask" not "deny"** — Human can always override. Ad-hoc agents remain possible. Consistent with "One human, full control."
- **Off by default** — `enforce_missions: false` means zero impact on existing installs. Opt-in for users who want enforcement.
- **Only checks Agent tool** — Other tools pass through normally.
- **Checks after trust rules** — If Agent is already blocked by firewall, Mission Gate doesn't fire.

### 4. Audit Events

Two new variants in `AuditEvent`:

```rust
MissionSpawn {
    mission_id: &'a str,
    pattern_id: &'a str,
    pattern_auto_created: bool,
    agent_count: usize,
}

MissionGate {
    session_id: &'a str,
    agent_id: Option<&'a str>,
}
```

Format in audit.log:
```
[2026-04-14T10:30:00Z] MISSION_SPAWN mission=jwt-auth pattern=code-review-cycle auto_created=false agents=3
[2026-04-14T10:31:00Z] MISSION_GATE session=abc123 agent=*
```

## Implementation

### Files to Modify

| File | Change |
|------|--------|
| `colmena-core/src/selector.rs` | +`spawn_mission()`, +`SpawnResult`, +`AgentPrompt`, +`MISSION_MARKER_PREFIX`, +`MissionConfig` |
| `colmena-core/src/audit.rs` | +`MissionSpawn`, +`MissionGate` event variants + format arms |
| `colmena-core/src/config.rs` | +`enforce_missions: bool` field on `FirewallConfig` (serde default false) |
| `colmena-mcp/src/main.rs` | +`mission_spawn` MCP tool, +`MissionSpawnInput` struct |
| `colmena-cli/src/main.rs` | +Mission Gate logic in `run_pre_tool_use_hook()` (step 4c) |
| `config/trust-firewall.yaml` | +`enforce_missions: false`, +mission_spawn restricted rule |
| `Cargo.toml` | Version bump 0.9.0 → 0.10.0 |
| `CLAUDE.md` | Add mission_spawn to MCP tools, Mission Gate conventions, enforce_missions docs |
| `README.md` | Add Mission Spawn section, update tool count (26 → 27) |
| `CHANGELOG.md` | Add M7.1 / v0.10.0 section |
| `docs/guide.md` | Add mission_spawn workflow example |

### Tests

| Test | Location |
|------|----------|
| `test_spawn_mission_with_matching_pattern` | `selector.rs` |
| `test_spawn_mission_auto_creates_pattern` | `selector.rs` |
| `test_spawn_mission_empty_library_fails` | `selector.rs` |
| `test_spawn_mission_marker_format` | `selector.rs` |
| `test_spawn_mission_includes_delegation_commands` | `selector.rs` |
| `test_enforce_missions_default_false` | `config.rs` |
| `test_enforce_missions_parses_true` | `config.rs` |
| `test_enforce_missions_missing_defaults_false` | `config.rs` |
| `test_mission_gate_blocks_bare_agent_when_enforced` | `integration.rs` |
| `test_mission_gate_allows_agent_with_marker` | `integration.rs` |
| `test_mission_gate_inactive_when_not_enforced` | `integration.rs` |
| `test_mission_gate_skips_non_agent_tools` | `integration.rs` |
| `test_mission_spawn_audit_event_format` | `audit.rs` |
| `test_mission_gate_audit_event_format` | `audit.rs` |

Expected: ~14 new tests.

## Verification

1. `cargo test --workspace` — all tests pass
2. `cargo clippy --workspace -- -W warnings` — clean
3. MCP: call `mission_spawn` with a dev mission → verify prompts contain mission markers
4. MCP: call `mission_spawn` with unknown domain → verify auto-creates pattern
5. CLI: set `enforce_missions: true` → spawn Agent without marker → verify "ask" response
6. CLI: set `enforce_missions: true` → spawn Agent with marker → verify passes through
7. CLI: set `enforce_missions: false` → spawn Agent without marker → verify no gate
8. Verify `library_select` and `library_generate` still work independently (not broken)
9. Verify SubagentStop still enforces review (M6.4 not regressed)
