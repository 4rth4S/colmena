# M7.2: Mission Sizing / `colmena suggest` — v0.11.0

**Status:** Planned (2026-04-14)
**Depends on:** M7.1 (v0.10.0) — mission_spawn + Mission Gate

## Context

Colmena can now create missions (M7.1) and has dev roles to fill them (M7). But there's no intelligence about *when* to use Colmena vs vanilla Claude Code. A user asking "fix this typo" shouldn't need a 3-agent mission with peer review and ELO calibration.

The brainstorm session (2026-04-13) established: *"Minimum threshold: 3 agents (orchestrator/auditor + 2 workers). Below that there's no meaningful review, no useful ELO signal, no trust to calibrate."*

Design principle: *"Honesty over hype. If you don't need Colmena, Colmena tells you."*

**Goal:** Add mission sizing logic that analyzes task descriptions and recommends whether to use Colmena, how many agents, which pattern, and which roles. Expose via CLI (`colmena suggest`) and MCP (`mission_suggest`).

**User story:**
> `colmena suggest "fix typo in README"`
> → "Complexity: trivial. You don't need Colmena for this. Use Claude Code directly."
>
> `colmena suggest "implement JWT authentication with refresh tokens, rate limiting, and audit logging"`
> → "Complexity: medium. Recommended: 3 agents (developer + tester + auditor). Pattern: refactor-safe."

## Design Decisions

### 1. `suggest_mission_size()` Core Function

```rust
pub enum Complexity {
    Trivial,   // 1 agent — don't use Colmena
    Small,     // 2 agents — marginal benefit, warn user
    Medium,    // 3-4 agents — sweet spot for Colmena
    Large,     // 5-6 agents — full orchestration
}

pub struct MissionSuggestion {
    pub complexity: Complexity,
    pub recommended_agents: usize,
    pub needs_colmena: bool,          // false if < 3 agents
    pub suggested_pattern: Option<String>,
    pub suggested_roles: Vec<String>,
    pub confidence: f64,              // 0.0-1.0
    pub reason: String,
}

pub fn suggest_mission_size(
    description: &str,
    roles: &[Role],
    patterns: &[Pattern],
) -> MissionSuggestion
```

### 2. Sizing Logic

**Domain detection:** Analyze description for distinct domain keywords:

| Domain | Keywords (examples) |
|--------|-------------------|
| Code | implement, develop, build, feature, code, refactor, migrate |
| Testing | test, coverage, validate, edge case, regression, QA |
| Security | vulnerability, pentest, audit, OWASP, CVE, exploit |
| Documentation | docs, document, README, guide, API docs, changelog |
| Architecture | design, architecture, tradeoff, ADR, interface, API design |
| Review | review, quality, standards, code review, best practices |
| Operations | deploy, CI/CD, pipeline, monitor, infrastructure |

**Complexity scoring:**

| Domains detected | Complexity | Agents | needs_colmena |
|-----------------|------------|--------|---------------|
| 0-1 | Trivial | 1 | false |
| 2 | Small | 2 | false (warn: marginal benefit) |
| 3 | Medium | 3 | true |
| 4+ | Large | 4-6 | true |

**Adjustments:**
- Keywords indicating risk ("production", "migration", "security", "compliance") bump complexity +1
- Keywords indicating scope ("full", "comprehensive", "end-to-end", "complete") bump complexity +1
- Keywords indicating simplicity ("fix", "typo", "rename", "small", "quick") reduce complexity -1

**Pattern matching:** Reuses `select_patterns()` from M7 to suggest the best pattern. If no pattern matches, suggest using `mission_spawn` (which auto-creates patterns).

**Role suggestion:** Uses `map_topology_roles()` from M7 to suggest which roles fill the pattern's slots for the given mission.

**Confidence:** Based on keyword match density. High keyword overlap = high confidence. Ambiguous descriptions get lower confidence with a suggestion to be more specific.

### 3. `colmena suggest` CLI Command

New clap subcommand:

```bash
colmena suggest "<mission description>"
```

**Output format (needs_colmena = true):**
```
Mission Analysis
================

Description: "implement JWT authentication with refresh tokens and audit logging"

Complexity:    medium
Agents:        3
Pattern:       refactor-safe (sequential)
Roles:         developer → tester → auditor
Confidence:    0.78

Domains detected: code, testing, security

→ Ready to go:
  colmena library select --mission "implement JWT authentication with refresh tokens and audit logging"
  # or use mcp__colmena__mission_spawn via MCP
```

**Output format (needs_colmena = false):**
```
Mission Analysis
================

Description: "fix typo in README"

Complexity:    trivial
Agents:        1

⚡ You don't need Colmena for this. Use Claude Code directly.

Why: Single-domain task (documentation) with low complexity. 
     Colmena adds value with 3+ agents for cross-domain coordination.
```

### 4. `mission_suggest` MCP Tool

```rust
#[derive(Debug, Deserialize, JsonSchema)]
struct MissionSuggestInput {
    /// Mission description to analyze
    mission: String,
}
```

- **Rate-limited:** No (read-only analysis, no side effects)
- **Restricted:** No (informational, doesn't create anything)
- **Output:** Same analysis as CLI, formatted for MCP consumption

This allows CC to programmatically check whether to use `mission_spawn` before committing to a multi-agent mission. The Mission Gate (M7.1) systemMessage can reference this tool:

```
"Mission gate: Use mcp__colmena__mission_suggest to check if this task needs 
a mission, or mcp__colmena__mission_spawn to create one."
```

### 5. Integration with Mission Gate

Update the Mission Gate systemMessage (from M7.1) to include `mission_suggest`:

```
"Mission gate: this Agent call has no Colmena mission binding.
 Use mcp__colmena__mission_suggest to check if you need a mission,
 or mcp__colmena__mission_spawn to create one directly.
 Approve manually to proceed without mission binding."
```

## Implementation

### Files to Modify

| File | Change |
|------|--------|
| `colmena-core/src/selector.rs` | +`suggest_mission_size()`, +`MissionSuggestion`, +`Complexity` enum, +domain detection keywords |
| `colmena-cli/src/main.rs` | +`suggest` clap subcommand + output formatting |
| `colmena-mcp/src/main.rs` | +`mission_suggest` MCP tool, +`MissionSuggestInput` |
| `colmena-cli/src/main.rs` | Update Mission Gate systemMessage to reference mission_suggest |
| `Cargo.toml` | Version bump 0.10.0 → 0.11.0 |
| `CLAUDE.md` | Add suggest command, mission_suggest MCP tool, sizing conventions |
| `README.md` | Add mission sizing section, product honesty principle |
| `CHANGELOG.md` | Add M7.2 / v0.11.0 section |
| `docs/guide.md` | Add mission sizing examples |

### Tests

| Test | Location |
|------|----------|
| `test_suggest_trivial_single_domain` | `selector.rs` |
| `test_suggest_small_two_domains` | `selector.rs` |
| `test_suggest_medium_three_domains` | `selector.rs` |
| `test_suggest_large_many_domains` | `selector.rs` |
| `test_suggest_risk_keywords_bump_complexity` | `selector.rs` |
| `test_suggest_simplicity_keywords_reduce` | `selector.rs` |
| `test_suggest_needs_colmena_threshold` | `selector.rs` |
| `test_suggest_pattern_matching` | `selector.rs` |

Expected: ~8 new tests.

## Verification

1. `cargo test --workspace` — all tests pass
2. `cargo clippy --workspace -- -W warnings` — clean
3. CLI: `colmena suggest "fix typo"` → trivial, no Colmena needed
4. CLI: `colmena suggest "implement auth with tests and security review"` → medium, suggests pattern + roles
5. CLI: `colmena suggest "full platform migration with security audit, testing, docs, and CI/CD"` → large
6. MCP: call `mission_suggest` → verify structured output
7. Verify Mission Gate message now references `mission_suggest`
8. Edge case: empty description → graceful error
9. Edge case: ambiguous description → lower confidence score
