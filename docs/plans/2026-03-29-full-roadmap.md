# Colmena — Full Roadmap (M0.5 → M3) with MCP Integration

> "Start small, grow faster. With great power comes great responsibility."

## Context

M0 Trust Firewall is complete and running. Colmena is currently a CLI-only binary that CC talks to via a PreToolUse hook (unidirectional: CC sends → colmena reacts). To enable M1-M3 features (library selection, knowledge bus, ELO), CC needs to **call colmena proactively** — not just during hook evaluation. MCP (Model Context Protocol) is the official CC mechanism for this.

**Architecture shift:** Refactor into a Rust workspace with a shared library crate. The hook binary stays fast (<100ms). A new MCP server binary exposes all colmena functions as CC tools. Both share the same core logic.

---

## New Architecture

```
colmena/
  Cargo.toml                    # Workspace root
  colmena-core/                 # Shared library (all business logic)
    src/lib.rs
    src/config.rs               # Firewall config loading + validation
    src/firewall.rs             # Rule evaluation engine
    src/delegate.rs             # Runtime delegations
    src/queue.rs                # Approval queue
    src/library.rs              # M1: Role/Pattern templates
    src/selector.rs             # M1: Pattern matching + mission generator
    src/bus.rs                  # M2: Knowledge bus signals
    src/elo.rs                  # M3: ELO scoring engine
    src/paths.rs                # Path resolution utilities
    src/models.rs               # Shared types (EvaluationInput, etc.)
  colmena-cli/                  # CLI binary (human terminal use + hook)
    src/main.rs                 # Clap CLI, hook hot path
    src/notify.rs               # macOS sound notifications
    src/install.rs              # Hook registration
  colmena-mcp/                  # MCP server binary (CC integration)
    src/main.rs                 # MCP server entry (rmcp, stdio transport)
    src/tools.rs                # Tool handlers (library_select, delegate, etc.)
  config/                       # Data files (same as now)
    trust-firewall.yaml
    queue/
    library/                    # M1: roles/, patterns/, prompts/
    missions/                   # M1: generated mission configs
    bus/                        # M2: signals/, subscriptions.yaml
    elo/                        # M3: scores.yaml, history/
```

**Key principle:** `colmena-core` has zero platform dependencies, zero I/O assumptions. CLI and MCP are thin adapters over core.

---

## Milestone Map

| Milestone | What | Depends on |
|-----------|------|-----------|
| **M0.5** | Workspace refactor + MCP server skeleton | M0 (done) |
| **M1** | Wisdom Library + Pattern Selector + mission generator | M0.5 |
| **M2** | Knowledge Bus + Agent spawn via MCP | M1 |
| **M3** | ELO Engine + dynamic trust calibration | M2 |

---

## M0.5 — Workspace Refactor + MCP Server

**Goal:** Same functionality as today, but split into workspace. MCP server exposes basic tools.

### Task 0.5.1: Create workspace structure

Convert single crate to workspace with 3 members:
- `colmena-core` — move config.rs, firewall.rs, delegate.rs, queue.rs + new models.rs, paths.rs
- `colmena-cli` — main.rs (hook + subcommands), notify.rs, install.rs
- `colmena-mcp` — skeleton MCP server with rmcp

Introduce `EvaluationInput` in core (protocol-agnostic version of HookPayload). CLI maps HookPayload → EvaluationInput. MCP maps its own input → EvaluationInput.

### Task 0.5.2: MCP server skeleton

Add `rmcp` dependency to colmena-mcp. Implement stdio transport with these initial tools:

```
mcp__colmena__config_check        # Validate firewall config
mcp__colmena__queue_list          # List pending approvals
mcp__colmena__delegate            # Add runtime delegation
mcp__colmena__evaluate            # Evaluate a tool call against firewall
```

Register in `.mcp.json`:
```json
{
  "mcpServers": {
    "colmena": {
      "command": "./target/release/colmena-mcp",
      "args": []
    }
  }
}
```

### Task 0.5.3: Verify all existing tests pass

All 52 tests must pass. Hook hot path unchanged. New MCP server tested with manual JSON-RPC calls.

### Verification: `cargo test --workspace`, MCP server responds to `tools/list`

---

## M1 — Wisdom Library + Pattern Selector

**Goal:** `mcp__colmena__library_select(mission: "audit payments API")` → recommends patterns → generates CLAUDE.md per agent → human reviews.

### Task 1.1: Library types + loading (colmena-core/library.rs)

Structs: `Role`, `Pattern`, `EloConfig`, `MentoringConfig`, `RolesSuggested`
Functions: `load_roles()`, `load_patterns()`, `load_prompt()`, `validate_library()`

### Task 1.2: YAML content — 4 roles, 4 prompts, 6 patterns

Create `config/library/roles/`, `patterns/`, `prompts/` with all 14 files.

### Task 1.3: Pattern selector + mission generator (colmena-core/selector.rs)

- `select_patterns(mission, patterns, roles) -> Vec<Recommendation>` — keyword scoring
- `generate_mission(mission, pattern, roles, dirs) -> Result<MissionConfig>` — generates CLAUDE.md per agent
- `detect_role_gaps(mission, roles) -> Vec<String>` — warns about missing roles
- `scaffold_role(id, description, library_dir) -> Result<()>` — creates role + prompt templates

### Task 1.4: CLI integration

```
colmena library list
colmena library show <id>
colmena library select --mission "..."
colmena library create-role --id "..." --description "..."
```

### Task 1.5: MCP tools for library

```
mcp__colmena__library_list         # List roles + patterns
mcp__colmena__library_show         # Show role/pattern details
mcp__colmena__library_select       # Score + recommend patterns for mission
mcp__colmena__library_generate     # Generate mission config (CLAUDE.md per agent)
mcp__colmena__library_create_role  # Scaffold new role
```

CC can now say: "Use the colmena library to select a pattern for auditing the payments API" → calls MCP tools → presents results natively.

### Task 1.6: Tests + docs

Unit tests for scoring, CLAUDE.md generation, role scaffolding.
Integration tests for CLI + MCP tool calls.
Update README, CLAUDE.md, guide.md.

### Verification: `colmena library select --mission "..."` + MCP tool call both return same recommendations

---

## M2 — Knowledge Bus + Agent Coordination

**Goal:** Agents publish findings as JSON signals. Other agents subscribe. MCP enables CC to spawn agents and inject signals.

### Task 2.1: Bus types + I/O (colmena-core/bus.rs)

Signal types: `FINDING`, `ALERT`, `CONTEXT`, `EVAL`, `REQUEST`
Functions: `publish_signal()`, `read_signals()`, `filter_for_agent()`, `archive_old_signals()`

Filesystem layout:
```
config/bus/
  signals/{timestamp}-{agent_id}-{type}.json
  subscriptions.yaml
```

### Task 2.2: Subscription config

```yaml
# config/bus/subscriptions.yaml
security_architect:
  subscribes_to: [FINDING, ALERT, CONTEXT]
  filter: "severity >= medium"
pentester:
  subscribes_to: [FINDING, CONTEXT, REQUEST]
  filter: "category in [endpoint, credential, injection, auth]"
```

### Task 2.3: MCP tools for bus

```
mcp__colmena__bus_publish          # Publish a signal (agent reports finding)
mcp__colmena__bus_read             # Read signals for an agent (filtered by subscription)
mcp__colmena__bus_status           # Bus health: signal count, agents active, latest signals
```

**This is the key:** CC agents call `mcp__colmena__bus_publish` to share findings and `mcp__colmena__bus_read` to consume. The bus is the P2P communication layer.

### Task 2.4: Agent spawn via MCP

```
mcp__colmena__mission_launch       # Spawn agents from a generated mission config
```

This reads the `config/missions/` directory generated in M1, and creates Agent Teams or spawns CC instances. Requires human confirmation before launch (the MCP tool returns a "confirm?" prompt).

### Task 2.5: CLI commands

```
colmena bus publish --type FINDING --agent pentester --severity high --description "..."
colmena bus read --agent security-architect
colmena bus status
colmena mission launch <mission-dir>
```

### Task 2.6: PostToolUse hook for signal injection

A new hook (PostToolUse or Notification) that checks for new bus signals after each agent action and injects relevant ones into the agent's context. This is the "subscription injection" from the spec.

### Verification: Two agents can publish/read signals through the bus via MCP

---

## M3 — ELO Engine + Meritocratic Hierarchy

**Goal:** Agents earn scores based on performance. High-ELO agents lead missions. ELO influences trust levels.

### Task 3.1: ELO types + scoring (colmena-core/elo.rs)

```yaml
# config/elo/scores.yaml
pentester:
  global: 1500
  categories:
    web_vulnerabilities: 1500
    api_security: 1500
```

Scoring formula: standard ELO with weighted sources (human validation highest, peer review weighted by evaluator ELO).

Functions: `update_score()`, `get_scores()`, `suggest_lead()`, `suggest_mentor()`, `cold_start_check()`

### Task 3.2: Integration points

- **Selector:** `library_select` uses ELO scores to assign leads (highest-ELO in mission category leads)
- **Firewall:** ELO generates `agent_overrides` — high-ELO agents get expanded trust, low-ELO get more checkpoints
- **Bus:** `EVAL` signals feed into ELO updates

### Task 3.3: MCP tools for ELO

```
mcp__colmena__elo_scores           # View current ELO scores
mcp__colmena__elo_update           # Record a score event (human validation, peer review)
mcp__colmena__elo_suggest_lead     # Who should lead for a given mission category?
mcp__colmena__elo_suggest_mentor   # Who should mentor whom?
```

### Task 3.4: CLI commands

```
colmena elo scores
colmena elo update --agent pentester --category web_vulnerabilities --delta +25 --source "human_validation"
colmena elo leaderboard
```

### Task 3.5: Trust calibration

After ELO updates, `colmena-core` can generate suggested `agent_overrides` for the firewall:
- Agent with ELO > 1800 in category → expanded trust for relevant tools
- Agent with ELO < 1400 → more checkpoints

### Verification: ELO scores update correctly, selector uses them for lead selection, firewall respects agent_overrides

---

## MCP Tools Summary (all milestones)

| Tool | Milestone | Description |
|------|-----------|-------------|
| `config_check` | M0.5 | Validate firewall config |
| `queue_list` | M0.5 | List pending approvals |
| `delegate` | M0.5 | Add runtime delegation |
| `evaluate` | M0.5 | Evaluate tool call against firewall |
| `library_list` | M1 | List roles + patterns |
| `library_show` | M1 | Show role/pattern details |
| `library_select` | M1 | Recommend patterns for mission |
| `library_generate` | M1 | Generate mission CLAUDE.md configs |
| `library_create_role` | M1 | Scaffold new role |
| `bus_publish` | M2 | Publish signal (finding, alert, etc.) |
| `bus_read` | M2 | Read filtered signals for agent |
| `bus_status` | M2 | Bus health overview |
| `mission_launch` | M2 | Spawn agents from mission config |
| `elo_scores` | M3 | View ELO scores |
| `elo_update` | M3 | Record score event |
| `elo_suggest_lead` | M3 | Suggest mission leader |
| `elo_suggest_mentor` | M3 | Suggest mentoring pairs |

---

## Implementation Order

```
M0.5 (workspace + MCP skeleton)     ← START HERE
  ↓
M1 (library + selector + generator)
  ↓
M2 (bus + agent spawn)
  ↓
M3 (ELO + trust calibration)
```

Each milestone: implement in core → expose via CLI → expose via MCP → tests → docs → commit.

---

## Verification (end-to-end)

```bash
# All tests pass
cargo test --workspace

# Clippy clean
cargo clippy --workspace -- -W warnings

# CLI works
colmena library select --mission "audit PCI-DSS compliance"
colmena bus status
colmena elo scores

# MCP works (CC can call tools)
# In a CC session: "use colmena to select a pattern for auditing the payments API"
# CC calls mcp__colmena__library_select → gets recommendations → presents to user

# Hook still works (<100ms)
echo '{"session_id":"test",...}' | colmena hook --config config/trust-firewall.yaml
```
