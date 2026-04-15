# Contributing to Colmena

How to set up, build, test, and submit changes.

---

## Dev Setup

### Prerequisites

- Rust stable toolchain (edition 2021). No nightly features required.
- Git

### Clone and Build

```bash
git clone git@github.com:4rth4S/colmena.git
cd colmena
cargo build --workspace --release
```

This produces two binaries:
- `target/release/colmena` — CLI + hook handler
- `target/release/colmena-mcp` — MCP server

### Run Tests

```bash
cargo test --workspace         # All 4 crates
cargo test -p colmena-core     # Single crate
cargo test -p colmena-filter   # Single crate
```

### Lint

```bash
cargo clippy --workspace -- -W warnings
```

Clippy must pass before any release. CI enforces this.

### First-Time Setup (Register Hooks + MCP)

```bash
./target/release/colmena setup
```

This creates config files, registers hooks in `~/.claude/settings.json`, and registers the MCP server in `~/.mcp.json`. Idempotent — safe to run again.

---

## Workspace Structure

| Crate | Binary | Purpose |
|-------|--------|---------|
| `colmena-core` | (library) | All business logic: config, firewall, delegations, ELO, reviews, calibration, library, missions. Zero platform deps. |
| `colmena-cli` | `colmena` | CLI subcommands + CC hook handler. Maps hook payloads to core types. |
| `colmena-filter` | (library) | 4-stage output filtering pipeline for Bash tool outputs. |
| `colmena-mcp` | `colmena-mcp` | MCP server exposing 27 tools via JSON-RPC over stdio. Uses rmcp + tokio. |

Both binaries depend on `colmena-core`. The CLI also depends on `colmena-filter`. The MCP server depends on both.

---

## How To: Add a New Firewall Rule

Edit `config/trust-firewall.yaml`. Rules live in three sections: `trust_circle` (auto-approve), `restricted` (ask), `blocked` (deny).

### Rule Schema

```yaml
- tools: [ToolName1, ToolName2]   # Required: list of CC tool names
  conditions:                      # Optional: ALL must match
    bash_pattern: '^safe_cmd\b'    # Regex for Bash commands (single-quoted!)
    path_within: ['${PROJECT_DIR}'] # Component-based directory check
    path_not_match: ['*.env']       # Glob on filename only (last path component)
  action: auto-approve             # auto-approve | ask | block (kebab-case)
  reason: 'Why this rule exists'   # Human-readable
```

### Gotchas

- **YAML regex escaping**: Always use single quotes for `bash_pattern`. Double quotes interpret `\b` as backspace.
- **Action is kebab-case**: `auto-approve`, not `autoApprove` or `auto_approve`.
- **`bash_pattern` only applies to Bash tool**: If your rule has `tools: [Bash, Read]`, the bash_pattern is checked for Bash calls but skipped for Read calls.
- **`path_not_match` matches filename only**: `*.env` blocks `foo.env` but not `foo.env.production`.
- **`path_within` is component-based**: Uses `Path::starts_with()`, not string prefix. `/project` does not match `/project-evil/file`.
- **Regex compiled at load time**: Invalid regex in YAML config causes `compile_config()` to return an error, triggering the safe fallback (ask). In ELO overrides (JSON), invalid regex is silently skipped and the rule won't match.

### Protecting New Config Files

If you add a new config file that agents should not modify, add its glob pattern to the `path_not_match` list in the Write/Edit trust_circle rule (`trust-firewall.yaml:64`).

---

## How To: Add a New MCP Tool

### 1. Define Input Type + Handler

In `colmena-mcp/src/main.rs`:

```rust
#[derive(Debug, Deserialize, JsonSchema)]
struct MyNewToolInput {
    /// Description for the tool parameter
    my_param: String,
}

// In the #[tool_router] impl block:
#[tool(name = "my_new_tool", description = "What this tool does")]
async fn my_new_tool(&self, params: Parameters<MyNewToolInput>) -> Result<CallToolResult, McpError> {
    let input = params.inner();
    Ok(CallToolResult::success(vec![Content::text("result")]))
}
```

### 2. Rate Limiting + Error Sanitization

If the tool modifies state, add rate limiting (`self.rate_limiter.check("my_new_tool")`). Always sanitize errors with `sanitize_error()` to prevent leaking filesystem paths. Source: `rate_limit.rs`, `colmena-core/src/sanitize.rs`.

### 3. Firewall Classification

Read-only tools need no firewall entry. State-modifying tools should be added to `restricted` in `trust-firewall.yaml`.

---

## How To: Add a New Role

### 1. Create the YAML File

Create `config/library/roles/my-role.yaml`:

```yaml
name: My Role
id: my_role
icon: "🔧"
description: "One-line description of what this role does"

system_prompt_ref: prompts/my-role.md

default_trust_level: ask     # auto-approve | ask | restricted
tools_allowed:
  - Read
  - Glob
  - Grep
  - mcp__colmena__findings_list  # MCP tools use full name
  - mcp__caido__*                # Glob patterns supported

specializations:
  - keyword_1
  - keyword_2

elo:
  initial: 1500
  categories:
    keyword_1: 1500
    keyword_2: 1500

mentoring:
  can_mentor: []
  mentored_by: [security_architect]
```

### 2. Create the System Prompt

Create `config/library/prompts/my-role.md` with: core responsibilities, methodology (5 phases), escalation triggers, output format, and boundaries.

### 3. Embed in Binary

Add files to `colmena-cli/src/defaults.rs` via `include_str!()` so `colmena setup` can install them.

### 4. Key Conventions

- `tools_allowed` supports exact names and glob patterns (`mcp__caido__*`).
- Dev roles start at `ask` trust; security roles vary (`researcher` is `auto-approve`, `pentester` is `restricted`).
- Only the auditor role has `role_type: auditor` (exempts from SubagentStop review check).

---

## How To: Add a New Pattern

### 1. Create the YAML File

Create `config/library/patterns/my-pattern.yaml`:

```yaml
name: My Pattern
id: my-pattern
source: custom
description: >
  Multi-line description of the pattern's orchestration approach.
topology: hierarchical    # One of 7: hierarchical, sequential, adversarial,
                          # peer, fan-out-merge, recursive, iterative
communication: hub-and-spoke
when_to_use:
  - "Scenario 1 where this pattern fits"
  - "Scenario 2"
when_not_to_use:
  - "Scenario where this pattern is wrong"
pros:
  - "Advantage 1"
cons:
  - "Disadvantage 1"
estimated_token_cost: medium    # low | medium | high
estimated_agents: "3-5"         # Minimum 3 (enforced)
roles_suggested:
  oracle: security_architect
  workers: [pentester, auditor]
elo_lead_selection: true
```

### 2. Embed in Binary

Add to `colmena-cli/src/defaults.rs` via `include_str!()`.

### 3. Key Conventions

- All patterns require minimum 3 agents (2 workers + auditor). Source: `colmena-core/src/pattern_scaffold.rs:96-106`.
- The `topology` field maps to one of 7 `PatternTopology` variants, which determines the slot structure generated by `topology_slots()`.
- Iterative and Recursive topologies automatically include an evaluator/Judge slot.
- `elo_lead_selection: true` means the highest-ELO agent in the squad becomes the reviewer lead.

---

## Testing

### Unit Tests (Core)

Core tests use `env!("CARGO_MANIFEST_DIR")` + `../config/` to reach workspace root config files.

### Integration Tests (CLI)

Integration tests spawn the CLI binary as a subprocess and pipe JSON via stdin. Use `Path::parent()` for workspace root, never string concatenation with `..`.

### Running Specific Tests

```bash
cargo test -p colmena-core test_evaluate       # Run tests matching name
cargo test -p colmena-cli -- --nocapture        # Show println output
```

---

## Code Conventions

### Error Handling

- Use `anyhow::Result` everywhere. Never panic in the hook path.
- Safe fallbacks per hook type:
  - **PreToolUse**: any error → `ask` (never `deny` or crash)
  - **PostToolUse**: any error → passthrough (return original output unchanged)
  - **PermissionRequest**: any error → no output (CC continues to prompt user)
  - **SubagentStop**: any error → approve (never trap an agent)

### File I/O

- Atomic writes for shared state: write to temp file in same directory, then rename. Source: `delegate.rs:94-112`.
- No `HOME=/tmp` fallback. If `HOME` is unset, exit with error. Source: `paths.rs:22-25`.
- Log rotation at 10MB for audit.log, elo-events.jsonl, filter-stats.jsonl.

### Performance

- Hook path must complete in <100ms. No network calls, no heavy I/O.
- Regex patterns compiled once at config load time (`compile_config()`), not at evaluation time.
- Exception: ELO override regex patterns are compiled at evaluation time because they come from JSON, not YAML config. Source: `firewall.rs:71-79`.

### Naming

- Rust: snake_case for functions/variables, PascalCase for types. Standard Rust conventions.
- YAML config: kebab-case for actions (`auto-approve`, not `autoApprove`).
- JSON (hook protocol): camelCase for field names (`hookEventName`, `permissionDecision`).

---

## PR Workflow

### Branching

Always create a branch. Never commit to `main`.

- `feature/` — new features
- `fix/` — bug fixes
- `chore/` — maintenance, deps, refactoring
- `docs/` — documentation changes

### Before Submitting

1. `cargo test --workspace` — all tests pass
2. `cargo clippy --workspace -- -W warnings` — no warnings
3. `cargo build --workspace --release` — release build succeeds

### CI Checks

GitHub Actions (`ci.yml`) runs on every PR to `main`:

| Job | Command |
|-----|---------|
| Test | `cargo test --workspace` |
| Clippy | `cargo clippy --workspace -- -W warnings` |
| Build Release | `cargo build --workspace --release` |

All three must pass before merge.

### Version

Single workspace version in `Cargo.toml`. Bump version + update docs together when releasing.

---

## See Also

- [Architecture](architecture.md) -- system overview, data flows, trust model, MCP internals
- [Internals](internals.md) -- edge cases, safety contracts, things that will bite you
- [Getting Started](../user/getting-started.md) -- user-facing setup guide
- [README](../../README.md) -- project overview and quick start
