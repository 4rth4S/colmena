# Contributing to Colmena

How to set up, build, test, and submit changes. If you only have 5 minutes,
read the TL;DR below and come back when you hit friction.

---

## TL;DR — Your First PR in One Hour

This is the shortest path from zero to a merged PR. Assumes you already have
a Rust stable toolchain and a GitHub account.

```bash
# 1. Clone + build (~3 min on a warm machine)
git clone git@github.com:4rth4S/colmena.git
cd colmena
cargo build --workspace --release

# 2. Run the full CI suite locally — this is what GitHub Actions will run
cargo fmt --all -- --check                      # formatting
cargo clippy --workspace -- -D warnings         # no lint warnings
cargo test --workspace                          # all tests
cargo build --workspace --release               # release build succeeds

# 3. Pick something small — typo fix, doc clarification, clippy lint, new test.
#    Avoid your first PR being a feature. See "Good first PRs" below.

# 4. Branch + commit (convention: fix/, chore/, feat/, docs/)
git checkout -b docs/fix-typo-architecture
$EDITOR docs/dev/architecture.md
git add docs/dev/architecture.md
git commit -m "docs(architecture): fix typo in section 3"

# 5. Push + open PR against main
git push -u origin docs/fix-typo-architecture
gh pr create --fill --label docs

# 6. Wait for CI. All 6 checks must pass (fmt, test, clippy, build, audit, deny).
#    Coco merges PRs manually — do not self-merge.
```

**Good first PRs:**

- Fix a broken link in `docs/`.
- Add a clippy suggestion that clippy flags on your machine.
- Add a missing test for an edge case you find in `colmena-core`.
- Add a role or pattern to `config/library/` (scope it small — one role, one prompt).
- Improve an error message (sanitization still required — never leak paths).

---

## 1. Dev Setup

### Prerequisites

- **Rust stable** (edition 2021). No nightly features required. Pinned in
  `rust-toolchain.toml` — `rustup` will pick up the right toolchain
  automatically.
- **Git**.
- Optional: `cargo install cargo-audit cargo-deny` if you want to run the
  security CI checks locally before pushing.

### Clone and Build

```bash
git clone git@github.com:4rth4S/colmena.git
cd colmena
cargo build --workspace --release
```

Produces two binaries:

- `target/release/colmena` — CLI + hook handler.
- `target/release/colmena-mcp` — MCP server.

### Run the Test Suite

```bash
cargo test --workspace            # All 4 crates, fast
cargo test -p colmena-core         # Single crate
cargo test -p colmena-filter       # Filter crate
cargo test -p colmena-cli           # CLI integration (spawns subprocess, slower)
cargo test -p colmena-mcp           # MCP tests
```

Where tests live:

| Crate            | Test location                                       | Style                                           |
|------------------|-----------------------------------------------------|--------------------------------------------------|
| `colmena-core`   | `colmena-core/src/**/*.rs` (`#[cfg(test)] mod tests`) | Unit tests, filesystem via `tempfile`           |
| `colmena-filter` | `colmena-filter/src/**/*.rs`                         | Per-filter unit tests + pipeline integration    |
| `colmena-cli`    | `colmena-cli/tests/integration.rs`                    | Spawns `colmena hook` / `colmena mission spawn` subprocess, pipes JSON via stdin |
| `colmena-mcp`    | `colmena-mcp/src/**/*.rs`                             | Unit tests + tool-routing tests                 |

Integration tests reach the workspace root via `Path::parent()` — never string
concat `..`. Core tests use `env!("CARGO_MANIFEST_DIR")` + `../config/`.

### Lint

```bash
cargo clippy --workspace -- -D warnings
```

Clippy is strict in CI (`-D warnings` since PR #25). New code must be
clippy-clean before push. If you disagree with a specific clippy suggestion,
add an `#[allow(clippy::...)]` with a one-line comment explaining why — don't
silence across the whole crate.

### Format

```bash
cargo fmt --all                        # write
cargo fmt --all -- --check             # verify (what CI runs)
```

### First-Time Local Setup (Register Hooks + MCP)

If you want to dogfood Colmena on itself — which is the fastest way to
understand the system — run `setup` once after your first release build:

```bash
./target/release/colmena setup
```

This creates config files under `~/colmena/` (or wherever `COLMENA_HOME`
points), registers hooks in `~/.claude/settings.json`, and registers the MCP
server in `~/.mcp.json`. Idempotent. Preview with `setup --dry-run`.

---

## 2. Workspace Structure

| Crate            | Binary         | Purpose                                                                                    |
|------------------|----------------|--------------------------------------------------------------------------------------------|
| `colmena-core`   | (library)      | All business logic: config, firewall, delegations, ELO, reviews, calibration, library, missions, manifest, emitters. Zero platform deps. |
| `colmena-cli`    | `colmena`      | CLI subcommands + CC hook handler. Maps hook payloads to core types.                        |
| `colmena-filter` | (library)      | 4-stage output filtering pipeline for Bash tool outputs + prompt-injection detector.       |
| `colmena-mcp`    | `colmena-mcp`  | MCP server exposing 27 tools via JSON-RPC over stdio. Uses `rmcp` + `tokio`.                |

Both binaries depend on `colmena-core`. The CLI also depends on
`colmena-filter`. The MCP server depends on both.

See [Architecture](architecture.md) for the full module map inside
`colmena-core`.

---

## 3. How To: Add a New Firewall Rule

Edit `config/trust-firewall.yaml`. Rules live in three sections:
`trust_circle` (auto-approve), `restricted` (ask), `blocked` (deny).

### Rule Schema

```yaml
- tools: [ToolName1, ToolName2]   # Required: list of CC tool names
  conditions:                      # Optional: ALL must match
    bash_pattern: '^safe_cmd\b'    # Regex for Bash commands — SINGLE-QUOTED in YAML
    path_within: ['${PROJECT_DIR}']
    path_not_match: ['*.env']
  action: auto-approve             # auto-approve | ask | block (kebab-case)
  reason: 'Why this rule exists'
```

### Gotchas

- **YAML regex escaping**: always single-quote `bash_pattern`. Double quotes
  interpret `\b` as a backspace character, not a regex word boundary.
- **Action is kebab-case**: `auto-approve`, not `autoApprove` or
  `auto_approve`.
- **`bash_pattern` only applies to Bash**: a rule with
  `tools: [Bash, Read]` checks the pattern for Bash and skips it for Read.
- **`path_not_match` matches filename only**: `*.env` blocks `foo.env` but
  not `foo.env.production`.
- **`path_within` is component-based**: uses `Path::starts_with()`, not
  string prefix. `/project` does not match `/project-evil/file` (this is a
  deliberate security fix — see `docs/dev/internals.md`).
- **Regex compiled at load time**: invalid regex triggers
  `compile_config()` warning and the rule silently fails to match, which
  falls through to a less permissive rule or default Ask. ELO-override
  regex compiles at evaluation time instead — same failure mode.

### Protecting a New Config File

If you add a new config file that agents should never modify, add its glob
pattern to the `path_not_match` list of the Write/Edit `trust_circle` rule in
`trust-firewall.yaml`. That list already covers the live ones
(`trust-firewall.yaml`, `runtime-delegations.json`, `alerts.json`,
`session-gate.json`, etc.).

---

## 4. How To: Add a New MCP Tool

### 1. Define Input Type + Handler

In `colmena-mcp/src/main.rs`:

```rust
#[derive(Debug, Deserialize, JsonSchema)]
struct MyNewToolInput {
    /// Description for the tool parameter (agent-facing).
    my_param: String,
}

// In the #[tool_router] impl block:
#[tool(name = "my_new_tool", description = "What this tool does")]
async fn my_new_tool(
    &self,
    params: Parameters<MyNewToolInput>,
) -> Result<CallToolResult, McpError> {
    let input = params.inner();
    Ok(CallToolResult::success(vec![Content::text("result")]))
}
```

### 2. Rate Limiting + Error Sanitization

If the tool modifies state (`create_*`, `review_*`, `mission_*`), add rate
limiting: `self.rate_limiter.check("my_new_tool")`. Always sanitize errors
with `sanitize_error()` to prevent leaking filesystem paths. Source:
`colmena-core/src/sanitize.rs`.

### 3. Firewall Classification

Read-only tools need no firewall entry. State-modifying tools should be
added to `restricted` in `trust-firewall.yaml` so a human confirms each
invocation — unless the tool is both agent-safe and fully scoped by its own
logic (rare).

### 4. Document It

Add the tool to the MCP table in `architecture.md` §5 and, if it changes
end-user behavior, to `docs/guide.md`.

---

## 5. How To: Add a New Role

### 1. Create the YAML File

Create `config/library/roles/my-role.yaml`:

```yaml
name: My Role
id: my_role
icon: "🔧"
description: "One-line description of what this role does"

system_prompt_ref: prompts/my-role.md

default_trust_level: ask           # auto-approve | ask | restricted
tools_allowed:
  - Read
  - Glob
  - Grep
  - mcp__colmena__findings_query   # MCP tools use full name
  - mcp__colmena__review_submit    # workers MUST have this for ELO to close
  - mcp__caido__*                  # glob patterns supported

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

Create `config/library/prompts/my-role.md` with five sections: Core
Responsibilities, Methodology (5 phases), Escalation, Output Format,
Boundaries.

### 3. Embed in the Binary

Add the two files to `colmena-cli/src/defaults.rs` via `include_str!()` so
`colmena setup` installs them. If you skip this, the role won't exist on
fresh installs.

### 4. Conventions

- `tools_allowed` supports exact names and glob patterns
  (`mcp__caido__*`, `mcp__colmena__findings_*`).
- Workers must include `mcp__colmena__review_submit` + `findings_query`.
- Reviewers must include `mcp__colmena__review_evaluate` + `findings_query`.
  (See `emitters::claude_code::REVIEWER_REQUIRED_TOOLS` /
  `WORKER_REQUIRED_TOOLS`.)
- Dev roles typically start at `ask` trust; security roles vary. ELO
  calibration moves them.
- Only the auditor has `role_type: auditor` — exempts it from the SubagentStop
  review check.

---

## 6. How To: Add a New Pattern

### 1. Create the YAML File

Create `config/library/patterns/my-pattern.yaml`:

```yaml
name: My Pattern
id: my-pattern
source: custom
description: >
  Multi-line description of the orchestration approach.
topology: hierarchical   # One of 7: hierarchical, sequential, adversarial,
                         # peer, fan-out-merge, recursive, iterative
communication: hub-and-spoke
when_to_use:
  - "Scenario 1 where this pattern fits"
when_not_to_use:
  - "Scenario where this pattern is wrong"
pros:
  - "Advantage 1"
cons:
  - "Disadvantage 1"
estimated_token_cost: medium      # low | medium | high
estimated_agents: "3-5"            # minimum 3 (enforced)
roles_suggested:
  oracle: security_architect
  workers: [pentester, auditor]
elo_lead_selection: true
```

### 2. Embed in the Binary

Add to `colmena-cli/src/defaults.rs` via `include_str!()`.

### 3. Conventions

- Minimum 3 agents (2 workers + auditor). Source:
  `colmena-core/src/pattern_scaffold.rs`.
- The `topology` field maps to a `PatternTopology` variant, which determines
  slot structure via `topology_slots()`.
- `iterative` and `recursive` topologies automatically include an
  evaluator/Judge slot.
- `elo_lead_selection: true` makes `generate_mission` pick the highest-ELO
  agent in the squad as reviewer lead.

---

## 7. How To: Add a New Mission Manifest (M7.3)

`colmena mission spawn --from manifest.yaml` takes a manifest describing the
mission and generates everything: subagent files, delegations, per-agent
prompts. See `colmena-core/src/mission_manifest.rs` for the type; example:

```yaml
id: 2026-04-21-payments-audit
pattern: plan-then-execute
mission_ttl_hours: 8

roles:
  - name: security_architect
    scope:
      owns: ["docs/threat-model.md"]
      forbidden: ["src/**"]
    task: |
      Produce the threat model for the payments API.

  - name: pentester
    scope:
      owns: []
      forbidden: ["src/**"]
    task: |
      Execute recon + auth bypass tests on the payments API.

  - name: auditor
    scope:
      owns: []
      forbidden: []
    task: |
      Evaluate pentester + security_architect artifacts with QPC scoring.
```

Requirements:

- `id`, `pattern`, at least one role with non-empty `name` — otherwise
  validation fails and the CLI exits non-zero.
- `mission_ttl_hours` must be 1–24 (default 8).
- Every role name must exist in `config/library/roles/` — otherwise the CLI
  prints the `library create-role` command and exits.

---

## 8. Code Conventions

### Error Handling

- `anyhow::Result` everywhere. Never panic in the hook path.
- Safe fallbacks per hook type:
  - **PreToolUse**: any error → `ask` (never `deny` or crash).
  - **PostToolUse**: any error → passthrough (return original output
    unchanged).
  - **PermissionRequest**: any error → no output (CC continues to prompt the
    user).
  - **SubagentStop**: any error → approve (never trap an agent).
- Filter pipeline: each filter is wrapped in `catch_unwind`. A panicking
  filter is skipped with a `"filter_name:PANICKED"` note.

### File I/O

- Atomic writes for shared state: write to temp file in the same directory,
  then rename. Source: `delegate.rs`.
- No `HOME=/tmp` fallback. If `HOME` is unset, exit with error. Source:
  `paths.rs`.
- Log rotation at 10 MB for `audit.log`, `elo-events.jsonl`,
  `filter-stats.jsonl`.

### Performance

- PreToolUse path must complete in <100 ms. No network calls, no heavy I/O.
- Regex patterns compiled once at config load time (`compile_config()`).
  Exception: ELO override regex patterns compile at evaluation time because
  they come from JSON, not the YAML compile pass. Invalid regex silently
  fails — the rule won't match.

### Naming

- Rust: `snake_case` for functions/variables, `PascalCase` for types.
- YAML config: kebab-case for `Action` (`auto-approve`, not `autoApprove`).
- Hook JSON protocol: `camelCase` for CC-facing fields (`hookEventName`,
  `permissionDecision`, `updatedMCPToolOutput`). Translation handled by
  `#[serde(rename = "camelCase")]` in `hook.rs`.

### Documentation

- Public types and functions in `colmena-core` need doc comments. Use
  `///` with a first-line summary and (optionally) a detail paragraph.
- `CHANGELOG.md` uses [Keep a Changelog](https://keepachangelog.com/)
  sections: Added / Changed / Fixed / Removed / Security. Bump on every
  shipped PR.

---

## 9. PR Workflow

### Branching

Always create a branch. **Never commit to `main`** — branch protection is
enforced.

Branch name prefixes:

- `feat/` — new features
- `fix/` — bug fixes
- `chore/` — maintenance, deps, refactoring, releases
- `docs/` — documentation changes
- `test/` — test-only changes
- `style/` — formatting only (rare)

### Commit Message Conventions

Use [Conventional Commits](https://www.conventionalcommits.org/)-style
subjects. Keep the subject ≤72 chars. Body optional but preferred for
non-trivial changes. Examples:

```
fix(mission): --session-gate now actually activates Mission Gate
feat(cli): add `colmena mission prompt-inject --mode terse`
docs(architecture): rewrite for M7.3 live-surface
chore(release): bump workspace version to 0.12.2
test(integration): cover enforce_missions=false + 3+ roles border case
```

Scope (`(mission)`, `(cli)`, `(core)`, `(mcp)`, `(filter)`, `(docs)`,
`(release)`) is optional but useful.

### Before Submitting

Run the full CI locally:

```bash
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
cargo test --workspace
cargo build --workspace --release
# Optional but recommended before a release-relevant PR:
cargo audit
cargo deny check
```

If any step fails, fix it before pushing. CI runs the same six jobs and
blocks the merge if any fail.

### Opening the PR

```bash
git push -u origin <branch>
gh pr create --fill --label <label>
```

Labels to use:

- `bug` — `fix/` branches
- `feature` — `feat/` branches
- `docs` — `docs/` branches
- `chore` — `chore/` branches
- `security` — anything touching trust rules, firewall, sanitization, hooks

The repo uses a PR template (`.github/PULL_REQUEST_TEMPLATE.md`) — fill it
out. Link relevant roadmap milestone (`M7.3`, `M7.4`, …) in the description.

### Branch Protection

`main` has required-status-checks enabled. All six CI jobs must pass before
merge:

| Job            | Command                                    |
|----------------|--------------------------------------------|
| Format         | `cargo fmt --all -- --check`               |
| Test           | `cargo test --workspace`                   |
| Clippy         | `cargo clippy --workspace -- -D warnings`  |
| Build Release  | `cargo build --workspace --release`        |
| Security Audit | `cargo audit`                              |
| Dependency Policy | `cargo deny check`                      |

Additional rules:

- Approval required from @4rth4S (Coco).
- Self-approval is disabled — you cannot approve your own PRs.
- Force-push to `main` is blocked.
- No `--no-verify`, no skipping hooks, no bypassing signing — ever.
- **Coco merges PRs manually.** Do not self-merge, do not use `--squash` /
  `--rebase` buttons unless Coco explicitly asks.

### Version

Single workspace version in the top-level `Cargo.toml`. Bump on every
release. Docs referencing the version (`README.md`, `docs/guide.md`) must be
updated in the same PR.

Current: **0.12.2** (M7.3 live-surface shipped).

---

## 10. What "Done" Means

Before you mark a PR ready for review, verify:

- [ ] All six CI jobs pass locally and on the PR.
- [ ] New public types/functions in `colmena-core` have doc comments.
- [ ] New features are covered by tests (unit + at least one integration if
      they touch hooks or MCP).
- [ ] `CHANGELOG.md` updated under `[Unreleased]`.
- [ ] If you added a new default file, it's embedded in
      `colmena-cli/src/defaults.rs` via `include_str!()`.
- [ ] If you added a new runtime file, it's in `trust-firewall.yaml`'s
      `path_not_match` so agents can't overwrite it.
- [ ] If you changed a hook payload shape, you tested the deserializer with
      CC's actual payload (not just your own fixture — CC's field names
      historically have surprises like `tool_response` vs `tool_output`).
- [ ] The PR description references the milestone it belongs to
      (`M7.3`, `M7.4`, …).

---

## See Also

- [Architecture](architecture.md) — system overview, data flows, trust model, MCP internals.
- [Internals](internals.md) — edge cases, safety contracts, things that will bite you.
- [User Guide](../guide.md) — walking example using `colmena mission spawn`.
- [README](../../README.md) — project overview and quickstart.

<p align="center">built with ❤️‍🔥 by AppSec</p>
