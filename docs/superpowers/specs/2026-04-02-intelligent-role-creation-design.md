# M6: Intelligent Role & Pattern Creation — v0.6.0

**Status:** Implemented (2026-04-03)

## Context

`library_create_role` (MCP + CLI) generated empty scaffold files with TODO placeholders. No `scaffold_pattern` existed — patterns were manually created. When `library_select` found no matching pattern, it returned nothing useful. This was the #1 friction point for new users and for adding roles on-the-fly.

**Goal:** Upgrade `library_create_role` to generate a complete, ready-to-use role from just an ID and description. Add `library_create_pattern` for pattern scaffolding. Make `library_select` suggest creating a pattern when no existing one matches.

**User story:**
> "CC, generame un web developer role en colmena para misiones de desarrollo de sitios web dinámicos frontend"
> → CC calls `mcp__colmena__library_create_role(id: "web_developer", description: "frontend developer for dynamic web apps with React/Tailwind")`
> → Colmena generates complete YAML + complete 5-section system prompt
> → CC can review/refine inline, or it's ready to use immediately

## Design Decisions

### 1. RoleCategory — 8 categories (not 4)

Original proposal had 4 (Offensive, Defensive, Development, Research). Expanded to 8 because each must produce **materially different** output across tools, trust level, permissions, methodology, and safety rails.

| Category | Trust Level | Key Tools | Methodology Phases |
|----------|-------------|-----------|-------------------|
| **Offensive** | restricted | Bash(restricted), Read, Write, Edit, Glob, Grep, WebFetch, WebSearch, Agent | Enumerate → Fingerprint → Test → Validate → Document |
| **Defensive** | ask | Bash(restricted), Read, Glob, Grep, WebFetch, WebSearch | Detect → Triage → Investigate → Contain → Document |
| **Compliance** | ask | Read, Glob, Grep, WebFetch, WebSearch | Scope → Map Controls → Collect Evidence → Assess Gaps → Document |
| **Architecture** | ask | Bash, Read, Write, Edit, Glob, Grep, WebFetch, WebSearch, Agent | Assess → Model → Design → Validate → Document |
| **Research** | auto-approve | Read, Glob, Grep, WebFetch, WebSearch | Discover → Collect → Analyze → Correlate → Document |
| **Development** | ask | Bash, Read, Write, Edit, Glob, Grep, WebFetch, WebSearch | Understand → Plan → Implement → Test → Document |
| **Operations** | restricted | Bash(restricted), Read, Write, Edit, Glob, Grep, WebFetch, WebSearch | Inventory → Assess → Configure → Verify → Document |
| **Creative** | auto-approve | Read, Write, Edit, Glob, Grep, WebFetch, WebSearch | Research → Outline → Draft → Review → Finalize |

Categories with `restricted` trust get a `permissions` block with `bash_patterns` for safe commands. Others get no permissions block.

**Detection:** Keyword scoring (not first-match). Each category has 10-15 detection keywords. Highest score wins. Ties broken by preferring less-privileged categories. Default fallback: Development.

### 2. PatternTopology — 7 topologies aligned with agentic-patterns.com

Aligned with established patterns from https://www.agentic-patterns.com/patterns (157 documented patterns) rather than inventing our own taxonomy.

| Topology | Communication | agentic-patterns.com Equivalent | Existing Colmena Pattern |
|----------|--------------|-------------------------------|-------------------------|
| **Hierarchical** | hub-and-spoke | Oracle-Workers, Plan-Then-Execute | oracle-workers, plan-then-execute, mentored-execution, caido-pentest |
| **Sequential** | chain | Pipeline | pipeline |
| **Adversarial** | structured-exchange | Multi-Agent Debate, Opponent Processor | debate |
| **Peer** | broadcast | Swarm Consensus | swarm-consensus |
| **FanOutMerge** | map-reduce | LLM Map-Reduce | (new) |
| **Recursive** | delegation-tree | Sub-Agent Spawning, Tree-of-Thought | (new) |
| **Iterative** | loop | Reflection Loop, Progressive Escalation | (new) |

Each topology generates different `roles_suggested` slot structures (e.g., Hierarchical: lead + workers[], Adversarial: debater_a + debater_b + judge).

### 3. Pattern creation is not scope creep

A role without a pattern is an orphan that nobody uses automatically. Building both together means the feature is complete from day one. Implementation split into parallel squads by file ownership.

### 4. Prompts are starting points

Generated prompts are generic templates — customization done by human or CC after generation. No inline comments like `<!-- customize here -->`. The prompt reads like a real role prompt with substantive content in all 5 sections.

### 5. MCP writes directly + returns content

`library_create_role` writes files and returns full content (YAML + prompt) inline for CC to review without needing a separate Read call. Same for `library_create_pattern`.

### 6. Pattern suggestion on no match

When `library_select` finds no matching pattern for a mission, it now suggests creating one with the recommended topology and provides the CLI command.

## Architecture

### New files

- **`colmena-core/src/templates.rs`** — Role intelligence module
  - `RoleCategory` enum (8 variants) with `Display`, `FromStr`
  - `detect_category(description)` — keyword scoring
  - `generate_role_yaml(id, description, category)` — complete YAML
  - `generate_role_prompt(id, description, category)` — 5-section markdown
  - `infer_specializations(description, category)` — 3-8 slugs from keywords
  - 17 unit tests

- **`colmena-core/src/pattern_scaffold.rs`** — Pattern scaffolding module
  - `PatternTopology` enum (7 variants) with `Display`, `FromStr`
  - `detect_topology(description)` — keyword scoring
  - `generate_pattern_yaml(id, name, description, topology)` — complete YAML
  - `scaffold_pattern(id, description, topology, library_dir)` — file creation
  - `suggest_pattern_for_mission(mission)` — returns `PatternSuggestion`
  - 10 unit tests

### Modified files

- **`colmena-core/src/selector.rs`** — `scaffold_role` refactored to accept `Option<RoleCategory>`, delegates to templates module. Re-exports pattern_scaffold types.
- **`colmena-core/src/lib.rs`** — Added `pub mod templates` and `pub mod pattern_scaffold`
- **`colmena-mcp/src/main.rs`** — Updated `library_create_role` (+ category param, inline content), added `library_create_pattern` tool, updated `library_select` with pattern suggestion
- **`colmena-cli/src/main.rs`** — Added `--category` to create-role, added `create-pattern` subcommand with `--topology`

### Parallel squad execution

Two squads worked in isolated git worktrees for zero-conflict parallel execution:

```
Squad A (Role Intelligence)          Squad B (Pattern Scaffolding)
─────────────────────────            ──────────────────────────────
templates.rs (NEW)                   pattern_scaffold.rs (NEW)
selector.rs:812 (scaffold_role)      selector.rs:8 (pub use re-export)
lib.rs (+1 line)                     lib.rs (+1 line)
```

Integration phase (MCP + CLI) applied sequentially after both squads completed.

## CLI

```
colmena library create-role --id X --description "Y" [--category Z]
colmena library create-pattern --id X --description "Y" [--topology Z]
```

## MCP Tools

```
library_create_role    — create role with intelligent defaults (8 categories)
library_create_pattern — create pattern with topology detection (7 topologies)
```

## Scope

| Component | LOC |
|-----------|-----|
| templates.rs | ~870 |
| pattern_scaffold.rs | ~810 |
| selector.rs changes | ~40 |
| MCP integration | ~80 |
| CLI integration | ~50 |
| Docs sync | ~30 |
| **Total** | **~2121** (vs 480 estimated — scope expanded to include patterns + 8 categories) |

## Verification

```bash
# Build
cargo build --workspace --release

# Tests — 244 total (27 new), 0 failures
cargo test --workspace

# Clippy — 0 warnings
cargo clippy --workspace -- -W warnings

# E2E: Create a development role (auto-detect)
colmena library create-role --id web-developer --description "frontend developer for React and Tailwind web apps"
# → category: Development, trust: ask, tools: Bash+Read+Write+Edit+..., 5-section prompt

# E2E: Create an offensive role (explicit category)
colmena library create-role --id cloud-pentester --description "cloud security testing on AWS" --category offensive
# → trust: restricted, bash_patterns: curl/nmap/python, offensive methodology

# E2E: Create a pattern (auto-detect)
colmena library create-pattern --id parallel-audit --description "parallel compliance auditors with synthesizer" --topology peer
# → topology: peer, communication: broadcast, roles_suggested with participants[] + synthesizer

# E2E via MCP: library_select with no match → suggests creating pattern
```
