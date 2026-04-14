# M7: Generic Roles + Patterns + Topology Mapping — v0.9.0

**Status:** Planned (2026-04-14)

## Context

Colmena's library has 6 security-focused roles and 7 patterns. This covers pentesting and security architecture workflows well, but developers using Colmena for general software engineering (writing features, reviewing code, running tests, refactoring) have no built-in roles. They must create custom roles via `library_create_role` every time.

The brainstorm session (2026-04-13) identified this as the #1 gap before launch: *"Generic roles must be battle-tested before shipping."* Without dev roles, `library_select` returns security patterns for dev tasks, and `map_topology_roles` (new) can't assign meaningful roles to Worker/Defensive slots.

**Goal:** Add 4 generic development roles + 3 dev workflow patterns + topology-aware role mapping + auditor evaluation framework + inter-agent token efficiency directive.

**User story:**
> "Necesito un squad para implementar autenticación JWT: un dev que codee, un tester que valide, y un auditor que revise todo"
> → `library_select --mission "implement JWT authentication"` matches `code-review-cycle` or `refactor-safe`
> → Roles: developer + tester + auditor already in library, ready to use
> → `map_topology_roles` auto-assigns developer→Worker, tester→Worker, auditor→Judge

## Design Decisions

### 1. Four Generic Roles

| Role ID | Category | Trust Level | Bash Scope | Why this trust level |
|---------|----------|-------------|------------|---------------------|
| `developer` | development | ask | build/test/lint commands | New role, no ELO history. Can write code + run builds. |
| `code_reviewer` | development | ask | read-only: git diff/log/blame, test runners | Reviews code, doesn't modify it. Bash for analysis only. |
| `tester` | development | ask | test frameworks + coverage tools | Writes tests + runs suites. No production commands. |
| `architect` | architecture | ask | minimal: git log, tree, wc | Evaluates tradeoffs, writes docs. Write scoped to `docs/` and config files only. |

**Developer** has `Agent` in `tools_allowed` — can spawn sub-agents for subtasks (still gated by Colmena firewall). Other roles don't spawn agents.

**Code-reviewer is NOT the auditor.** The code-reviewer evaluates code quality, bugs, style, performance. The auditor evaluates the code-reviewer's work using QPC dimensions (see section 4). Different concerns, different ELO tracks.

**All start at trust "ask"** — ELO calibration elevates them over time. No shortcuts for new roles.

### 2. Bash Permissions per Role

Each role gets a `permissions` block with `bash_patterns` (regex) and `path_within` scoping:

**developer:**
```yaml
permissions:
  bash_patterns:
    - '^(cargo|npm|pnpm|yarn|bun|make|go |python |pip |pytest|jest|vitest|eslint|prettier|rustfmt|clippy)'
    - '^git (status|diff|log|add|commit|branch|checkout|stash|show)'
    - '^(ls|cat|head|tail|wc|find|tree|mkdir|cp|mv)\b'
  path_within:
    - '${MISSION_DIR}'
  path_not_match:
    - '*.env'
    - '*credentials*'
    - '*secret*'
```

**code_reviewer:**
```yaml
permissions:
  bash_patterns:
    - '^git (diff|log|blame|show|status)'
    - '^(cargo test|npm test|pytest|jest|vitest|go test)'
    - '^(ls|cat|head|tail|wc|find|tree|grep|rg)\b'
  path_within:
    - '${MISSION_DIR}'
  path_not_match:
    - '*.env'
    - '*credentials*'
```

**tester:**
```yaml
permissions:
  bash_patterns:
    - '^(cargo test|npm test|pytest|jest|vitest|go test|mocha|cypress|playwright)'
    - '^(cargo|npm|pip) (install|add)\b'
    - '^git (status|diff|log)'
    - '^(ls|cat|head|tail|wc|find|tree)\b'
  path_within:
    - '${MISSION_DIR}'
  path_not_match:
    - '*.env'
    - '*credentials*'
```

**architect:**
```yaml
permissions:
  bash_patterns:
    - '^git (log|diff|show|blame)'
    - '^(ls|cat|head|tail|wc|find|tree|grep|rg|tokei|cloc|scc)\b'
  path_within:
    - '${MISSION_DIR}'
    - 'docs/'
  path_not_match:
    - '*.env'
    - '*credentials*'
```

### 3. Three Dev Workflow Patterns

#### `code-review-cycle` (Iterative topology)
```
developer completes full feature → review_submit → auditor evaluates → feedback
```
- **Agents:** 2 (developer + auditor)
- **Token cost:** low
- **ELO lead:** false
- **SubagentStop invariant:** Developer finishes entirely, then submits. Sequential, not concurrent. No deadlock with SubagentStop hook — developer calls `review_submit` before stopping.
- **roles_suggested:** `agent: developer`, `critic: auditor`

#### `docs-from-code` (Sequential topology)
```
architect reads codebase → developer generates docs → auditor validates accuracy
```
- **Agents:** 3 (architect → developer → auditor)
- **Token cost:** low
- **ELO lead:** false
- **Note:** `developer` fills the writer slot. `technical_writer` role planned for post-launch.
- **roles_suggested:** `stage_1: architect`, `stage_2: developer`, `stage_3: auditor`

#### `refactor-safe` (Sequential topology)
```
developer refactors → tester validates nothing broke → auditor approves
```
- **Agents:** 3 (developer → tester → auditor)
- **Token cost:** low
- **ELO lead:** false
- **Key invariant:** Tester runs test suite BEFORE auditor evaluates. If tests fail, pipeline halts.
- **roles_suggested:** `stage_1: developer`, `stage_2: tester`, `stage_3: auditor`

All patterns validated against existing invariants: author≠reviewer, no reciprocal review, min 2 scores.

### 4. `map_topology_roles()` — Topology-Aware Slot Mapping

New public function in `pattern_scaffold.rs`:

```rust
pub fn map_topology_roles(
    topology: PatternTopology,
    mission: &str,
    role_ids: &[String],
    role_specializations: &HashMap<String, Vec<String>>,
) -> Vec<(String, String)>  // (slot_name, real_role_id)
```

**Slot types** (new enum `SlotRoleType`):

| Type | Semantic | Preferred roles (priority order) |
|------|----------|----------------------------------|
| Lead | Orchestrator, coordinator | security_architect, architect |
| Offensive | Active testing, implementation | pentester, web_pentester, api_pentester, developer |
| Defensive | Review, validation, protection | code_reviewer, auditor, security_architect |
| Research | Discovery, analysis | researcher, architect |
| Worker | General execution | developer, tester |
| Judge | Final evaluation | auditor |

**Mapping per topology:**

| Topology | Slot 1 | Slot 2 | Slot 3 | Slot 4+ |
|----------|--------|--------|--------|---------|
| Hierarchical | Lead | Offensive | Research | — |
| Sequential | Research | Defensive | Offensive | — |
| Adversarial | Offensive | Defensive | Judge | — |
| Peer | Offensive | Defensive | Research | Lead (synthesizer) |
| FanOutMerge | Lead | Offensive | Research | Defensive (reducer) |
| Recursive | Lead | Offensive | Research | — |
| Iterative | Worker | Judge | — | — |

**Tie-breaking:** When multiple roles match a slot type, score by overlap of mission keywords vs role `specializations`. Highest overlap wins.

**Invariant:** No role assigned to more than one slot.

**Re-exported from selector.rs** for convenience:
```rust
pub use crate::pattern_scaffold::{map_topology_roles, ...};
```

### 5. Auditor Evaluation Framework — 3 Dimensions

Update `auditor.yaml` system prompt to formalize evaluation on three dimensions:

1. **Quality** (1-10) — Is the work well-executed? Code quality for devs, accuracy for researchers, clarity for writers, thoroughness for pentesters.
2. **Precision** (1-10) — Does the output match the objective? No scope creep, no missed requirements, no hallucinated findings.
3. **Comprehensiveness** (1-10) — How much of the reasoning scope was covered? Edge cases, alternatives, implications considered?

**No code changes required.** `review_evaluate` already accepts `HashMap<String, f64>` for scores. The auditor uses `quality`, `precision`, `comprehensiveness` as score keys. `calibrate_auditor` already displays scores by name — now they'll be consistent and meaningful.

The auditor is **role-agnostic**: evaluates a developer's code the same way it evaluates a researcher's findings. This makes ELO signal meaningful across all roles.

### 6. Inter-Agent Token Efficiency Directive

`generate_mission()` (in selector.rs) injects a communication protocol section into every agent's CLAUDE.md when generating a mission:

```markdown
## Colmena Inter-Agent Protocol
When communicating with other agents in this mission:
- Facts only. No explanations unless requested.
- Format: [finding] [evidence] [severity/status]. Next.
- Reference artifacts as path:line — no prose descriptions.
- Skip articles, filler, hedging, pleasantries.
- NEVER compress: code, commands, file contents, configurations, error messages.
- Human-facing output: normal verbosity (this protocol is agent-to-agent only).
```

**Design principles:**
- **Native, zero dependencies.** Inspired by Caveman (JuliusBrussee/caveman) but Colmena's own implementation.
- **Agent→agent only.** More aggressive than Caveman because the receiver doesn't need explanations, just data.
- **Code stays intact.** Compression applies to communication, never to artifacts. A `fn` is never abbreviated.
- **Automatic.** Injected by `generate_mission()`, applies to ALL roles in mission mode (existing + new).

Expected savings: 40-70% on inter-agent communication tokens based on Caveman benchmarks. Actual impact logged to `filter-stats.jsonl` via existing PostToolUse pipeline.

## Implementation

### Files to Create

| File | Description |
|------|-------------|
| `config/library/roles/developer.yaml` | Developer role definition |
| `config/library/roles/code_reviewer.yaml` | Code Reviewer role definition |
| `config/library/roles/tester.yaml` | Tester role definition |
| `config/library/roles/architect.yaml` | Architect role definition |
| `config/library/prompts/developer.md` | Developer system prompt (5 sections) |
| `config/library/prompts/code_reviewer.md` | Code Reviewer system prompt (5 sections) |
| `config/library/prompts/tester.md` | Tester system prompt (5 sections) |
| `config/library/prompts/architect.md` | Architect system prompt (5 sections) |
| `config/library/patterns/code-review-cycle.yaml` | Iterative dev→review pattern |
| `config/library/patterns/docs-from-code.yaml` | Sequential docs generation pattern |
| `config/library/patterns/refactor-safe.yaml` | Sequential refactor→test→approve pattern |

### Files to Modify

| File | Change |
|------|--------|
| `colmena-core/src/pattern_scaffold.rs` | +`map_topology_roles()`, +`SlotRoleType`, +`SlotDesc`, +topology_slots(), +preferred_roles() |
| `colmena-core/src/selector.rs` | Re-export `map_topology_roles`, +inter-agent directive in `generate_mission()` |
| `config/library/prompts/auditor.md` | Add QPC evaluation framework |
| `Cargo.toml` | Version bump 0.8.0 → 0.9.0 |
| `CLAUDE.md` | Add M7 conventions, update role/pattern counts, version |
| `README.md` | Add dev roles + patterns, update counts |
| `CHANGELOG.md` | Add M7 / v0.9.0 section |
| `docs/guide.md` | Add dev workflow examples |
| `colmena-cli/src/defaults.rs` | Add `include_str!()` entries for new role/pattern/prompt files (embedded in binary) |

### Tests

| Test | Location |
|------|----------|
| `test_map_topology_roles_hierarchical` | `pattern_scaffold.rs` |
| `test_map_topology_roles_adversarial` | `pattern_scaffold.rs` |
| `test_map_topology_roles_iterative` | `pattern_scaffold.rs` |
| `test_map_topology_roles_no_duplicates` | `pattern_scaffold.rs` |
| `test_map_topology_roles_empty_library` | `pattern_scaffold.rs` |
| `test_map_topology_roles_mission_keyword_scoring` | `pattern_scaffold.rs` |
| `test_new_roles_load_valid` | `library.rs` or integration |
| `test_new_patterns_load_valid` | `library.rs` or integration |
| `test_select_patterns_matches_dev_mission` | `selector.rs` |
| `test_generate_mission_includes_interagent_directive` | `selector.rs` |
| `test_interagent_directive_not_in_solo_mode` | `selector.rs` |

Expected: ~12 new tests, total ~315.

## Verification

1. `cargo test --workspace` — all tests pass
2. `cargo clippy --workspace -- -W warnings` — clean
3. `colmena library list` — shows 10 roles, 10 patterns
4. `colmena library show developer` — complete role with permissions
5. `colmena library select --mission "implement JWT auth"` — matches dev patterns
6. Manual: generate a mission with new roles, verify CLAUDE.md contains inter-agent directive
