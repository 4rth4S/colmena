# M7.15 Mission Manifest — Software Architect Review

Author: `colmena_architect` (m7-15-arch-software)
Date: 2026-05-01
Lens: data model, API ergonomics, integration with the existing Rust workspace, agnosticidad cross-domain.
Output budget: ≤800 lines.

## TL;DR

1. The manifest type Coco "thought already existed" partially does: `colmena-core/src/mission_manifest.rs` already defines `MissionManifest { id, pattern, mission_ttl_hours, roles[{name, scope{owns,forbidden}, task}] }`, consumed by `colmena mission spawn --from <file>` (CLI), but **not** by the `mission_spawn` MCP tool nor by `mission_spawn(text, pattern_id)` callers. M7.15 is mostly about **completing the type, exposing it through MCP, and making it the single canonical entry point** — not about inventing it from zero.
2. The proposed shape in the brief is largely correct but **collapses two concerns** that should stay separate: *spawn-time configuration* (squad, paths, budget) and *runtime gates* (`acceptance_criteria`, `mission_gate: enforce`). Mixing them without explicit lifecycles will tax future versions.
3. **Multi-instance agents** (`count: 3`, `instances: [...]`) are necessary for the BBP iteration speed problem, but they break two existing invariants: (a) "exactly one auditor per mission" and (b) ELO accumulates per-`role_id`. The manifest must distinguish *role* (ELO bucket) from *instance* (delegation `agent_id`); the rest of the codebase already has the seams.
4. The shape **is genuinely agnostic** if we drop `hosts` as a top-level field and treat all domain colour through a uniform `scope` block + free-form `metadata`. Three concrete examples (BBP, Colmena self-dev, incident response) compile against the same schema below.
5. **Backward compat is cheap:** `mission_spawn(text, pattern_id)` becomes a thin adapter that synthesises a minimal `MissionManifest` and calls the manifest path. Single source of truth, zero breakage.
6. **Hard blockers from the M7.3 dogfood are exactly three** — `mission_spawn` `description` omission, scope gap (path_within), anti-reciprocal cross-mission. The other two known bugs (library_select destructive default, suggest agent inflation) are not blockers; they live in adjacent CLI surface.
7. **Refined estimate:** 22–30h MVP feels right but slightly optimistic given the multi-instance ELO bookkeeping and the auditor invariant rewrite. **Realistic 28–36h MVP + 8–12h hard blockers**, with `acceptance_criteria` as **opt-in doc-only in v1** and machine-checked in M7.16.

## 1. Manifest shape — definitive

### 1.1 What we keep from the proposal

```yaml
mission_id: bbp-followup-3706175
goal: "..."
pattern: bbp-impact-chain
budget: { max_hours, max_agents }
agents:
  - role: ...
    count: ...
scope:
  paths: [...]
  bash_patterns: { extra_allow: [...] }
acceptance_criteria: [...]
mission_gate: enforce
auditor_pool: ["auditor"]
inter_agent_protocol: terse
```

### 1.2 What changes and why

| Field | Verdict | Reason |
|---|---|---|
| `mission_id` | KEEP | Already maps to `MissionManifest.id`. Used as `mission_id` in delegations, mission marker, review submission. |
| `goal` | RENAME → `description` | The codebase already has `Role.description`, `Pattern.description`. Use the same word. `goal` is fine as alias. |
| `pattern` | KEEP, **make optional** | A manifest with explicit `agents[]` should not require a pattern; the pattern is for *role assignment*, but the user is overriding that. Keep `pattern` as optional hint for prompt generation (topology, role types, communication style) and validation. |
| `budget.max_hours` | KEEP, validate ≤ `MAX_TTL_HOURS` (24h). Caps `mission_ttl_hours`. |
| `budget.max_agents` | KEEP, validate against expanded `agents[].count` total. |
| `agents[].count` / `instances[]` | KEEP, see §2 for semantics. |
| `scope.paths` | KEEP, **becomes the only path source**. Replaces ad-hoc `${MISSION_DIR}` rewriting in `pattern.workspace_scope`. |
| `scope.hosts` | DROP from top-level | `hosts` is BBP-specific cosmetics. If kept, it becomes domain-leaky. Move under `scope.metadata.hosts` for purely informational use, or wire it through `bash_patterns.extra_allow` (`^curl.*coinbase\.com`) which is what actually enforces it. |
| `scope.bash_patterns.extra_allow` | KEEP | Plumbs into role-bound delegations as `bash_pattern` regex. |
| `scope.bash_patterns.extra_deny` | ADD | Symmetric. Prevents an instance from running specific commands even if its role would normally allow them. Cheap to wire. |
| `scope.path_not_match` | ADD | The codebase already has this (`*.env`, `*credentials*`); manifests must let users add per-mission exclusions (e.g. `prod/*.tf`). |
| `acceptance_criteria` | KEEP as **doc-only in v1** | See §8. Machine-checking is a separate milestone. |
| `mission_gate: enforce` | KEEP | Maps to firewall config `enforce_missions: bool` for this session — the manifest is already the trigger Coco wants ("when source: role delegations exist, enforce_missions toggles true"). |
| `auditor_pool` | KEEP, default `["auditor"]` | Maps to `available_roles` in `review_submit`. |
| `inter_agent_protocol` | KEEP, enum: `terse \| verbose` | Toggles whether `INTER_AGENT_DIRECTIVE` is appended. Default `terse` for ≥2 agents (current behaviour). |
| `metadata` | ADD | Free-form `HashMap<String,String>` for domain colour: `target_program`, `incident_id`, `pr_number`, etc. Never read by core logic, surfaces in audit log + agent prompts. |
| `tags` | ADD (`Vec<String>`) | Free-form tags. Lets analytics/leaderboards group missions (`bbp`, `dev`, `incident`, `research`). |

### 1.3 Final canonical YAML

```yaml
# v1.0
mission_id: <slug>                  # required, unique, ASCII slug
description: "..."                  # required, free-form
pattern: <pattern_id>               # optional; library hint or "custom"
mission_ttl_hours: 8                # optional, default 8, max 24

# Squad — agents drive role assignment + instance fan-out.
agents:
  - role: <role_id>                 # required, must exist in library
    count: 1                        # optional, default 1
    instances:                      # optional, name overrides for count>1
      - <instance_suffix>
    task: "..."                     # optional, free-form per-role brief
    scope:                          # optional, role-instance scope override
      owns: [...]
      forbidden: [...]
    model: <model_id>               # optional, overrides Role.model

# Mission-wide scope (default for all agents unless agent.scope set).
scope:
  paths:                            # required if any tool reads/writes
    - <absolute or ${MISSION_DIR}>
  path_not_match:                   # optional
    - "*.env"
  bash_patterns:                    # optional
    extra_allow: ['^curl.*coinbase\.com']
    extra_deny:  ['^rm -rf /']

# Governance.
mission_gate: enforce               # enforce | observe | off (default: enforce)
auditor_pool: ["auditor"]           # default ["auditor"]
inter_agent_protocol: terse         # terse | verbose (default terse if agents>=2)
acceptance_criteria:                # doc-only v1, machine-checked v2 (M7.16)
  - "PoC submitted to H1"
  - "All findings have severity"

# Limits.
budget:
  max_hours: 8
  max_agents: 12

# Free-form domain colour, never gates anything.
metadata:
  target_program: coinbase
  incident_id: INC-2026-0501
tags: [bbp, web]
```

### 1.4 What is missing from the brief

- **Schema version field**. Add `version: 1`. Future migrations need a discriminator.
- **Per-agent model override**. Already proposed above (`agents[].model`); `Role.model` exists today but the manifest must let an operator override it without editing the role YAML.
- **Per-instance prompt addendum**. `agents[].instances` is currently just naming; missions like BBP wave-2 want `squad-a` to focus on COOP, `squad-b` on origin spoofing, `squad-c` on PoC validation. Solve by `instances[]` becoming `Vec<InstanceSpec { suffix, prompt_addendum }>`. Default: just a string suffix (backwards compatible parsing).

### 1.5 What sobra (drop or move)

- `hosts:` (covered above).
- `goal:` redundant with `description:`.
- Anything domain-specific in top-level fields: `program`, `cve`, `vuln_class`, etc. — all into `metadata`.

## 2. Multi-instance agents

### 2.1 Problem

Today: `mission_spawn` collapses every `RoleAssignment` to a single `agent_id == role_id`. ELO log stores events keyed by `role_id`. Delegations are `(tool, agent_id, conditions)`. Mission Gate checks `agent_id`.

BBP iteration needs 3 simultaneous `bbp_pentester_web` agents pivoting independently. If they all share `agent_id = bbp_pentester_web`:

- Three `RuntimeDelegation` rows with same `(tool, agent_id)` collapse on `decide_merge` (`delegate.rs:1012`).
- All three hit the same `path_within: [${MISSION_DIR}]` → file collisions inevitable.
- `review_submit` pairs author=`bbp_pentester_web`, reviewer=`auditor` repeatedly, and the per-mission anti-reciprocal counter (after M7.3.1 fix) blocks the second submission.

### 2.2 Proposal — `agent_id` as `<role_id>` or `<role_id>-<suffix>`

Manifest expansion at parse time produces *N* logical "instance descriptors":

```rust
pub struct InstanceDescriptor {
    pub role_id: String,            // ELO bucket — always the role
    pub agent_id: String,           // delegation id — role_id when count==1, role_id-suffix otherwise
    pub instance_suffix: Option<String>,
    pub task: String,
    pub scope: ManifestScope,
    pub model: Option<String>,
    pub prompt_addendum: Option<String>,
}
```

Rules:

- `count: 1` and no `instances` → `agent_id == role_id`. Backwards compatible. ELO/delegations identical to today.
- `count: N` and `instances == None` → suffixes auto-generated `s1, s2, …, sN`. `agent_id = "<role>-s1"`, etc.
- `count: N` and `instances == Some(vec![...])` → must satisfy `len() == N`; suffixes from manifest. `agent_id = "<role>-<suffix>"`.

Subagent files at `~/.claude/agents/<role>-<suffix>.md` with `name:` matching `agent_id` so CC routes correctly (per the ELO success recipe item 1). The frontmatter `description` field also gets fixed here (M7.3 dogfood blocker).

### 2.3 ELO model: per-role, not per-instance

ELO accumulates against `role_id`, not `agent_id`. This matches today's behaviour and Coco's mental model ("3 squads of `bbp_pentester_web` are 3 ELO events for `bbp_pentester_web`, not for `bbp_pentester_web-s1`"). The benefit:

- Reviewer diversification (M7.7) still operates on roles.
- Calibration warm-up (3-review minimum) accumulates across instances.
- ELO leaderboards stay readable.

The cost is one tiny rule in `review.rs`: when looking up "what role did this `agent_id` belong to?", strip the `-<suffix>` portion or look it up from the active mission's `MissionManifest`. Trivial.

### 2.4 Path scoping per instance

Each instance gets its own `${MISSION_DIR}/agents/<role>-<suffix>/` workspace, and its delegations include both `${MISSION_DIR}/agents/<role>-<suffix>` and any path declared in `agents[].scope.owns`. The mission-wide `scope.paths` are merged in. This is just a loop over instances when generating delegations — `selector.rs:421-580` already does it for role assignments; replace with instance descriptors.

### 2.5 Auditor invariant — clarification

"Exactly one auditor per mission" is hardcoded at `selector.rs:322-345`. With multi-instance, this becomes "exactly one *role* with `role_type: auditor`, with `count == 1`". Add the count check; reject manifests with auditor `count > 1` and a clear error message: *"Auditor role must have count: 1; centralized review is a Colmena invariant. See CLAUDE.md §Missions & Agent Identity."*

### 2.6 Anti-reciprocal across instances

Inside one mission with 3 `bbp_pentester_web` instances and 1 `auditor`:

- All 3 instances submit reviews; reviewer is always `auditor`.
- The pair `(author=bbp_pentester_web, reviewer=auditor)` exists 3 times.
- After M7.3.1 fix (filter is per-mission, not global), this is allowed within the mission only because the auditor never reviews instances 1, then instance 2 reviews auditor — that pattern doesn't exist in centralized-auditor missions.
- One subtle case: if `bbp_pentester_web-s1` reviews `bbp_pentester_web-s2` (which only happens if `available_roles` was broadened), the per-mission anti-reciprocal filter must compare `(author_role, reviewer_role)`, not `(author_agent_id, reviewer_agent_id)`. **This is the right semantics anyway** — reciprocity is between roles, not arbitrary instance pairs. Add this normalisation in M7.3.1 fix.

## 3. Integration with existing codebase

### 3.1 Where `MissionManifest` lives

Already at `colmena-core/src/mission_manifest.rs`. Plan: **extend the existing struct in place; do not introduce a `MissionManifestV2`**. Use `serde(default)` on every new field for back-compat with existing manifests (the few that exist).

### 3.2 Module layout (proposed)

```text
colmena-core/src/
├── mission_manifest.rs       # existing — extend in place
│   ├── MissionManifest       # add: description, scope, mission_gate, auditor_pool,
│   │                         #      inter_agent_protocol, acceptance_criteria,
│   │                         #      budget, metadata, tags, version
│   ├── ManifestAgent         # NEW — replaces the loose "ManifestRole" with multi-instance
│   ├── ManifestScope         # extend: path_not_match, bash_patterns
│   ├── ManifestBudget        # NEW
│   ├── BashPatternsRule      # NEW { extra_allow, extra_deny }
│   ├── InstanceDescriptor    # NEW — expansion product
│   └── expand()              # NEW — MissionManifest → Vec<InstanceDescriptor>
│
├── selector.rs               # generate_mission/spawn_mission consume InstanceDescriptors
│   └── (refactor) RoleAssignment → derived from InstanceDescriptor
│
├── delegate.rs               # unchanged; receives instance-aware agent_ids
└── review.rs                 # add per-mission filter (M7.3.1 fix); normalise role pair
```

### 3.3 Struct skeleton (Rust)

```rust
// mission_manifest.rs (proposed v1 shape)

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissionManifest {
    #[serde(default = "default_version")]
    pub version: u32,                       // schema version, 1 for now

    pub id: String,                         // existing — mission_id
    #[serde(default)]
    pub description: String,                // alias of "goal"; required when not legacy

    #[serde(default)]
    pub pattern: String,                    // optional now, was required

    #[serde(default = "default_ttl_hours")]
    pub mission_ttl_hours: i64,

    pub agents: Vec<ManifestAgent>,         // replaces existing `roles: Vec<ManifestRole>`

    #[serde(default)]
    pub scope: ManifestScope,               // mission-wide default

    #[serde(default)]
    pub mission_gate: MissionGateMode,      // enforce | observe | off

    #[serde(default = "default_auditor_pool")]
    pub auditor_pool: Vec<String>,

    #[serde(default)]
    pub inter_agent_protocol: Option<InterAgentMode>,

    #[serde(default)]
    pub acceptance_criteria: Vec<String>,   // doc-only v1

    #[serde(default)]
    pub budget: Option<ManifestBudget>,

    #[serde(default)]
    pub metadata: HashMap<String, String>,

    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestAgent {
    pub role: String,                       // role_id in library

    #[serde(default = "one")]
    pub count: u32,

    #[serde(default)]
    pub instances: Vec<InstanceSpec>,

    #[serde(default)]
    pub task: String,

    #[serde(default)]
    pub scope: ManifestScope,               // overrides mission scope

    #[serde(default)]
    pub model: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum InstanceSpec {
    Suffix(String),                         // "squad-a"
    Detailed { suffix: String, prompt_addendum: Option<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ManifestScope {
    #[serde(default)]
    pub owns: Vec<String>,                  // existing field name
    #[serde(default)]
    pub paths: Vec<String>,                 // alias to "owns" if both set; mission-wide
    #[serde(default)]
    pub forbidden: Vec<String>,
    #[serde(default)]
    pub path_not_match: Vec<String>,
    #[serde(default)]
    pub bash_patterns: BashPatternsRule,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BashPatternsRule {
    #[serde(default)]
    pub extra_allow: Vec<String>,
    #[serde(default)]
    pub extra_deny: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum MissionGateMode {
    #[default]
    Enforce,
    Observe,
    Off,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InterAgentMode { Terse, Verbose }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestBudget {
    pub max_hours: Option<i64>,
    pub max_agents: Option<u32>,
}

// Expansion — used by spawn_mission internally.
#[derive(Debug, Clone)]
pub struct InstanceDescriptor {
    pub role_id: String,
    pub agent_id: String,                   // role_id, or role_id-<suffix>
    pub instance_suffix: Option<String>,
    pub task: String,
    pub scope: EffectiveScope,              // mission ∪ agent ∪ instance
    pub model: Option<String>,
    pub prompt_addendum: Option<String>,
}

impl MissionManifest {
    pub fn expand(&self) -> Vec<InstanceDescriptor> { /* ... */ }
}
```

### 3.4 Backward compat at the type level

`MissionManifest.roles` (the existing `Vec<ManifestRole>`) and `MissionManifest.agents` (new) — keep both, with a **manual `Deserialize` impl** that:

1. Tries `agents:` first (v1 shape).
2. Falls back to `roles:` (legacy) and translates each `ManifestRole { name, scope, task }` to `ManifestAgent { role: name, count: 1, instances: [], task, scope, model: None }`.
3. Refuses both being set with a clear error.

This means every existing manifest under `config/missions/*.yaml` still loads. Tests in `mission_manifest.rs::tests` keep passing.

### 3.5 Where `mission_spawn` consumes it

`selector::spawn_mission(...)` already takes `manifest: Option<&MissionManifest>` (line 1393). The internal flow becomes:

1. If `manifest.is_some()` → call `manifest.expand()` and **bypass** pattern-driven role assignment for the squad list. Use the pattern only for prompt scaffolding (topology hints, communication style).
2. If `manifest.is_none()` → keep current behaviour (text + optional `pattern_id`). For the MCP path, synthesise a minimal manifest:
   ```rust
   let synth = MissionManifest::synthesise(&mission_text, pattern_id, defaults)?;
   spawn_mission(..., Some(&synth), ...)
   ```

This collapses two code paths into one canonical one and preserves zero-line behavioural changes for existing API callers.

### 3.6 MCP surface

```rust
// colmena-mcp/src/main.rs

#[derive(Debug, Deserialize, JsonSchema)]
struct MissionSpawnInput {
    /// Either a free-form mission description (legacy) OR a manifest payload.
    mission: Option<String>,
    pattern_id: Option<String>,
    /// New: inline manifest YAML (or JSON via serde_yml — same parser).
    manifest_yaml: Option<String>,
    /// New: path to a manifest file (read by the host process; subject to firewall path rules).
    manifest_path: Option<String>,
}
```

Rule: at least one of `mission` / `manifest_yaml` / `manifest_path` must be set. Yaml-first, path-second, text-last (pure backwards compat).

## 4. Agnosticidad — three concrete examples

### 4.1 BBP wave (the original use case)

```yaml
version: 1
mission_id: bbp-coinbase-wave-2
description: "Coinbase wallet primitives audit; chain or kill 9 candidates."
pattern: bbp-impact-chain
mission_ttl_hours: 8
agents:
  - role: bbp_pentester_web
    count: 3
    instances:
      - suffix: coop
        prompt_addendum: "Focus on COOP/COEP/CORP primitives only."
      - suffix: bidi
        prompt_addendum: "Focus on bidirectional handshake primitives."
      - suffix: poc
        prompt_addendum: "Validate PoC chain candidates."
  - role: bbp_pentester_api
    count: 1
  - role: weaponizer
    count: 1
  - role: auditor
    count: 1
scope:
  paths:
    - /home/fr33m4n/bugbounty/CoinBase
    - ${MISSION_DIR}
  bash_patterns:
    extra_allow: ['^curl.*coinbase\.com', '^cast call .* --rpc-url']
auditor_pool: ["auditor"]
mission_gate: enforce
metadata:
  target_program: coinbase
  prior_report: 3706175
tags: [bbp, web, web3]
```

### 4.2 Colmena self-dev (refactor)

```yaml
version: 1
mission_id: m7-15-mission-manifest
description: "Implement M7.15 manifest type, MCP exposure, expand() logic."
pattern: peer
mission_ttl_hours: 8
agents:
  - role: developer
    count: 2
    instances: [core-types, mcp-surface]
    scope:
      owns:
        - colmena-core/src/mission_manifest.rs
        - colmena-mcp/src/main.rs
        - colmena-cli/src/main.rs
  - role: code_reviewer
    count: 1
  - role: auditor
    count: 1
scope:
  paths:
    - /home/fr33m4n/colmena
  path_not_match: ["*.env", "*credentials*", "trust-firewall.yaml"]
auditor_pool: ["auditor"]
mission_gate: enforce
acceptance_criteria:
  - "cargo test --workspace passes"
  - "cargo clippy -- -D warnings clean"
  - "docs/dev/internals.md updated"
tags: [colmena, dev, refactor]
```

### 4.3 Incident response (ops)

```yaml
version: 1
mission_id: incident-2026-0501-api-latency
description: "p95 spike on /v1/checkout, root-cause + mitigate."
pattern: incident-response  # would need scaffolding; falls through to auto-create
mission_ttl_hours: 4        # tighter — this is a fire
agents:
  - role: sre
    count: 2
    instances: [primary, secondary]
  - role: devops_engineer
    count: 1
  - role: auditor
    count: 1
scope:
  paths:
    - ${MISSION_DIR}
    - /var/log/k8s
  bash_patterns:
    extra_allow: ['^kubectl get|describe|logs', '^helm status', '^aws logs (filter|tail)']
    extra_deny: ['^kubectl delete', '^aws.*delete']
auditor_pool: ["auditor"]
mission_gate: enforce
acceptance_criteria:
  - "Root cause documented"
  - "Mitigation deployed"
  - "Post-mortem draft committed"
metadata:
  incident_id: INC-2026-0501
  pagerduty_alert: PD-AB12
tags: [ops, incident, sre]
```

### 4.4 Test of agnosticidad

| Field | BBP | Self-dev | Incident |
|---|---|---|---|
| `pattern` | `bbp-impact-chain` (private) | `peer` (public) | `incident-response` (auto-created) |
| `agents[].role` | `bbp_pentester_*` | `developer` | `sre`, `devops_engineer` |
| `scope.bash_patterns.extra_allow` | `curl.*coinbase` | (none) | `kubectl|helm|aws` |
| `metadata` | `target_program` | (none) | `incident_id`, `pagerduty_alert` |
| `acceptance_criteria` | (omitted, doc-only) | `cargo test`, `clippy` | "Root cause documented" |

No field is hardcoded to a domain. The only domain-specific knowledge lives in:
- `metadata.*` — opaque key/values.
- `scope.bash_patterns.extra_allow` — domain regex.
- `tags[]` — for analytics.

Pass.

## 5. Backward compatibility recommendation

**Keep `mission_spawn(text, pattern_id)` as the documented MCP entry**; route both signatures through the new manifest path internally. Reasoning:

- 4 validated power users + the dogfood corpus + every example in `docs/user/getting-started.md` rely on the text form.
- The MCP tool is consumed by Claude Code, not just humans; an LLM that writes `mission_spawn(text="...")` should keep working.
- Internally, replace the two-path branch in `spawn_mission()` with a single manifest-driven path.

Concrete recommendation:

1. Extend `MissionSpawnInput` with optional `manifest_yaml` / `manifest_path`.
2. Inside the MCP handler:
   - If manifest provided, parse and use it.
   - Else, synthesise a manifest from `mission_text`, optional `pattern_id`, library defaults.
3. Both paths feed the same `selector::spawn_mission(... Some(&manifest) ...)`.
4. CLI `colmena mission spawn --from <file>` keeps working unchanged (it already takes a manifest).
5. Add `colmena mission spawn --inline` for piped manifests; useful for CI.

## 6. Validation rules

Hard rules (`validate()` returns `Err`):

1. `mission_id` non-empty, ASCII slug `[a-z0-9-]+`, ≤ 64 chars.
2. `description` non-empty when `version >= 1` and `agents.len() >= 2`.
3. `mission_ttl_hours` in `(0, MAX_TTL_HOURS]` (24).
4. `agents.len() >= 1`; if `>= 2`, exactly one role has `role_type: auditor` and that role has `count == 1`.
5. Every `agents[].role` exists in the merged library (public ∪ private).
6. `agents[].count >= 1`. If `instances` set, `instances.len() == count`.
7. Instance suffixes are unique within an agent and slug-safe (`[a-z0-9-]+`).
8. Total instances ≤ `budget.max_agents` (when budget set).
9. `scope.paths` non-empty when any `agents[].role` has tools_allowed including `Read|Write|Edit|Glob|Grep|Bash`.
10. Every regex in `scope.bash_patterns.extra_allow|extra_deny` compiles.
11. `auditor_pool` is non-empty; every entry must be a known role id.
12. `mission_gate` ∈ {`enforce`, `observe`, `off`}.
13. `pattern`, when set and not the literal `"custom"`, must exist in the library OR auto-create logic accepts it. **Soft-fail** to auto-create on missing pattern, with a warning, never a hard error (matches today's behaviour).
14. No `${HOME}`, `${USER}`, raw `$(…)`, backticks, or `..` traversal in any path field. Reuse `library::normalize_path` + `starts_with(library_canonical)` symmetric checks.
15. `acceptance_criteria` items each ≤ 200 chars (cosmetic guard against runaway prompts).

Soft rules (warnings, not errors):

- `budget.max_hours < mission_ttl_hours`: warn, take min.
- `mission_gate: off` with `auditor_pool` set: warn, gate is off so review is voluntary.
- `metadata` keys not in `^[a-z][a-z0-9_]*$`: warn.

## 7. Migration path

### 7.1 `colmena mission init`

```bash
colmena mission init <mission-id> [--from-text "<description>"]
                                  [--pattern <pattern_id>]
                                  [--role <role_id>...]
                                  [--output <path>]
```

Generates a manifest skeleton at `config/missions/<mission-id>.yaml` (or stdout with `-o -`):

```yaml
version: 1
mission_id: <mission-id>
description: "<from-text or stub>"
pattern: <pattern_id or "TODO: choose a pattern; see colmena library list>"
mission_ttl_hours: 8
agents:
  - role: <role_id>      # one entry per --role
    count: 1
  - role: auditor        # always added — invariant
    count: 1
scope:
  paths:
    - ${MISSION_DIR}
mission_gate: enforce
auditor_pool: ["auditor"]
tags: []
```

If `--from-text` was passed and the user didn't pre-list `--role`s, run the existing `select_patterns` + `map_topology_roles` + `detect_role_gaps` pipeline to **suggest** roles (commented out lines, user uncomments). Read-only by default; only writes the file when explicit path is given.

### 7.2 Migrating an ad-hoc `mission_spawn(text, pattern_id)` call

```bash
# 1. Generate manifest from the same text Coco would have used
colmena mission init bbp-followup --from-text "...wave 2 audit..." \
        --pattern bbp-impact-chain \
        --role bbp_pentester_web --role weaponizer \
        --output config/missions/bbp-followup.yaml

# 2. Hand-edit count/instances/scope as needed
$EDITOR config/missions/bbp-followup.yaml

# 3. Run
colmena mission spawn --from config/missions/bbp-followup.yaml
```

### 7.3 `colmena mission validate <file>`

Pure read-only validator (`MissionManifest::from_path` + `validate()`), prints all errors and warnings, exits 0 only when clean. Mandatory CLI tool for the dogfood loop. Required for `colmena doctor` integration in M7.16.

### 7.4 Discovery

Existing missions at `config/missions/<date>-<slug>/` already write a `mission.yaml` (see `selector.rs:393-407`) that is a *summary*, not a manifest. Two options:

- **Option A (preferred)**: extend `selector::generate_mission` to also emit a `manifest.yaml` (the canonical input that produced the mission). Bidirectional — operators can read what was spawned and re-spawn from it.
- **Option B**: add `colmena mission export <id>` that reverse-engineers a manifest from the existing mission directory + delegations. Useful for missions created before M7.15.

I recommend doing both, A as part of M7.15 MVP (cheap), B as M7.15.1 (deferred).

## 8. Acceptance criteria — recommendation

**Doc-only in v1. Machine-checked in v2 (M7.16).**

Reasoning (cost/benefit):

- **Doc-only cost**: ~0h. Just append a section to each agent's CLAUDE.md saying "your mission accepts only when these are true" and let the auditor enforce in `review_evaluate`.
- **Doc-only benefit**: agents and the auditor know the bar; reviews can cite criteria; humans can audit.
- **Machine-checked cost**: 8–14h to design the gate, the criteria DSL (regex? command exit code? file-presence check?), the integration with `SubagentStop`, the failure modes (criterion fails → mission stays open → who can override?). It's an entire feature.
- **Machine-checked benefit**: prevents the mission from "closing" prematurely. But humans review missions on `/exit` and via `colmena stats` anyway.

So: ship doc-only in v1, ensure the format is forward-compatible. A criterion is a `String` today; in v2 it becomes a tagged enum:

```rust
// v2 (M7.16)
pub enum AcceptanceCriterion {
    Doc(String),                                  // current — passes if marked done by auditor
    BashSucceeds { cmd: String, timeout_secs: u32 },
    FileExists(String),
    ReviewsAllPositive { min_score: u32 },        // every review_evaluate ≥ N
    FindingsCountBelow { severity: String, max: u32 },
}
```

The serde representation can use `serde(untagged)` so a v1 `String` deserialises as `Doc(string)` automatically. Forward-compat secured.

## 9. Hard blockers — feature dependencies

### 9.1 Hard blockers (must fix in or before M7.15)

| Bug | Fix scope | Why blocker |
|---|---|---|
| **M7.3 `description` omission in subagent files** (`project_mission_spawn_missing_description.md`) | ~2h. Inject `description: <Role.description>` in `emitters::claude_code::write_subagent_file`. | Without this, multi-instance agent files at `~/.claude/agents/<role>-<suffix>.md` will **silently fail to load in CC**. Multi-instance is the headline feature — it must work first try. |
| **M7.3 scope gap (`path_within: [${MISSION_DIR}]`)** (`project_mission_spawn_scope_gap.md`) | ~3h. Wire `scope.paths` from manifest into `generate_role_delegations`. | The whole point of the manifest is that the operator declares paths. The current code hard-codes `${MISSION_DIR}` as the only `path_within`. Manifest-declared `scope.paths` must replace it. |
| **M7.3.1 anti-reciprocal cross-mission filter** (`project_review_reciprocal_cross_mission_bug.md`) | ~3h. Scope filter to `existing.mission == current.mission`; normalise to role pair. | Multi-instance + 8h missions = multiple `review_submit` cycles. Pre-fix, second wave breaks. |
| **Auditor invariant generalisation to multi-instance** | ~2h. Modify `selector.rs:322-345` to "exactly one role with `role_type: auditor`, `count == 1`". | Manifest cannot proceed without this — multi-instance auditor is a footgun. |

Total hard blocker work: **8–10h**, possibly parallelisable into one squad.

### 9.2 Soft blockers (workarounds exist; can ship M7.15 without)

| Bug | Workaround | Recommendation |
|---|---|---|
| `library_select` destructive on EOF (`project_library_select_destructive_default.md`) | Use `colmena library show` + `colmena suggest` for read-only. | Ship M7.15 without; fix in M7.4. |
| `colmena suggest` agent count inflation (`project_suggest_agent_count_inflation.md`) | Manual `--max-agents`. | Ship M7.15 without. |
| Queue lifecycle bug | Cosmetic. | Out of scope. |
| `delegate add` lacking condition flags | Manifest replaces this entirely. | M7.15 will obsolete the gap. |

### 9.3 Companion (must ship together for solid foundations — see `feedback_solid_foundations.md`)

- `colmena mission init` (§7.1).
- `colmena mission validate` (§7.3).
- MCP exposure (§3.6).

Skipping any of the three creates a partial feature that requires CLI gymnastics to actually use. Ship them together.

## 10. Estimated hours — refined

The brief proposed 22–30h MVP + 10h blockers. Let me break it down.

### 10.1 Hard blockers (parallelisable squad)

| Task | Hours |
|---|---|
| M7.3 `description` injection + tests | 2 |
| M7.3 scope gap (manifest-driven `path_within`) | 3 |
| M7.3.1 anti-reciprocal per-mission + role-pair normalisation | 3 |
| Auditor invariant generalisation | 2 |
| **Subtotal** | **10** |

### 10.2 M7.15 MVP (manifest core)

| Task | Hours |
|---|---|
| Extend `MissionManifest` struct + serde back-compat (`roles` ↔ `agents` translation) | 3 |
| `expand()` → `Vec<InstanceDescriptor>` + tests for each variant (count=1, count=N, instances list) | 3 |
| `validate()` v1 (15 hard rules + soft warnings) | 3 |
| Refactor `selector::spawn_mission` to consume `InstanceDescriptor` instead of `RoleAssignment` directly | 4 |
| Refactor `selector::generate_mission` for instance-aware delegations + subagent file paths | 3 |
| Wire `scope.bash_patterns.extra_allow|extra_deny` into delegation generation | 2 |
| MCP `mission_spawn` exposure (`manifest_yaml`/`manifest_path` fields, parsing, error mapping) | 2 |
| `colmena mission init` CLI | 3 |
| `colmena mission validate` CLI | 1 |
| Manifest export — write `manifest.yaml` alongside `mission.yaml` (Option A above) | 2 |
| Tests: 3 manifest examples (BBP, self-dev, incident) parse + validate + dry-run spawn cleanly | 3 |
| Docs: update `CLAUDE.md` §"Missions & Agent Identity", `docs/user/getting-started.md`, add `docs/dev/mission-manifest.md` | 3 |
| **Subtotal** | **32** |

### 10.3 Total

| Bucket | Hours |
|---|---|
| Hard blockers | 10 |
| M7.15 MVP (manifest core) | 32 |
| **Total** | **42** |

If the operator wants **doc-only acceptance criteria** included (§8), add 2h for prompt section + auditor instruction wording. **44h total**.

If `acceptance_criteria` machine-checking ships in v1 (against my recommendation), add 8–14h. **52–58h.**

### 10.4 Optimistic vs realistic

The brief's 22–30h MVP is achievable only if:
- Multi-instance is dropped (-8h on `expand()` + delegation refactor).
- `mission init` is dropped (-3h).
- Manifest export is dropped (-2h).
- We accept that subagent files for instances may not load (M7.3 fix deferred → -2h, but the feature is broken on day 1).

That gets us to ~24h, but at the cost of shipping a manifest type that **only the CLI can use, only with single-instance agents, and that operators cannot bootstrap without hand-writing YAML**. That's a half-feature.

Recommended path: **42h with the foundations** (manifest + multi-instance + init + validate + MCP), **44h with doc-only acceptance**, defer machine-checked acceptance to M7.16.

## 11. Open questions / contradictions

### 11.1 Existing `MissionManifest.roles` vs proposed `agents`

The current type uses `roles: Vec<ManifestRole>`. Coco said *"Pense que ya estaba esto"* — partially right. The CLI `mission spawn --from` works today, but it is so minimal (no count, no scope.paths, no scope.bash_patterns, no mission_gate, no metadata) that it cannot solve the BBP friction. The rename `roles → agents` is justified because:

- "Roles" is the library taxonomy (`Role.id`).
- "Agents" is what's spawned (instance descriptors).

A manifest that lists *agents* maps to runtime state; a manifest that lists *roles* maps to library taxonomy. The new shape is closer to the runtime concept.

**Open question:** is `roles → agents` rename worth the back-compat dance? **My answer: yes**, because (a) the alternative is keeping a confusing field name, (b) only a handful of manifests exist (the dogfood ones), and (c) the deserialiser handles both for one milestone, then `roles:` gets a deprecation warning, then drops in M7.17.

### 11.2 `mission_gate: enforce` vs firewall config

Today, `enforce_missions` lives in `trust-firewall.yaml` as a session-wide flag. The manifest field would override it for the duration of this mission's session. **Question for SRE/Security**: is per-mission override sound, or should the firewall config remain the single source of truth?

My recommendation: the manifest sets `enforce_missions: true` for the **lifetime of the mission's delegations**, never lower than the firewall config. (You can manifest your way *into* enforcement, never *out of* it.) This matches the "human authority > ELO" precedence rule.

### 11.3 Pattern auto-creation when manifest declares unknown pattern

`spawn_mission` currently auto-creates a pattern when none matches the keyword score. With a manifest, the user explicitly named a pattern. If it doesn't exist:

- **Strict**: fail validation, force `colmena library create-pattern` first.
- **Lenient (current behaviour)**: auto-create scaffold, warn loudly.

Recommendation: **strict by default, `--allow-auto-create` flag on `mission spawn` to opt in**. Manifests are declarative; silent auto-creation surprises operators.

### 11.4 Per-instance ELO

We chose per-role (§2.3). Question for Security Architect: does this affect calibration? My read: no, because ELO categories already span sub-skills within a role. Multi-instance just means more events per role per unit time, which the temporal decay already handles.

### 11.5 `instances` as `Vec<String>` vs `Vec<InstanceSpec>`

The brief shows `instances: [squad-a, squad-b, squad-c]` (plain strings). My proposal allows both via `serde(untagged)`. **Open question**: do we ship the prompt-addendum form in v1 or defer? My recommendation: **ship in v1**, because BBP wave-2 already needs different focus per instance (COOP vs bidi vs PoC), and the friction Coco reported was exactly this — three same-prompt instances all running the same plan.

### 11.6 Does `pattern` carry semantic meaning when `agents[]` is explicit?

Today `Pattern.topology_slots` drives role assignment. With manifest's explicit `agents[]`, the topology-driven mapping is bypassed (see `selector.rs:1520-1542`, already implemented). What `pattern` still controls:

- `pattern.workspace_scope: repo-wide` — overrides path scoping.
- `pattern.communication` — affects prompt scaffolding.
- `pattern.elo_lead_selection` — defunct under centralised auditor invariant.

Recommendation: **keep `pattern` optional**; when set, drive only prompt scaffolding (tone, communication style, workspace_scope). When unset, fall back to a synthesised "custom" pattern with sensible defaults. Avoid the "pattern is required for a manifest" footgun.

## 12. Recommendation summary

1. **Yes, ship M7.15.** The friction Coco hit on 2026-05-01 is real, and the manifest type already exists in nascent form — finishing it is leverage.
2. **Shape**: extend `MissionManifest` in place (`agents[]`, `scope`, `mission_gate`, `auditor_pool`, `inter_agent_protocol`, `acceptance_criteria` doc-only, `budget`, `metadata`, `tags`, `version`). Keep back-compat via dual deserialisation of `roles:` ↔ `agents:`.
3. **Multi-instance**: `agents[].count` and `agents[].instances`. Expand to `InstanceDescriptor` at runtime; ELO accumulates per-role; `agent_id` carries `<role>-<suffix>` for unique delegations and unique subagent files.
4. **Auditor invariant**: exactly one role with `role_type: auditor`, `count == 1`. Reject multi-auditor manifests at validation time.
5. **Backward compat**: synthesise a manifest from `mission_spawn(text, pattern_id)` calls; route both paths through the same `selector::spawn_mission`.
6. **Companion features (must ship together)**: `colmena mission init`, `colmena mission validate`, MCP `manifest_yaml`/`manifest_path` inputs, manifest export alongside `mission.yaml`.
7. **Acceptance criteria**: doc-only in v1, machine-checked in M7.16. Forward-compatible serde.
8. **Hard blockers (10h)**: M7.3 `description` omission, M7.3 scope gap, M7.3.1 anti-reciprocal, auditor invariant. All four must land before or with M7.15.
9. **Total estimate**: 42h (44h with doc-only criteria). The brief's 22–30h is achievable only if multi-instance, mission init, and manifest export are dropped — which would ship a half-feature.
10. **Domain agnosticidad**: passes the three-domain test (BBP, self-dev, incident) without any field carrying domain-specific semantics. Domain colour lives in `metadata`, `tags`, and `scope.bash_patterns` regex.

End of SW-ARCHITECT.md.
