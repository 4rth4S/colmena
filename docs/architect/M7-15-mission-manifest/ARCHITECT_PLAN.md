# M7.15 Mission Manifest — Unified Architect Plan

**Synthesizer:** Orchestrator (Claude Opus 4.7), 2026-05-01
**Source reviews:** `SW-ARCHITECT.md` (793 líneas, lens: data model + integration), `SECURITY-ARCHITECT.md` (676 líneas, lens: STRIDE + invariants), `SRE.md` (631 líneas, lens: failure modes + ergonomics)
**Status:** Design ready — pending operator review + scope decision before implementation kickoff
**Audience:** Coco (operator) + future Colmena Developer agent

---

## TL;DR — what this plan delivers

1. **M7.15 is mostly extension, not greenfield.** `colmena-core/src/mission_manifest.rs` already defines a primitive `MissionManifest`; `colmena mission spawn --from <file>` is wired in CLI. M7.15 = (a) extend the type, (b) expose it through MCP for *preview only*, (c) add the ops surface (`mission init`, `mission status`, `mission abort`), (d) close known M7.3 dogfood blockers, (e) add security invariants for the new trust boundary.
2. **Three hard blockers must land first or in parallel** — fixed order doesn't matter, but M7.15 ships fragile without all three:
   - **M7.3.1 anti-reciprocal cross-mission fix** (Security flags as critical: manifest swarms with `auditor_pool: ["auditor"]` silently break ELO without it).
   - **M7.3 `description` omission in auto-gen subagent files** (CC silently omits agents → ELO cycle broken end-to-end).
   - **M7.3 scope gap** (workers can't reach external paths like `/home/<user>/bugbounty/CoinBase` declared in manifest).
3. **Acceptance criteria is doc-only in v1.** Mechanizing it requires a sandboxed checker (write-protected workspace + signed completion), and that's M7.16 work. v1 surfaces criteria in agent prompts + auditor verbal enforcement.
4. **`mission_spawn --manifest` is CLI-only, not MCP-callable.** MCP exposes `mission_manifest_show` as read-only preview returning the CLI command to apply (same pattern as `delegate` MCP today). Otherwise an agent with Write tool can self-spawn elevated swarms.
5. **Manifest-injected `agent_overrides` go in a NEW file** `runtime-agent-overrides.json` (separate from version-controlled `trust-firewall.yaml`). Auto-removed by `mission deactivate`. Otherwise scope leaks past mission lifecycle.
6. **Realistic timeline: 50-65h total focused work** (1.5-2 weeks calendar with dogfood):
   - 8-12h blocker fixes (M7.3 desc + scope + M7.3.1 anti-reciprocal)
   - 28-36h MVP manifest work (extend struct, multi-instance, validation, MCP preview, security controls, basic ops surface)
   - 6-10h ergonomics surface (`mission init`, `mission status`, `mission abort`, error messages, dry-run output, examples)
   - 8-12h dogfood + edge case fixes (always underestimated)
7. **Honest friction-reduction estimate: ~20%, NOT 50%.** SRE called this out — the BBP wave-2 reduction comes from hygiene + reproducibility + auto-permissions, not raw spawn speed. If we sell M7.15 as "50% faster", it fails its own smoke test.

---

## 1. Unified manifest shape (v1)

Resolves SW shape (canonical YAML) + Security invariants (caps + rejections) + SRE ergonomics (init template, validation feedback). Single source of truth for the implementation.

```yaml
# mission-manifest.yaml — schema version 1
version: 1                                    # required, parser discriminator
mission_id: bbp-followup-3706175              # required, ASCII slug, unique
description: "Practical exploitation chain hunt for H1 #3706175"
                                              # required, free-form, max 512 chars
author: coco                                  # required, free-text provenance (logged)

pattern: bbp-impact-chain                     # OPTIONAL — library hint or "custom"
mission_ttl_hours: 8                          # optional, default 8, max 24

# Squad — agents drive role assignment + instance fan-out.
agents:
  - role: bbp_pentester_web                   # required, must exist in library
    count: 3                                  # optional, default 1, max 5 per role
    instances:                                # optional; required for count>1 (Security: explicit names)
      - squad-a
      - squad-b
      - squad-c
    task: "Verify popup hijack PoC..."        # optional, free-form per-role brief
    scope:                                    # optional, role-instance scope override
      owns: [findings/squad-a/]
      forbidden: [.env]
    model: claude-opus-4-7                    # optional, overrides Role.model

  - role: weaponizer
    count: 1
  - role: auditor
    count: 1                                  # MUST be 1 — invariant rejection if >1

# Mission-wide scope (defaults for all agents unless agent.scope overrides).
scope:
  paths:                                      # required if any tool reads/writes
    - /home/coco/bugbounty/CoinBase           # absolute, canonicalized at apply
    - ${MISSION_DIR}                          # always implicitly added
  path_not_match:                             # optional; merged with hardcoded list
    - "*.env"
    - "cdp_keys*"
  bash_patterns:                              # optional
    extra_allow:
      - '^curl -[a-zA-Z]+ https://[A-Za-z0-9.-]+\.(coinbase\.com|base\.app)\b[^&;|`$()]*$'
      # Security mandate: must have ^ anchor; must NOT match chain operators;
      # validator rejects greedy patterns like '^curl.*coinbase\.com'.
    extra_deny:
      - '^rm -rf'

# Governance.
mission_gate: enforce                         # enforce | observe | off (default: enforce)
auditor_pool: ["auditor"]                     # default ["auditor"] (centralized invariant)
                                              # broader pool requires CLI flag --allow-broad-auditor-pool
inter_agent_protocol: terse                   # terse | verbose (default terse if agents>=2)

# Limits (caps hardcoded in core, manifest CANNOT raise).
budget:
  max_hours: 8                                # ≤ mission_ttl_hours, ≤ 24
  max_agents: 12                              # ≤ 25 sum across all instances

# Doc-only in v1 (M7.15). Surfaced in prompts + review template, NOT machine-checked.
acceptance_criteria:
  - "PoC chain reproducible from clean browser"
  - "All findings have severity tier with CVSS"

# Free-form metadata. Never gates decisions; surfaces in audit + prompts.
metadata:
  target_program: coinbase-bbp
  ticket: H1-3706175
tags: [bbp, web, coinbase]
```

### 1.1 Field-by-field convergence resolution

| Field | SW says | Security says | SRE says | **Resolution** |
|---|---|---|---|---|
| `version` | ADD | ADD discriminator | ADD | **ADD, required, integer 1** |
| `goal` vs `description` | rename to `description` | secrets-scan max 512 chars | descriptive | **`description` required, max 512** |
| `author` | not addressed | required for provenance | optional | **REQUIRED — Security wins (audit trail)** |
| `pattern` | optional | not addressed | optional | **OPTIONAL** |
| `agents[].count` | semantic clarification | ≤5/role, ≤25 total | needed for BBP | **CAP: ≤5/role, ≤25 sum** |
| `agents[].instances` | optional, can auto-gen `s1..sN` | mandatory if count>1, namespace `<mission_id>__<suffix>` | named is clearer | **Mandatory if count>1; agent_id = `<mission_id>__<role>-<suffix>` for global uniqueness; review.rs strips namespace for ELO bucketing per role** |
| `scope.paths` | required if tools read/write | absolute only, canonicalized, hardcoded blocklist | clear | **REQUIRED, absolute, canonicalized; hardcoded never-allow list (§2 invariants)** |
| `scope.hosts` (top-level) | DROP | hint only, NOT network firewall, no CIDR, no localhost | drop | **DROP top-level; if needed, surface as `metadata.target_hosts` documentation; bash_pattern generation explicit, not host-driven** |
| `scope.bash_patterns.extra_allow` | additive | layered validation: anchor required, no catch-all, chain-greedy rejection | clear | **Strict validator (§2)** |
| `scope.bash_patterns.extra_deny` | ADD | symmetric | useful | **ADD** |
| `scope.path_not_match` | ADD | merged with hardcoded | useful | **ADD** |
| `acceptance_criteria` | doc-only v1 | doc-only v1, mechanize M7.16 with sandboxing | doc-only v1 | **Doc-only v1; surface in prompts + review template** |
| `mission_gate` | enforce/observe/off | manifest can RAISE never LOWER | clear | **Manifest can RAISE the gate level beyond config; never bypass `enforce_missions: true` from operator** |
| `auditor_pool` | default `["auditor"]` | broader requires CLI ack | clear | **Default `["auditor"]`; broader pools require `--allow-broad-auditor-pool` CLI flag** |
| `inter_agent_protocol` | terse/verbose | not addressed | not addressed | **terse if agents>=2, verbose otherwise; default keeps current behaviour** |
| `budget.max_hours` | ≤24 | ≤24 | soft warn 80%, hard at 100% | **≤24; soft warn at 80% via alerts.json; hard cap NOT enforced in v1 (deferred to M7.15.1)** |
| `budget.max_agents` | sum check | hardcoded ≤25 | cheap to enforce | **HARDCODED ≤25; enforced at apply time** |
| `metadata` | free-form | not security-relevant | not addressed | **ADD as `HashMap<String,String>`** |
| `tags` | free-form | not security-relevant | useful for analytics | **ADD as `Vec<String>`** |

### 1.2 Three agnostic example manifests (proof of cross-domain shape)

To validate Coco's concern that the shape works beyond pentest:

**Pentest (BBP):** above example.

**Dev refactor (Colmena self-dev):**
```yaml
version: 1
mission_id: m7-15-impl
description: "Implement M7.15 Mission Manifest end-to-end"
author: coco
pattern: colmena-self-dev
mission_ttl_hours: 16
agents:
  - { role: colmena_architect, count: 1 }
  - { role: colmena_developer, count: 2, instances: [core, cli] }
  - { role: colmena_code_reviewer, count: 1 }
  - { role: auditor, count: 1 }
scope:
  paths: [/home/coco/colmena, ${MISSION_DIR}]
  bash_patterns:
    extra_allow: ['^cargo (build|test|clippy|fmt)\b']
mission_gate: enforce
auditor_pool: ["auditor"]
metadata: { milestone: M7.15 }
tags: [dev, rust, colmena-self]
```

**Incident response (SRE ops):**
```yaml
version: 1
mission_id: inc-2026-0501-prod-latency
description: "Investigate p99 latency spike on api gateway prod"
author: sre-oncall
pattern: incident-response       # if exists in library; else custom
mission_ttl_hours: 4
agents:
  - { role: sre, count: 1 }
  - { role: software_engineer, count: 1 }
  - { role: auditor, count: 1 }
scope:
  paths: [/home/coco/incident-2026-0501, ${MISSION_DIR}]
  bash_patterns:
    extra_allow:
      - '^kubectl (get|describe|logs|top) '
      - '^curl https://(grafana|prometheus)\.internal\b'
mission_gate: enforce
metadata:
  ticket: INC-2026-0501
  pager_id: PD-12345
tags: [incident, prod]
```

The schema accepts all three with no domain-specific top-level fields. Domain colour lives in `metadata`, `tags`, and `bash_patterns.extra_allow` regex content. **Agnosticidad verificada.**

---

## 2. Security invariants (hardcoded, manifest cannot override)

From `SECURITY-ARCHITECT.md` §12. These are the floor — no manifest can lower them.

### 2.1 Files always blocked (Bash + Write/Edit)

`audit.log`, `colmena-errors.log`, `runtime-delegations.json`, `trust-firewall.yaml`, `filter-config.yaml`, `filter-stats.jsonl`, `elo-overrides.json`, `revoked-missions.json`, `alerts.json`, `reviews/`, `findings/` (existing protections from CLAUDE.md §"Config & Data"), plus new: `*.manifest.yaml`, `manifest.snapshot.yaml`, `manifest.sha256`, `runtime-agent-overrides.json` (the new file from §3).

### 2.2 Paths never reachable

Hardcoded prefix blocklist after `Path::canonicalize`:
- `/etc`, `/root`, `/var/log`, `/proc`, `/sys`, `/boot`, `/dev`
- `/home/<user>/.ssh`, `/home/<user>/.aws`, `/home/<user>/.config/gcloud`, `/home/<user>/.config/op`, `/home/<user>/.gnupg`, `/home/<user>/.kube`
- `/Users/<user>/Library/Keychains` (macOS)
- Any path containing `..` after canonicalize (defense in depth)

### 2.3 Hosts never reachable (via bash_pattern generation)

`169.254.169.254`, `127.0.0.1`, `localhost`, `0.0.0.0`, RFC1918 ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), `metadata.google.internal`. Operator can opt-in to loopback only via `--allow-loopback` CLI flag (single-host mission only).

### 2.4 Bash patterns always blocked

Extends current `blocked` tier in firewall: `rm -rf /`, `dd if=/dev/`, `mkfs.`, `:(){ :|:& };:`, `wget http(s)?://.*-O /tmp/.*sh`, `chmod 777 /`, `chmod -R 777`, `chown -R root`. Plus regex pre-flight: any `extra_allow` regex matched against these sentinel strings → manifest rejected.

### 2.5 Manifest fields never honored

`role_type`, `default_trust_level` overrides, `disable_audit_log`, `disable_blocked_tier`, `bypass_session_gate`. Parser rejects with explicit error.

### 2.6 Caps hardcoded

- `agents[].count ≤ 5` per role
- `sum(agents[].count) ≤ 25` total
- `mission_ttl_hours ≤ 24`
- `scope.paths ≤ 32` entries, each ≤ 256 chars
- `scope.bash_patterns.extra_allow ≤ 20` regexes total, each ≤ 256 chars
- `scope.bash_patterns.extra_deny ≤ 50` regexes total
- `acceptance_criteria ≤ 10` items, each ≤ 200 chars
- `description` ≤ 512 chars
- Manifest YAML file ≤ 64KB
- Subprocess pre-flight regex compile under `regex::RegexBuilder::size_limit(100_000)` and `dfa_size_limit(1_000_000)`

### 2.7 Bash regex extra_allow validator (P0)

For each entry `R` in `scope.bash_patterns.extra_allow`:
1. Compile under strict size budget. Fail → reject manifest.
2. Must start with `^`. Otherwise reject (forces operator to think about prefix).
3. Must NOT match any sentinel string from §2.4. Otherwise reject.
4. Must NOT match the test string `<R-prefix> && rm -rf /` or `<R-prefix>; cat ~/.aws/credentials`. Chain-greedy detection. If yes, reject as "regex is overly broad — chain operators bypass it".
5. Must NOT be `^.*$`, `^.+$`, `.*`, `.+`, or empty. Catch-all detection.

These rules turn `^curl.*coinbase\.com` (greedy) into `^curl -[a-zA-Z]+ https://[A-Za-z0-9.-]+\.coinbase\.com\b[^&;|\`$()]*$` (anchored, host-bound, chain-safe).

---

## 3. Runtime agent_overrides — separate file from `trust-firewall.yaml`

Critical Security recommendation, SW agreed.

**New file:** `$COLMENA_HOME/config/runtime-agent-overrides.json` — same atomic-write pattern as `runtime-delegations.json`. Schema:

```json
{
  "missions": {
    "bbp-followup-3706175": {
      "applied_at": "2026-05-01T14:23:00Z",
      "manifest_sha256": "abc123...",
      "overrides": {
        "bbp_pentester_web": [
          {
            "tools": ["Bash"],
            "conditions": { "bash_pattern": "^curl ..." },
            "action": "auto-approve",
            "reason": "Manifest bbp-followup-3706175 — curl scoped"
          }
        ]
      }
    }
  }
}
```

**Lifecycle:**
- Written on `mission_spawn --manifest` apply
- Loaded by firewall hook AFTER `config.agent_overrides` (file-based wins on collision — preserves "human authority > manifest" precedence per CLAUDE.md)
- Removed entry on `mission deactivate <id>` — atomic update
- TTL-bound: entries expire when `mission_ttl_hours` elapses (lazy GC on hook invocation)

**Why not `trust-firewall.yaml`:** that file is human-curated, version-controlled, never machine-mutated. Manifest-injected overrides are ephemeral per-mission. Mixing them breaks the audit trail and risks scope leak past mission lifecycle.

---

## 4. Multi-instance agents — `agent_id` namespacing

Resolved between SW and Security:

```rust
pub struct InstanceDescriptor {
    pub role_id: String,                  // ELO bucket — always the role
    pub agent_id: String,                 // namespaced for delegation/Mission Gate uniqueness
    pub instance_suffix: Option<String>,  // None when count==1
    pub task: String,
    pub scope: ManifestScope,
    pub model: Option<String>,
    pub prompt_addendum: Option<String>,
}

// agent_id construction (Security mandate for global uniqueness):
fn build_agent_id(mission_id: &str, role_id: &str, suffix: Option<&str>) -> String {
    match suffix {
        None => role_id.to_string(),                          // count==1 backward-compat
        Some(s) => format!("{mission_id}__{role_id}-{s}"),    // collision-proof across missions
    }
}

// ELO bucket lookup (review.rs):
fn role_for_agent_id(agent_id: &str) -> &str {
    // strip "<mission_id>__" prefix and "-<suffix>" suffix
    // implementation: split on "__" then on "-"
}
```

**Rules:**
- `count: 1`, no `instances` → `agent_id = role_id`. Backward compat.
- `count: N` → `instances` mandatory (Security strict). `agent_id = "<mission_id>__<role_id>-<suffix>"`.
- ELO accumulates per `role_id` (strip namespace). Reviewer diversification (M7.7) operates on roles.
- Subagent files at `~/.claude/agents/<agent_id>.md` with `name:` matching `agent_id` so CC routes correctly. The frontmatter `description` field MUST be present (M7.3 description omission fix is a hard blocker).
- Auditor invariant: `count == 1` exactly. Manifest with auditor `count: 2+` rejected.
- Anti-reciprocal filter normalizes to `(role_role)`, not `(agent_id, agent_id)` — fixes M7.3.1 and unblocks multi-instance review cycles.

---

## 5. CLI surface (P0 ergonomics)

From SRE §1, §3. Without these, M7.15 ships fragile.

### 5.1 `colmena mission init <slug>` (P0)

```bash
colmena mission init bbp-followup-3706175 \
  --pattern bbp-impact-chain \
  --for "Practical exploitation chain hunt for H1 #3706175"
# → writes ./bbp-followup-3706175.mission.yaml
```

Generated template:
- Pre-fills `mission_id: <YYYY-MM-DD>-<slug>` matching `config/missions/` convention
- Resolves `--pattern` against library; pre-fills `agents:` from pattern's `roles_suggested`
- Without `--pattern`: runs `library_select` against `--for`; pre-fills top match
- Inline-comment every field with type, default, examples, library link
- `acceptance_criteria` block commented-out with 2-3 examples per pattern category

### 5.2 `colmena mission validate <file>` (P0)

```bash
colmena mission validate ./bbp-followup-3706175.mission.yaml
# → ✓ Manifest valid
# OR
# → ✗ ERROR line 23:5: Unknown role 'bbp_pentester'
#       Suggestion: did you mean 'bbp_pentester_web' or 'bbp_pentester_api'?
#       Run: colmena library list --kind role --filter bbp
```

`ManifestError` enum with line+col + suggestion + fix command. Reuses `colmena config check` idiom.

### 5.3 `colmena mission spawn --manifest <file>` (P0)

Already exists as `--from <file>`. Rename to `--manifest` for clarity; keep `--from` as alias for backward compat. Add:
- `--dry-run` (already exists; expand output to per-delegation detail with `tool/agent/conditions/expires_at`)
- `--format json` for CI pipelines
- Default behavior: `--dry-run` first, prompt operator to confirm, then apply (interactive). `--apply` flag skips prompt (CI/scripts).

### 5.4 `colmena mission status <id>` (P0)

From SRE §3.1 — replaces 6-command reconstruction with single command:
```
Mission: bbp-followup-3706175
Pattern: bbp-impact-chain  (private library)
Spawned: 2026-05-01 14:23 UTC  (2h17m ago, 5h43m remaining)
Gate:    ON (--session-gate, mission TTL)
Manifest: /home/coco/.../bbp-followup-3706175.mission.yaml (sha256: abc123...)

Agents (4 spawned, 4 active):
  squad-a (bbp_pentester_web)   submitted ✓   reviewed ✓   ELO +12
  squad-b (bbp_pentester_web)   submitted ✓   reviewed ⏳   pending review by auditor
  squad-c (bbp_pentester_web)   running       0 findings yet
  auditor                       active        2 reviews pending

Budget: 4 agents / 12 max  ·  2h17m / 8h budget (28%)
Alerts: 0 unread
```

### 5.5 `colmena mission abort <id>` (P0)

Distinct from `mission deactivate`. `abort` = emergency:
- Revokes all delegations
- Removes manifest-injected `runtime-agent-overrides.json` entries
- Marks pending reviews as `Aborted` state (not `Invalidated`)
- Removes auto-gen `~/.claude/agents/<agent_id>.md` files for this mission
- Logs `MISSION_ABORT` audit event with reason
- Surfaces in `mission list` as `aborted`, not `expired`

`deactivate` is the gentle cleanup post-mission; `abort` is the panic button mid-mission.

### 5.6 `colmena mission init --from-history` (P1)

SRE proposal — adoption ramp for ad-hoc users who already ran missions via `Agent` direct. Reads recent `audit.log` entries for the current session, identifies subagent_type spawn patterns, proposes a manifest skeleton that reproduces the flow. Saves operator from "where do I start" friction.

---

## 6. MCP surface

Resolved Security CLI-only vs SW MCP-exposure tension:

### 6.1 Read-only MCP (P0)

`mcp__colmena__mission_manifest_show <path>` — parses + validates a manifest YAML, returns the structured view + the CLI command to apply. Same pattern as `delegate` MCP today (per CLAUDE.md §"MCP Server: MCP delegate/revoke tools are read-only — return CLI commands for human confirmation, never execute directly").

### 6.2 Read-only MCP for status (P0)

`mcp__colmena__mission_status <id>` — same content as CLI. Allows other agents to query mission state for inter-agent coordination.

### 6.3 NOT exposed via MCP (Security mandate)

- `mission_spawn --manifest` apply (CLI human-invoked only)
- `mission abort` (CLI only — emergency action)
- `mission deactivate` (CLI only — already pattern)
- `mission init` (CLI only — file-creating)

Rationale: any of these MCP-exposed lets a compromised agent self-spawn or self-cleanup elevated swarms.

### 6.4 Rate-limiting

Generative manifest MCPs (`manifest_show` if it parses) get standard 30 calls/min limit. Status MCP: not rate-limited (read-only informational).

---

## 7. Hard blockers — must land before or with M7.15

### 7.1 M7.3.1 anti-reciprocal cross-mission scope fix (~3-5h)

`submit_review` in `review.rs:141-147` filters reviewer candidates against full reviews store (all missions). Per `project_review_reciprocal_cross_mission_bug.md`, this blocks legitimate cross-mission reviewer reuse. Fix: scope filter to `existing.mission == current.mission`. Without this fix, manifest swarms with `auditor_pool: ["auditor"]` silently break ELO after the second mission ever shipped.

### 7.2 M7.3 description omission in auto-gen subagent files (~2-4h)

Per `project_mission_spawn_missing_description.md`. `selector::spawn_mission` writes `~/.claude/agents/<role_id>.md` without `description:` frontmatter → CC silently omits the agent → ELO cycle never closes. Fix: emit `description: <role.description from library>` in frontmatter. Trivial but blocks closure.

### 7.3 M7.3 scope gap (~4-6h)

Per `project_mission_spawn_scope_gap.md`. Workers scoped to `${MISSION_DIR}` cannot reach external paths declared in manifest scope (e.g. `/home/coco/bugbounty/CoinBase`). Fix: `delegate add` accepts `--bash-pattern` and `--path-within` flags; manifest spawn passes these from `scope.paths` and `scope.bash_patterns`. Required for any cross-domain manifest where mission_dir isn't the workspace.

**Total blocker budget: 9-15h.** Cannot ship M7.15 without these or a soft-fallback documented as known limitation.

---

## 8. Out of scope for v1 (deferred)

| Feature | Defer to | Reason |
|---|---|---|
| Acceptance criteria machine-checking | M7.16 | Requires sandboxed checker; theater otherwise |
| `mission resume <id>` | M7.16+ | Abort is final by design; resume needs checkpoint format |
| Webhook alerts | M7.16+ | Stderr/file alerts.json sufficient for v1 |
| `cpu_hours` budget mode | M7.16+ | Wall-clock + agent-count enough |
| `mission cost` real tokens | M7.16+ | Requires CC API integration |
| `failure_tolerance: N-of-M` | M7.16+ | Single-instance fail-and-stop is fine for v1 |
| Crypto-signing manifests | M7.16 | Single-user assumption v1 |
| YAML aliases/anchors support | never | Reject; obfuscates scope review |
| CIDR ranges in scope.hosts | M7.17+ | Too easy to misuse |
| Live reload of manifest | never | Tampering surface; deactivate + re-spawn |
| Reconcile mode (kubectl-style apply) | M7.17+ | v1 contract is "apply additive" |
| Prometheus export | M7.17+ | No daemon mode |
| `mission_spawn --manifest` MCP | never | Security: agent self-spawn risk |

---

## 9. Open questions for operator decision

1. **Auditor pool flexibility.** Default `["auditor"]` enforced; broader pools require `--allow-broad-auditor-pool` CLI flag. Acceptable, or want broader pools always-allowed by manifest-only?
2. **Manifest dir allowlist.** Security recommends manifests must live under `$COLMENA_HOME/missions/manifests/` by default. Coco may prefer `--manifest-dir <path>` config override. Default + override list?
3. **`mission init --from-history` priority.** P1 in this plan. Coco may want it P0 if adoption ramp is critical. Costs extra ~6-8h.
4. **`auto-elevate after 2× yes` integration.** Coco's feature request (memory: `project_firewall_auto_elevate_2x_yes.md`). Companion or separate milestone? Recommendation: M7.15.1 immediately after M7.15 ships, since it amplifies manifest value (manifests declare permanent scope, auto-elevate adds session-scoped extension on the fly).
5. **Friction reduction expectation calibration.** SRE flagged ~20% realistic, not 50%. Operator buy-in needed before kickoff so success criteria is honest.

---

## 10. Timeline + scope summary

| Phase | Hours | Calendar |
|---|---|---|
| Hard blockers (M7.3 desc + scope gap + M7.3.1 anti-reciprocal) | 9-15h | 2-3 days |
| MVP manifest extension (struct, multi-instance, validation, security controls, runtime-agent-overrides.json) | 28-36h | 4-5 days |
| Ergonomics surface (`mission init`, `validate`, `status`, `abort`, errors, dry-run output, examples × 4 domains) | 8-12h | 1-2 days |
| MCP read-only surface (`manifest_show`, `mission_status`) | 2-3h | 0.5 day |
| Dogfood + edge case fixes | 8-12h | 2-3 days (across 5 missions piloto) |
| **Total v1** | **55-78h** | **~2 weeks calendar focused** |

If `--from-history` and `auto-elevate 2× yes` go in v1: +14-20h = ~3 weeks calendar.

**Realistic delivery target:** **2-3 weeks from kickoff** assuming half-time dedication and dogfood findings reveal 2-3 fixes that push edge cases.

---

## 11. Validation / acceptance criteria for the M7.15 milestone itself

To know we shipped right:

1. **Replay test passes.** Given `mission_id`, `colmena audit replay <mission_id>` reconstructs manifest as applied + scope diff vs current `trust-firewall.yaml`. (Security §1.3)
2. **5 dogfood missions complete cleanly** across 3+ domains (pentest, dev, ops minimum). 0 critical bugs, ≤3 P1 findings.
3. **Security regression suite passes:** all 12 invariants (§2) test-covered with rejection cases.
4. **Friction reduction verified:** baseline (Coco BBP wave-2 ad-hoc, ~12 spawns 4-6h) vs manifest-driven equivalent. Target: ≥20% calendar time reduction. Honest measurement.
5. **Three example manifests in repo** (security pentest, dev refactor, incident response) compile + validate + spawn dry-run cleanly.
6. **All hard blockers (M7.3 desc, scope gap, M7.3.1) closed before M7.15 PR merges.**

---

## 12. Source documents

This plan synthesizes:
- `/home/fr33m4n/colmena/docs/architect/M7-15-mission-manifest/SW-ARCHITECT.md` — data model, integration, multi-instance ELO model, agnosticism examples, refined hours estimate
- `/home/fr33m4n/colmena/docs/architect/M7-15-mission-manifest/SECURITY-ARCHITECT.md` — STRIDE threat model, scope binding controls, hardcoded invariants, audit + replay, MCP-vs-CLI boundary, manifest sharing leaks
- `/home/fr33m4n/colmena/docs/architect/M7-15-mission-manifest/SRE.md` — failure modes mapped (disk full, session close orphans, agent panic), observability gaps + proposed CLI surface, idempotency contract, dogfood plan, friction quantification

Each source doc retains its full lens; this unified plan resolves contradictions explicitly and prioritizes for shipping.

---

**Recommended next step:** operator (Coco) reviews this plan, decides on the 5 open questions in §9, then a Colmena Developer agent picks up implementation starting from §7 hard blockers.
