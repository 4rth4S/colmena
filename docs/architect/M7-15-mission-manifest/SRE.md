# M7.15 Mission Manifest — SRE / Platform Engineer Review

**Reviewer:** SRE / Platform Engineer (peer of `colmena_architect` + Security Architect)
**Date:** 2026-05-01
**Scope:** operational lens — failure modes, observability, ergonomics, migration, kill switches, dogfood plan. NO security analysis (Security peer). NO data model (Software Architect peer).
**Verdict:** direction is sound and partially implemented. `colmena-core/src/mission_manifest.rs` ships a primitive `MissionManifest`; `colmena mission spawn --from <file>` is wired in `colmena-cli/src/main.rs:2146`. Unfinished work is mostly **operational surface** — status/logs/abort, budget, migration story for ad-hoc users like the Coco BBP session 2026-05-01. Shape proposed is workable but has 4 P0 ergonomic gaps that must ship in v1 or M7.15 gets dogfooded once and abandoned.

---

## 0. Grounding — what exists vs what M7.15 adds

M7.15 is **not** greenfield. Anchor on this before designing.

### Already shipped (M7.3 → M7.14)

| Capability | Where | Notes |
|---|---|---|
| Manifest parse + validate | `colmena-core/src/mission_manifest.rs` | Fields today: `id`, `pattern`, `mission_ttl_hours`, `roles[].{name,scope,task}` |
| `mission spawn --from <file>` | `colmena-cli/src/main.rs:2146` | Loads YAML, validates roles exist in library, calls `spawn_mission()` |
| Shortcut flags | same | `--mission/--pattern/--role/--scope/--task` build manifest in-memory |
| `--dry-run` | `selector::spawn_mission(..., dry_run)` | Composes prompts in memory, no persistence |
| `--extend-existing` | same | Skip delegations whose TTL ≥ requested |
| `--overwrite` | same | Clobber existing `.md` even if not auto-generated |
| `--session-gate` | same | Sentinel writes session gate active for mission TTL |
| `mission list` | `run_mission_list` | Per-mission delegation counts + expiry |
| `mission deactivate` | `main.rs:2059` | Revokes delegations + removes auto-gen `.md` + clears session-gate sentinel |
| Mission Gate auto-activation | `cfg.is_mission_gate_active(...)` | `enforce_missions: true` OR session sentinel OR live `source: role` delegations |
| Auto-gen subagent files | `selector::spawn_mission` writes `~/.claude/agents/<role_id>.md` | Auto-generated marker → deactivate cleans only its own files |
| Repo-wide pattern scope | `apply_repo_wide_scope()` in `selector.rs:1576` | `pattern.workspace_scope: repo-wide` rewrites `path_within` + secret exclusions |

### Missing (M7.15 scope candidates)

1. Multi-instance per role (`count: N`, `instances: [...]`) — fundamental shape gap
2. Budget fields (`max_hours`, `max_agents`)
3. Acceptance criteria
4. Auditor pool selection (`auditor_pool: ["auditor"]`) — hard-coded today
5. Inter-agent protocol declaration — hard-coded today
6. **Status/logs/cost/abort/resume** — only `list` + `deactivate` exist
7. **Init template** (`mission init <name>`)
8. **From-history retrofit** (`mission init --from-history`)
9. Hosts/extra-allow bash patterns — operator runs `delegate add` manually post-spawn
10. **Idempotency contract** — implementation-defined today

Schema additions (1-5, 9) are Software Architect's call. Surface additions (6-8) are pure SRE/Platform and dominate this review.

---

## 1. Day-1 ergonomics — primer manifest

### 1.1 Discoverability — `colmena mission init <name>` [P0]

Today's path requires knowing the YAML shape cold. No `init`, no `--print-schema`. Coco's bypass on 2026-05-01 was the rational response.

```bash
colmena mission init <slug> [--pattern <id>] [--for "<mission text>"]
# writes ./<slug>.mission.yaml with fully-commented template
```

The template MUST:
- Resolve `--pattern` against library, pre-fill `roles:` from `roles_suggested`. Without `--pattern`, run `library_select` against `--for` text, pre-fill top match.
- Pre-fill `mission_id: <YYYY-MM-DD>-<slug>` (matches `config/missions/` convention).
- Inline-comment every field: type, default, examples, link to library.
- Commented-out `acceptance_criteria` block with 2-3 examples per pattern.

**Quantification:** Coco's BBP wave-2 was ~12 ad-hoc spawns over 4-6h. If `init` writes a working template in <30s and operator edits in <5min, manifest authoring drops from "intimidating" to "one-time edit." Without `init`, M7.15 reproduces the same wall under a new name.

### 1.2 Validation feedback [P0]

Today: `MissionManifest::from_yaml` calls `serde_yml::from_str(...).context("...")` and bails. `serde_yml`'s native error has line numbers but no domain context.

Wrap parse + validate with `ManifestError`:

```
ManifestError::MissingField     { field: "pattern", line: 3, suggestion: "try 'peer' / 'caido-pentest' / `colmena library list --kind pattern`" }
ManifestError::UnknownPattern   { value, line, candidates: [...] }   // levenshtein-3 suggestions
ManifestError::UnknownRole      { value, line, candidates: [...] }
ManifestError::ScopePathOutsideRepo { path, line }                    // hard-fail destructive paths
ManifestError::TtlOverMax       { value, max: 24, line }
```

Every variant: `[colmena] ERROR <line:col>: <msg>\nSuggestion: <action>`. No stack traces unless `RUST_LOG=debug`. **Reuse `colmena config check` idiom** — it already does this for `trust-firewall.yaml`.

### 1.3 Dry-run — exists, surface harder

`spawn_mission(..., dry_run: true)` skips persistence. But:
- `--dry-run` documented inline in `mission spawn --help` only.
- Output prints `(dry-run) N delegations WOULD be created` — count only, no detail.

**Proposal:** default dry-run output expands every delegation (tool/agent/condition/expires_at). Add `--format json` for CI. Every README example ships with the dry-run output as a comment block so operators sanity-check before spawning.

**Failure if not done:** operator runs spawn, gets surprised by delegations, runs `delegate revoke` manually, distrusts the tool. Per `feedback_data_before_proposals.md` — trust breaks when behavior is invisible.

### 1.4 Idempotency contract [P0]

Today: `spawn_mission(extend_existing: true)` skips delegations whose TTL ≥ requested. `--overwrite` controls subagent file clobber. **No documented contract** for manifest re-application.

| Scenario | Today | Operator expectation |
|---|---|---|
| Same manifest, same content, second run | New delegations added (TTL extended), `.md` respected if not auto-gen | Idempotent — converge to "all defined, no duplicates" |
| Edited (added role) | New role's delegations added, old roles untouched | "diff and apply" — sync to manifest |
| Edited (removed role) | Old role's delegations stay live | "diff and apply" — removed roles revoked |
| Different manifest, same `id` | Treats as same mission | Should fail loudly |

**v1 contract: "apply, don't reconcile."** Spawn is additive — adds delegations + subagent files declared in manifest, up to TTL. Does NOT remove what's no longer in manifest. Operator uses `mission deactivate` + re-spawn for clean restart.

Reconcile (Kubernetes-style "apply == desired state") needs stored last-applied to diff. Storage adds complexity v1 should not pay. "Apply additive + deactivate to reset" composes cleanly. **Document this loudly** — implicit "idempotent or not?" is a footgun under load.

---

## 2. Failure modes durante mission

### 2.1 Agent fails mid-mission

Colmena does not run agents — CC does. If a subagent panics/OOMs, CC reports to operator; Colmena observes absence of `review_submit`.

**Failure mode:** worker dies before `review_submit`. SubagentStop would block Stop without review, but the hook never fires (process killed). Pending review stays `Submitted`; reviewer has nothing to evaluate; ELO cycle stalls.

**Today's detection:** none until `mission status` (proposed) or `colmena review list --state pending` shows old entries.

**Proposal:**
- `mission status` (§3.1): per-agent state `started | submitted | reviewed | stalled (>N min)`.
- Stale-worker GC: if `review_submit` never arrived after mission_ttl elapsed, mark mission `partial`, log `MISSION_PARTIAL` audit event. **Do NOT auto-retry** — operator decides.
- Multi-instance configurable: `failure_tolerance: any | all | N-of-M` (§7.2).

Mirrors M7.14's `gc_stale_pending` in `queue.rs`. Lazy: GC runs on `mission status` calls, not as daemon.

### 2.2 Operator closes CC session mid-mission [critical]

Operators run multiple foreground CC sessions per `feedback_foreground_agents.md`.

| Dies | Persists | Risk |
|---|---|---|
| CC process | Delegations (TTL-bound), `runtime-delegations.json`, audit.log, ELO log, `~/.claude/agents/<role>.md` | **Auto-gen `.md` files persist for days; on next session they fire if delegations re-apply** |
| Mission gate sentinel | TTL-bound, expires per `mission_ttl_hours` | OK — self-cleans |
| Pending reviews | `config/reviews/pending/` | Stay until reviewer evaluates or stale-invalidate |
| Active subagents | Killed with CC | OK |

**Sharp edge:** auto-gen `.md` files outlive CC. Without `mission deactivate`, they're orphans — a future session could load them with stale context if Mission Gate is OFF.

**Proposal:**
- **SessionEnd hook** (M7.11 already queued). Extend to detect active mission delegations + surface banner:
  ```
  Colmena — session ending with N active missions
    bbp-followup-3706175 — 3 agents, 2h25m remaining
    refactor-cleanup-x   — 1 agent,  4h12m remaining

    Run `colmena mission deactivate <id>` to revoke on exit,
    or leave them (TTL expires automatically).
  ```
- **Optional auto-deactivate:** off by default. Opt-in via `COLMENA_DEACTIVATE_ON_SESSION_END=1`.
- **`mission list --orphan`:** missions whose subagent files exist in `~/.claude/agents/` but all delegations expired/revoked. Cleanup candidates.

This binds M7.11 to M7.15: banner is the surface, manifest is the structured state.

### 2.3 Network outage during `review_submit`

`review_submit` is local MCP — no network, just disk I/O. Real risks: disk failure, concurrent CC sessions colliding on same review file. `review.rs` uses atomic writes (temp + rename); if rename fails, MCP errors, agent retries, SubagentStop blocks Stop until success.

**Genuine risk:** auditor MCP times out → worker waits forever (SubagentStop is hard gate).

**Proposal:**
- `MCPError::ServerUnavailable` raises dual-channel alert: stderr + `alerts.json`.
- Manifest field `review_submit_timeout_seconds` (default 30s, max 120s). If MCP doesn't ack, abort with: "Colmena MCP unavailable — check `colmena doctor`".

Out of scope v1: distributed retry, queueing failed submits.

### 2.4 Disk full mid-mission

Worst-first ordering (smallest writes most often = first to fail):

1. **`audit.log`** — append on every firewall decision. Largest write freq. Hook safe-fallback: stderr, continue.
2. **`runtime-delegations.json`** — atomic rewrite on delegation change. Atomic fail → original preserved.
3. **`config/reviews/pending/<id>.json`** — small writes on `review_submit`. Failure blocks SubagentStop indefinitely (§2.3).
4. **`elo-events.jsonl`** — append on `review_evaluate`. Failure → ELO event lost, role rating stale.
5. **`config/queue/pending/...`** — pre-tool-use. Disk-full on enqueue → hook returns ask without queue presence; `colmena queue list` empty.

**Proposal:**
- Extend `colmena doctor` with `--check disk-space` (warn if `colmena_home` filesystem <500MB free).
- Mission spawn pre-flight: refuse spawn if filesystem <100MB free. Cheap, hard fail.
- Document failure ordering in `docs/dev/internals.md`.

Out of scope v1: quota enforcement, audit.log rotation (known issue, flag for architect peer — `audit.log` is currently unrotated).

---

## 3. Observability del manifest lifecycle

### 3.1 `colmena mission status <id>` [P0]

Today: `mission list` (one-line summary) + `delegate list` (per-tool detail). No per-mission detail. For an active mission with 8 agents and 12h budget, operator runs 6 commands (`mission list + delegate list + review list + findings list + alerts list + grep audit.log`) to reconstruct state.

```
Mission: bbp-followup-3706175
Pattern: bbp-impact-chain  (private library)
Spawned: 2026-05-01 14:23 UTC  (2h17m ago, 5h43m remaining)
Gate:    ON (--session-gate, mission TTL)

Agents (4 spawned, 4 active):
  squad-a (bbp_pentester_web)   submitted ✓   reviewed ✓   ELO +12
  squad-b (bbp_pentester_web)   submitted ✓   reviewed ⏳   pending review by auditor
  squad-c (bbp_pentester_web)   running  ⏳   submitted? no
  weaponizer                    n/a      —    awaiting human gate
  auditor                       active   ✓    1 review in flight

Budget:
  max_agents: 12   used: 4    OK
  max_hours:   8   used: 2.3  OK (29%)

Findings: 3 (1 critical, 2 medium)
Reviews:  4 submitted, 3 evaluated, 1 pending
Alerts:   0 unacknowledged

Next steps:
  - squad-b: reviewer (auditor) has pending review — will block on Stop
  - squad-c: hasn't called review_submit yet
```

**Cost:** medium. All sources (delegations, audit log filtered by mission_id, reviews dir, findings, alerts) have helpers in `colmena-core`. Wiring is `colmena-cli` UI work. **Win:** completeness — operator can't forget to grep audit log.

### 3.2 `colmena mission logs <id> --follow` [P1]

Not strictly needed v1 if `mission status` is solid. Still high-value for SSH/headless.

- `mission logs <id>`: tail of `audit.log` filtered by mission_id + reviews dir watcher + alerts. Single stream, prefixed: `[FW] [REVIEW] [ALERT] [FINDING]`.
- `--follow`: like `tail -f`. Stops on Ctrl-C or mission_ttl elapsed.
- `--since <duration>`: tail-style replay.

Cost: low — `notify` crate + format. Polling fallback for NFS/CIFS.

### 3.3 Metrics — Prometheus export

**NO for v1.** Colmena is CLI + hooks + MCP. Not a long-running service. Prom expects scrape endpoint → daemon mode + port + auth + on-call. Cost vs benefit:
- **Benefit:** ops/SRE users with existing Prom stacks.
- **Cost:** new daemon, port surface, auth question, "Colmena daemon down" pages.

**Better v1:** structured JSON from `mission status --format json` + `mission logs --format json`. Operators pipe to `jq`/cron. Pull-based via cron is fine for single-operator. **Defer to M7.16+** if 2+ operators ask.

### 3.4 Statusline integration [P1]

Existing tmux statusline (per `project_queue_lifecycle_bug.md`, patched 2026-04-24) shows queue count per session.

```
[hive] q=2 m=1 (bbp-followup) ⏰5h43m
       │     │  │              │
       │     │  │              └─ mission TTL remaining
       │     │  └─ active mission slug (most recent)
       │     └─ active mission count
       └─ pending queue prompts
```

Cost: low. Add `colmena mission active --session <sid> --format compact` returning `<count>:<latest-slug>:<remaining-secs>`. **Boundary:** statusline must NOT call MCP (latency-sensitive). Pure CLI read of `runtime-delegations.json` + TTL math. <10ms cold.

---

## 4. Budget enforcement

This is where proposal vs operational reality diverge most. Be ruthless.

### 4.1 `budget.max_hours` semantics

| Definition | Where measured | Honest? |
|---|---|---|
| Wall-clock since spawn | `now - mission.spawned_at` | Yes — simple, observable |
| Sum of agent wall-clock | sum of (review_submit_ts - spawn_ts) | Approx — idle agents over-counted |
| Sum of CC tool-call durations | requires CC instrumentation | Out of scope |
| Sum of audit event spans | proxy via `mission_id` events | Plausible but noisy |

**v1: wall-clock since spawn.** Simplest, observable, matches operator's mental model. Field `budget_mode: wall | cpu` for future, default wall.

### 4.2 `budget.max_agents` semantics

Distinct roles vs total instances?

**v1: total instances.** Aligns with cost (each instance = separate context window) and operator intuition.

### 4.3 Soft cap vs hard cap

- 80% → `BUDGET_WARNING` alert + statusline blink. Mission continues.
- 100% → mission `over_budget` in `mission status`. NEW agent spawns refused, existing continue. `mission extend <id> --hours N` extends TTL on all delegations (explicit ack).
- 150% → optional `auto_deactivate_on_overrun: true`. Default: false.

**Honest complexity assessment:** budget enforcement is NOT free.
- Per-call lookup: ~1ms (read JSON, count). Within hook latency budget.
- New file: `config/missions/<id>/state.json` — last-known counts. Atomic write + optimistic concurrency (mtime check before write).
- Race: concurrent CC sessions firing hooks for same mission → atomic writes mandatory.

**Recommendation:** ship `max_agents` v1 (cheap — count delegations with mission_id at spawn). **Defer `max_hours` enforcement to M7.15.1** with soft warning v1. Don't fake hard enforcement. The BBP session that motivated this proposal didn't stress budget — request is anticipatory, not validated. Ship cheap, defer expensive.

### 4.4 Partial execution / resume

Budget exhausted mid-mission:
- State → `partial`.
- Existing agents finish current tool calls (no kill).
- New spawns refused with actionable error: "Mission budget exhausted. `mission extend <id> --hours N` or `mission deactivate <id>`."
- Operator extends or closes; both audited.

True resume from saved checkpoint is **not v1**. M7.16+.

---

## 5. Kill switches y rollback

### 5.1 `mission abort <id>` [P0]

Today `mission deactivate` revokes delegations + removes auto-gen .md + clears session-gate. It does NOT:
- Kill running subagents (CC manages — no API surface).
- Revert `agent_overrides` added during mission (today: not added by `mission_spawn` per reading `selector::spawn_mission`; verify with architect peer).
- Mark mission state `aborted` (no state file today).

**`mission abort <id> [--keep-findings] [--keep-reviews]`:**

1. Revoke all delegations (existing `revoke_by_mission`).
2. Remove auto-gen `.md` files (existing).
3. Clear session-gate sentinel (existing).
4. Write state.json: `{"state": "aborted", "aborted_at": "...", "by": "operator"}`.
5. Mark all pending reviews for this mission as `Invalidated` (reuses `ReviewState::Invalidated` from `review.rs`). Frees reviewer slots.
6. Audit: `MISSION_ABORT { mission_id, reason }`.
7. Best-effort: notify CC to kill agents (no API today — log + tell operator to Ctrl-C).

**`deactivate` vs `abort`:**
- `deactivate`: graceful. Mission completed normally — wind down, preserve everything.
- `abort`: emergency. Stop everything, log, alert.

Two commands because the audit narrative matters (`MISSION_DEACTIVATE` vs `MISSION_ABORT` — different intent, different post-mortem).

### 5.2 Emergency env var [P1]

`COLMENA_DISABLE_MANIFEST_SPAWN=1` rejects `mission spawn`: "Manifest spawn disabled. Use --shortcut flags for one-off spawn." Pattern matches `chain_aware: false` kill switch.

### 5.3 `mission resume <id>` [P2]

If operator aborts by mistake, they want recovery. But: delegations gone (re-spawn re-creates), reviews `Invalidated` (cannot un-invalidate by hash design), .md files removed (re-spawn re-creates).

**v1: don't add `mission resume`.** Document abort as irreversible — operator re-runs `mission spawn --from <manifest>`. Lost data is bounded (TTL-scoped delegations + 1h-old reviews at worst). Revisit if 3+ "I aborted by mistake" incidents in dogfood.

---

## 6. Migration path

### 6.1 `mission init --from-history` [P0 for adoption]

Motivating event was Coco bypassing `mission_spawn`. Migration play: take that bypassed session and **retrofit** into a manifest. Operator sees "oh, my ad-hoc workflow IS a manifest, I just didn't know."

`colmena mission init --from-history --since "2h ago" [--session <id>]`. Reads `audit.log` for window, identifies:
1. Distinct agents spawned (via `Agent` tool calls + prompts).
2. Roles inferred from naming (e.g. `bbp_pentester_web` → library lookup).
3. Tool patterns (Bash patterns, Read paths) → `scope` block.
4. Mission marker (if any) → mission_id; if none, prompt for slug.

Writes draft manifest with comments: `# inferred from audit log between T0 and T1 — review and edit before applying`.

**Quantification:** Manual manifest from cold ~30-60min. `--from-history` reduces to ~5-10min (operator reviews/cleans inferred manifest). 6× speedup on migration. **Without this, ad-hoc users have no migration ramp** — they eat the cost or stay ad-hoc forever.

Cost: medium. Audit log parser exists (CLI stats reads it). Role/scope inference is heuristic — false positives OK (operator edits before apply). v1 is a **skeleton**, not a perfect manifest.

### 6.2 Backward compat

Current `mission spawn --mission --pattern --role` shortcut MUST keep working. Operators have muscle memory. The shortcut path constructs `MissionManifest` in-memory (`main.rs:2200`) and feeds the same code path. **Already forward-compatible by accident-of-design.** Document: "every spawn produces a manifest internally; `--from <file>` is the explicit form."

### 6.3 Documentation — example manifests [P0]

Per CLAUDE.md and validated users, Colmena spans 4 domains. Example library MUST cover all four out of the gate.

| File | Domain | Pattern | Roles | Why |
|---|---|---|---|---|
| `bbp-coinbase.mission.yaml` | Pentest | `bbp-impact-chain` (private overlay) | bbp_pentester_web ×3, weaponizer, auditor | Validates pentester case |
| `refactor-cleanup.mission.yaml` | Dev | `peer` | developer ×2, code_reviewer, auditor | Shows `workspace_scope: repo-wide` |
| `incident-runbook.mission.yaml` | DevOps | `hierarchical` | sre, devops_engineer, auditor | Shows kubectl/helm `bash_patterns.extra_allow` |
| `literature-review.mission.yaml` | Research | `fan-out-merge` | researcher ×4, architect | Shows non-security agnosticism |

Every example MUST: compile with `mission spawn --from <file> --dry-run` (test in CI); be commented; include dry-run output as comment block; reference public-library roles or note "private overlay required" with link.

**4 examples, not 1.** If M7.15 ships pentest-only, devops/SRE adoption stalls — they need to see "this is MY workflow."

---

## 7. Multi-instance agents (`count: 3`)

### 7.1 Foreground vs background

Per `feedback_foreground_agents.md`: foreground default for cost visibility. `count: 3` spawns 3 agents — operator sees 3 token-counters in CC.

Manifest field `instances_run_mode: foreground | background` (default foreground). Background opt-in + warns: "WARNING: 3 background agents will not show token usage in real time."

### 7.2 Failure tolerance

| Field | Behavior |
|---|---|
| `failure_tolerance: any` | If any 1 of 3 submits, mission continues. Non-submitters = best-effort. |
| `failure_tolerance: all` | All 3 must submit. If 1 fails, mission `partial`. |
| `failure_tolerance: N-of-M` | Quorum. |

**v1: ship only `all` and `any`.** `N-of-M` over-engineered for v1. Default for `count > 1` is `any`.

### 7.3 Namespace collision

If two manifests both declare `instances: [squad-a]`, agent_id collides — `squad-a` resolves to whichever delegation applied last.

**Namespace agent_ids with `<mission_id>-<instance_name>`.** `bbp-followup-3706175-squad-a` and `refactor-cleanup-squad-a` don't collide. `instances: [...]` is the friendly name; internal ID is prefixed. Statusline shows friendly name + slug; audit log uses full ID.

Backward compat: existing single-instance spawns (`role: developer` no `count`/`instances`) keep using bare role_id (current behavior). New collision risk bounded to multi-instance roles defined v1+.

---

## 8. Stats integration

### 8.1 Tag stats by mission_id [P1]

Today `colmena stats` aggregates across all sessions. For mission attribution, audit.log entries need `mission_id` field. Per quick `grep`, the field exists for several event types (`MissionDeactivate`, etc.).

Extend `Decision` (firewall) and `FilterSavings` audit events with `mission_id: Option<String>` (nullable). Stats reader filters by mission_id. Backward compat: missing field = `null`.

### 8.2 `mission cost <id>` [P2]

Operator wants per-mission token spend. Colmena doesn't see CC's API usage — only its own routing.

**Possible:** tool calls per mission, output tokens saved by filter, rough wall-clock per agent.

**Not possible without CC API integration:** actual tokens, cache hit rate.

Ship `mission cost <id>` v1 with proxy metrics + clear caveats. Better partial number with disclaimer than no number:

```
Mission: bbp-followup-3706175
  Tool calls:        247
  Tokens filtered:   ~12,400 (saved from agent context)
  Wall-clock:        2h17m active
  Estimated tokens:  not available (CC API integration pending)

  Filter-saved-tokens / 247 calls = ~50 tokens/call avg → reasonable
```

---

## 9. Alerting mid-mission

### 9.1 Triggers [P1]

Today `alerts.json` is append-only with `alerts_ack`. M7.15 fires on:

| Trigger | Severity | Reasoning |
|---|---|---|
| Budget 80% | warning | Soft cap heads-up |
| Budget 100% | high | Hard cap, action required |
| Agent stalled >10min | warning | Operator should check |
| Scope violation attempted | high | Operator should know |
| Suspicious pattern (5x deny in 60s) | high | Possible runaway loop |
| Mission TTL <30min | info | Renewal heads-up |
| Mission deactivate/abort | info | Audit completeness |

Implementation: post-hoc checks in `mission status`. **No real-time alerting** (would need daemon). `mission status` reads state, computes conditions, writes new alerts. Lazy.

### 9.2 Channel

**Stay with `alerts.json` + stderr.** Webhook surfaces operator data outside the box → auth + rate limiting + crypto. M7.16+ at earliest.

Surface in M7.11 SessionEnd banner:
```
Colmena — session summary
  ...
  Active alerts:    3 unacknowledged (1 high, 2 warning)
                    Run `colmena alerts list` to see them.
```

Alerts visible at session close without polling daemon.

---

## 10. Dogfood loop

### 10.1 Pilot missions [P0]

Per `project_colmena_users_validated.md`, 4 power users. Plan covers ≥3 domains.

| # | Mission | Domain | Operator | Goal |
|---|---|---|---|---|
| 1 | `bbp-coinbase-wave-3` | Pentest | Coco | Re-run BBP via manifest, compare friction vs ad-hoc 2026-05-01 |
| 2 | `colmena-self-dev-m716` | Dev | Coco | Drive M7.16 implementation; tests `workspace_scope: repo-wide` |
| 3 | `personal-research-X` | Research | Coco | Note-taking pattern; tests non-security agnosticism |
| 4 | `incident-staging-runbook` | DevOps | external SRE (if available) | Tests `devops_engineer` + `bash_patterns.extra_allow` |
| 5 | (catch-up) re-run any of above | Same | Same | Validates idempotency + re-run UX |

**Definition of done v1:** 0 P0 bugs in 5 sequential successful pilots. P1/P2 OK if logged.

### 10.2 Metrics

| Metric | How | Target |
|---|---|---|
| Time to first spawn (authoring + apply) | Wall-clock `mission init` → `mission spawn --from` | <10min including learning |
| Error rate | CLI errors before successful spawn | <2 first-time, <1 thereafter |
| Manifest LOC (excl. comments) | `wc -l` | <100 LOC |
| Time-to-deactivate | Wall-clock "done" → ack | <30s |
| Post-mission ELO movement | `elo show` diff | ≥1 ELO event per agent (cycle closed) |
| Operator NPS (qualitative) | "Easier than ad-hoc, harder, or same?" | "Easier" from 3/4 power users |

**Headline test:** BBP wave-2 was ~12 spawns, 4-6h. With manifest:
- First-time setup (incl. init template): ~15-20min
- Subsequent sessions reusing manifest: <5min
- Apply: ~30s (spawn + verify dry-run)
- Mission run: same time (manifest doesn't speed agent execution)

**Friction reduction estimate: ~20% on a 4-6h session.** Not 50%. If proposal sells "50% reduction" it fails the smoke test. Honest framing: M7.15 is **operational hygiene + reproducibility**, not raw speed. Pitch: *"check the manifest into the repo, run again next sprint."* For one-shot missions, ad-hoc remains rational.

### 10.3 Who runs

Coco runs 3 pilots. External SRE (if available) runs 1 incident pilot. NPS conversational — not a Form. 5 sequential runs over ~2 weeks. If cross-user not available, accept Coco-only — better validated than not validated.

---

## 11. Friction reduction medible

### 11.1 Honest comparison

| Phase | Ad-hoc (Coco 2026-05-01) | Manifest v1 |
|---|---|---|
| Setup (one-time per mission) | 0 min (just spawn) | 15-20min first time, <5min reuse |
| Per-spawn cost | ~30s (one Agent + ack) | 30s for whole batch |
| Mid-mission cross-ref | Manual: `delegate list`, audit grep, ELO check | `mission status` (one cmd) |
| Mid-mission scope expansion | Manual `delegate add` per path/pattern | Edit manifest + `mission spawn --extend-existing` |
| Wind-down | Manual `delegate revoke` + `~/.claude/agents/` cleanup | `mission deactivate` (one cmd) |
| Teardown safety (orphans) | Operator may forget .md cleanup | Auto-handled |

**Wins big:** wind-down + cross-ref. **Ties or loses:** first-time setup. If operator doesn't reuse manifest (one-shot), manifest is slower than ad-hoc.

### 11.2 What must be true for M7.15 to feel worth it

- Day-1: `mission init` → working manifest in <10min.
- Day-1: dry-run output is trustworthy and complete.
- Day-N: re-running is idempotent and predictable (§1.4).
- Day-N: `mission status` answers "what's going on?" in <2s.
- Day-N: `mission deactivate` cleans up in <30s.
- Day-X: manifest is operator's record-of-truth — they edit YAML, not CLI args.

If any fail, operator goes back to ad-hoc + grumbles. Measure against these gates, not marketing.

---

## 12. Compatibility con auto-elevate 2× yes

Per `project_firewall_auto_elevate_2x_yes.md` (request 2026-05-01). Question: manifest active, operator approves same `(agent_type, pattern)` 2× in 10min — what happens?

| Manifest state | Auto-elevate behavior |
|---|---|
| No manifest | Per memory's design — session-scoped delegation, audit reason `auto-elevated:2x-confirm` |
| Manifest active, pattern in `scope.bash_patterns.extra_allow` | Already auto-approved, never asks. No-op. |
| Manifest active, pattern NOT in extra_allow but operator approves 2× | **3 options below** |

Three options for the third row:
- **(a)** Add session-scoped delegation (matches non-manifest behavior). Log *divergence event*: `MANIFEST_DIVERGENCE { mission_id, pattern, suggestion: "consider adding to manifest extra_allow" }`. **Do NOT mutate manifest file** — that's tampering with version-controlled state.
- **(b)** Refuse auto-elevate when manifest active. Operator must edit manifest. Higher friction, more honesty.
- **(c)** Hybrid: prompt on second `y`: "Add to manifest? [y/N]" if interactive.

**Recommendation: (a).** Auto-elevate as session delegation + audit divergence. Operator reviews divergences in `mission status` and updates manifest manually before next run. Preserves manifest integrity (file is source of truth, never silently mutated). Reduces in-session friction. Surfaces divergence so manifest improves over time.

Surface in `mission status`:
```
Divergences (auto-elevated this session, not in manifest):
  curl https://wallet.coinbase.com/X    (3× elevated; consider adding to scope.bash_patterns.extra_allow)
```

Operator stays unblocked, manifest stays honest, divergence is observable. The audit divergence event IS the product feedback signal — count of divergences per mission tells operator "your manifest is incomplete in N ways."

---

## 13. Priority summary

### P0 — must ship in M7.15 v1, or it's a bridge to nowhere

1. §1.1 `mission init` template generator — without this, authoring stays a wall.
2. §1.2 Actionable validation errors — line/col + suggestions, not stack traces.
3. §1.4 Idempotency contract documented — "apply additive + `deactivate` to reset". Pinned in user docs.
4. §3.1 `mission status <id>` — without status, mid-mission observability is multi-command grep.
5. §5.1 `mission abort <id>` — distinct from `deactivate`. Audit narrative + emergency UX.
6. §6.1 `mission init --from-history` — adoption ramp for ad-hoc users like Coco 2026-05-01.
7. §6.3 4 example manifests (pentest + dev + devops + research) — non-security adoption blocked otherwise.
8. §10 dogfood plan: 5 pilots + metrics.
9. §11 honest friction-reduction quantification in user docs. ~20% on long missions.

### P1 — strong v1, surviveable to defer to M7.15.1

1. §3.2 `mission logs --follow` — quality-of-life.
2. §3.4 Statusline integration — small win for tmux users.
3. §4 budget enforcement (max_agents only) — `max_hours` deferred with soft warning v1.
4. §5.2 `COLMENA_DISABLE_MANIFEST_SPAWN` — kill switch parity with chain_aware.
5. §7 multi-instance with `count` + `instances` + namespacing — required if any pilot wants parallel squads.
6. §8.1 mission_id tag in audit events — needed for `mission cost`.
7. §9 alerting + SessionEnd banner integration — composes with M7.11.
8. §12 auto-elevate divergence handling — depends on auto-elevate landing (still feature request).

### P2 — defer to M7.16+ unless dogfood demands

1. §3.3 Prometheus export — daemon mode, big lift, not validated.
2. §4.1 `cpu_hours` budget mode — wall-clock fine v1.
3. §5.3 `mission resume` — abort is final; revisit if pain shows.
4. §8.2 `mission cost` (real tokens) — proxy metrics OK; CC API is the unlock.
5. Webhook alerts — security/auth burden.
6. `failure_tolerance: N-of-M` — `any`/`all` cover 95%.

---

## 14. Convergence notes for ARCHITECT_PLAN.md

**SRE × Software Architect overlaps:**
- §1.4 idempotency — I want "apply additive + deactivate to reset"; SA verifies data model supports it (state.json schema, last-applied tracking).
- §3.1 `mission status` — data model decision (state.json vs computed-on-demand) is theirs; UX shape mine.
- §7 multi-instance — namespace decision (`<mission_id>-<instance_name>`) affects delegation lookup; their data model call.

**SRE × Security Architect overlaps:**
- §2.4 disk-full → audit gap — first to fail = worst integrity loss. SA weighs in on whether `audit.log` rotation is now blocking.
- §5 abort semantics — does "abort marks reviews Invalidated" leak partial state to subsequent missions?
- §9 alerting on scope violations — SA's playbook on what counts as worth alerting.
- §12 auto-elevate divergence — leaking pattern shape across sessions a leak risk? My take: no (operator already knows what they approved). Flag it.

**SRE explicitly defers to peers:**
- Manifest *schema* extensions (`count`, `instances`, `acceptance_criteria`, `auditor_pool`, `inter_agent_protocol`) — Software Architect.
- Hash/signature/integrity of manifest file — Security Architect.
- Threat model around malicious manifest (could request scope on `/etc/`) — Security Architect.

**Operational invariants the merged plan must preserve:**

1. Hook latency <100ms (CLAUDE.md). Manifest lookups in hot path must be cached or O(1). Don't read state.json on every PreToolUse.
2. Hook safe-fallback: any error → ask (Pre), passthrough (Post), approve (SubagentStop). Manifest enforcement must not deny.
3. Atomic writes everywhere: state.json, deactivate, abort. Concurrent sessions are common.
4. No new daemon processes. Everything stays CLI + hooks + the existing MCP server.
5. Backward compat: existing `mission spawn --mission --pattern --role` shortcuts keep working forever. Manifest is canonical, shortcuts are sugar.

---

## 15. One-line takeaway

The manifest direction is right and partially built. M7.15 succeeds operationally if it ships the **9 P0 items in §13** and dogfoods 5 pilots cross-domain. It fails if it's only "manifest YAML schema + `--from <file>`" — that's already shipped, and the operator who motivated this proposal already bypassed it. The unfinished work is `init` template, `status`, `abort`, `from-history`, and 4 cross-domain examples. Everything else is P1/P2 polish.
