# Colmena M2 — Peer Review Protocol + ELO Engine + Findings Store

> Design spec for M2 of the Colmena roadmap.
> Supersedes the Knowledge Bus + Agent Spawn portion of the original hivemind design.
> Date: 2026-03-30

---

## 1. Context and Motivation

### What M2 was originally

The original M2 design (hivemind-design.md) defined two components:
- **Knowledge Bus** — async persistent message bus between agents (FINDING, ALERT, CONTEXT signals)
- **Agent Spawn via MCP** — `mission_launch` tool to spawn agents from M1 mission configs

### Why we're changing it

After evaluating against Claude Code's native capabilities (March 2026):

| Original M2 Feature | CC Native Equivalent | Verdict |
|---|---|---|
| Async signal bus | `SendMessage` (sync, direct) | CC covers 95% of cases. Bus adds complexity without clear consumer. |
| Agent spawn via MCP | `Agent` tool + `SendMessage` + worktrees | Fully redundant. |
| PostToolUse signal injection | CC only supports PreToolUse hooks | Not implementable. |
| Peer review protocol | Nothing | **Real gap — no structured evaluation between agents.** |
| ELO/rating system | Nothing | **Real gap — no way to track agent quality over time.** |
| Persistent findings | Nothing | **Real gap — findings lost between sessions.** |

### What M2 is now

Three components that deliver value CC doesn't have:

1. **Review Protocol** — structured peer review between agents with trust-gated automation
2. **ELO Engine** — agent quality ratings calculated from append-only review log with temporal decay
3. **Findings Store** — persistent, queryable knowledge base that grows with each review

This also absorbs part of the original M3 (ELO Engine) since peer review without ELO is meaningless and ELO without peer review has no input.

### Pain points solved

- **Primary (B):** No structured way for agents to evaluate each other's work. Without this, there's no signal for who should lead future missions.
- **Secondary (C):** Human manually copies findings between agents. Findings store automates this without losing oversight.

---

## 2. Review Protocol

### Flow

```
1. Agent completes work
   → review_submit(artifact_path, mission_id)
   → Colmena: SHA256 hash of artifact, create review entry
   → Colmena: assign reviewer (different role, not reciprocal)
   → State: PENDING

2. Human sees pending review (or auto-approve if within trust threshold)
   → State: IN_REVIEW

3. Reviewer agent receives:
   - The original artifact
   - Rubric generated from author's role specializations
   - Mission context

4. Reviewer evaluates
   → review_evaluate(review_id, scores={dim1: N, dim2: N, ...}, findings=[...])
   → Colmena: verify artifact_hash matches (detect tampering)
   → Colmena: persist findings to store
   → State: EVALUATED

5. Trust gate:
   → IF score_average >= 7.0 AND no finding with severity=critical
     → State: COMPLETED (auto)
     → ELO updated for both author and reviewer
   → IF score_average < 7.0 OR finding severity=critical
     → State: NEEDS_HUMAN_REVIEW
     → Human decides outcome
   → Floor: Colmena NEVER auto-approves reviews with score_average < 5.0
     regardless of config

6. Audit log records the entire flow
```

### Reviewer assignment

```
1. List roles in the mission different from author
2. Exclude roles that the author already reviewed in this mission (anti-collusion)
3. MVP: pick first available
   Post-MVP (vision B): pick highest ELO
4. If nobody available → queue for human assignment
```

### Rubric generation

No hardcoded rubrics. Each role already has `specializations` in its YAML from M1. The rubric is generated dynamically:

- Pentester with specializations `[web_vulnerabilities, api_security, authentication]` → rubric asks for scores on those 3 dimensions
- Minimum 2 dimensions per rubric (security invariant)
- Scores are integers 1-10

### Review states

```
PENDING → IN_REVIEW → EVALUATED → COMPLETED
                                 → NEEDS_HUMAN_REVIEW → COMPLETED
                                                      → REJECTED
```

---

## 3. ELO Engine

### Core principle

ELO is NOT mutable state. It's an append-only log of events. The current rating is calculated by replaying the log with temporal decay applied.

### Storage

`config/elo/elo-log.jsonl` — one JSON event per line:

```json
{"ts": "2026-03-30T15:30:00Z", "agent": "pentester", "event": "reviewed", "delta": 12, "reason": "score 8.2/10 from security_architect", "mission": "audit-pci", "review_id": "r_001"}
{"ts": "2026-03-30T15:30:00Z", "agent": "pentester", "event": "finding_against", "delta": -8, "reason": "missed websocket scope", "mission": "audit-pci", "review_id": "r_001"}
{"ts": "2026-03-30T15:30:00Z", "agent": "security_architect", "event": "review_quality", "delta": 5, "reason": "found valid gap in pentester output", "mission": "audit-pci", "review_id": "r_001"}
```

### Delta calculation

| Event | Delta |
|---|---|
| Review score >= 8/10 | Author: `+(score - 7) * 3` |
| Review score 5-7/10 | Author: `0` (neutral) |
| Review score < 5/10 | Author: `-(6 - score) * 4` |
| Finding severity=critical against author | Author: `-10` |
| Finding severity=high against author | Author: `-5` |
| Reviewer detects valid finding | Reviewer: `+5` |
| Reviewer gives high score and another reviewer contradicts | Reviewer: `-8` |

### Temporal decay

Applied at read time (lazy), not as a background process:

```
delta_effective = delta * decay_factor

decay_factor:
  < 7 days:    1.0  (full weight)
  7-30 days:   0.7
  30-90 days:  0.4
  > 90 days:   0.1  (nearly irrelevant)
```

### Baseline

All agents start at 1500, as already defined in M1 role YAML (`elo.initial`).

### Rating calculation

```
current_rating = baseline + sum(delta_effective for each event)
```

### ELO influence (MVP — Vision B)

- `elo_ratings` MCP tool returns leaderboard with trend and decay
- M1 `library_select` suggests agents with higher ELO for lead roles
- Human still makes final decision

### ELO influence (Post-MVP — Vision C)

- Agents with high ELO get more permissive firewall rules
- Agents with low ELO get more restricted
- Threshold-based, human-configurable

### Post-MVP: K-factor

```
K = 40 if < 10 total reviews    (fast calibration)
K = 20 if 10-30 reviews         (stabilizing)
K = 10 if > 30 reviews          (established)

delta_final = delta_base * (K / 20)
```

Not included in MVP — with 2-6 agents per mission, nobody will have 30 reviews soon.

---

## 4. Findings Store

### What it is

An append-only knowledge base that grows with each review. Findings are a natural byproduct of peer review. Not a bus, not a chat — structured records that any future agent can query.

### Storage

`config/findings/<mission-id>/<review-id>.json`:

```json
{
  "review_id": "r_001",
  "mission": "2026-03-30-audit-pci-dss",
  "author_role": "pentester",
  "reviewer_role": "security_architect",
  "artifact_path": "agents/pentester/findings-report.md",
  "artifact_hash": "sha256:a1b2c3...",
  "timestamp": "2026-03-30T15:30:00Z",
  "scores": {
    "web_vulnerabilities": 7,
    "api_security": 9,
    "authentication": 6
  },
  "score_average": 7.3,
  "findings": [
    {
      "category": "completeness",
      "severity": "medium",
      "description": "Report covers API endpoints but misses WebSocket connections",
      "recommendation": "Extend scope to include WebSocket transport"
    }
  ]
}
```

### Query interface

`findings_query` MCP tool with filters:

```
findings_query(role="pentester", severity="high", limit=10)
findings_query(category="authentication", mission="current")
findings_query(reviewer_role="security_architect", after="2026-03-01", before="2026-03-31")
```

All filters are optional. Without filters, returns most recent findings (default limit: 20).

### What it's NOT

- Not a bus — nobody receives findings proactively
- Not a chat — no conversation, structured records only
- Not a replacement for audit log — audit log records flow (who reviewed what), findings store records content (what was found)

---

## 5. Security — Hardcoded Invariants

From STRIDE+DREAD threat modeling of this design:

### Threats and mitigations

| # | Threat | DREAD | Type | Mitigation |
|---|---|---|---|---|
| 1 | ELO farming / collusion | 9.0 | Elevation of Privilege | No reciprocal reviews in same mission. Reviewer rotation. Human dashboard. |
| 2 | Self-review | 8.5 | Spoofing | `author_role != reviewer_role` — hardcoded, not config. |
| 3 | Threshold bypass via config tampering | 8.0 | Elevation of Privilege | Floor hardcoded at 5.0. Config writes require human approval (M0 firewall). |
| 4 | Score file tampering | 7.8 | Tampering | ELO from append-only log, not mutable state. Audit trail detects edits. |
| 5 | Rubber stamp reviews | 7.5 | Tampering | Multi-dimension rubrics. Flagging when no findings on complex artifacts. Reviewer ELO drops if contradicted. |
| 6 | Artifact tampering between submit and review | 6.5 | Tampering | SHA256 hash at submit, verified at evaluate. Mismatch → review invalidated. |

### Invariant table

| # | Invariant | Where | On violation |
|---|---|---|---|
| 1 | `author_role != reviewer_role` | `review.rs` assign | Reject — review not created |
| 2 | No reciprocal review in same mission | `review.rs` assign | Assign different reviewer or queue for human |
| 3 | Artifact hash verified at evaluate | `review.rs` evaluate | Review invalidated, flag to human |
| 4 | ELO log append-only, only Colmena writes | `elo.rs` — no direct MCP write tool | Agents have no path to manipulate ELO |
| 5 | Auto-approve floor hardcoded at 5.0 | `review.rs` — constant | Cannot be overridden by config |
| 6 | Minimum 2 score dimensions per review | `review.rs` validate | Reject if only 1 score submitted |

---

## 6. Architecture — Modules and Files

### New modules in `colmena-core`

```
colmena-core/src/
  review.rs    — Review protocol: submit, assign, evaluate, state machine
  elo.rs       — ELO engine: delta calculation, decay, rating from log
  findings.rs  — Findings store: persist, query, filter by date/role/category
```

### New config and data files

```
config/
  review-config.yaml       — thresholds, reviewer assignment rules
  reviews/
    pending/               — reviews awaiting reviewer or human
    completed/             — finished reviews
  findings/
    <mission-id>/          — findings grouped by mission
      <review-id>.json
  elo/
    elo-log.jsonl          — append-only, one event per line
```

### New MCP tools (6)

| Tool | Called by | Purpose |
|---|---|---|
| `review_submit` | Author agent | "I'm done, this needs review" — registers artifact + hash |
| `review_list` | Human or lead | View pending/in-progress/completed reviews |
| `review_evaluate` | Reviewer agent | Submit multi-dimension scores + findings |
| `elo_ratings` | Anyone | View ELO leaderboard with trend and decay applied |
| `findings_query` | Any agent | Search findings by role/category/severity/date/mission |
| `findings_list` | Human or lead | List recent findings (simple alias for findings_query) |

### New CLI subcommands (3)

```
colmena review list                        # View review queue
colmena review show <review-id>            # Review detail
colmena elo show                           # ELO leaderboard
```

### Modified files (not new)

| File | Change |
|---|---|
| `colmena-core/src/lib.rs` | Add `pub mod review, elo, findings` |
| `colmena-cli/src/main.rs` | Review + ELO subcommands |
| `colmena-mcp/src/main.rs` | 6 new MCP tools |
| `config/trust-firewall.yaml` | Review MCP tools in restricted (ask) |
| `.gitignore` | `config/reviews/`, `config/findings/`, `config/elo/` |
| `CLAUDE.md` | Document M2 tools and flow |

### What does NOT change

- `firewall.rs` — no trust evaluation changes (post-MVP, vision C)
- `delegate.rs` — does not interact with reviews
- `queue.rs` — review has its own queue, does not reuse the approval queue
- `audit.rs` — used as-is, review events logged to same audit.log

---

## 7. Scope boundaries

### In MVP

- Review protocol (submit → assign → evaluate → trust gate → ELO update)
- ELO with temporal decay, global score per agent
- Findings store with date/role/category/severity/mission filters
- 6 MCP tools, 3 CLI subcommands
- 6 security invariants hardcoded
- Audit logging of all review events

### Post-MVP (noted, not designed)

- Review protocol as independent library/project
- K-factor in ELO calculation
- ELO per category (not just global)
- ELO influences firewall trust rules (vision C)
- Web dashboard for visualization
- Automatic reviewer selection by ELO (vision B enhancement)

### Explicitly NOT in scope

- Knowledge Bus (async signal passing between agents)
- Agent Spawn via MCP (CC has Agent tool)
- PostToolUse hook injection (CC doesn't support it)
- Real-time review (reviewer is spawned, does work, returns — not streaming)

---

## 8. Open questions (resolved during brainstorming)

| Question | Resolution |
|---|---|
| Is an async bus worth building? | No — CC has SendMessage, bus has more cons than pros |
| Should mission_launch exist? | No — CC Agent tool + worktrees cover this |
| When does peer review trigger? | Agent calls review_submit. Trust-gated: auto for routine, human for exceptions. |
| Should ELO influence real decisions? | MVP: metrics + suggestions (B). Post-MVP: trust rules (C). |
| Does the findings store scale? | JSON files + filtering is fine for dozens of missions. SQLite migration is mechanical if needed. |
| Should decay be in MVP? | Yes — without it, stale ratings mislead. Lazy calculation, no background process. |
| Should K-factor be in MVP? | No — few agents means few reviews, decay solves the urgent problem. |

---

*built with ❤️‍🔥 by AppSec*
