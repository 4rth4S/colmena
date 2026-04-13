# M6.4 — Enforced Peer Review via SubagentStop + Centralized Auditor

## Problem

Colmena missions inject review instructions into agent CLAUDE.md files, but peer review is voluntary. Nothing prevents workers from stopping without calling `review_submit`. The ELO system accumulates no data because reviews are optional.

## Solution

1. **SubagentStop hook** blocks mission workers from stopping until they call `review_submit`
2. **Centralized auditor** replaces cross-review — one role evaluates all workers with consistent criteria
3. **Alerts system** surfaces low-score reviews in-CC without blocking autonomous flow
4. **Auditor calibration** lets the human validate auditor accuracy on-demand via MCP

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Who reviews | Centralized auditor | Consistent criteria, meaningful ELO, no deadlocks |
| Enforcement | SubagentStop hook | Blocks at the semantic moment of stopping |
| Worker unblocks when | `review_submit` done | Doesn't wait for auditor — agile |
| Low score handling | Warning, no block | Autonomous flow, human checks when they want |
| Auditor calibration | Human opt-in `calibrate_auditor` | No interruption during missions |
| Notifications | In-CC only (MCP tools) | No desktop noise |
| Payload type | Separate `SubagentStopPayload` | Lifecycle events != tool events |

## Architecture

### Hot Path (Autonomous, no human)

Worker finishes -> calls `review_submit` -> attempts to stop -> SubagentStop hook checks delegation (`source: "role"`) -> checks `role_type != "auditor"` -> checks review exists for agent+mission -> approve or block.

Auditor: picks up pending reviews -> calls `review_evaluate` with scores + findings + `evaluation_narrative` -> alert if trust_gate returns NeedsHumanReview -> stops (exempt from review check).

### Cold Path (Human Opt-In)

`calibrate_auditor` MCP tool: presents last N auditor evaluations with reasoning narrative + 3 alternative approaches the auditor considered. Presented in session language (stored in English).

`calibrate_auditor_feedback` MCP tool: human picks best option. Auditor ELO adjusts: +10 (agreed), -5 (chose auditor's own alternative), -10 (wrote own correction, saved as finding).

## New Components

- `SubagentStopPayload` + `SubagentStopResponse` in hook.rs (separate from HookPayload)
- `has_submitted_review()` in review.rs
- `evaluation_narrative: Option<String>` in ReviewEntry
- `role_type: Option<String>` in Role struct (auditor.yaml: `role_type: auditor`)
- `colmena-core/src/alerts.rs` — new module: Alert struct, create/list/ack
- 4 new MCP tools: `alerts_list`, `alerts_ack`, `calibrate_auditor`, `calibrate_auditor_feedback`
- Hook routing refactor: peek `hook_event_name` from raw JSON, then deserialize to correct type
- SubagentStop registered as 4th hook in settings.json

## Security Properties

1. Safe fallback: SubagentStop error -> approve (never trap agent)
2. Auditor exempt via role YAML, not delegation flag (human-controlled)
3. Alerts append-only, agents can't ack
4. `calibrate_auditor_feedback` in restricted (ELO modification needs oversight)
5. `alerts.json` in path_not_match (agents can't write directly)

built with ❤️‍🔥 by AppSec
