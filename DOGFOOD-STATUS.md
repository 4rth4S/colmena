# M7.3 Dogfood — Status and resume plan

**Date written:** 2026-04-20
**Branch:** `dogfood/m73-docs-overhaul` (this worktree)
**Status:** READY TO EXECUTE — everything staged, awaiting the real mission spawn.

---

## One-command resume

From a fresh Claude Code session, after restoring context via the resume prompt below:

```bash
cd /home/fr33m4n/colmena-dogfood-docs
colmena mission spawn \
  --from tests/fixtures/missions/2026-04-20-m73-docs-overhaul.yaml \
  --session-gate
```

What that does:
- Writes `~/.claude/agents/architect.md` (developer.md + auditor.md already exist and passed minimums check).
- Writes ~32 delegations to `~/colmena/config/runtime-delegations.json` (bundled `Read/Write/Edit/Glob/Grep/Bash/review_submit/review_evaluate/findings_query` + bash_patterns per role).
- Creates `~/colmena/config/missions/2026-04-20-m73-docs-overhaul/` with per-agent CLAUDE.md files (scope + task + review protocol pre-filled).
- Writes session-gate sentinel at `~/colmena/config/session-gate.json` with expiry = now + 6h.
- Prints: `Mission Gate: ON (--session-gate override active)`.
- Prints: `Next steps: spawn agent '<role>' with prompt at: <path>` for each of 3 roles.

Then: read each generated CLAUDE.md and spawn the Agent tool with that prompt as the subagent input. Orchestrator (me or the operator) dispatches all 3 in sequence (not parallel — single shared git worktree means sequential edits).

---

## Pre-requisites (all done, verified)

- [x] PR 1 merged to `main` @ `6610437` (M7.3.1 anti-reciprocal per-mission fix).
- [x] PR 2 (`feat/m73-core-auto-closure`, 10 commits, v0.12.1) pushed to origin; NOT merged yet.
- [x] PR 3 (`feat/m73-live-surface`, 11 commits, v0.12.2) pushed to origin; NOT merged yet.
- [x] Binaries installed globally:
  - `/home/fr33m4n/.cargo/bin/colmena` → v0.12.2 (PR 1 + PR 2 + PR 3 combined)
  - `/home/fr33m4n/.cargo/bin/colmena-mcp` → v0.12.2
- [x] Dogfood worktree: `/home/fr33m4n/colmena-dogfood-docs` on branch `dogfood/m73-docs-overhaul` off `feat/m73-live-surface`.
- [x] Mission manifest at `tests/fixtures/missions/2026-04-20-m73-docs-overhaul.yaml`.
- [x] Dry-run validated on 2026-04-20:
  - Mission id: `2026-04-20-m73-docs-overhaul` (date-prefixed, consistent with delegations + mission marker).
  - 3 subagent prompts composed (developer + architect + auditor).
  - 2 existing subagent files respected (developer.md + auditor.md — minimums check passed).
  - 1 subagent file would-be-written (architect.md).
  - 32 delegations would-be-created.
  - Mission Gate: ON (--session-gate override active).
  - Zero disk writes during dry-run (verified: no mission dir, no architect.md).

---

## Bugs found + fixed during dogfood pre-flight

1. **CC comma-separated `tools:` format (commit `0de728c`, pushed)** — operator's existing `~/.claude/agents/*.md` files use the CC idiomatic `tools: Read, Write, Edit` format (comma-separated string). PR 3's parser originally expected a YAML list. Fixed: `SubagentFrontmatter` now has a custom deserializer that accepts both formats; `write_subagent_file` emits the CC idiomatic form to match. 2 new tests added. Affected commit is the 11th on the `feat/m73-live-surface` branch.

## Bugs found during review + deferred (non-blocking)

1. **CLI error sanitization** — errors from CLI subcommands (not the hook path) currently go through `main()`'s catch-all that sanitizes paths. Result: `"parsing frontmatter in <path>"` instead of the actual file. This is the MCP-safety default leaking into CLI UX. Should be fixed as a follow-up PR — not blocking M7.3 merge.

---

## What the mission is meant to prove

The M7.3 milestone's promise: **every `colmena mission spawn` closes the ELO cycle by construction, without operator setup of the 6 recipe mechanisms.**

The 6 mechanisms — and how M7.3 delivers each:

| # | Mechanism | M7.3 delivers via |
|---|---|---|
| 1 | `~/.claude/agents/<role>.md` with `name:` == delegation `agent_id` | PR 3: `mission_spawn` writes the files, respects operator ones that pass minimums |
| 2 | `tools:` frontmatter includes review MCP tools + delegations match | PR 2 T1: reviewer YAMLs updated; PR 2 T5: bundling |
| 3 | Mission marker embedded in spawn prompt | PR 2 T5 + prompt-enrichment (pre-existing in core) |
| 4 | SubagentStop + reviewer gates active | PR 3 T3: Mission Gate auto-activates via `Option<bool>` + session override |
| 5 | Auditor `role_type: auditor` exempt from worker review | Pre-existing (library YAML convention) |
| 6 | Scope-explicit prompts with `review_submit` pre-filled | PR 2 T2 + T5: `emitters::claude_code` + `generate_mission` manifest injection |

Success looks like:
- Developer and architect both call `mcp__colmena__review_submit` for their docs artifacts.
- Auditor receives both reviews (per-mission pool: `["auditor"]`).
- Auditor calls `mcp__colmena__review_evaluate` for each with QPC scores.
- ELO log shows delta entries for developer, architect, auditor.
- `colmena elo show` leaderboard updated.
- `colmena review list --state completed` shows 2 completed reviews.

---

## If something fails

- **"No eligible reviewer"** on `review_submit`: the M7.3.1 fix should prevent this. If it still happens, the anti-reciprocal scope bug regressed — check PR 1's changes in `review.rs` are on main.
- **Agent Stop without review_submit**: Mission Gate didn't engage. Check `~/colmena/config/session-gate.json` exists + isn't expired.
- **CC asks human for each tool call**: delegations didn't bundle correctly. Run `colmena delegate list` and confirm `source: "role"` entries for each agent_id.
- **Subagent file minimums fail for an agent**: run `colmena mission spawn ... --overwrite` to regenerate (keeps `.md.colmena-backup`).

Rollback if the mission gets stuck:
```bash
colmena mission deactivate --id 2026-04-20-m73-docs-overhaul
git checkout -- docs README.md    # in the dogfood worktree
```

`mission deactivate` removes the delegations + session-gate sentinel + auto-generated architect.md (developer.md + auditor.md are preserved because they lack the marker).

---

## Branches + PR reference

| Branch | Version | Origin status | Next action |
|---|---|---|---|
| `main` @ `6610437` | 0.12.0 | PR 1 merged | none |
| `feat/m73-core-auto-closure` | 0.12.1 | pushed (no PR) | open PR after dogfood validates |
| `feat/m73-live-surface` | 0.12.2 | pushed (no PR) | open PR after dogfood validates |
| `dogfood/m73-docs-overhaul` | 0.12.2 | pushed (no PR) | run mission here |

Specs + plans:
- Spec: `docs/superpowers/specs/2026-04-19-m73-elo-cycle-auto-closure-design.md` (local to main repo, gitignored)
- Plans: `docs/superpowers/plans/2026-04-19-pr{1,2,3}-*.md` (local to main repo, gitignored)
