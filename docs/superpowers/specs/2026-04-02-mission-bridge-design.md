# Mission Bridge — Agent Spawn + Review + ELO Pipeline

## Context

Colmena generates missions with per-agent CLAUDE.md files and delegations, but today the pipeline stops at generation — the human must manually copy prompts and spawn agents. There's no automatic review cycle, so ELO ratings stay at 1500/UNCALIBRATED for all agents. The value of the calibration system (M3) is unrealized.

This spec bridges that gap: enriching `library_generate` output so agents flow naturally into spawn → work → review → ELO, while keeping the human in control of all trust-escalating decisions.

## Principles

1. **Human always in the loop** for trust-escalating decisions
2. **Agents never modify other agents** — mentors suggest, humans decide
3. **Existing infra first** — use findings store, ELO engine, calibration as-is
4. **Read-only MCP** — no new tools that write to disk without human confirmation

## Design

### Part A: Mission → Spawn → Review Pipeline

#### A1. Enriched `library_generate` output

`generate_mission()` in `colmena-core/src/selector.rs` gains a new parameter: `elo_ratings: &[AgentRating]` (from `colmena-core/src/elo.rs`).

At generation time:
1. Look up ELO for each role in the pattern
2. Assign **reviewer lead** = role with highest ELO (ties broken by `default_trust_level: "high"`)
3. If all agents are UNCALIBRATED (0 reviews), fall back to the role with `default_trust_level: "high"` (today: `security_architect`)
4. Single-agent missions skip review assignment

The output string from the MCP `library_generate` handler appends a new section:

```
## Review Lead
Assigned: {role_id} (ELO: {elo}, tier: {tier})
Escalation: scores < 7.0 or critical findings → human review

## Agent Prompts (ready for Agent tool)

### {role_id} (slot: {slot})
Prompt: config/missions/{date}-{slug}/agents/{role_id}/CLAUDE.md
```

**Files modified:**
- `colmena-core/src/selector.rs` — `generate_mission()` accepts ELO ratings, assigns reviewer lead
- `colmena-mcp/src/main.rs` — `library_generate` handler calls `elo::leaderboard()` and passes ratings to `generate_mission()`

#### A2. Review instructions injected into CLAUDE.md

Each generated CLAUDE.md gets a closing section based on the agent's role in the review:

**For worker agents:**
```markdown
## Post-Work Protocol

When your work is complete:
1. Commit all changes to your worktree branch
2. Call `mcp__colmena__review_submit` with:
   - artifact_path: your worktree branch path or commit diff
   - author_role: "{role_id}"
   - mission: "{mission_id}"
   - available_roles: [{all_role_ids}]
3. Wait for review feedback
```

**For the reviewer lead:**
```markdown
## Review Responsibility

You are the designated reviewer (highest ELO in this squad).
When you receive review assignments:
1. Read the artifact (diff/commit) thoroughly
2. Call `mcp__colmena__review_evaluate` with scores and findings
3. If score < 7.0 or any critical finding → flag for human review, do NOT auto-complete
4. Category "prompt_improvement" for suggestions about the agent's approach/prompt
```

**Files modified:**
- `colmena-core/src/selector.rs` — `build_agent_claude_md()` (or equivalent) appends review instructions
- `config/library/prompts/review-worker-instructions.md` — template for worker review section (new file)
- `config/library/prompts/review-lead-instructions.md` — template for reviewer lead section (new file)

#### A3. No new MCP tools needed

The pipeline uses existing tools in sequence:
1. `library_generate` (enriched) → generates mission + prompts
2. Human confirms delegations via CLI
3. Human/orchestrator spawns agents via Agent tool
4. Agents work in worktrees
5. Agents call `review_submit` when done (from CLAUDE.md instructions)
6. Reviewer lead calls `review_evaluate` (from CLAUDE.md instructions)
7. ELO updates automatically (existing logic in review_evaluate handler)
8. Human calls `calibrate` when ready (existing CLI)

### Part B: Mentor Suggestions (read-only)

#### B1. Prompt improvement findings

When the reviewer lead evaluates an agent's work and identifies approach/prompt issues, they submit findings with:
- `category: "prompt_improvement"`
- `severity: "medium"` or `"low"` (never critical — these are suggestions, not bugs)
- `description`: what could be improved in the agent's prompt/approach
- `recommendation`: specific suggested change

These findings are stored in the existing findings store (`config/findings/`). No new storage mechanism needed.

#### B2. Human reviews mentor suggestions on-demand

The human can query mentor suggestions at any time:
```
mcp__colmena__findings_query(category: "prompt_improvement")
```

Or via CLI:
```
colmena findings query --category prompt_improvement
```

The human sees:
- Which agent received the suggestion
- What the mentor (high-ELO reviewer) recommends
- The severity and context

The human then decides whether to:
- Edit the role prompt in `config/library/prompts/{role}.md`
- Adjust role permissions in `config/library/roles/{role}.yaml`
- Ignore the suggestion
- Disagree and note it (no action needed — findings are informational)

#### B3. No automatic prompt modification

Agents CANNOT:
- Write to `config/library/prompts/` (protected by path_not_match if needed)
- Write to `config/library/roles/`
- Modify another agent's CLAUDE.md
- Change ELO ratings or calibration settings

The mentor's opinion flows through the findings store, which is append-only and queryable. The human is the only actor who modifies prompts and roles.

### Part C: CLAUDE.md Session Protocol

Already implemented in PR #5. Two lines in CLAUDE.md:
- Before ending: call `session_stats`
- Before spawning: check `library_select`

No additional work needed.

## Files to Create

| File | Purpose |
|------|---------|
| `config/library/prompts/review-worker-instructions.md` | Template appended to worker CLAUDE.md |
| `config/library/prompts/review-lead-instructions.md` | Template appended to reviewer lead CLAUDE.md |

## Files to Modify

| File | Change |
|------|--------|
| `colmena-core/src/selector.rs` | `generate_mission()` accepts ELO ratings, assigns reviewer lead, injects review instructions into CLAUDE.md |
| `colmena-mcp/src/main.rs` | `library_generate` handler queries ELO leaderboard before calling `generate_mission()`, passes ratings |

## Files NOT Modified

- `colmena-core/src/review.rs` — existing review logic unchanged
- `colmena-core/src/elo.rs` — existing ELO calculation unchanged
- `colmena-core/src/findings.rs` — existing findings store unchanged
- `colmena-core/src/calibrate.rs` — existing calibration unchanged
- `config/trust-firewall.yaml` — no new rules needed

## Verification

1. `cargo test --workspace` — no regressions
2. `library_generate` with a test mission:
   - Output includes "Review Lead" section with ELO-based assignment
   - Generated CLAUDE.md files include review instructions
   - Worker CLAUDE.md has `review_submit` instructions
   - Reviewer CLAUDE.md has `review_evaluate` instructions
3. Simulate full cycle:
   - Generate mission → confirm delegations → spawn agents → work → review_submit → review_evaluate
   - Verify ELO updates after review
   - Verify findings with category "prompt_improvement" are queryable
4. Edge cases:
   - All agents UNCALIBRATED → falls back to high trust level role
   - Single-agent mission → no review section generated
   - Mission with no Bash roles → no bash_pattern validation issues

## What This Does NOT Include

- Automatic agent spawning from MCP (human still triggers Agent tool)
- Automatic prompt modification based on findings
- New MCP tools
- Changes to the firewall or delegation system
- Hook on Agent tool (Camino 1 — deferred to future milestone)
