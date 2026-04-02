# M4: Mentor Prompt Refinement via Debate

## Context

With the mission bridge (M3.5), agents now go through the review cycle: work → review_submit → review_evaluate → ELO update. The reviewer lead (highest ELO) evaluates worker output and can submit findings.

What's missing: a structured process where higher-ELO agents analyze *why* a lower-ELO agent underperformed and suggest concrete prompt improvements. Today, findings describe issues in the work output, but not in the agent's instructions.

## Problem

After several missions, the human sees that `pentester` consistently scores lower than `auditor`. The ELO reflects this, but doesn't explain *why*. The human has to manually read all findings, correlate patterns, and figure out what to change in `config/library/prompts/pentester.md`.

## Solution

Use the existing **debate** and **mentored-execution** patterns to generate prompt improvement suggestions. These suggestions are stored as findings with `category: "prompt_improvement"` and surfaced to the human on-demand. The human decides what to apply.

### Core Principle

**Agents suggest, humans decide.** No agent can modify another agent's prompt, role YAML, or permissions. Suggestions flow through the findings store — append-only, queryable, traceable.

## Design

### 1. Prompt Review Mission

A new use case for `library_generate`: the human triggers a "prompt review" mission after noticing ELO disparities or recurring issues.

**Trigger (human):**
```
"Review pentester's prompt — they've been scoring low on thoroughness"
```

**Pattern selected:** `debate` or `mentored-execution` depending on context:
- `debate` when two agents disagree on approach (offense vs defense perspective on the prompt)
- `mentored-execution` when a clear senior/junior dynamic exists (mentor reviews the mentee's prompt)

**What happens:**
1. `library_generate` creates the mission with the prompt review context
2. The debaters/mentor receive the target agent's current prompt + recent findings + ELO history
3. They analyze and produce structured suggestions
4. Suggestions are submitted as findings via `review_submit` → `review_evaluate`
5. Human queries suggestions via `findings_query(category: "prompt_improvement")`

### 2. Prompt Improvement Finding Structure

Findings with `category: "prompt_improvement"` use a structured description format:

```json
{
  "category": "prompt_improvement",
  "severity": "medium",
  "description": "pentester prompt lacks explicit instruction for checking authorization on every endpoint, not just login flows",
  "recommendation": "Add to pentester.md section 'Testing Methodology': 'For every endpoint discovered, verify authorization controls — not just authentication. Check horizontal and vertical privilege escalation.'"
}
```

Key fields:
- `category`: always `"prompt_improvement"` — this is what makes them queryable
- `severity`: `"medium"` or `"low"` — never `"critical"` or `"high"` (these are suggestions, not bugs)
- `description`: what's weak or missing in the current prompt
- `recommendation`: specific text or structural change to the prompt

No new data structures needed — this uses the existing `Finding` struct.

### 3. Human Review Workflow

The human queries prompt improvement suggestions when ready:

```
mcp__colmena__findings_query(category: "prompt_improvement")
```

Or filtered by target agent:
```
mcp__colmena__findings_query(category: "prompt_improvement", author_role: "pentester")
```

The human sees all suggestions with context (who suggested, which mission, what severity). Then decides:
- **Apply**: edit `config/library/prompts/{role}.md` or `config/library/roles/{role}.yaml`
- **Ignore**: no action needed, the finding stays in the store for reference
- **Disagree**: no action, but the human can note this for calibration context

### 4. New Prompt Template: Review Context

When a prompt review mission is generated, the debate/mentor agents need context about the target agent. A new section is injected into their CLAUDE.md:

```markdown
## Prompt Review Context

You are reviewing the prompt for: **{target_role_name}** ({target_role_id})

### Current Prompt
{contents of config/library/prompts/{target_role}.md}

### Recent ELO Performance
- Current ELO: {elo}
- Trend (7d): {trend}
- Review count: {review_count}
- Trust tier: {tier}

### Recent Findings Against This Agent
{list of recent findings where author_role == target_role_id, last 10}

### Your Task
Analyze this agent's prompt and recent performance. Submit findings with
category "prompt_improvement" for any weaknesses or gaps you identify.
Focus on actionable, specific suggestions — not vague advice.
```

### 5. Implementation

#### Files to Modify

| File | Change |
|------|--------|
| `colmena-core/src/selector.rs` | Add `generate_prompt_review_context()` function that loads target role's prompt, ELO, and recent findings. Called by `generate_mission()` when mission text contains prompt review keywords. |
| `colmena-mcp/src/main.rs` | `library_generate` handler passes target role context when detected |
| `config/library/prompts/prompt-review-context.md` | Template for the review context section (new file) |

#### Files NOT Modified

| File | Reason |
|------|--------|
| `colmena-core/src/findings.rs` | Existing Finding struct already supports `category` field |
| `colmena-core/src/review.rs` | Existing review flow handles prompt_improvement findings |
| `colmena-core/src/elo.rs` | ELO calculation unchanged — prompt improvement findings still generate deltas |
| `config/trust-firewall.yaml` | No new rules needed |

### 6. Detection Heuristic

How does `generate_mission()` know this is a prompt review mission vs a normal mission?

**Option: keyword detection in mission text.** If mission text contains patterns like:
- "review {role} prompt"
- "improve {role} instructions"  
- "why is {role} scoring low"
- "refine {role} approach"

Then `generate_mission()` includes the prompt review context section for the target role.

**Fallback:** if no role is detected, skip the context injection — the mission proceeds as normal. No false positives risk because the context section is additive (doesn't break anything if included unnecessarily).

### 7. Debate Flow for Prompt Review

Using the existing `debate` pattern:

```
Human: "Review pentester prompt — scoring low on thoroughness"
  → library_select → debate pattern recommended
  → library_generate creates mission:

  debater_offense (pentester): 
    "Argue that the current pentester prompt IS adequate.
     Defend its structure and instructions."
  
  debater_defense (auditor):
    "Argue that the pentester prompt needs improvement.
     Identify gaps based on recent low scores."
  
  judge (security_architect) [REVIEWER LEAD]:
    "Evaluate both arguments. Submit findings with
     category 'prompt_improvement' for actionable changes."

  All three receive: prompt review context (current prompt + ELO + findings)
```

The judge's findings become the prompt improvement suggestions. The human reviews them later.

### 8. Mentored Execution Flow for Prompt Review

Using the existing `mentored-execution` pattern:

```
Human: "Help pentester improve — they keep missing auth checks"
  → library_select → mentored-execution recommended
  → library_generate creates mission:

  mentor (security_architect) [REVIEWER LEAD]:
    "Review the mentee's prompt and recent work.
     Identify specific gaps and suggest improvements."
  
  mentee (pentester):
    "Reflect on your recent work. What would you change
     about your approach if you could redo the last mission?"

  Both receive: prompt review context
```

The mentor submits prompt_improvement findings. The mentee's self-reflection provides additional signal.

## Verification

1. `cargo test --workspace` — no regressions
2. Generate a prompt review mission with "review pentester prompt":
   - Verify debate agents receive prompt review context
   - Verify context includes current prompt text + ELO + recent findings
3. Submit prompt_improvement findings via review_evaluate:
   - Verify findings are queryable via `findings_query(category: "prompt_improvement")`
4. Verify no agent can write to `config/library/prompts/` (protected by path_not_match or trust rules)
5. Edge cases:
   - Mission text doesn't mention a valid role → no context injected, normal mission
   - Target role has no findings → context shows "No findings yet"
   - Target role has no ELO events → shows "UNCALIBRATED, ELO: 1500"

## What This Does NOT Include

- Automatic prompt modification (agents suggest, humans decide)
- New MCP tools (uses existing findings_query, review_submit, review_evaluate)
- Changes to ELO calculation (prompt_improvement findings still affect author ELO normally)
- New patterns (uses existing debate + mentored-execution)
- UI for comparing prompt versions (the human edits the .md file directly)

## Scope Estimate

- 1 new function in `selector.rs` (~80 lines): `generate_prompt_review_context()`
- Keyword detection in `generate_mission()` (~20 lines)
- 1 new prompt template (~30 lines)
- MCP handler adjustment (~10 lines)
- Total: ~140 lines of Rust + 1 template file
