# Use Cases

Concrete workflows showing what Colmena does differently than vanilla Claude Code.

---

## 1. Solo Developer: Trust Firewall as Safety Net

**Scenario.** You're using Claude Code for feature development. You want it to read files, run tests, and edit code freely -- but you don't want it force-pushing, deleting directories, or merging PRs without your say.

**Setup.** Just `colmena setup`. The default `trust-firewall.yaml` handles this out of the box:

- Auto-approves: `Read`, `Write`, `Edit` (within project), `Glob`, `Grep`, safe Bash (`ls`, `cat`, `grep`, `git log`), `cargo build`, `cargo test`
- Asks: `rm`, `curl -X`, `git push`, `Agent` spawning
- Blocks: `git push --force`, `rm -rf /`, `gh pr merge`

**What Colmena does differently.** Without Colmena, Claude Code prompts you for every tool call or you grant blanket permissions. With Colmena, you get surgical control: safe operations flow without interruption, dangerous ones always pause.

**Result.** Typical solo session: ~80% of tool calls auto-approved, ~15% asked (you confirm with one keypress), ~5% blocked. Every decision logged to `config/audit.log`.

```bash
# Check your session stats anytime
colmena stats
```

---

## 2. Feature Implementation: Plan, Build, Review

**Scenario.** You need to add a new feature that touches multiple modules. You want an architect to plan the approach, a developer to implement it, and a reviewer to validate quality before you merge.

**Step 1: Check if you need Colmena**

```bash
colmena suggest "add rate limiting to the API with tests and review"
```

Output tells you: complexity score, recommended number of agents, relevant domains. If it recommends 3+ agents, Colmena adds value over vanilla Claude Code.

**Step 2: Spawn the mission**

Use the MCP tool from within a Claude Code session:

```
mcp__colmena__mission_spawn(
  mission="add rate limiting to the API with tests and review"
)
```

This does everything in one call:
1. Selects the best orchestration pattern (likely "Plan Then Execute" for feature work)
2. Maps real roles to topology slots -- assigns architect, developer, code reviewer
3. Generates a `CLAUDE.md` for each agent with role prompt, mission context, trust level, and review instructions
4. Creates scoped delegations (8-hour TTL) for each agent's allowed tools
5. Assigns the highest-ELO agent as reviewer lead
6. Returns ready-to-paste prompts for each agent

**Step 3: Launch agents**

Paste the generated prompts into Claude Code `Agent` tool calls. Each agent has:
- A mission marker (`<!-- colmena:mission_id=... -->`) for tracking
- Scoped delegations auto-approved by the PermissionRequest hook
- SubagentStop hook enforcing peer review before the agent can stop

**What Colmena does differently.** Without Colmena, you'd manually write each agent's prompt, hope they don't step on each other's files, and have no way to enforce review. With Colmena, each agent has exactly the permissions its role needs, peer review is mandatory, and you can revoke an entire mission's permissions instantly with `colmena mission deactivate --id <mission-id>`.

---

## 3. Documentation Sprint: Docs from Code (Real Example)

**Scenario.** Your codebase has grown and documentation is stale. You want to generate accurate docs from actual source code, not hallucinated descriptions.

**This is a real example.** The documentation you're reading right now was created using this exact workflow. Here's how it went:

**The pattern.** "Docs from Code" (sequential topology, 3 agents):

1. **Architect** (stage 1): Reads the entire codebase, produces structured architecture notes with file paths and line numbers
2. **Developer** (stage 2): Takes the notes, writes the documentation
3. **Auditor** (stage 3): Reviews the docs for accuracy against the source code

```bash
colmena library show docs-from-code
```

**Spawn it:**

```
mcp__colmena__mission_spawn(
  mission="create comprehensive documentation from source code",
  pattern_id="docs-from-code"
)
```

**What actually happened in our run.** We expanded the 3-agent pattern to 6 agents across 4 waves:

```
Wave 1:  [Architect]                  ← read all 4 crates, produced structured notes
              │
         ┌────┴────┐
Wave 2:  [User Writer]  [Dev Writer]  ← wrote docs in parallel (no file conflicts)
              │              │
Wave 3:  [User Review]  [Dev Review]  ← reviewed in parallel (20 issues found + fixed)
              └────┬────┘
Wave 4:       [Auditor]               ← final validation, 7 spot-checks against source
```

**Results:**
- 6 documentation files produced (getting-started, use-cases, architecture, contributing, internals + this README)
- 20 issues caught and fixed before delivery (fabricated examples, wrong exit codes, broken commands)
- ~327 tool calls across all agents, ~78% auto-approved by Colmena

**What Colmena does differently.** The sequential pattern enforces order -- writers can't start until the architect's notes exist. The auditor catches hallucinated APIs or wrong file paths. Each agent's trust is scoped: the architect can't modify code, the developer can't modify source files. And the reviewers found real bugs -- commands that would have failed if a user tried them.

---

## 4. Code Review Cycle: Iterative Quality

**Scenario.** You have a feature branch that needs thorough review. You want systematic quality improvement, not just a single pass.

**The pattern.** "Code Review Cycle" uses a sequential topology with 3 agents:

1. **Developer**: Implements or refactors the code
2. **Code Reviewer**: Reviews for quality, best practices, bugs (read-only -- no Write/Edit access)
3. **Auditor**: Evaluates both the code and the review quality

```bash
colmena library show code-review-cycle
```

The cycle repeats: developer implements → reviewer flags issues → developer fixes → reviewer re-checks. The auditor scores each round via the QPC framework (Quality + Precision + Comprehensiveness, 1-10 each).

**Spawn it:**

```
mcp__colmena__mission_spawn(
  mission="review and improve error handling in the config module"
)
```

**What Colmena does differently.** The code reviewer is genuinely read-only -- Colmena enforces that it cannot call Write or Edit, only Read/Glob/Grep. Review findings feed into ELO ratings. Over time, agents that produce better reviews earn elevated trust; poor reviewers get restricted.

**Key commands during the cycle:**

```bash
colmena review list --state pending    # See pending reviews
colmena review show r_1713200000_a1b2  # Review details
colmena elo show                       # Check trust standings
colmena calibrate run                  # Apply ELO-based trust adjustments
```

---

## 5. Large Refactoring: Safe Changes with Review

**Scenario.** You need to refactor a core module -- rename types, restructure files, update all call sites. You want confidence that nothing breaks.

**The pattern.** "Refactor Safe" (sequential topology, 3 agents):

1. **Developer**: Makes the structural changes, runs tests at each step
2. **Code Reviewer**: Reviews the diff for correctness, missed call sites, API breakage (read-only -- no Write/Edit)
3. **Auditor**: Validates that tests pass, no regressions, and the refactoring is complete

```bash
colmena library show refactor-safe
```

**Spawn it:**

```
mcp__colmena__mission_spawn(
  mission="refactor the config module to split parsing from validation"
)
```

**What Colmena does differently.** The code reviewer is genuinely read-only -- Colmena enforces that it cannot call Write or Edit, only Read/Glob/Grep. This prevents the reviewer from "helpfully" fixing things and muddying the diff. The developer's Bash access includes `cargo test` and `cargo clippy` but not destructive commands. If the refactoring breaks tests, the auditor flags it before you merge.

---

## Common Operations Across All Use Cases

### Checking mission status

```bash
colmena mission list                # Active missions with delegation counts
```

### Revoking a mission mid-session

```bash
colmena mission deactivate --id 2026-04-15-refactor-config-module
```

This revokes all delegations for every agent in the mission. Even if Claude Code has "learned" to allow those tools via session rules, the PreToolUse hook's mission revocation check fires first and denies.

### Monitoring agent trust

```bash
colmena elo show                    # ELO leaderboard with ratings
colmena calibrate show              # Trust tiers per agent
colmena calibrate run               # Apply ELO → firewall adjustments
colmena calibrate reset             # Clear all ELO overrides (emergency)
```

### Querying findings

Findings are queried via MCP tools from within a Claude Code session (ask Claude to call them):

```
mcp__colmena__findings_query(severity="critical")
mcp__colmena__findings_query(mission_id="2026-04-15-refactor-config-module")
mcp__colmena__findings_list()
```

### Checking alerts

Low review scores trigger alerts automatically. Query and acknowledge them via MCP tools:

```
mcp__colmena__alerts_list(severity="high")
mcp__colmena__alerts_ack(alert_id="all")  # After reviewing
```

---

## When to Use Colmena vs. Vanilla Claude Code

Use `colmena suggest` to get a data-driven recommendation:

```bash
colmena suggest "fix a typo in the README"
# → complexity=low, recommended_agents=1, verdict: use CC directly

colmena suggest "add rate limiting to the API with tests and review"
# → complexity=medium, recommended_agents=3+, verdict: use Colmena

colmena suggest "refactor auth module, migrate database schema, update all consumers"
# → complexity=high, recommended_agents=5+, verdict: use Colmena
```

The threshold is 3+ recommended agents. Below that, Colmena's orchestration overhead isn't worth it -- just use Claude Code directly. At 3+, the trust firewall, scoped permissions, peer review enforcement, and ELO calibration start paying off.

---

## What's Next

- [Getting Started](getting-started.md) -- installation and first run in 5 minutes
- [User Guide](../guide.md) -- detailed walkthrough with a payments API audit example
- [Architecture](../dev/architecture.md) -- how the four crates work together
- [Contributing](../dev/contributing.md) -- set up your dev environment and submit PRs

---

built with ❤️‍🔥 by AppSec
