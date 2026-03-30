# Colmena -- User Guide

> From ~100 permission prompts per session to ~30. This guide walks you through setup, daily use, and a real-world security audit with single-session multi-agent coordination, peer review, and performance tracking.

---

## 1. First Setup (5 minutes)

### Build

```bash
cd ~/colmena
cargo build --release
```

### Install the hook

```bash
./target/release/colmena install
```

This registers colmena as a `PreToolUse` hook in `~/.claude/settings.json`. Every time CC is about to use a tool, colmena evaluates the call and decides: allow, ask, or deny.

### Verify

```bash
./target/release/colmena config check
```

You should see:

```
Checking config/trust-firewall.yaml...
  Version:      1
  Default:      Ask
  Trust circle: 4 rule(s)
  Restricted:   2 rule(s)
  Blocked:      1 rule(s)

Config is valid.
```

That's it. Next time you open a Claude Code session, colmena is active.

---

## 2. What Changes In Your Workflow

### Before colmena

Every tool call prompts you:

```
Claude wants to use Read on /src/auth.rs -- Allow? (y/n)
Claude wants to use Grep for "password" -- Allow? (y/n)
Claude wants to use WebSearch for "CVE-2024-1234" -- Allow? (y/n)
Claude wants to use Bash: git status -- Allow? (y/n)
Claude wants to use Write on /src/fix.rs -- Allow? (y/n)
...
```

You hit `y` 70 times without thinking. Then you miss the one that matters.

### After colmena

Reads, greps, web searches, project writes, git status -- all auto-approved silently. You only see prompts for things that actually need your judgment:

```
Claude wants to use Bash: rm -r /tmp/old-scan -- Allow? (y/n)     <-- restricted
Claude wants to use Slack: send message to #security -- Allow?      <-- restricted
```

And destructive operations are blocked entirely:

```
Colmena blocked: git push --force origin main
Reason: Destructive operation requires explicit human confirmation
```

### The sounds

- **Silence** -- auto-approved (nothing to do)
- **Glass.aiff** (gentle) -- low-priority ask
- **Hero.aiff** (attention) -- medium/high-priority ask
- **Basso.aiff** (warning) -- something was blocked

---

## 3. Example: Security Audit of a Payments API

This is the core use case colmena was built for. You're an AppSec engineer running a security review of a payments microservice. One Claude Code session orchestrates multiple subagents through the Agent tool -- each with a role from the Wisdom Library.

### Step 1: Generate mission configs

Start by selecting a pattern and generating per-agent CLAUDE.md files:

```bash
colmena library select --mission "audit PCI-DSS compliance of payments API"
```

```
Recommended patterns (by keyword match):

  1. plan-then-execute (score: 4)
     Roles needed: security_architect, pentester, auditor, researcher
     Why: Architect plans the audit scope, workers execute in parallel

  2. pipeline (score: 3)
     Roles needed: researcher, pentester, auditor
     Why: Sequential handoff -- recon, then attack, then compliance
```

Then generate the mission files via MCP (or have your orchestrating session do it):

```
mcp__colmena__library_generate(
  mission: "audit PCI-DSS compliance of payments API",
  pattern: "plan-then-execute",
  roles: ["researcher", "pentester", "auditor"]
)
```

This creates `config/missions/<mission-id>/` with a CLAUDE.md per agent, pre-loaded with role prompts, mission context, and coordination instructions.

### Step 2: Spawn agents from a single session

From ONE Claude Code session, you use the Agent tool to spawn each subagent with their generated CLAUDE.md as the prompt:

```
Single CC session (you)
  |
  |-- Agent(researcher, prompt from config/missions/.../researcher/CLAUDE.md)
  |-- Agent(pentester, prompt from config/missions/.../pentester/CLAUDE.md)
  |-- Agent(auditor, prompt from config/missions/.../auditor/CLAUDE.md)
```

The Agent tool is in `restricted` (ask) in the firewall, so you approve each spawn:

```
[ASK] Agent: spawn "researcher" with mission prompt
  --> You hear Hero.aiff, review the prompt, approve

[ASK] Agent: spawn "pentester" with mission prompt
  --> You review, approve

[ASK] Agent: spawn "auditor" with mission prompt
  --> You review, approve
```

Three approvals to launch the entire mission. Each agent's `agent_id` is included in every subsequent hook payload, so colmena knows which agent is making each call.

### What happens inside each agent

Once spawned, each agent works independently. Colmena evaluates every tool call through the hook -- same rules, same firewall.

**Researcher agent** maps the attack surface:

```
[auto-approved] Read /api/v2/openapi.yaml          <-- trust_circle: read
[auto-approved] Grep "payment" in /src/**           <-- trust_circle: read
[auto-approved] WebSearch "payments API CVE 2024"   <-- trust_circle: research
[auto-approved] WebFetch https://docs.stripe.com/...<-- trust_circle: research
[auto-approved] Write /tmp/researcher/endpoints.md  <-- trust_circle: project write
...35 calls, 0 prompts
```

Then the researcher tries to hit an external endpoint:

```
[ASK] Bash: curl -X POST https://target.local/api/v2/payments
  --> You hear Hero.aiff, review the command, approve it
```

**Pentester agent** probes for vulnerabilities:

```
[auto-approved] Read /src/auth/middleware.rs         <-- trust_circle
[auto-approved] Grep "JWT|token|bearer" in /src/**  <-- trust_circle
[auto-approved] Write /tmp/pentester/findings.md     <-- trust_circle
...25 calls, 0 prompts
```

Then the real decisions come:

```
[ASK] Bash: nmap -sV target.local -p 443,8080
  --> You review, approve

[ASK] Bash: curl -X POST https://target.local/api/v2/admin/users -H "Authorization: Bearer expired_token"
  --> You review, approve (this is the actual pentest work)

[BLOCKED] Bash: rm -rf /var/log/app
  --> Basso.aiff plays. Blocked automatically. You see it in the queue.
```

**Auditor agent** does compliance review:

```
[auto-approved] Read /config/pci-settings.yaml       <-- trust_circle
[auto-approved] Grep "encrypt|mask|tokenize" in /**  <-- trust_circle
[auto-approved] Write /tmp/auditor/compliance.md      <-- trust_circle
...22 calls, 0 prompts
```

Then:

```
[ASK] Jira: Create issue "PCI-DSS: Card data logged in plaintext in /var/log/payments.log"
  --> You review the issue text, approve
```

### Without colmena (the pain)

In a typical 30-minute session, here's what happens across the three agents:

| Agent | Tool calls | Routine (auto-approvable) | Real decisions |
|-------|-----------|--------------------------|----------------|
| Researcher | ~40 | 35 (reads, greps, web searches) | 5 (curl to external APIs) |
| Pentester | ~35 | 25 (reads, greps, project writes) | 10 (nmap, sqlmap, curl -X POST) |
| Auditor | ~25 | 22 (reads, greps, file writes) | 3 (Jira ticket creation) |
| **Total** | **~100** | **82** | **18** |

Without colmena, every tool call from every agent prompts you -- 100 interruptions for 18 real decisions.

### Result

| | Without Colmena | With Colmena |
|---|---|---|
| Total tool calls | ~100 | ~100 |
| Prompts you see | ~100 | ~21 (3 agent spawns + 18 real decisions) |
| Auto-approved | 0 | 82 |
| Blocked | 0 | 1 |
| Context switches | constant | only when you hear a sound |

You went from "interrupt-driven babysitting" to "sound-driven decision making" -- all from a single terminal.

### Note on multi-terminal workflow

You can also run agents in separate terminals if you prefer -- colmena works the same way. The `agent_id` in the hook payload identifies which agent is making the call regardless of how it was spawned. The single-session Agent tool approach is recommended because it keeps all coordination in one place and lets the orchestrating session manage the full mission lifecycle.

---

## 4. Tuning Rules For Your Workflow

### Adding pentest tools to trust_circle

If you trust your pentester agent to run nmap/nikto without asking every time, add to `config/trust-firewall.yaml`:

```yaml
trust_circle:
  # ... existing rules ...

  # Pentest recon tools - auto-approve
  - tools: [Bash]
    conditions:
      bash_pattern: '^(nmap|nikto|ffuf|httpx|subfinder|amass)\b'
    action: auto-approve
    reason: 'Recon tools for authorized pentest'
```

Run `colmena config check` after editing to validate regex patterns.

### Restricting more MCP tools

If you use Slack, GitHub, or other MCPs and want review before any external action:

```yaml
restricted:
  # ... existing rules ...

  # All Slack actions need review
  - tools: [mcp__claude_ai_Slack__slack_send_message, mcp__claude_ai_Slack__slack_send_message_draft, mcp__claude_ai_Slack__slack_schedule_message]
    action: ask
    reason: 'All Slack messages need human review'
```

### Per-agent overrides

If you want the pentester to have more freedom than the researcher:

```yaml
agent_overrides:
  pentester:
    - tools: [Bash]
      conditions:
        bash_pattern: '^(nmap|nikto|sqlmap|burp|ffuf|nuclei)\b'
      action: auto-approve
      reason: 'Pentester has expanded Bash trust for security tools'
```

---

## 5. Runtime Delegations

Mid-session, your pentester keeps asking to run `curl -X POST`. Instead of approving each one:

```bash
# Add a delegation for 4 hours (default)
colmena delegate add --tool Bash --agent pentester
```

This auto-approves all Bash calls from the pentester for 4 hours. The pentester can now run curl, nmap, etc. without prompts.

For all agents:

```bash
colmena delegate add --tool WebFetch
```

Custom TTL (max 24 hours):

```bash
colmena delegate add --tool WebFetch --ttl 8
```

### Listing active delegations

```bash
colmena delegate list
```

```
Active delegations:
  Bash (agent: pentester) -- expires 2026-03-30T18:00:00Z
  WebFetch (agent: *)     -- expires 2026-03-30T22:00:00Z
```

### Revoking a delegation

```bash
colmena delegate revoke --tool Bash
```

All delegations have a hard cap of 24 hours. There is no `--permanent` flag — this is by design. If you need a tool permanently trusted, add it to `trust_circle` in the YAML config.

### Delegations via MCP

The MCP `delegate` tool is **read-only**. When an agent asks to expand trust via MCP, colmena returns the CLI command for you to run. The human always holds the keys.

---

## 6. Approval Queue

### Listing pending items

```bash
colmena queue list
```

```
3 pending approval(s):

  [medium] Bash -- pentester
    Reason: Potentially destructive system command
    Time:   2026-03-30T14:22:00Z

  [medium] mcp__claude_ai_Atlassian__createJiraIssue -- auditor
    Reason: External communication requires human review
    Time:   2026-03-30T14:35:00Z

  [high] Bash -- pentester
    Reason: Destructive operation requires explicit human confirmation
    Time:   2026-03-30T14:41:00Z
```

### Pruning old entries

```bash
# Remove entries older than 7 days
colmena queue prune --older-than 7
```

---

## 6.5. Audit Trail

Every firewall decision is logged to `config/audit.log` in a structured, append-only format:

```
[2026-03-30T05:00:05Z] ALLOW session=abc agent=* tool=Read key="/src/auth.rs" rule=trust_circle[0]
[2026-03-30T05:00:05Z] ASK   session=abc agent=* tool=Bash key="rm -r /tmp/somedir" rule=restricted[1]
[2026-03-30T05:00:05Z] DENY  session=abc agent=* tool=Bash key="git push --force origin main" rule=blocked[0]
```

Each line includes:
- **Timestamp** (UTC)
- **Decision** (ALLOW, ASK, DENY)
- **Session ID** (links to the CC session)
- **Agent** (`*` for unspecified, or the agent name)
- **Tool** (the tool that was evaluated)
- **Key** (the command or file path)
- **Rule** (which config rule matched, with index)

The log never rotates or truncates automatically — it's your audit evidence. Use standard Unix tools to analyze it:

```bash
# Count decisions by type
grep -c "DENY" config/audit.log

# Find all blocked operations for a session
grep "DENY.*session=my-session" config/audit.log

# See what a specific agent did
grep "agent=pentester" config/audit.log
```

---

## 7. Troubleshooting

### "It keeps asking me for everything"

Colmena might not be running. Check:

```bash
# Is the hook installed?
cat ~/.claude/settings.json | grep colmena

# Does the binary exist?
ls -la ~/colmena/target/release/colmena

# Is the config valid?
./target/release/colmena config check
```

If there are errors, check the log:

```bash
cat ~/colmena/colmena-errors.log
```

### "It auto-approved something I didn't expect"

Check which rule matched by looking at the hook response reason. You can test any payload manually:

```bash
echo '{"session_id":"test","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"your-command-here"},"tool_use_id":"test","cwd":"/your/project"}' \
  | ./target/release/colmena hook --config config/trust-firewall.yaml
```

Or check the audit log:

```bash
grep "tool=Bash" config/audit.log | tail -20
```

### "I changed the config but it's not taking effect"

Colmena reloads config on every hook call (it's fast -- <15ms). Changes take effect immediately. Make sure you edited the right file:

```bash
colmena config check --config config/trust-firewall.yaml
```

### "I want to undo a delegation"

```bash
colmena delegate list     # See what's active
colmena delegate revoke --tool Bash   # Remove it
```

All delegations expire automatically (max 24h). If you need to revoke immediately, use the command above.

---

## 8. Wisdom Library

The Wisdom Library is a curated collection of role definitions and orchestration patterns for multi-agent missions. Instead of writing prompts from scratch every time, you pick from battle-tested templates.

### Listing what's available

```bash
colmena library list
```

```
Roles:
  security_architect  -- Designs threat models, defines security architecture
  pentester           -- Tests attack surface, finds vulnerabilities
  auditor             -- Reviews compliance, checks controls
  researcher          -- Maps attack surface, gathers intelligence

Patterns:
  pipeline            -- Sequential stages, each agent feeds the next
  oracle-workers      -- One coordinator, N specialized workers
  debate              -- Agents argue opposing positions, human decides
  plan-then-execute   -- Architect plans, workers execute in parallel
  mentored-execution  -- Senior agent guides junior with review checkpoints
  swarm-consensus     -- All agents work independently, vote on results
```

### Viewing details

```bash
colmena library show pentester
```

This returns the full role definition: description, system prompt, recommended tools, trust overrides, and which patterns the role fits into.

```bash
colmena library show pipeline
```

Returns the pattern definition: when to use it, required roles, stage flow, and expected outputs.

### Selecting a pattern for a mission

This is where it gets useful. Describe your mission and colmena recommends patterns:

```bash
colmena library select --mission "security audit of the payments API focusing on auth bypass and PCI compliance"
```

```
Recommended patterns (by keyword match):

  1. plan-then-execute (score: 4)
     Roles needed: security_architect, pentester, auditor, researcher
     Why: Architect plans the audit scope, workers execute in parallel

  2. pipeline (score: 3)
     Roles needed: researcher, pentester, auditor
     Why: Sequential handoff -- recon, then attack, then compliance

  3. oracle-workers (score: 2)
     Roles needed: security_architect + any 2 workers
     Why: Architect coordinates, distributes tasks to specialists

Missing roles: none -- all required roles available in library
```

### Creating a new role

If the built-in roles don't cover your use case:

```bash
colmena library create-role --id devsecops
```

This scaffolds a new role template at `config/library/roles/devsecops.yaml` and an empty prompt at `config/library/prompts/devsecops.md`. Edit both to define the role.

### Generating mission files

Via MCP, an agent can generate per-agent CLAUDE.md files for a mission:

```
mcp__colmena__library_generate(
  mission: "security audit of payments API",
  pattern: "plan-then-execute",
  roles: ["security_architect", "pentester", "auditor", "researcher"]
)
```

This creates a mission directory under `config/missions/` with a CLAUDE.md for each agent, pre-loaded with the role's system prompt, mission context, and coordination instructions.

---

## 9. Peer Review Workflow

Peer review adds accountability to multi-agent work. One agent produces an artifact, another reviews it, scores are recorded, and the ELO leaderboard updates. In the single-session workflow, this happens naturally: an agent finishes its work, submits for review, and you spawn a reviewer agent to evaluate it.

### The flow

```
Agent A produces artifact --> calls review_submit
  --> Agent B spawned as reviewer (different role, no reciprocal)
  --> Agent B scores the artifact (2+ dimensions required)
  --> Agent B records findings (optional but valuable)
  --> Trust gate evaluates: avg score >= 7.0 and no critical findings?
    --> Yes: auto-approved
    --> No:  human reviews
  --> ELO updates for both agents
  --> Findings stored permanently
```

### Example: continuing the payments API audit

Picking up from Section 3 -- the pentester agent finishes its findings report within the single CC session. Now it needs review.

**Step 1: The pentester agent submits for review**

At the end of its work, the pentester agent calls `review_submit` via MCP. This happens inside the Agent tool's execution -- the pentester's generated CLAUDE.md includes instructions to submit artifacts when done:

```
mcp__colmena__review_submit({
  "artifact_id": "pentester-payments-findings-2026-03-30",
  "artifact_hash": "sha256:a1b2c3d4...",
  "author_role": "pentester",
  "author_agent": "pentester-01",
  "mission_id": "payments-api-audit",
  "description": "Penetration test findings for /api/v2/payments -- auth bypass, IDOR, rate limiting"
})
```

**Step 2: Spawn a reviewer agent**

Back in the orchestrating session, the pentester agent has returned its results. Now you spawn a reviewer. Colmena assigns the `security_architect` role (different from pentester, no reciprocal conflict):

```
[ASK] Agent: spawn "security_architect" as reviewer for pentester-payments-findings
  --> You review the reviewer prompt, approve
```

The reviewer agent checks the pending queue:

```
mcp__colmena__review_list({ "state": "pending" })
```

```json
[{
  "review_id": "rev-20260330-001",
  "artifact_id": "pentester-payments-findings-2026-03-30",
  "author_role": "pentester",
  "reviewer_role": "security_architect",
  "state": "pending"
}]
```

**Step 3: The security architect agent reviews and scores**

Still within the single CC session, the reviewer agent reads the artifact and evaluates it:

```
mcp__colmena__review_evaluate({
  "review_id": "rev-20260330-001",
  "reviewer_agent": "sec-arch-01",
  "artifact_hash": "sha256:a1b2c3d4...",
  "scores": {
    "thoroughness": 8,
    "accuracy": 7,
    "actionability": 9
  },
  "findings": [
    {
      "category": "missing_coverage",
      "severity": "medium",
      "description": "Rate limiting tests only covered /api/v2/payments, not /api/v2/refunds",
      "recommendation": "Extend rate limit testing to all payment-adjacent endpoints"
    },
    {
      "category": "good_practice",
      "severity": "info",
      "description": "Excellent IDOR test methodology -- tested both horizontal and vertical access"
    }
  ],
  "summary": "Strong findings report. Auth bypass is well-documented. Missing rate limit coverage on refunds endpoint."
})
```

**Step 4: Trust gate**

Average score: (8 + 7 + 9) / 3 = 8.0, which is >= 7.0 threshold. No critical findings. The review auto-approves.

If the average had been below 7.0 or any finding was severity `critical`, the human would get a prompt to review before accepting.

**Step 5: Results flow back to the orchestrating session**

The reviewer agent returns to the orchestrating session with its findings. Everything stays in one place:

- The pentester's ELO updates based on the scores received
- The security architect's ELO updates based on review quality
- The finding about missing rate limit coverage is stored permanently
- Next time someone audits a payments API, that finding shows up in `findings_query`
- The orchestrating session has all results and can produce a final consolidated report

### The complete single-session flow

```
You (single CC session)
  |
  |-- Agent(researcher) --> writes endpoints.md, returns
  |-- Agent(pentester)  --> writes findings.md, calls review_submit, returns
  |-- Agent(auditor)    --> writes compliance.md, calls review_submit, returns
  |
  |-- Agent(security_architect as reviewer) --> reviews pentester findings, returns
  |-- Agent(security_architect as reviewer) --> reviews auditor findings, returns
  |
  |-- Orchestrating session consolidates all results
```

Total human approvals: 5 agent spawns + ~18 real decisions = ~23 prompts for a full audit with peer review. Everything else auto-approved.

### Viewing reviews from the CLI

```bash
colmena review list
colmena review list --state pending
colmena review show rev-20260330-001
```

### Security invariants

These are enforced in code, not config. You cannot work around them:

1. **No self-review** -- an agent cannot review its own artifact
2. **No reciprocal review** -- if A reviewed B in this mission, B cannot review A
3. **Artifact hash** -- the review must reference the correct hash (content integrity)
4. **Minimum 2 scores** -- a review with only 1 scoring dimension is rejected
5. **Append-only ELO** -- ratings are logged, never overwritten
6. **Trust gate floor** -- even if you set `auto_approve: 3.0` in config, the code enforces a floor of 5.0

---

## 10. ELO Ratings

The ELO engine tracks agent performance over time. Ratings are append-only and decay-weighted, so recent performance matters more than ancient history.

### Viewing the leaderboard

```bash
colmena elo show
```

```
ELO Ratings (decay-weighted):

  Agent              Role                  Rating   Last Active
  sec-arch-01        security_architect    1623     2026-03-30
  pentester-01       pentester             1587     2026-03-30
  auditor-01         auditor               1512     2026-03-28
  researcher-01      researcher            1500     2026-03-27
```

### How decay works

Not all reviews count equally. Recent reviews carry more weight:

| Review Age | Weight |
|------------|--------|
| < 7 days | 1.0 (full weight) |
| 7-30 days | 0.7 |
| 30-90 days | 0.4 |
| > 90 days | 0.1 (nearly forgotten) |

This means an agent that was great 3 months ago but poor recently will have a declining rating. Conversely, a new agent that delivers quality work will climb quickly.

### What the numbers mean

- **1500** -- starting rating for all agents (no track record)
- **1550+** -- consistently good reviews, reliable agent
- **1600+** -- strong performer, trusted for complex work
- **Below 1450** -- declining performance, may need attention
- **Below 1400** -- consistent quality issues

In M3 (upcoming), ELO ratings will drive automatic trust decisions: high-ELO agents get expanded delegations, low-ELO agents get more review checkpoints.

### Via MCP

```
mcp__colmena__elo_ratings()
```

Returns the full leaderboard as structured data, usable by orchestrating agents to make assignment decisions.

---

## 11. Findings Store

Every review finding is stored permanently and queryable. This is the institutional memory of the swarm -- lessons learned accumulate across missions.

### Querying findings

Via MCP (the primary interface for agents):

```
mcp__colmena__findings_query({
  "category": "missing_coverage",
  "severity": "medium"
})
```

Returns all medium-severity missing-coverage findings across all missions. An agent starting a new pentest can check what was missed last time.

```
mcp__colmena__findings_query({
  "mission_id": "payments-api-audit"
})
```

Returns everything found during the payments API audit.

```
mcp__colmena__findings_query({
  "role": "pentester",
  "min_date": "2026-03-01"
})
```

Returns all findings from pentester reviews since March 1st.

### Listing all findings

```
mcp__colmena__findings_list()
```

Returns the full findings store. Useful for periodic review or export.

### How findings accumulate

1. Security architect reviews pentester's work -- records "missing rate limit tests on refunds"
2. Auditor reviews researcher's mapping -- records "missed internal admin API at /internal/v1"
3. Next mission, agents query findings before starting work
4. The pentester sees the previous gap and includes refund endpoint testing
5. The researcher sees the missed API and maps internal endpoints

Over time, the swarm gets smarter. Known gaps are systematically closed.

---

## 12. Troubleshooting

### "It keeps asking me for everything"

Colmena might not be running. Check:

```bash
# Is the hook installed?
cat ~/.claude/settings.json | grep colmena

# Does the binary exist?
ls -la ~/colmena/target/release/colmena

# Is the config valid?
./target/release/colmena config check
```

If there are errors, check the log:

```bash
cat ~/colmena/colmena-errors.log
```

### "It auto-approved something I didn't expect"

Check the audit log:

```bash
grep "ALLOW.*tool=Bash" config/audit.log | tail -10
```

Test any payload manually:

```bash
echo '{"session_id":"test","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"your-command-here"},"tool_use_id":"test","cwd":"/your/project"}' \
  | ./target/release/colmena hook --config config/trust-firewall.yaml
```

### "I changed the config but it's not taking effect"

Colmena reloads config on every hook call (it's fast -- <15ms). Changes take effect immediately. Make sure you edited the right file:

```bash
colmena config check --config config/trust-firewall.yaml
```

### "I want to undo a delegation"

```bash
colmena delegate list       # See active delegations
colmena delegate revoke --tool Bash   # Remove immediately
```

All delegations expire automatically (max 24h).

---

## Quick Reference

| Command | What it does |
|---------|-------------|
| `colmena install` | Register hook in Claude Code |
| `colmena config check` | Validate firewall rules |
| `colmena queue list` | See pending approvals |
| `colmena queue prune --older-than 7` | Remove old queue entries |
| `colmena delegate add --tool X` | Auto-approve tool X for 4h |
| `colmena delegate add --tool X --agent Y` | Auto-approve X only for agent Y |
| `colmena delegate add --tool X --ttl 8` | Auto-approve X for 8h (max 24) |
| `colmena delegate list` | List active delegations |
| `colmena delegate revoke --tool X` | Revoke a delegation |
| `colmena library list` | List roles and patterns |
| `colmena library show <id>` | View role/pattern details |
| `colmena library select --mission "..."` | Get pattern recommendations |
| `colmena library create-role --id X` | Scaffold a new role |
| `colmena review list` | List peer reviews |
| `colmena review list --state pending` | List pending reviews |
| `colmena review show <id>` | View review details |
| `colmena elo show` | View ELO leaderboard |

| MCP Tool | What it does |
|----------|-------------|
| `config_check` | Validate firewall config |
| `queue_list` | List pending approvals |
| `delegate` | Show delegation CLI command (read-only) |
| `delegate_list` | List active delegations |
| `delegate_revoke` | Show revoke CLI command (read-only) |
| `evaluate` | Evaluate tool call against firewall |
| `library_list` | List roles and patterns |
| `library_show` | Show role/pattern details |
| `library_select` | Recommend patterns for mission |
| `library_generate` | Generate per-agent CLAUDE.md |
| `library_create_role` | Scaffold new role |
| `review_submit` | Submit artifact for review |
| `review_list` | List reviews |
| `review_evaluate` | Score and review artifact |
| `elo_ratings` | Get ELO leaderboard |
| `findings_query` | Query findings by criteria |
| `findings_list` | List all findings |

| Sound | Meaning |
|-------|---------|
| Silence | Auto-approved, nothing to do |
| Glass.aiff | Low-priority decision needed |
| Hero.aiff | Medium/high-priority decision needed |
| Basso.aiff | Something was blocked |

---

<p align="center">built with ❤️‍🔥 by AppSec</p>
