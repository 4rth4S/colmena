# Colmena — User Guide

> A walking example: running a PCI-DSS audit of a payments API with a
> three-agent mission via `colmena mission spawn --from manifest.yaml`.
> From ~100 permission prompts per session to ~20, with auditor review and
> ELO calibration closing the cycle automatically.

This guide is the "I-saw-it-work" artifact. If you want feature-level *why*,
read the [README](../README.md). For architecture internals, see
[docs/dev/architecture.md](dev/architecture.md).

---

## 1. Setup (2 minutes)

```bash
cd ~/colmena
cargo build --workspace --release
./target/release/colmena setup
```

`colmena setup` does everything in one command:

- Registers Pre/PostToolUse/PermissionRequest/SubagentStop hooks in
  `~/.claude/settings.json`.
- Registers the MCP server in `~/.mcp.json` (global).
- Validates config and library files.
- Prints a verification checklist.

Restart Claude Code after setup to pick up the MCP server.

**Preview first?** Run `colmena setup --dry-run`.

**Standalone install** (release binary, no repo clone): `setup` embeds all
default config + library files in the binary. Run anywhere and it creates
`~/.colmena/` with everything needed. Override with `COLMENA_HOME=/custom
colmena setup`.

**Install Mode B** — point your own Claude Code at this repo and let it
bootstrap everything. See [docs/install-mode-b.md](install-mode-b.md).

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

`colmena doctor` runs a full health check (binary, hooks, MCP, library,
runtime, permissions).

---

## 2. What Changes In Your Workflow

### Before Colmena

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

### After Colmena

Reads, greps, web searches, project writes, `git status` — all auto-approved
silently. You only see prompts for things that actually need judgment:

```
Claude wants to use Bash: rm -r /tmp/old-scan -- Allow? (y/n)     # restricted
Claude wants to use Slack: send message to #security -- Allow?     # restricted
```

Destructive operations are blocked entirely:

```
Colmena blocked: git push --force origin main
Reason: Destructive operation requires explicit human confirmation
```

### The Sounds

- **Silence** — auto-approved (nothing to do).
- **Glass.aiff** (gentle) — low-priority ask.
- **Hero.aiff** (attention) — medium/high-priority ask.
- **Basso.aiff** (warning) — something was blocked.

---

## 3. The Walking Example: PCI-DSS Audit of a Payments API

This is the core use case. You're an AppSec engineer auditing a payments
microservice. One Claude Code session orchestrates three specialist
subagents. As of M7.3, the entire setup is **one command** — manifest in,
mission out.

### Step 1: Write the Mission Manifest

Create `mission.yaml`:

```yaml
id: 2026-04-21-payments-audit
pattern: plan-then-execute
mission_ttl_hours: 8

roles:
  - name: security_architect
    scope:
      owns: ["missions/2026-04-21-payments-audit/threat-model.md"]
      forbidden: ["src/**"]
    task: |
      Produce the threat model for the payments API. STRIDE + DREAD.
      Identify PCI-DSS scope boundary. Output: threat-model.md.

  - name: pentester
    scope:
      owns: []
      forbidden: ["src/**"]
    task: |
      Execute recon + auth bypass + IDOR + rate-limit tests against the
      payments API. Output: findings.md per class, referencing the threat
      model section numbers.

  - name: auditor
    scope:
      owns: []
      forbidden: []
    task: |
      Evaluate security_architect and pentester artifacts with QPC
      (Quality + Precision + Comprehensiveness, 1-10 each). Block any
      critical finding from reaching the client report.
```

What this does:

- `id` is stamped into the `<!-- colmena:mission_id=... -->` marker embedded
  in every agent's prompt and every ELO event.
- `pattern: plan-then-execute` is resolved against the Wisdom Library.
- `mission_ttl_hours: 8` caps every generated delegation at 8 hours.
- `scope.owns` becomes the `[SCOPE]` section in each agent's CLAUDE.md.
- `scope.forbidden` becomes the "Do NOT touch" list.
- `task` is pre-filled into `[TASK]`; the review protocol is auto-appended
  with `review_submit` parameters for the operator's agent.

Don't know which pattern to pick? Ask Colmena:

```bash
colmena library select --mission "PCI-DSS audit of payments API, focus on auth bypass and IDOR"
```

Or, if you're not sure whether Colmena is overkill for the job:

```bash
colmena suggest "fix a typo in the README"
# -> complexity: trivial, agents: 1
# -> You don't need Colmena for this. Use Claude Code directly.

colmena suggest "PCI-DSS audit of payments API, focus on auth bypass, IDOR, and rate limiting"
# -> complexity: medium, agents: 3-4
# -> Ready to go: colmena library select --mission "..."
```

### Step 2: Spawn the Mission (one command)

```bash
colmena mission spawn --from mission.yaml
```

What happens (you'll see this on stdout):

```
Mission spawned: 2026-04-21-payments-audit
  OK 3 subagent prompts composed
  OK 7 delegations created
  WARN 1 delegation preserved (already exist with sufficient TTL)
       - Read/pentester (expires 2026-04-22T02:14:00Z)
  OK 3 subagent files written
  INFO Mission Gate: auto-activated (enforce_missions unset, role delegations live)
```

Three things happened on disk:

1. **`~/.claude/agents/security_architect.md`,
   `pentester.md`, `auditor.md`** — written with `name: <role_id>` in
   frontmatter, `colmena_auto_generated: true` marker, and `tools:`
   including `mcp__colmena__review_submit` (or `review_evaluate` for the
   auditor) and `mcp__colmena__findings_query`. The `name` field is what CC
   propagates as the agent identity in hook payloads — critical for ELO to
   track the right agent.
2. **`config/runtime-delegations.json` updated** — 7 delegations for the
   three roles: `Read`, `Write` scoped to `${MISSION_DIR}`, `Bash` with role-
   specific `bash_patterns`, `mcp__colmena__*` for review + findings. All
   expire in 8 hours (or at the manifest's `mission_ttl_hours` cap).
3. **`config/missions/2026-04-21-payments-audit/agents/<role>/CLAUDE.md`** —
   one file per agent with the composed prompt (role base + scope + task +
   review protocol + inter-agent directive + mission marker).

**Mission Gate auto-activation** — because `enforce_missions` is unset in
`trust-firewall.yaml` and the spawn just added `source: "role"` delegations,
the gate flips to ON automatically. Agent tool calls without a mission
marker will Ask from now until those delegations expire. If your YAML
explicitly says `enforce_missions: false`, Colmena respects that — and if
the mission has 3+ roles, it aborts with three explicit options
(`--session-gate` one-off, flip YAML to `true`, or `--no-gate-confirmed`
observation mode). The operator always chooses consciously.

### Step 3: Spawn Subagents from a Single Session

From your orchestrating CC session, spawn each role via the Agent tool
using the generated `CLAUDE.md` as the prompt. The Agent tool is in
`restricted` (Ask), so you approve each spawn:

```
[ASK] Agent: spawn "security_architect" with mission prompt
  -> You hear Hero.aiff, review the prompt, approve
[ASK] Agent: spawn "pentester" with mission prompt
  -> You review, approve
[ASK] Agent: spawn "auditor" with mission prompt
  -> You review, approve
```

Three approvals to launch the entire mission.

### What Happens Inside Each Agent

Each agent works independently. Colmena evaluates every tool call through
the PreToolUse hook — same rules, same firewall, same audit log.

**`security_architect`** reads the codebase, produces the threat model:

```
[auto-approved] Read /api/v2/openapi.yaml       # trust_circle: Read
[auto-approved] Grep "payment" in /src/**        # trust_circle: Grep
[auto-approved] Write /missions/.../threat-model.md  # scoped Write delegation
...
[MCP] review_submit(mission, author_role="security_architect",
                    artifact_paths=["threat-model.md"],
                    available_roles=["auditor"])
  -> Review rev-001 assigned to auditor
```

Then the architect attempts to Stop. SubagentStop fires:

```
SubagentStop: agent=security_architect
  - source:"role" delegation? yes
  - role_type:"auditor"? no
  - has_submitted_review()? yes (rev-001)
  -> approve
```

The architect returns to the orchestrating session.

**`pentester`** probes for vulnerabilities:

```
[auto-approved] Read /src/auth/middleware.rs       # trust_circle
[auto-approved] Grep "JWT|token|bearer" in /src/**
[auto-approved] Write /missions/.../findings.md     # scoped
...
[ASK] Bash: nmap -sV target.local -p 443,8080
  -> You review, approve (this is the actual pentest work)
[ASK] Bash: curl -X POST https://target.local/api/v2/admin/users -H "Authorization: Bearer expired_token"
  -> You review, approve
[BLOCKED] Bash: rm -rf /var/log/app
  -> Basso.aiff plays. Blocked automatically.
[MCP] review_submit(mission, author_role="pentester", ..., available_roles=["auditor"])
```

**`auditor`** evaluates both artifacts with QPC:

```
[auto-approved] Read /missions/.../threat-model.md
[auto-approved] Read /missions/.../findings.md
[MCP] review_evaluate(review_id="rev-001",
                      scores={quality: 8, precision: 9, comprehensiveness: 7},
                      findings=[...],
                      evaluation_narrative="Strong STRIDE coverage, missing DREAD...")
[MCP] review_evaluate(review_id="rev-002",
                      scores={quality: 9, precision: 8, comprehensiveness: 9},
                      findings=[{category: "missing_coverage", severity: "medium", ...}])
```

The auditor has `role_type: auditor` in YAML, so SubagentStop exempts it —
it is the reviewer, not a review author.

### Step 4: The Cycle Closes

After both reviews complete:

- `config/elo-events.jsonl` has 4 new events (2 authors + 2 reviewers, each
  with their delta).
- `config/reviews/completed/rev-001.json` and `rev-002.json` exist.
- `config/findings/2026-04-21-payments-audit/*.json` stores each finding
  permanently.
- `config/alerts.json` may have entries if any score < 5.0 or any critical
  finding was recorded.

Check the leaderboard:

```bash
colmena elo show
```

```
ELO Ratings (decay-weighted):

  Agent                Role                   Rating   Last Active
  auditor              auditor                1585     2026-04-21
  security_architect   security_architect     1572     2026-04-21
  pentester            pentester              1541     2026-04-21
```

Calibrate:

```bash
colmena calibrate run
```

After 3+ reviews, the ELO tier determines firewall overrides. An `Elevated`
pentester (ELO ≥ 1600, 3+ reviews) gets auto-approve on the role's
`tools_allowed` in future missions. A `Probation` agent (ELO < 1100) has
Bash and WebFetch blocked.

### Step 5: Close the Mission

```bash
colmena mission deactivate --id 2026-04-21-payments-audit
```

This:

1. Clears the session-gate sentinel (`session-gate.json`, if present).
2. Revokes all delegations for the mission from
   `runtime-delegations.json`.
3. Marks each agent_id in `revoked-missions.json` (kill switch — any
   subsequent calls from those agents return `deny` at PreToolUse step 7,
   even if CC had learned session rules via PermissionRequest).
4. Deletes `~/.claude/agents/security_architect.md`, `pentester.md`,
   `auditor.md` — but **only those with the `colmena_auto_generated: true`
   marker**. Operator-authored files are never touched.

### Result: Count the Prompts

In a typical 30-minute audit across three agents:

| Agent              | Tool calls | Routine (auto-approved)                      | Real decisions    |
|--------------------|------------|----------------------------------------------|-------------------|
| security_architect | ~30        | 28 (reads, greps, scoped writes)             | 2 (external web)  |
| pentester          | ~40        | 28 (reads, greps, scoped writes, MCP review) | 12 (nmap, curl)   |
| auditor            | ~20        | 20 (reads, MCP review_evaluate)              | 0                 |
| **Total**          | **~90**    | **~76**                                      | **~14**           |

| Without Colmena            | With Colmena (M7.3)                                      |
|----------------------------|----------------------------------------------------------|
| ~90 prompts                | ~17 prompts (3 Agent spawns + ~14 real decisions)        |
| 0 auto-approved            | ~76 auto-approved (silent)                               |
| 0 blocked                  | 1 blocked (`rm -rf /var/log/app`)                        |
| Constant context switches  | Only when you hear a sound                                |
| ELO cycle never closes     | ELO cycle closes for free — no manual review_submit setup|

You went from "interrupt-driven babysitting" to "sound-driven decision
making" — with accountability per agent, per role, permanently recorded.

---

## 4. Scaling: Delegations Mid-Session

The mission manifest handles the common case. Sometimes mid-session, you
want to expand trust for an ad-hoc reason:

```bash
# Auto-approve all Bash calls from pentester for 4h (default)
colmena delegate add --tool Bash --agent pentester

# Custom TTL (max 24h)
colmena delegate add --tool WebFetch --ttl 8

# Scoped to one CC session only
colmena delegate add --tool Bash --agent pentester --session $COLMENA_SESSION
```

List + revoke:

```bash
colmena delegate list
colmena delegate revoke --tool Bash
```

All delegations have a hard cap of 24 hours. There is no `--permanent` flag
— if you need a tool permanently trusted, add it to `trust_circle` in YAML.

**MCP `delegate` is read-only.** An agent that calls the `delegate` MCP
tool gets back the CLI command for you to run. The human always holds the
keys.

---

## 5. Tuning Rules For Your Workflow

### Adding Pentest Tools to `trust_circle`

If you trust your pentester agent to run nmap/nikto without asking every
time, add to `config/trust-firewall.yaml`:

```yaml
trust_circle:
  - tools: [Bash]
    conditions:
      bash_pattern: '^(nmap|nikto|ffuf|httpx|subfinder|amass)\b'
    action: auto-approve
    reason: 'Recon tools for authorized pentest'
```

Run `colmena config check` after editing.

### Per-Agent Overrides

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

YAML `agent_overrides` beat ELO overrides — if you pin a rule by hand, ELO
calibration cannot undo it.

**Matching key.** The firewall looks up each override block against two fields
in every hook payload:

1. `agent_id` — the per-invocation identity Claude Code assigns. For
   `mission_spawn`-generated delegations this is the stable role id
   (`pentester`, `researcher`). For custom subagents spawned directly, recent
   CC versions emit an opaque per-spawn hash that changes every run.
2. `agent_type` — the stable agent class name, which equals the `name:` field
   in the subagent `.md` frontmatter (e.g. `cron-worker`, `pentester`).

The lookup tries `agent_id` first, then falls back to `agent_type`. The
practical effect: author your `agent_overrides` against the stable agent
name, and they apply regardless of which field CC populates. This makes
single-agent scoped permissions usable outside the mission_spawn workflow
(e.g. launchd-triggered autonomous subagents, one-shot triage bots), while
preserving the mission flow's existing semantics.

Runtime delegations follow the same dual-field match: a delegation created
with `colmena delegate add --tool X --agent cron-worker` fires whether
CC passes that name as `agent_id` or `agent_type`.

### Restricting MCP Tools

```yaml
restricted:
  - tools:
      - mcp__claude_ai_Slack__slack_send_message
      - mcp__claude_ai_Slack__slack_schedule_message
    action: ask
    reason: 'All Slack messages need human review'
```

---

## 6. Approval Queue and Audit Trail

### Queue

```bash
colmena queue list
```

```
3 pending approval(s):

  [medium] Bash -- pentester
    Reason: Potentially destructive system command
    Time:   2026-04-21T14:22:00Z

  [high]   Bash -- pentester
    Reason: Destructive operation requires explicit human confirmation
    Time:   2026-04-21T14:41:00Z
```

Prune:

```bash
colmena queue prune --older-than 7   # remove entries older than 7 days
```

### Audit Trail

Every firewall decision is logged to `config/audit.log`:

```
[2026-04-21T05:00:05Z] ALLOW session=abc agent=pentester tool=Read key="/src/auth.rs" rule=trust_circle[0]
[2026-04-21T05:00:05Z] ASK   session=abc agent=pentester tool=Bash key="nmap -sV target.local" rule=restricted[1]
[2026-04-21T05:00:05Z] DENY  session=abc agent=pentester tool=Bash key="git push --force origin main" rule=blocked[0]
```

Event types include `ALLOW`, `ASK`, `DENY`, `DELEGATE_CREATE`,
`DELEGATE_MATCH`, `DELEGATE_EXPIRE`, `DELEGATE_REVOKE`, `MISSION_ACTIVATE`,
`MISSION_DEACTIVATE`, `ROLE_TOOLS_ALLOW` (PermissionRequest auto-approve),
`AGENT_STOP` (SubagentStop approved after review verification), and
`TIMEOUT`.

Log rotates at 10 MiB (`audit.log` → `audit.log.1`).

Analyze with standard tools:

```bash
grep -c "DENY" config/audit.log                         # count blocks
grep "DENY.*session=my-session" config/audit.log         # per-session
grep "agent=pentester" config/audit.log                  # per-agent
```

---

## 7. Wisdom Library

Battle-tested role definitions and orchestration patterns. Instead of
writing prompts from scratch, pick templates.

```bash
colmena library list
```

```
Roles (Security):
  security_architect  -- Designs threat models, defines security architecture
  pentester           -- Tests attack surface, finds vulnerabilities
  auditor             -- Reviews compliance, checks controls
  researcher          -- Maps attack surface, gathers intelligence
  web_pentester       -- Caido-native web application pentester
  api_pentester       -- Caido-native API pentester

Roles (Development):
  developer           -- Writes code, implements features, runs builds
  code_reviewer       -- Reviews code quality, finds bugs (read-only)
  tester              -- Writes tests, runs suites, measures coverage
  architect           -- System design, tradeoff analysis, technical docs

Roles (DevOps / SRE):
  devops_engineer     -- CI/CD, infra-as-code, deployments
  sre                 -- Reliability, observability, incident response
  platform_engineer   -- Developer platforms, internal tooling

Patterns (Security):
  pipeline            -- Sequential stages, each agent feeds the next
  oracle-workers      -- One coordinator, N specialized workers
  debate              -- Agents argue opposing positions, human decides
  plan-then-execute   -- Architect plans, workers execute in parallel
  mentored-execution  -- Senior agent guides junior with review checkpoints
  swarm-consensus     -- All agents work independently, vote on results
  caido-pentest       -- Caido-native pentesting workflow

Patterns (Development):
  code-review-cycle   -- Developer implements, auditor reviews, feedback loop
  docs-from-code      -- Architect reads, developer writes docs, auditor validates
  refactor-safe       -- Developer refactors, tester validates, auditor approves
```

```bash
colmena library show pentester        # role details
colmena library show plan-then-execute # pattern details
colmena library select --mission "…"   # recommend patterns
colmena library create-role --id devsecops --description "…"
colmena library create-pattern --id threat-hunt --description "…"
```

See [Contributing](dev/contributing.md) for how to add roles and patterns
that ship in the binary.

---

## 8. Peer Review and the ELO Cycle

Peer review adds accountability. The cycle is closed automatically by
`mission spawn` since M7.3:

```
Agent finishes work -> review_submit (MCP)
  SubagentStop blocks Stop until review_submit succeeded.
Auditor spawned as reviewer (or picks up pending via review_list)
  -> review_evaluate (MCP)
  SubagentStop blocks Stop until review_evaluate completed.
Trust gate (hardcoded floor 5.0): avg score >= 7.0 + no critical finding
  -> auto-approved
  otherwise -> alerts.json entry + human review via alerts_list / alerts_ack
ELO updates for both author and reviewer
  append to elo-events.jsonl
Findings stored permanently
  findings/<mission>/*.json — queryable by role, category, severity, date, mission
```

Review invariants (enforced in `review.rs`, cannot be bypassed):

1. No self-review (`author != reviewer`).
2. No reciprocal review **within the same mission** (M7.3.1 — per-mission,
   not global; cross-mission reviewer reuse is now supported).
3. Artifact hash must match at submit and evaluate.
4. Minimum 2 score dimensions per evaluation.
5. Append-only ELO — ratings logged, never overwritten.
6. Trust gate floor 5.0 — even config `auto_approve: 3.0` cannot bypass it.

### Viewing Reviews

```bash
colmena review list
colmena review list --state pending
colmena review show rev-20260421-001
```

### Querying Findings

Via MCP (primary interface for agents):

```
mcp__colmena__findings_query({
  category: "missing_coverage",
  severity: "medium"
})

mcp__colmena__findings_query({
  mission_id: "2026-04-21-payments-audit"
})

mcp__colmena__findings_query({
  role: "pentester",
  min_date: "2026-03-01"
})
```

Or via CLI for ad-hoc listing:

```bash
colmena review list --state completed
```

The findings store is the institutional memory. A pentester starting a new
engagement queries previous missions' `missing_coverage` findings and
includes them in scope automatically.

---

## 9. Dynamic Trust Calibration

After agents accumulate ≥3 auditor reviews, their ELO determines a trust tier.

```bash
colmena calibrate show
#  pentester              ELO:1650  reviews:5   tier:ELEVATED
#  researcher             ELO:1480  reviews:4   tier:STANDARD
#  new-agent              ELO:1500  reviews:1   tier:UNCALIBRATED

colmena calibrate run
#  Trust tier changes:
#    pentester -- standard -> elevated (ELO: 1650)
#  Updated config/elo-overrides.json.
```

Tiers:

| Tier          | ELO          | Min reviews | Effect                                                   |
|---------------|--------------|-------------|----------------------------------------------------------|
| Uncalibrated  | any          | < 3         | Default rules (warm-up)                                  |
| Elevated      | ≥ 1600       | ≥ 3         | Auto-approve role's `tools_allowed`                      |
| Standard      | 1300–1599    | ≥ 3         | Default rules                                            |
| Restricted    | 1100–1299    | ≥ 3         | Ask for everything                                       |
| Probation     | < 1100       | ≥ 3         | Bash + WebFetch blocked, others Ask                      |

Safety properties:

- **Blocked rules always win** — ELO cannot override blocked ops
  (`git push --force`, `rm -rf /`, etc.).
- **YAML beats ELO** — human-defined `agent_overrides` in
  `trust-firewall.yaml` outrank ELO-derived overrides.
- **Elevated Bash guard** — even Elevated agents get Ask for Bash unless
  the role defines explicit `bash_patterns`.
- **Kill switch** — `colmena calibrate reset` instantly clears all ELO
  overrides.
- **Warm-up** — agents need 3+ reviews before calibration applies (no blind
  trust).

---

## 10. Output Filtering (PostToolUse)

Colmena doesn't just control what tools can do — it cleans up what they
return. PostToolUse intercepts Bash outputs, saving tokens and keeping
context clean.

Pipeline order (clean first, hard cap last):

1. **ANSI strip** — remove escape sequences.
2. **Stderr-only** — if exit ≠ 0 and stderr has content, discard stdout noise.
3. **Dedup** — collapse 3+ consecutive identical lines.
4. **Truncate** — max 150 lines / 30K chars (below CC's 50K limit). Preserves
   head + tail, cuts from the middle.

Then the static **prompt-injection detector** scans for 10 canonical patterns
(OWASP LLM-01 + tag injection + exfiltration) and prepends a warning banner
if matched — without mutating the content.

Config in `config/filter-config.yaml`:

```yaml
max_output_lines: 150
max_output_chars: 30000       # < CC's 50K
dedup_threshold: 3
error_only_on_failure: true
strip_ansi: true
enabled: true

[prompt_injection]
enabled: true
patterns_custom: []
```

Measure impact:

```bash
colmena stats
colmena stats --session $COLMENA_SESSION
```

Shows total chars saved, estimated tokens saved, average reduction %, top
commands by savings. Data comes from `config/filter-stats.jsonl` (append-
only, 10MB rotation).

Safety guarantees:

- If any filter panics, it's skipped — others continue.
- If the entire pipeline fails, the original output returns unchanged.
- PostToolUse never returns `ask` or `deny` — filter or passthrough.

---

## 11. Alerts

When `review_evaluate` triggers `NeedsHumanReview` (score < 5.0 or critical
finding), an alert is written to `config/alerts.json`. Alerts are
**append-only** — agents cannot acknowledge or delete them.

Via MCP:

```
mcp__colmena__alerts_list({acknowledged: false})
mcp__colmena__alerts_ack({alert_ids: ["a_..."]})
```

`session_stats` shows the unacknowledged alert count before you close a
session. If there's an open critical alert, you see it before it's too
late.

---

## 12. Auditor Calibration (optional, human-initiated)

Want to check your auditors are calibrated well? M6.4 added a bilingual
(en/es) calibration flow:

```
mcp__colmena__calibrate_auditor()
-> Returns the last N auditor evaluations with narrative + alternatives.

mcp__colmena__calibrate_auditor_feedback({review_id, choice, correction?})
-> choice:
     "agreed"        -> auditor ELO +10
     "chose_alternative" -> auditor ELO -5
     "wrote_correction"   -> auditor ELO -10, saved as finding
```

Use sparingly — this is a human-driven sanity check, not a routine task.

---

## 13. Troubleshooting

### "It keeps asking me for everything"

```bash
cat ~/.claude/settings.json | grep colmena       # hook installed?
ls -la ~/colmena/target/release/colmena           # binary exists?
./target/release/colmena config check              # config valid?
cat ~/colmena/colmena-errors.log                   # error log?
colmena doctor                                     # full health check
```

### "It auto-approved something I didn't expect"

Check the rule that matched via the hook response reason, or inspect the
audit log:

```bash
grep "ALLOW.*tool=Bash" config/audit.log | tail -10
```

Test any payload manually:

```bash
echo '{"session_id":"test","hook_event_name":"PreToolUse",
       "tool_name":"Bash","tool_input":{"command":"your-command-here"},
       "tool_use_id":"test","cwd":"/your/project"}' \
  | ./target/release/colmena hook --config config/trust-firewall.yaml
```

### "I changed the config but it's not taking effect"

Colmena reloads config on every hook call (<15 ms). Changes are immediate.
Double-check you edited the right file:

```bash
colmena config check --config config/trust-firewall.yaml
```

### "Mission Gate won't activate / stay active"

With M7.3 the gate has three states. Check:

```bash
colmena doctor
# -> Mission Gate: ON (auto-activated — enforce_missions unset, role delegations live)
#    or
# -> Mission Gate: ON (--session-gate override active, expires 2026-04-21T22:00:00Z)
#    or
# -> Mission Gate: OFF (explicit in YAML, operator choice)
```

If your YAML says `enforce_missions: false` and you want the gate one-off
for a mission, use `colmena mission spawn --session-gate`. Clears on
`mission deactivate`.

### "ELO isn't moving"

Common cause: agent name mismatch. Check that:

1. `~/.claude/agents/<role>.md` has `name: <role_id>` in frontmatter — must
   match the delegation's `agent_id`.
2. `tools_allowed` on the role YAML includes `mcp__colmena__review_submit`
   (workers) or `mcp__colmena__review_evaluate` (reviewers).
3. The mission prompt includes the `<!-- colmena:mission_id=… -->` marker.

`mission spawn` handles all three automatically since M7.3. If you're
running a manual flow, see `colmena mission prompt-inject --mode terse`.

### "I want to undo a delegation immediately"

```bash
colmena delegate list
colmena delegate revoke --tool Bash
```

All delegations expire automatically (max 24h). For mission-wide revocation:
`colmena mission deactivate --id <mission>`.

---

## 14. Quick Reference

### CLI

| Command | What it does |
|---------|-------------|
| `colmena install` | Register hooks in Claude Code |
| `colmena setup [--dry-run] [--force]` | One-command onboarding |
| `colmena config check` | Validate firewall rules |
| `colmena doctor` | Full health check |
| `colmena queue list` | Pending approvals |
| `colmena queue prune --older-than 7` | Remove old queue entries |
| `colmena delegate add --tool X` | Auto-approve X for 4h |
| `colmena delegate add --tool X --agent Y [--ttl 8] [--session S]` | Scoped delegation |
| `colmena delegate list` | List active delegations |
| `colmena delegate revoke --tool X [--agent Y]` | Revoke a delegation |
| `colmena library list` | List roles and patterns |
| `colmena library show <id>` | Role / pattern details |
| `colmena library select --mission "…"` | Pattern recommendations |
| `colmena library create-role --id X --description "…"` | Scaffold a new role |
| `colmena library create-pattern --id X --description "…"` | Scaffold a new pattern |
| `colmena mission list` | Active missions with delegation counts |
| `colmena mission spawn --from manifest.yaml` | One-step mission creation (M7.3) |
| `colmena mission spawn --mission "…" --pattern X --role A --role B …` | Shortcut, no manifest |
| `colmena mission deactivate --id X` | Revoke all delegations + subagent files for a mission |
| `colmena mission prompt-inject --mode terse` | Emit INTER_AGENT_DIRECTIVE for manual Agent spawns |
| `colmena review list [--state pending]` | List auditor reviews |
| `colmena review show <id>` | Review detail |
| `colmena elo show` | ELO leaderboard |
| `colmena calibrate run` | Apply ELO-based trust tiers |
| `colmena calibrate show` | Current tiers per agent |
| `colmena calibrate reset` | Clear all ELO overrides |
| `colmena suggest "…"` | Mission sizing — should you use Colmena? |
| `colmena stats [--session X]` | Filter + firewall savings summary |

### MCP (27 tools)

| Tool | What it does |
|------|-------------|
| `config_check` | Validate firewall config |
| `queue_list` | Pending approvals |
| `delegate` | Return delegation CLI command (read-only) |
| `delegate_list` | Active delegations |
| `delegate_revoke` | Return revoke CLI command (read-only) |
| `evaluate` | Evaluate a tool call against the firewall |
| `library_list` | Roles + patterns |
| `library_show` | Role / pattern details |
| `library_select` | Recommend patterns for a mission |
| `library_generate` | Generate per-agent CLAUDE.md |
| `library_create_role` | Create role (intelligent defaults) |
| `library_create_pattern` | Create pattern (topology detection) |
| `review_submit` | Submit artifact for auditor review |
| `review_list` | List reviews |
| `review_evaluate` | Score + review artifact |
| `elo_ratings` | ELO leaderboard |
| `findings_query` | Query findings by criteria |
| `findings_list` | Recent findings |
| `alerts_list` | List alerts |
| `alerts_ack` | Acknowledge alert(s) |
| `calibrate_auditor` | Present auditor evaluations for human calibration |
| `calibrate_auditor_feedback` | Adjust auditor ELO based on human feedback |
| `mission_spawn` | One-step mission creation |
| `mission_suggest` | Mission sizing analysis |
| `mission_deactivate` | Return deactivation CLI command (read-only) |
| `calibrate` | Show calibration state + actions |
| `session_stats` | Prompts saved + tokens saved + alert count |

### Sounds

| Sound       | Meaning                                    |
|-------------|--------------------------------------------|
| Silence     | Auto-approved, nothing to do               |
| Glass.aiff  | Low-priority decision needed               |
| Hero.aiff   | Medium/high-priority decision needed       |
| Basso.aiff  | Something was blocked                      |

---

## See Also

- [README](../README.md) — project overview, value prop, personas.
- [Getting Started](user/getting-started.md) — zero-to-running in 5 minutes.
- [Use Cases](user/use-cases.md) — concrete workflows.
- [Install Mode B](install-mode-b.md) — point your CC at the repo.
- [Architecture](dev/architecture.md) — system internals.
- [Contributing](dev/contributing.md) — how to add rules, roles, patterns, tools.
- [Internals](dev/internals.md) — edge cases, safety contracts, gotchas.

<p align="center">built with ❤️‍🔥 by AppSec</p>
