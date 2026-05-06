# Colmena — Reference Guide

> A subsystem-by-subsystem reference for the trust firewall, delegations, missions,
> manifests, ELO calibration, MCP tools, audit trail, and security invariants.
> v0.14.0 — 31 MCP tools — 622 tests.

This is the deep reference. If you want the 5-minute setup, see
[Getting Started](user/getting-started.md). For concrete workflows with
copy-pasteable manifests, see [Use Cases](user/use-cases.md).

---

## 1. Firewall

The trust firewall evaluates every tool call before it reaches Claude Code.
Decisions are deterministic — YAML rules compiled to regex at load time, no
LLM calls in the hot path. Each decision is written to the audit log with the
matching rule ID.

### How it works

Every tool call passes through the PreToolUse hook. The firewall evaluates
against these checks in strict order:

```
blocked > delegations > agent_overrides > runtime-agent-overrides > ELO >
restricted > chain_aware > chain_guard > mission_revocation > trust_circle >
defaults
```

The first match wins. If no rule matches, the default is `ask` (safe
fallback).

| Position | Check | Result |
|----------|-------|--------|
| 1 | blocked | deny (not overridable) |
| 2 | delegations | allow (TTL-scoped) |
| 3 | agent_overrides (YAML) | allow or ask |
| 4 | runtime-agent-overrides | allow (from auto-elevate) |
| 5 | ELO calibration | allow or ask |
| 6 | restricted | ask |
| 7 | chain_aware | per-piece eval |
| 8 | chain_guard | ask (legacy) |
| 9 | mission_revocation | deny |
| 10 | trust_circle | allow |
| 11 | defaults | ask |

### Chain-aware Bash evaluation (M7.10)

Bash commands with `&&`, `||`, `;`, or `|` are split into individual pieces
(quote-aware). Each piece is re-evaluated against blocked, restricted, and
trust_circle rules.

- One block in any piece → the whole command is blocked.
- One ask in any piece → the whole command asks.
- All pieces auto-approved → the whole command is auto-approved.

Subshells (`$(...)`) and backticks fall back to the legacy chain_guard (ask).
Bare assignments (`KEY=value`) auto-approve as no-op pieces.

The chain-aware evaluator is on by default. Disable it in `trust-firewall.yaml`:

```yaml
chain_aware: false
```

Setting `chain_aware: false` activates the legacy chain_guard, which asks on
every chain operator. This increases friction — only disable if a specific
chain pattern breaks under the new evaluator.

### Trust circle rules

Add tools that your agents use frequently:

```yaml
trust_circle:
  - tools: [Read, Grep, Write]
    conditions:
      path_within: /home/user/project
    action: auto-approve
    reason: 'Read, grep, and write within project directory'

  - tools: [Bash]
    conditions:
      bash_pattern: '^(git status|git diff|git log|git branch|git stash)\b'
    action: auto-approve
    reason: 'Safe git read operations'

  - tools: [Bash]
    conditions:
      bash_pattern: '^(cargo build|cargo test|cargo fmt|cargo check)\b'
    action: auto-approve
    reason: 'Rust build and test commands'

  - tools: [Bash]
    conditions:
      bash_pattern: '^(cd|ls|find|grep|cat|head|tail|wc|sort|uniq|echo|printf)\b'
    action: auto-approve
    reason: 'Safe read-only shell commands'
```

### Restricted rules

Tools that need human judgment every time:

```yaml
restricted:
  - tools:
      - mcp__claude_ai_Slack__slack_send_message
    action: ask
    reason: 'All Slack messages need human review'

  - tools:
      - Agent
    action: ask
    reason: 'Agent spawn requires human approval'
```

### Blocked rules

Operations that must never execute:

```yaml
blocked:
  - tools: [Bash]
    conditions:
      bash_pattern: '^(git push --force|git push -f)\b'
    action: deny
    reason: 'Force push is blocked — PRs are merged by human only'
```

### Per-agent overrides (YAML)

Override trust per agent. These beat ELO calibration — if you pin a rule by
hand, ELO cannot undo it.

```yaml
agent_overrides:
  pentester:
    - tools: [Bash]
      conditions:
        bash_pattern: '^(nmap|nikto|sqlmap|ffuf|nuclei)\b'
      action: auto-approve
      reason: 'Pentester runs recon tools without asking'
```

The firewall matches against `agent_id` first, then falls back to
`agent_type`. `agent_type` is the stable agent class name from the subagent
file's `name:` frontmatter. Author overrides against the stable name and they
apply regardless of which field CC populates.

### Validate the config

```bash
colmena config check
```

You should see:

```
Config valid.
Version: 1
Trust circle: 4 rule(s)
Restricted: 2 rule(s)
Blocked: 1 rule(s)
```

Changes to `trust-firewall.yaml` take effect immediately — the config is
reloaded on every hook call (<15 ms).

### MCP tool

```bash
mcp__colmena__config_check()   # validate firewall config
mcp__colmena__evaluate()       # test a tool call against the firewall
```

---

## 2. Delegations

Delegations are time-scoped permission grants. They authorize a specific tool
for a specific agent for a limited time. Add them mid-session without editing
YAML.

### CLI

```bash
# Auto-approve all Bash from pentester for 4 hours
colmena delegate add --tool Bash --agent pentester

# Custom TTL (max 24 hours)
colmena delegate add --tool WebFetch --ttl 8

# Scoped to one CC session only
colmena delegate add --tool Bash --agent pentester --session $COLMENA_SESSION

# List active delegations
colmena delegate list

# Revoke a delegation
colmena delegate revoke --tool Bash
```

### Rules

- All delegations have a TTL. Max 24 hours. No `--permanent` flag.
- Delegations without `expires_at` are skipped on load (no permanent
  delegations via JSON injection).
- Expired delegations are logged as DELEGATE_EXPIRE events on load.
- `--session` limits delegation scope to one CC session. Without it, the
  delegation applies to all sessions (global scope — use with caution).
- Bash delegations require `bash_pattern` or `path_within` conditions.
  `bash_pattern` is validated as a compilable regex before persisting.

### Bash patterns

When delegating Bash, you must specify what commands are allowed:

```bash
# Allow specific commands with regex
colmena delegate add --tool Bash --agent pentester \
  --condition 'bash_pattern' --value '^(nmap|curl|ffuf)\b'

# Allow commands within a project directory
colmena delegate add --tool Bash --agent developer \
  --condition 'path_within' --value '/home/user/project'
```

The `bash_pattern` is matched against the full command string. It must be a
valid regex. The `path_within` matches against the working directory.

Bash delegations without either condition are rejected at creation time.

### Session scoping

```bash
# Get the current session ID
echo $COLMENA_SESSION

# Scope delegation to one session
colmena delegate add --tool Bash --agent pentester \
  --session "$COLMENA_SESSION"

# Without --session, the delegation is global — applies to all CC sessions.
# A warning is shown for global delegations.
```

Session-scoped delegations are written to `runtime-delegations.json` with a
`session_id` field. The firewall checks the session ID on every hook call
and skips delegations that don't match the active session.

### MCP tools (read-only)

The MCP `delegate` and `delegate_revoke` tools return CLI commands for the
human to run. Agents cannot create delegations directly.

```bash
mcp__colmena__delegate()        # returns CLI command for delegation
mcp__colmena__delegate_list()   # list active delegations
mcp__colmena__delegate_revoke() # returns CLI command for revocation
```

---

## 3. Missions

Missions are the unit of multi-agent work. A mission spawns a squad of agents
with role-specific prompts, delegations, and an auditor. The SubagentStop
hook enforces that workers submit reviews before stopping.

### Lifecycle

```
manifest → init → validate → spawn → work → review → deactivate
```

### Lifecycle in detail

```
                   +-- manifest (YAML)
                   |
        +--------- init ---------+
        |       --slug            |
        |       --from-history    |
        +-------------------------+
                   |
             +---- validate ----+
             | schema check      |
             | path blocklist    |
             | sentinel regexes  |
             | count caps        |
             +-------------------+
                   |
            +---- spawn ------+
            | from manifest   |
            | from CLI args   |
            +-----------------+
            |     |       |
            v     v       v
       agents  auditor  delegations
            |     |       |
            v     v       v
       work -> review_submit -> review_evaluate -> ELO update
            |
       SubagentStop gate checks:
         1. role delegation?     -- no: approve
         2. role_type: auditor?  -- yes: approve (exempt)
         3. review_submit done?  -- no: BLOCK
         4. pending reviews?     -- yes: BLOCK
            |
            v
       deactivate or abort
          revoke delegations
          remove subagent files
          write revoked-missions.json
```

### CLI

### What spawn does

When you run `colmena mission spawn --from manifest.yaml`, the following happens:

1. The manifest is parsed and validated (same checks as `colmena mission validate`).
2. For each agent in `agents[]`, an agent instance is created with role, task,
   and scope.
3. Delegations are created in `runtime-delegations.json` for each agent's tools.
4. Subagent `.md` files are written to `~/.claude/agents/<role_id>.md`.
5. Agent prompts are generated in the mission directory
   (`config/missions/<mission_id>/agents/<role>/CLAUDE.md`).
6. Runtime-agent-overrides are written to
   `config/runtime-agent-overrides.json` for per-agent scope and bash patterns.
7. If role-scoped delegations exist and `enforce_missions` is not explicitly
   `false`, Mission Gate activates automatically.

The output on stdout looks like:

```
Mission spawned: 2026-05-06-payments-audit
  OK 3 subagent prompts composed
  OK 7 delegations created
  OK 3 subagent files written
  INFO Mission Gate: auto-activated (enforce_missions unset, role delegations live)
```

Four things happen on disk:

1. **Agent prompts are generated** — one CLAUDE.md per agent with role base,
   scope, task, review protocol, inter-agent directive, and mission marker
   (`<!-- colmena:mission_id=... -->`).

2. **Delegations are created** — Read, Write scoped to `${MISSION_DIR}`,
   Bash with role-specific `bash_patterns`, MCP review tools. All expire at
   `mission_ttl_hours`.

3. **Subagent files are written** — `~/.claude/agents/<role>.md` with
   `name: <role_id>` in frontmatter, `colmena_auto_generated: true` marker.

4. **Runtime-agent-overrides are saved** — per-agent scope and bash patterns
   from the manifest are written to `runtime-agent-overrides.json`.

### SubagentStop gate

When a mission agent tries to stop, the SubagentStop hook checks:

1. Is this a role-scoped delegation? If not, approve.
2. Is this the auditor (role_type: auditor)? If yes, approve.
3. Has the agent called `review_submit`? If not, block.
4. Does the agent have pending reviews as reviewer? If yes, block until
   `review_evaluate` is called.

This ensures no agent escapes the ELO cycle.

### Mission Gate

When `source: role` delegations exist and `enforce_missions` is not
explicitly `false`, the gate activates automatically. Agent tool calls
without a mission marker will Ask.

Check gate state with `colmena doctor`.

### MCP tools

```bash
mcp__colmena__mission_spawn()        # one-step mission creation
mcp__colmena__mission_suggest()      # analyze mission complexity
mcp__colmena__mission_deactivate()   # returns CLI command (read-only)
mcp__colmena__mission_validate()     # validate a manifest file
mcp__colmena__mission_status()       # show mission status dashboard
mcp__colmena__mission_abort()        # returns CLI command (read-only)
mcp__colmena__mission_manifest_show() # preview manifest contents
```

---

## 4. Manifests (v1)

The `.mission.yaml` format is the declarative way to describe a mission.
Write it by hand or generate it with `colmena mission init`.

### Structure

```yaml
version: 1
mission_id: 2026-05-06-payments-audit
description: PCI-DSS compliance audit of the payments microservice
author: appsec-team

agents:
  - role: security_architect
    count: 1
    task: |
      Produce a STRIDE threat model for the target application.
      Output: missions/2026-05-06-payments-audit/threat-model.md
    scope:
      paths:
        - /home/user/project/src/payments
      path_not_match:
        - src/secrets
      bash_patterns:
        extra_allow:
          - '^cat /home/user/project/src/payments/.*\.(rs|toml|yaml)$'
        extra_deny:
          - 'rm'
          - 'curl'

  - role: pentester
    count: 2
    instances:
      - pentester-web
      - pentester-api
    model: claude-sonnet-4-7
    task: |
      Test auth bypass, IDOR, and rate limiting.

  - role: auditor
    count: 1
    task: |
      Evaluate artifacts with QPC framework.
      Quality + Precision + Comprehensiveness (1-10 each).

scope:
  paths:
    - /home/user/project
  path_not_match:
    - node_modules
    - target
  bash_patterns:
    extra_allow:
      - '^(cargo build|cargo test)\b'
    extra_deny:
      - 'git push'

mission_gate: enforce
auditor_pool:
  - auditor
budget:
  max_hours: 8
  max_agents: 12
acceptance_criteria:
  - All critical findings resolved before deployment
  - No regression in existing test suite
tags:
  - pci-dss
  - payments
```

### Fields

| Field | Required | Description |
|-------|----------|-------------|
| version | yes | Must be 1 |
| mission_id | yes | ASCII alphanumeric + hyphens |
| description | yes | Max 512 characters |
| author | yes | Who created this manifest |
| agents | yes | Array of agent definitions |
| scope | no | Global scope applied to all agents |
| mission_gate | no | enforce, observe, or off (default: enforce) |
| auditor_pool | no | Roles eligible to be auditor (default: ["auditor"]) |
| budget | no | max_hours (max 24), max_agents (max 25) |
| acceptance_criteria | no | Array of strings, max 10 items |
| tags | no | Array of strings |

### Agent fields

| Field | Required | Description |
|-------|----------|-------------|
| role | yes | Role ID from the Wisdom Library |
| count | no | Instance count (1-5, default 1) |
| instances | no | Instance names (must match count) |
| task | no | Free-text task description |
| scope | no | Per-agent scope overrides |
| model | no | Preferred model (e.g. claude-sonnet-4-7) |

### Scope fields

| Field | Description |
|-------|-------------|
| paths | Absolute paths the agent can access |
| path_not_match | Glob patterns to exclude |
| bash_patterns.extra_allow | Regex patterns for auto-approved Bash |
| bash_patterns.extra_deny | Regex patterns for blocked Bash |

### Validation

```bash
colmena mission validate mission.yaml
```

Validation checks:

- All paths are absolute and don't contain `..`
- No paths are in hard-blocked prefixes (`/etc`, `/root`, `/var/log`,
  `/proc`, `/sys`, `/boot`, `/dev`)
- No paths end with blocked suffixes (`.ssh`, `.aws`, `.config/gcloud`,
  `.config/op`, `.gnupg`, `.kube`)
- `extra_allow` regexes start with `^`, are not catch-all, don't match
  sentinel strings (`rm -rf /`, `dd if=/dev/`, etc.), and aren't chain-greedy
- `extra_deny` regexes pass the same sentinel check
- `extra_allow` max 20 regexes, `extra_deny` max 50
- Total agents across all roles does not exceed 25 (or `budget.max_agents`)
- Per-role `count` does not exceed 5
- Exactly 0 or 1 auditor instances
- `version` is 1
- No forbidden fields: `role_type`, `default_trust_level`,
  `disable_audit_log`, `disable_blocked_tier`, `bypass_session_gate`

### Auto-elevate

When the operator answers Y twice to the same Bash binary skeleton (e.g.,
`curl` twice, `kubectl get pods` twice) within a time window, Colmena
auto-creates a session-scoped delegation. The third call passes without
prompting.

Skeletons are extracted from individual pieces of a Bash chain. Known
meta-commands (git, cargo, docker, kubectl, gh, npm, go, etc.) include the
subcommand in the skeleton (e.g., `git diff`, `cargo build`).

Auto-elevate is configured in `trust-firewall.yaml`:

```yaml
auto_elevate:
  enabled: true
  max_skeleton_length: 40
  window_minutes: 60
  max_count: 5
```

State is stored in `config/auto-elevate-state.json` (max 200 entries).

### Runtime-agent-overrides

When a manifest spawns a mission, per-agent scope and bash patterns are
written to `config/runtime-agent-overrides.json`. These act like YAML
`agent_overrides` but are managed at runtime — created by `mission spawn`,
cleared by `mission deactivate`/`abort`.

```bash
colmena mission status --id 2026-05-06-payments-audit
```

Shows current runtime overrides, delegations, subagent files, and alerts.

### --from-history

Generate a mission manifest from Agent spawn history in the audit log:

```bash
colmena mission init --from-history
colmena mission init --from-history --session s_abc123
```

Scans `config/audit.log` for Agent tool spawns within session scope. Outputs
a `.mission.yaml` that recreates the squad composition. Agents not found in
the library are flagged for manual review.

### elo_bucket_for

The manifest can reference ELO buckets for role-based trust levels.
`elo_bucket_for()` maps a role ID to its ELO bucket string. This is used
internally by the mission generator to assign reviewer lead and trust tiers.

---

## Wisdom Library

The Wisdom Library holds battle-tested role definitions and orchestration
patterns. Instead of writing prompts from scratch, pick a template from the
library when defining your manifest's agent roles.

### Roles (13 built-in)

| Role | Category | Description |
|------|----------|-------------|
| security_architect | Security | Threat models, security architecture |
| pentester | Security | Attack surface testing, PoC exploits |
| auditor | Security | Compliance review, QPC evaluation |
| researcher | Security | Surface mapping, intelligence gathering |
| web_pentester | Security | Caido-native web application pentesting |
| api_pentester | Security | Caido-native API pentesting |
| developer | Development | Code, features, builds |
| code_reviewer | Development | Code quality review (read-only) |
| tester | Development | Test writing, suite execution |
| architect | Development | System design, technical docs |
| devops_engineer | DevOps | CI/CD, infra-as-code, deployments |
| sre | DevOps | Reliability, observability, incident response |
| platform_engineer | DevOps | Developer platforms, internal tooling |

### Patterns (10 built-in)

| Pattern | Topology | Description |
|---------|----------|-------------|
| pipeline | Sequential | Stages, each agent feeds the next |
| oracle-workers | Fan-out-merge | One coordinator, N specialized workers |
| debate | Adversarial | Opposing positions, human decides |
| plan-then-execute | Hierarchical | Architect plans, workers execute |
| mentored-execution | Hierarchical | Senior guides junior with review checkpoints |
| swarm-consensus | Peer | All work independently, vote on results |
| caido-pentest | Hierarchical | Caido-native pentesting workflow |
| code-review-cycle | Iterative | Developer implements, auditor reviews, loop |
| docs-from-code | Sequential | Architect reads, developer writes, auditor validates |
| refactor-safe | Iterative | Developer refactors, tester validates, auditor approves |

### CLI

```bash
# List all roles and patterns
colmena library list

# Show details for a specific role
colmena library show pentester

# Show details for a specific pattern
colmena library show plan-then-execute

# Get pattern recommendations for a mission
colmena library select --mission "PCI-DSS audit of web application"

# Create a new role (8 categories)
colmena library create-role --id devsecops --description "Developer security training"

# Create a new pattern (7 topologies)
colmena library create-pattern --id threat-hunt --description "Proactive threat hunting"
```

### Role model binding

Roles can declare a preferred model in their YAML definition (e.g.,
`claude-sonnet-4-7`, `claude-opus-4-7`). When a manifest agent sets
`model: claude-sonnet-4-7`, the `mission_spawn` output includes the model
hint in the header so the operator picks the right model when pasting the
prompt into the Agent tool:

```
### pentester (Pentester) [model: claude-sonnet-4-7]
```

### Private library overlay

Roles and patterns can be split across two directories:

- **Public**: `config/library/` (version-controlled, ships with Colmena)
- **Private**: `$COLMENA_PRIVATE_LIBRARY` (default `~/.colmena-private/library/`)

Private entries with the same `id` override public ones. Use this for
experimental or personal roles that must not ship in the public repository.
If the private directory does not exist, behavior is unchanged.

---

## 6. ELO and Calibration

ELO is an append-only rating system with temporal decay. Trust tiers are
derived from ELO ratings. The cycle: agents produce work → review_submit →
reviewer evaluates → ELO updates → findings stored → trust tiers recalibrated.

### How ELO works

Ratings are stored as append-only JSONL in `config/elo-events.jsonl`. New
events append; nothing is ever overwritten. The current rating is calculated
at read time by replaying all events with temporal decay.

**Author delta** (based on average review score):

| Score | Delta |
|-------|-------|
| >= 8 | +(score - 7) * 3 (reward) |
| 5-7 | 0 (neutral) |
| < 5 | -(6 - score) * 4 (penalty) |

**Finding penalties:**

| Severity | Penalty |
|----------|---------|
| critical | -10 |
| high | -5 |

**Reviewer reward:**

| Action | Delta |
|--------|-------|
| Any finding | +5 |

### Temporal decay

Weights decay based on event age at read time:

| Age | Weight |
|-----|--------|
| 0-7 days | 1.0x |
| 7-30 days | 0.7x |
| 30-90 days | 0.4x |
| 90+ days | 0.1x |

### Trust tiers

After 3+ reviews, ELO determines the trust tier:

| Tier | ELO | Effect |
|------|-----|--------|
| Elevated | >= 1600 | Auto-approve role's tools_allowed |
| Standard | 1300-1599 | Default rules |
| Restricted | 1100-1299 | Ask for everything |
| Probation | < 1100 | Bash + WebFetch blocked, others Ask |
| Uncalibrated | any (reviews < 3) | Default rules (warm-up) |

### CLI

```bash
# Show ELO leaderboard
colmena elo show

# Show current trust tiers
colmena calibrate show

# Apply ELO-based trust tiers (writes elo-overrides.json)
colmena calibrate run

# Clear all ELO overrides
colmena calibrate reset
```

### Safety properties

- Blocked rules always win. ELO cannot override blocked operations.
- YAML beats ELO. Human-defined `agent_overrides` in trust-firewall.yaml
  outrank ELO-derived overrides.
- Elevated Bash guard: even Elevated agents get Ask for Bash unless the role
  defines explicit `bash_patterns`.
- Calibrate reset instantly clears all ELO overrides.
- Warm-up: agents need 3+ reviews before calibration applies.
- Trust gate floor is 5.0 (hardcoded). Config can raise but not lower.

### MCP tools

```bash
mcp__colmena__elo_ratings()                # view leaderboard
mcp__colmena__calibrate()                  # show calibration state + actions
mcp__colmena__calibrate_auditor()          # present evaluations for human review
mcp__colmena__calibrate_auditor_feedback() # adjust auditor ELO from feedback
```

---

## 7. MCP Tools (31 total)

Colmena exposes 31 tools through the MCP protocol. Grouped by category.

### Firewall and Delegations (7 tools)

| Tool | What it does | Rate-limited | Restricted |
|------|-------------|-------------|------------|
| `config_check` | Validate trust-firewall.yaml | no | no |
| `evaluate` | Test a tool call against firewall | no | no |
| `queue_list` | List pending approvals | no | no |
| `delegate` | Request delegation (returns CLI command) | no | restricted |
| `delegate_list` | List active delegations | no | no |
| `delegate_revoke` | Request delegation revocation (returns CLI) | no | restricted |
| `calibrate` | Show calibration state | no | no |

### Wisdom Library (6 tools)

| Tool | What it does | Rate-limited | Restricted |
|------|-------------|-------------|------------|
| `library_list` | List roles and patterns | no | no |
| `library_show` | Show role or pattern details | no | no |
| `library_select` | Recommend patterns for a mission | no | no |
| `library_generate` | Generate per-agent CLAUDE.md from pattern | yes (30/min) | restricted |
| `library_create_role` | Create a new role with intelligent defaults | yes (30/min) | restricted |
| `library_create_pattern` | Create a new pattern with topology detection | yes (30/min) | restricted |

### Auditor Review (3 tools)

| Tool | What it does | Rate-limited | Restricted |
|------|-------------|-------------|------------|
| `review_submit` | Submit artifact for auditor review | yes (30/min) | restricted |
| `review_list` | List reviews (pending/completed) | no | no |
| `review_evaluate` | Submit scores and findings as reviewer | yes (30/min) | restricted |

### ELO and Findings (4 tools)

| Tool | What it does | Rate-limited | Restricted |
|------|-------------|-------------|------------|
| `elo_ratings` | ELO leaderboard with temporal decay | no | no |
| `findings_query` | Search findings by role, category, severity | no | no |
| `findings_list` | List recent findings | no | no |
| `session_stats` | Show prompts saved + tokens saved + alerts | no | no |

### Alerts and Calibration (4 tools)

| Tool | What it does | Rate-limited | Restricted |
|------|-------------|-------------|------------|
| `alerts_list` | List review alerts | no | no |
| `alerts_ack` | Acknowledge alert(s) by ID | yes (30/min) | restricted |
| `calibrate_auditor` | Present evaluations for human calibration | no | no |
| `calibrate_auditor_feedback` | Adjust auditor ELO from human feedback | yes (30/min) | restricted |

### Operations (7 tools)

| Tool | What it does | Rate-limited | Restricted |
|------|-------------|-------------|------------|
| `mission_spawn` | One-step mission creation | yes (30/min) | restricted |
| `mission_suggest` | Analyze mission complexity | no | no |
| `mission_deactivate` | Return deactivation CLI command | no | no |
| `mission_validate` | Validate a mission manifest file | no | no |
| `mission_status` | Show mission status dashboard | no | no |
| `mission_abort` | Return abort CLI command | yes (30/min) | restricted |
| `mission_manifest_show` | Preview manifest contents | yes (30/min) | no |

### Rate limiting

Generative tools (library_generate, review_submit, review_evaluate,
library_create_role, library_create_pattern, mission_spawn,
mission_deactivate, mission_abort, mission_manifest_show, alerts_ack,
calibrate_auditor_feedback) are limited to 30 calls per minute per tool.

---

## 8. Audit and Findings

Every firewall decision and lifecycle event is logged. Findings from reviews
are stored permanently and queryable.

### Audit log

`config/audit.log` is append-only JSONL. Every decision has a matching
rule ID, tool name, agent, and session.

```
[2026-05-06T05:00:05Z] ALLOW session=abc agent=pentester tool=Read key="/src/auth.rs" rule=trust_circle[0]
[2026-05-06T05:00:05Z] ASK   session=abc agent=pentester tool=Bash key="nmap -sV target.local" rule=restricted[1]
[2026-05-06T05:00:05Z] DENY  session=abc agent=pentester tool=Bash key="git push --force origin main" rule=blocked[0]
```

Event types: `ALLOW`, `ASK`, `DENY`, `DELEGATE_CREATE`, `DELEGATE_MATCH`,
`DELEGATE_EXPIRE`, `DELEGATE_REVOKE`, `MISSION_ACTIVATE`,
`MISSION_DEACTIVATE`, `ROLE_TOOLS_ALLOW`, `AGENT_STOP`, `TIMEOUT`.

Log rotates at 10 MiB (`audit.log` -> `audit.log.1`).

```bash
grep -c "DENY" config/audit.log
grep "agent=pentester" config/audit.log
```

### Findings store

Findings are stored as individual JSON files in `config/findings/` organized
by mission. They are queryable by role, category, severity, date, and
mission.

Severity is one of: `critical`, `high`, `medium`, `low`.

```bash
# Via CLI (limited to review listing)
colmena review list
colmena review list --state pending
colmena review show rev-20260506-001
```

```bash
# Via MCP (primary interface for agents)
mcp__colmena__findings_query({ mission: "2026-05-06-payments-audit" })
mcp__colmena__findings_query({ category: "missing_coverage", severity: "medium" })
mcp__colmena__findings_query({ author_role: "pentester" })
mcp__colmena__findings_list({ limit: 20 })
```

### Review lifecycle

```
1. Agent finishes work
2. Agent calls review_submit(MCP) with artifact + hash
   -> reviewer assigned (random, author != reviewer, no reciprocal)
3. Reviewer calls review_evaluate(MCP) with scores + findings
   -> trust gate: avg >= 7.0 and no critical finding = auto-complete
   -> otherwise: alert written to alerts.json for human review
4. ELO updates for both author and reviewer
5. Findings stored permanently
6. SubagentStop allows agent to stop
```

### Review invariants (hardcoded)

1. No self-review (author != reviewer).
2. No reciprocal review within the same mission.
3. Artifact hash verified at submit and evaluate.
4. Minimum 2 score dimensions per evaluation.
5. Append-only ELO — ratings logged, never overwritten.
6. Trust gate floor at 5.0 — even config cannot bypass.

### Alerts

When a review triggers NeedsHumanReview (score < 5.0 or critical finding),
an alert is written to `config/alerts.json`. Alerts are append-only —
agents cannot acknowledge or delete them.

```bash
mcp__colmena__alerts_list({ acknowledged: false })
mcp__colmena__alerts_ack({ alert_id: "all" })
```

`session_stats` shows unacknowledged alert count before you close a session.

---

## 9. Security

Colmena is designed with deterministic governance and tamper-evident audit.
No LLM calls in the hot path. No external services. All data is
filesystem-based and git-versionable.

### No LLM calls in the hot path

Every firewall decision uses YAML rules compiled to regex. Zero LLM
inference per call. Latency is under 15ms per hook invocation.

### Deterministic rules

Same config + same tool input = same decision. No LLM classifier, no
heuristics, no "maybe" outcomes. Every decision is traceable to a specific
rule ID.

### Hardcoded invariants

These cannot be overridden by config or ELO:

- **Path blocklist**: `/etc`, `/root`, `/var/log`, `/proc`, `/sys`, `/boot`,
  `/dev` are never reachable by manifest scope.
- **Config protection**: `trust-firewall.yaml`, `runtime-delegations.json`,
  `audit.log`, `elo-overrides.json`, filter stats files, settings files,
  `revoked-missions.json`, `alerts.json`, reviews directory, and findings
  directory are protected via `path_not_match` in the trust_circle Write rule.
- **Bash sentinel blocking**: Patterns matching `rm -rf /`, `dd if=/dev/`,
  `mkfs.`, `chmod 777 /`, and similar destructive commands are blocked in
  manifest `extra_allow` regexes.
- **Count caps**: Per-role count ≤ 5, total agents ≤ 25, TTL ≤ 24 hours.
- **Forbidden manifest fields**: `role_type`, `default_trust_level`,
  `disable_audit_log`, `disable_blocked_tier`, `bypass_session_gate` are
  rejected at parse time.

### Tamper-evident audit log

- Append-only. Log rotates at 10 MiB.
- Every decision includes the matching rule ID.
- Any auditor can replay the log and explain why a call was allowed, asked,
  or blocked.

### Atomic writes

Config files are written with temp + rename. Concurrent CC instances do not
produce partial writes.

### Path normalization

Path comparison uses component-based normalization, not `canonicalize()`.
This avoids symlink bypass attacks while staying in the hook latency budget.

### File permission checks

On Unix, Colmena warns if critical config files are world-writable.

### Kill switches

- `colmena calibrate reset` instantly clears all ELO overrides.
- `colmena mission deactivate --id <mission>` revokes all delegations and
  writes each agent ID to `revoked-missions.json`. Any subsequent tool call
  from a revoked agent returns deny.
- `colmena mission abort --id <mission> --reason "..."` does the same with
  an abort reason logged in the audit trail.

### Safe hook fallbacks

| Hook | Error behavior |
|------|---------------|
| PreToolUse | Returns `ask` — never deny |
| PostToolUse | Passthrough (original output) |
| PermissionRequest | No output (CC continues prompting) |
| SubagentStop | Approve — never trap an agent |

### PermissionRequest hook (M6.3)

The PermissionRequest hook intercepts Claude Code's permission prompts. When
an agent has a `source: "role"` delegation and the tool is in the role's
`tools_allowed`, the hook auto-approves and teaches CC a session rule.
Subsequent calls for the same tool are auto-approved by CC without invoking
the hook at all.

This is different from trust_circle rules: PermissionRequest operates on
Claude Code's internal session rules, while trust_circle operates in the
PreToolUse firewall. The two layers complement each other.

Mission revocation overrides session rules. When a mission is deactivated or
aborted, each agent ID is written to `revoked-missions.json`. The PreToolUse
hook checks this list before CC checks its learned session rules, so a
revoked agent's tools are blocked immediately.

### Output filtering (PostToolUse)

PostToolUse intercepts Bash outputs before Claude Code processes them. The
goal is to save tokens and keep the context clean.

Pipeline order (clean first, hard cap last):

1. **ANSI strip** — remove escape sequences that waste tokens.
2. **Stderr-only on failure** — if exit code != 0 and stderr has content,
   discard stdout noise.
3. **Dedup** — collapse 3+ consecutive identical lines into one.
4. **Truncate** — max 150 lines / 30K chars (below CC's 50K limit).
   Preserves head and tail, cuts from the middle.

Then the static **prompt-injection detector** scans for 10 canonical
patterns (OWASP LLM-01 + tag injection + exfiltration) and prepends a
warning banner if matched — without mutating the content.

Each filter is wrapped in `catch_unwind`. If any filter panics, the others
continue. If the entire pipeline fails, the original output returns
unchanged. PostToolUse never returns "ask" or "deny" — filter or passthrough.

Config in `config/filter-config.yaml`:

```yaml
max_output_lines: 150
max_output_chars: 30000
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

Shows total chars saved, estimated tokens saved, average reduction, top
commands by savings. Data from `config/filter-stats.jsonl` (append-only,
10MB rotation).

### Atomic writes

All runtime files (delegations, ELO events, findings, overrides) are written
with a temporary file + rename pattern. If the write is interrupted, the old
file remains intact. Concurrent Claude Code instances do not produce partial
writes.

### Path normalization

Path comparisons use component-based normalization, not `canonicalize()`.
This avoids symlink bypass attacks while staying under the 15ms hook latency
budget. The normalized path is split into components, and comparisons are
done component-by-component. A path like `/home/user/project/../../etc/passwd`
is caught because `..` components are rejected.

### Config file protection

Critical config files are protected in the trust_circle Write rule via
`path_not_match` (filename-only glob matching):

- `trust-firewall.yaml`
- `runtime-delegations.json`
- `audit.log` / `audit.log.1`
- `elo-overrides.json`
- `filter-config.yaml` / `filter-stats.jsonl`
- `settings.json` / `settings.local.json`
- `revoked-missions.json`
- `alerts.json`
- `reviews/` (entire directory)
- `findings/` (entire directory)

On Unix, Colmena warns if any of these files are world-writable.

---

## Quick Reference

### CLI

| Command | What it does |
|---------|-------------|
| `colmena setup [--dry-run] [--force]` | One-command onboarding |
| `colmena doctor` | Full health check |
| `colmena config check` | Validate firewall rules |
| `colmena delegate add --tool X [--agent Y] [--ttl 8] [--session S]` | Scoped delegation |
| `colmena delegate list` | List active delegations |
| `colmena delegate revoke --tool X [--agent Y]` | Revoke a delegation |
| `colmena mission list` | Active missions |
| `colmena mission spawn --from manifest.yaml` | Spawn from manifest |
| `colmena mission init --slug X` | Scaffold new manifest |
| `colmena mission init --from-history [--session S]` | Generate manifest from history |
| `colmena mission validate <file>` | Validate manifest YAML |
| `colmena mission status --id X` | Mission status dashboard |
| `colmena mission deactivate --id X` | Graceful mission close |
| `colmena mission abort --id X [--reason "R"] [--force]` | Force mission abort |
| `colmena library list` | List roles and patterns |
| `colmena library show <id>` | Role or pattern details |
| `colmena library select --mission "..."` | Pattern recommendations |
| `colmena library create-role --id X --description "..."` | Scaffold a role |
| `colmena library create-pattern --id X --description "..."` | Scaffold a pattern |
| `colmena review list [--state pending]` | List reviews |
| `colmena review show <id>` | Review detail |
| `colmena elo show` | ELO leaderboard |
| `colmena calibrate run` | Apply ELO trust tiers |
| `colmena calibrate show` | Current tiers per agent |
| `colmena calibrate reset` | Clear all ELO overrides |
| `colmena suggest "..."` | Mission sizing analysis |
| `colmena stats [--session X]` | Filter + firewall savings |
| `colmena queue list` | Pending approvals |
| `colmena queue prune --older-than 7` | Clean old queue entries |

### MCP Tools (31)

| Tool | Category | What it does |
|------|----------|-------------|
| `config_check` | Firewall | Validate config |
| `evaluate` | Firewall | Test tool call against firewall |
| `queue_list` | Firewall | List pending approvals |
| `delegate` | Firewall | Request delegation (CLI command) |
| `delegate_list` | Firewall | List active delegations |
| `delegate_revoke` | Firewall | Request revocation (CLI command) |
| `calibrate` | Firewall | Show calibration state |
| `library_list` | Library | List roles and patterns |
| `library_show` | Library | Show role/pattern details |
| `library_select` | Library | Recommend patterns |
| `library_generate` | Library | Generate per-agent prompts |
| `library_create_role` | Library | Create role |
| `library_create_pattern` | Library | Create pattern |
| `review_submit` | Review | Submit artifact for review |
| `review_list` | Review | List reviews |
| `review_evaluate` | Review | Score artifact + findings |
| `elo_ratings` | ELO | ELO leaderboard |
| `findings_query` | ELO | Search findings |
| `findings_list` | ELO | Recent findings |
| `session_stats` | ELO | Prompts + tokens saved |
| `alerts_list` | Alerts | List alerts |
| `alerts_ack` | Alerts | Acknowledge alerts |
| `calibrate_auditor` | Alerts | Present evaluations |
| `calibrate_auditor_feedback` | Alerts | Adjust auditor ELO |
| `mission_spawn` | Operations | One-step mission creation |
| `mission_suggest` | Operations | Analyze mission complexity |
| `mission_deactivate` | Operations | Deactivate mission |
| `mission_validate` | Operations | Validate manifest |
| `mission_status` | Operations | Mission dashboard |
| `mission_abort` | Operations | Abort mission |
| `mission_manifest_show` | Operations | Preview manifest |

---

## See Also

- [Getting Started](user/getting-started.md) — zero to running in 5 minutes.
- [Use Cases](user/use-cases.md) — four real scenarios with manifests.
- [Install Mode B](install-mode-b.md) — point your CC at the repo.
- [README](../README.md) — project overview and value proposition.
