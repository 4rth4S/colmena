# Use Cases

Full tutorials for the four primary Colmena personas — **pentester**, **developer**, **devops**, **SRE** — plus a handful of cross-cutting examples. Each vignette is a working walkthrough: the setup, the spawn, the expected Colmena behavior, and what to look for when it runs.

Each tutorial is sized to ~10–15 minutes of hands-on time after `colmena setup`.

---

## 1. Pentest engagement (Caido-native web + API)

**Persona.** Pentester running an authorized engagement against a web application and its API surface. Caido is already installed and a project is loaded.

**Pattern.** `caido-pentest` — hierarchical topology with a security architect coordinating a web pentester and an API pentester.

### 1.1 Prerequisites

- Caido MCP server registered in `~/.mcp.json` (the Caido project you are allowed to test is open).
- Scope documented and signed off (rules of engagement).
- `colmena setup` done, `colmena doctor` green.

### 1.2 Decide whether to use Colmena

```bash
colmena suggest "bug bounty on the payments API and its admin dashboard, looking for BOLA, XSS, and auth bypasses"
```

Expected output: `complexity=medium-high`, `recommended_agents=3`, verdict: **use Colmena**. The mix of web + API surfaces plus a coordinating role is exactly what the `caido-pentest` pattern is for.

### 1.3 Pick the pattern explicitly

```bash
colmena library show caido-pentest
```

You will see:

- `topology: hierarchical`
- `communication: hub-and-spoke`
- `roles_suggested: { lead: security_architect, attacker_1: web_pentester, attacker_2: api_pentester }`

### 1.4 Spawn the mission

From inside a Claude Code session:

```
mcp__colmena__mission_spawn(
  mission="bug bounty on the payments API and its admin dashboard",
  pattern_id="caido-pentest"
)
```

Colmena produces:

- Three agent prompts with mission marker `<!-- colmena:mission_id=... -->`
- Scoped delegations (default 8h TTL) for `mcp__caido__*`, `Bash` limited to `nmap|nikto|nuclei|curl|python`, findings tools, `review_submit`
- Security architect assigned as reviewer lead
- Pre-filled `review_submit` call in each worker prompt

### 1.5 Launch the agents

Paste each generated prompt into a separate `Agent` tool call. Run them in parallel — the hierarchical topology allows web and API pentesters to work independently; the security architect synthesizes.

### 1.6 What Colmena enforces during the run

- **Bash is `restricted` by default for pentester roles.** Every `nmap` or `nuclei` run logs to `audit.log` with the rule ID.
- **No `rm -rf` or `git push --force` even with delegation.** Those rules live in `blocked` — delegations cannot override.
- **Findings go to the findings store.** `mcp__colmena__findings_list` returns them grouped by severity.
- **Workers cannot stop without `review_submit`.** The `SubagentStop` hook enforces this.
- **Stale review auto-invalidation.** If you re-run a worker after tweaking prompts, the prior pending review is auto-invalidated so the new one can pair with a reviewer.

### 1.7 Wrap up

When all workers have submitted, the security architect evaluates with `review_evaluate`:

```
mcp__colmena__review_evaluate(
  review_id="r_...",
  quality=8, precision=9, comprehensiveness=7,
  findings=[ ... ]
)
```

QPC scores feed the ELO log. If either pentester scored below the alert threshold, `mcp__colmena__alerts_list` will show a high-severity alert.

### 1.8 Audit-ready artifacts

Before you hand over the engagement report:

```bash
colmena stats --session $SESSION_ID       # prompts saved + tokens saved
colmena elo show                           # role standings
cat config/audit.log | wc -l               # every HTTP call, every nmap run
```

The `audit.log` plus the findings store are the engagement artifacts any auditor can replay.

---

## 2. Dev team code review cycle

**Persona.** Developer on a team. A feature branch is up, and you want systematic review before you merge — not a drive-by.

**Pattern.** `code-review-cycle` — sequential topology with developer → code_reviewer → auditor.

### 2.1 Why this pattern

- The code reviewer is **genuinely read-only**: `tools_allowed` excludes `Write` and `Edit`. It cannot "helpfully" fix things and muddy the diff.
- The auditor scores the work and the review via QPC (Quality + Precision + Comprehensiveness, 1–10 each).
- Both the developer and the code reviewer earn ELO from the auditor's scores. Over time, good reviewers climb to `Elevated` and get auto-approve on their role tools; rubber-stampers drop to `Probation`.

### 2.2 Decide whether to use Colmena

```bash
colmena suggest "review and harden error handling in the config loader, add tests"
```

Expected: `complexity=medium`, `recommended_agents=3`, verdict: **use Colmena**.

### 2.3 Spawn

```
mcp__colmena__mission_spawn(
  mission="review and harden error handling in the config loader, add tests"
)
```

Colmena defaults to `code-review-cycle` when the mission keywords match "review" and "harden" and "tests". If you want to force the pattern:

```
mcp__colmena__mission_spawn(
  mission="...",
  pattern_id="code-review-cycle"
)
```

### 2.4 Extend the developer's pre-approved Bash patterns

The developer role has `cargo (build|test|check|clippy)` and `git (status|diff|log)` pre-approved by default. If your project needs additional commands like `pytest` or `npm test`, the CLI does NOT let you delegate `Bash` directly — unscoped Bash auto-approve would bypass the firewall. Two supported paths:

**Option A — edit `config/trust-firewall.yaml`:** add an `agent_overrides` rule scoped by `bash_pattern`:

```yaml
agent_overrides:
  - agent: developer
    tool: Bash
    action: auto-approve
    bash_pattern: '^(pytest|npm test|yarn test)\b'
    reason: 'Developer test runners'
```

Reload takes effect on the next hook call — no CLI command needed. Run `colmena config check` to validate the YAML.

**Option B — let a mission generate it:** `mcp__colmena__mission_spawn` auto-generates role-scoped Bash delegations from each role's YAML patterns. If your mission includes the developer role, it gets these patterns applied for the mission's TTL without any manual YAML editing.

Why no CLI flag? Bash auto-approve without a regex scope is a firewall bypass — the CLI bails with a clear error if you try `colmena delegate add --tool Bash`. Scoped Bash lives in YAML (durable) or mission-generated delegations (ephemeral), never in ad-hoc CLI invocations.

### 2.5 Run the cycle

Paste prompts in order (developer, code_reviewer, auditor). The developer implements, submits for review. The code reviewer reads the diff, files findings. The auditor evaluates both.

### 2.6 What to watch

- `colmena review list --state pending` — current reviews waiting on an evaluator
- `colmena review show <review-id>` — the artifact hash, the reviewer, the state
- `colmena elo show` — the leaderboard per role
- `colmena calibrate show` — current trust tier per agent

### 2.7 Iterate

The cycle can repeat. Each iteration is a new artifact hash, a new review. The ELO log is append-only JSONL — nothing is ever mutated, every evaluation is replayable.

```bash
colmena calibrate run                 # apply ELO-based trust adjustments
```

If a reviewer is consistently finding real bugs, `calibrate run` will raise their tier to `Elevated` and the `PermissionRequest` hook will start auto-approving their role tools in CC sessions.

---

## 3. DevOps kubectl ops

**Persona.** DevOps engineer running a rollout, troubleshooting a pod, or iterating on helm charts. Claude Code will touch `kubectl`, `helm`, `terraform`, `aws`, `docker`.

**Role.** `devops_engineer` ships with exactly those bash patterns pre-approved and secrets paths blocked.

### 3.1 What's pre-approved

From `config/library/roles/devops_engineer.yaml`:

```yaml
bash_patterns:
  - '^docker\b'
  - '^docker-compose\b'
  - '^kubectl\b'
  - '^helm\b'
  - '^terraform\b'
  - '^ansible(-playbook)?\b'
  - '^aws\b'
  - '^gcloud\b'
  - '^az\b'
  - '^make\b'
  - '^gh\b'
  - '^git\b'
path_not_match:
  - '*.env'
  - '*credentials*'
  - '*.key'
  - '*.pem'
```

- Any read or non-destructive call on those tools is auto-approved at role tier.
- Any `Read`, `Write`, or `Edit` against paths matching the `path_not_match` globs is blocked — secrets stay out of the agent's context.

### 3.2 Spawn a rollout mission

```
mcp__colmena__library_select(mission="roll out the new helm chart to staging, watch kube events, rollback on error")
```

Pattern suggestion: `plan-then-execute` (plan → execute → audit). Spawn:

```
mcp__colmena__mission_spawn(
  mission="roll out the new helm chart to staging, watch kube events, rollback on error",
  pattern_id="plan-then-execute"
)
```

Once the mission is spawned, the `devops_engineer`'s full pattern set (kubectl, helm, terraform, docker, aws, gcloud, ansible, etc.) is auto-approved for the mission TTL. No further CLI setup is needed — `mission_spawn` emits the scoped Bash delegations from the role YAML automatically.

If you want a pattern NOT in the role YAML (e.g. a custom `^my-internal-tool\b`) either (a) add it to `config/library/roles/devops_engineer.yaml` → `bash_patterns` so the next mission spawn picks it up, or (b) add an `agent_overrides` rule in `trust-firewall.yaml` as shown in §2.4 above. The CLI does not accept `Bash` as a `delegate add` target — it bails to prevent unscoped Bash bypass.

### 3.3 What the firewall does during the run

- `kubectl get pods -n staging` → **allow** (role auto-approve)
- `helm upgrade --install myapp ./chart` → **allow**
- `kubectl delete namespace staging` → **ask** (destructive verb matches a `restricted` pattern)
- `terraform destroy -auto-approve` → **ask** (destructive verb)
- `git push --force` → **block** (always)
- Any read of `~/.kube/config.env` or `*.pem` → **block** (path rule)

Every decision lands in `config/audit.log`. If the rollout goes sideways, that log is your post-mortem.

### 3.4 Revoke mid-session

If something looks off and you want the agent to stop touching kubernetes right now:

```bash
colmena mission deactivate --id <mission-id>
```

This revokes every delegation for every agent in the mission. Even if CC has "learned" to allow `kubectl` via session rules, the `PreToolUse` mission revocation check fires first and denies.

### 3.5 Audit trail

```bash
grep kubectl config/audit.log | tail -n 50
colmena stats --session $CC_SESSION_ID
```

Every API call made against the cluster is attributable to a role, a session, and a rule ID.

---

## 4. SRE runbook execution

**Persona.** SRE responding to an alert. You want an agent to follow a runbook — inspect pods, logs, metrics, health endpoints — without ever writing to production state.

**Role.** `sre` pre-approves the read-side of ops (`kubectl get`, `prometheus`, `promtool`, `dig`, `journalctl`, `systemctl status/show/list-units`). Anything that writes routes through `ask`.

### 4.1 What's pre-approved

From `config/library/roles/sre.yaml`:

```yaml
bash_patterns:
  - '^kubectl\b'
  - '^helm\b'
  - '^curl\b'
  - '^prometheus\b'
  - '^promtool\b'
  - '^amtool\b'
  - '^journalctl\b'
  - '^systemctl (status|show|list-units)\b'
  - '^dig\b'
  - '^nslookup\b'
  - '^traceroute\b'
```

Note that `systemctl` is restricted to read-only subcommands. `systemctl restart` or `systemctl stop` falls through to the default `ask`. Same for destructive verbs on `kubectl` (`delete`, `apply -f`).

### 4.2 Spawn an investigation

```
mcp__colmena__mission_spawn(
  mission="investigate the 5xx spike on checkout-api, draft an incident note with timeline and suspected cause"
)
```

The role has `mcp__colmena__alerts_list` in `tools_allowed`, so the agent can pull current alerts into context. Findings the agent files during the investigation land in the findings store — queryable later by mission ID.

### 4.3 Enforcement during the run

- `kubectl get pods -n prod` → **allow**
- `kubectl logs checkout-api-xyz -n prod --tail=200` → **allow**
- `journalctl -u kubelet --since "1 hour ago"` → **allow**
- `curl -s https://checkout-api.prod/healthz` → **allow** (read-only curl matches the default `^curl\b` bash pattern in the sre role; a `-X POST` or `-X DELETE` would route to `ask`)
- `kubectl rollout restart deployment/checkout-api` → **ask**
- Any write to `*.env`, `*credentials*`, `*.key`, `*.pem` → **block**

### 4.4 Findings and alerts

Alerts are append-only. The SRE agent can read them but cannot acknowledge them — acknowledgements require a human via `mcp__colmena__alerts_ack` (in the `restricted` tier).

Findings filed by the agent during the investigation:

```
mcp__colmena__findings_query(mission_id="<mission-id>", severity="high")
```

Your post-incident report writes itself from the findings store and the `audit.log`.

### 4.5 Stop the investigation instantly

```bash
colmena mission deactivate --id <mission-id>
```

Every delegation for every agent in that mission is revoked. The investigation stops, the audit trail remains.

---

## 5. Large refactoring with safety rails

**Persona.** Developer or tech lead. You need to refactor a core module — rename types, restructure files, update all call sites — and you want confidence nothing breaks.

**Pattern.** `refactor-safe` — sequential: developer → code_reviewer (read-only) → auditor.

```
mcp__colmena__mission_spawn(
  mission="refactor the config module to split parsing from validation, preserve all public APIs"
)
```

**What Colmena enforces:**

- Developer has `Bash` patterns for `cargo (build|test|check|clippy)` and `git (status|diff|log)` — enough to validate refactors, not enough to push.
- Code reviewer is **read-only** — `tools_allowed` excludes `Write` and `Edit`. Reviewer reads the diff, writes findings only.
- Auditor validates that tests pass and the refactor is complete.

If the cycle finds regressions, the auditor's review fails and no elevated trust is earned. The work has to go back to the developer.

---

## 6. Documentation sprint (dogfooding note)

**Real context.** The earlier version of these docs was produced by Colmena using the `docs-from-code` pattern — architect reads the codebase, developer writes docs, auditor validates against source. This rewrite you're reading right now is the M7.3 dogfood mission (`2026-04-21-m73-docs-overhaul`) using the same pattern.

```
mcp__colmena__mission_spawn(
  mission="rewrite README and user-facing docs for first-time users",
  pattern_id="docs-from-code"
)
```

The sequential topology enforces order — writers can't start until the architect's notes exist. The auditor catches hallucinated APIs or wrong file paths before they reach users.

---

## Common operations across all use cases

### Mission lifecycle

```bash
colmena mission list                                  # active missions with delegation counts
colmena mission deactivate --id 2026-04-21-<slug>     # revoke all delegations for a mission
```

### Trust and ELO

```bash
colmena elo show                                      # leaderboard with ratings
colmena calibrate show                                # trust tiers per agent
colmena calibrate run                                 # apply ELO → firewall adjustments
colmena calibrate reset                               # clear all ELO-based overrides (emergency)
```

### Findings and alerts (via MCP from inside CC)

```
mcp__colmena__findings_query(severity="critical")
mcp__colmena__findings_query(mission_id="2026-04-15-refactor-config-module")
mcp__colmena__findings_list()

mcp__colmena__alerts_list(severity="high")
mcp__colmena__alerts_ack(alert_id="all")              # human-only, after reviewing
```

### Session summary

```bash
colmena stats                                         # total savings
colmena stats --session <session-id>                  # per-session savings
```

Before ending a CC session, ask your CC to call `mcp__colmena__session_stats` to print prompts saved and tokens saved.

---

## When to use Colmena vs vanilla Claude Code

Use `colmena suggest` for a data-driven recommendation:

```bash
colmena suggest "fix a typo in the README"
# → complexity=low, recommended_agents=1, verdict: use CC directly

colmena suggest "add rate limiting to the API with tests and review"
# → complexity=medium, recommended_agents=3+, verdict: use Colmena

colmena suggest "refactor auth module, migrate database schema, update all consumers"
# → complexity=high, recommended_agents=5+, verdict: use Colmena
```

The threshold is 3+ recommended agents. Below that, Colmena's orchestration overhead is not worth it. At 3+, the trust firewall, scoped permissions, auditor review enforcement, and ELO calibration start paying off.

---

## Where to go next

- [Getting Started](getting-started.md) — install and first run in 5 minutes
- [Install Mode B](../install-mode-b.md) — let your CC bootstrap Colmena
- [User Guide](../guide.md) — detailed walkthrough with a payments API audit example
- [Architecture](../dev/architecture.md) — how the four crates fit together
- [Contributing](../dev/contributing.md) — dev setup and PR workflow

---

built with ❤️‍🔥 by AppSec
