# Use Cases

Four full tutorials, one per persona. Each walks through a real scenario from problem to outcome. Every manifest is valid against the current library — copy, edit, and run.

---

## 1. Web App Pentest

**Persona.** Bug bounty hunter with a scoped target. You found potential vulnerabilities across multiple subdomains and need to verify exploitability, chain primitives, and produce a structured report that a triager can reproduce.

**Pattern.** `bbp-impact-chain` — fan-out-merge topology with two pentesters, a weaponizer, and an auditor.

### The problem

A single attack chain against a modern web application involves CORS misconfigurations, postMessage origin checks, and API authorization bugs. You cannot trace all the attack surfaces in one Claude session — the context window fills up, you lose track of which chain has PoC code and which is still speculative. You need separate agents, each owning a subset of the surface, with a centralized review that produces a single structured submission.

### The manifest

Create `webapp-pentest.mission.yaml`:

```yaml
version: 1
mission_id: webapp-pentest
description: "Practical exploitation chain hunt for a web app bounty target"
author: operator
pattern: bbp-impact-chain
mission_ttl_hours: 8
agents:
  - role: bbp_pentester_web
    count: 2
    instances: [squad-a, squad-b]
    task: "Verify and exploit web vulnerabilities on target"
    model: claude-opus-4-7
  - role: weaponizer
    task: "Validate impact chain, draft bounty report"
  - role: auditor
scope:
  paths:
    - /home/user/bugbounty/target
  path_not_match:
    - "*.env"
    - "cdp_keys*"
  bash_patterns:
    extra_allow:
      - '^curl -[a-zA-Z]+ https://[A-Za-z0-9.-]+\.target\.com\b[^&;|`$()]*$'
    extra_deny:
      - '^rm -rf'
mission_gate: enforce
auditor_pool: ["auditor"]
acceptance_criteria:
  - "PoC chain reproducible from clean browser"
  - "All findings have severity tier with CVSS"
tags: [bbp, web]
```

### Validate and spawn

```bash
colmena mission validate webapp-pentest.mission.yaml
colmena mission spawn --from webapp-pentest.mission.yaml
```

The validation checks that `bbp_pentester_web`, `bbp_pentester_api`, `weaponizer`, and `auditor` exist in the library. The spawn creates four agent prompts with mission markers.

### What happens during the run

- **squad-a** and **squad-b** each own a subdomain. They probe with `curl`, inspect JavaScript handlers, and chain exploits.
- **Chain-aware firewall** evaluates bash chains piece by piece — a long `curl | jq | tee` pipeline is checked per sub-command, not as one opaque blob.
- **The weaponizer** takes validated findings and builds a submission chain: entry point, exploit primitive, impact demonstration, fix recommendation.
- **The auditor** reviews each artifact. Scores feed ELO: `bbp_pentester_web` and `weaponizer` earn ratings based on reproducible evidence.

### How the agents interact

The `bbp-impact-chain` pattern uses fan-out-merge topology. squad-a and squad-b work in parallel — each gets a copy of the target scope but owns different subdomains. Each agent writes findings to the store as they go:

```
mcp__colmena__findings_list()
# → squad-a: 3 findings (2x postMessage origin bypass, 1x JSON-RPC parsing)
# → squad-b: 4 findings (1x CORS misconfig, 2x event handler race, 1x chain impact)
```

When both finish, the weaponizer reads their findings, validates the impact chain (entry -> exploit -> impact), and drafts the H1 submission. The auditor reviews each artifact with QPC scores.

The chain-aware firewall matters here. A bash chain like `curl -s https://target.com/api/v1/user | jq .id | tee -a findings.txt` is evaluated as three pieces: `curl` is allowed by the `extra_allow` pattern, `jq` is a read-only pipe and falls through to auto-approve, `tee -a findings.txt` writes to the scoped mission directory — allowed. Without chain-aware evaluation, that whole command would be one opaque blob matched against bash patterns, and the safe `jq` and `tee` pieces would trigger an ASK.

### Outcome

8 ELO events generated. Reproducible artifacts in the findings store. The triager accepts the submission because every chain has its own artifact with hash-verified evidence.

---

## 2. Dev refactor (Colmena self-dev)

**Persona.** Developer or tech lead. A Rust workspace with 4 crates needs a refactor that touches all crates — trust-firewall rules, ELO algorithm, CLI subcommands. One human with one Claude cannot track cross-crate side effects.

**Pattern.** `colmena-self-dev` — iterative topology with multiple developers, a code reviewer, and an architect.

### The problem

A refactor touches `colmena-core`, `colmena-cli`, `colmena-mcp`, and `colmena-filter` at the same time. If one agent owns the whole workspace, the context window is too small. If you split manually, you miss dependencies. You need agents scoped per crate, a coordinator to catch regressions, and a reviewer who reads the full diff.

### The manifest

Create `colmena-refactor.mission.yaml`:

```yaml
version: 1
mission_id: colmena-refactor
description: "Refactor Colmena's review subsystem to reduce coupling"
author: operator
pattern: colmena-self-dev
mission_ttl_hours: 16
agents:
  - role: colmena_developer
    count: 2
    instances: [core, cli]
    task: "Implement review subsystem refactor per ARCHITECT_PLAN"
  - role: colmena_code_reviewer
    task: "Review diffs with QPC framework"
  - role: auditor
scope:
  paths:
    - /home/user/colmena
  bash_patterns:
    extra_allow:
      - '^cargo (build|test|clippy|fmt)\b'
      - '^git (diff|log|status|add|commit)\b'
mission_gate: enforce
budget:
  max_hours: 16
  max_agents: 12
acceptance_criteria:
  - "All existing tests pass"
  - "No regression in review cycle"
  - "ELO events recorded for all agents"
tags: [dev, rust, colmena-self]
```

### Validate and spawn

```bash
colmena mission validate colmena-refactor.mission.yaml
colmena mission spawn --from colmena-refactor.mission.yaml
```

### What happens during the run

- **`workspace_scope: repo-wide`** — the pattern overrides the default mission-dir scope. Agents can read and write any file in the Colmena repo. Sensitive paths (`*.env`, `*credentials*`, `*secret*`, `*.key`, `*.pem`) are excluded automatically.
- **core agent** owns `colmena-core/`. **cli agent** owns `colmena-cli/` and `colmena-mcp/`. Each has `path_within` scoped to their crate.
- **Architect** reviews the diff after each iteration. If tests fail, the work goes back.
- **Auditor** scores with QPC. Low scores trigger alerts — the architect sees them via `mcp__colmena__alerts_list`.

### How the agents interact

The `colmena-self-dev` pattern uses iterative topology. Each iteration flows: developer works -> code reviewer reads -> architect evaluates -> loop until clean.

- **Iteration 1.** core agent refactors the review subsystem. CLI agent updates the command-line interface. Both write changes and submit for review.
- **Review gate.** colmena_code_reviewer reads both diffs, checks for cross-crate dependency leaks, files findings. If the reviewer finds that core and cli disagree on the data format, the iteration fails.
- **Architect decision.** If both pass review, the architect approves and the iteration closes. If either fails, the agents get the findings and start iteration 2.
- **Auditor.** After the final iteration, the auditor scores the full cycle with QPC. Low scores trigger alerts visible via `mcp__colmena__alerts_list`.

The `workspace_scope: repo-wide` flag is critical here. Without it, agents would be scoped to a mission directory and could not touch the project source tree. Sensitive paths (`*.env`, `*credentials*`, `*secret*`, `*.key`, `*.pem`) are excluded automatically — no agent reads credential files during the refactor.

### Outcome

Refactor lands in 2 hours. 12 reviews. Zero regressions on `cargo test --workspace`. ELO moves for both colmena_developer and colmena_code_reviewer roles.

---

## 3. Incident response (SRE latency spike)

**Persona.** On-call SRE at 3 AM. Production latency spiked. You need an agent to investigate — check pods, scrape metrics, tail logs — without exposing credentials or allowing any destructive operation.

**Pattern.** `plan-then-execute` — hierarchical topology with a coordinator and two workers.

### The problem

At 3 AM you want answers, not permission prompts. Every `kubectl get`, `curl` to the metrics endpoint, and `journalctl` query should be auto-approved because the role is scoped to read-only ops. But a hallucinated `kubectl delete` should be blocked — not asked, blocked. The agent must never see `~/.kube/config` or `.env` files.

### The manifest

Create `incident-latency.mission.yaml`:

```yaml
version: 1
mission_id: inc-prod-latency
description: "Investigate p99 latency spike on API gateway production"
author: sre-oncall
pattern: plan-then-execute
mission_ttl_hours: 4
agents:
  - role: platform_engineer
    task: "Investigate k8s cluster, check pod health and resource usage"
  - role: sre
    task: "Check metrics, logs, and recent deploys for regressions"
  - role: auditor
scope:
  paths:
    - /home/sre/incident-2026-0501
  bash_patterns:
    extra_allow:
      - '^kubectl (get|describe|logs|top|events)\b'
      - '^curl https://(grafana|prometheus)\.internal\b[^&;|`$()]*$'
    extra_deny:
      - '^kubectl (delete|apply|edit|patch|scale|exec)\b'
      - '^rm -rf'
      - '^sudo\b'
mission_gate: enforce
budget:
  max_hours: 4
  max_agents: 6
acceptance_criteria:
  - "Root cause identified with evidence from logs/metrics"
  - "Mitigation proposed or rollback confirmed"
  - "Incident report started"
metadata:
  ticket: INC-12345
tags: [incident, prod, sre]
```

### Validate and spawn

```bash
colmena mission validate incident-latency.mission.yaml
colmena mission spawn --from incident-latency.mission.yaml
```

### What the firewall enforces

- `kubectl get pods -n prod` — auto-approved (matches the `extra_allow` pattern)
- `kubectl logs checkout-api-xyz --tail=200` — auto-approved
- `journalctl -u kubelet --since "1 hour ago"` — auto-approved (sre role includes this)
- `curl -s https://grafana.internal/api/v1/query` — auto-approved
- `kubectl delete deployment checkout-api` — blocked (matches `extra_deny`)
- Any read of `*.env`, `*credentials*`, `*.key` — blocked by default path rules

The `extra_deny` list is important. It overrides what would otherwise be auto-approved by role bash patterns. You can expand the agent's capabilities with `extra_allow` and restrict them with `extra_deny` in the same manifest.

### Outcome

Root cause identified in 15 minutes: a canary deployment with a misconfigured connection pool. Incident report drafted with timeline and evidence from logs and metrics. Agent deactivated with `colmena mission deactivate --id inc-prod-latency`. Audit trail intact for the post-mortem.

---

## 4. Compliance audit (log replay)

**Persona.** Security engineer. A SOC 2 auditor asks: "Show me every decision the trust firewall made during last month's penetration test."

**Pattern.** `pipeline` — sequential topology. Three agents review the audit log in stages.

### The problem

The auditor wants evidence, not claims. You need to demonstrate that:
- Every tool call was evaluated against a rule
- Every decision has an audit trail with a matching rule ID
- No decisions were made outside the policy
- The audit log is append-only and tamper-evident

Your `config/audit.log` has entries like:

```
[2026-04-15T10:30:00Z] ALLOW session=sess_abc agent=* tool=Read key="src/main.rs" rule=trust_circle
[2026-04-15T10:30:05Z] ASK   session=sess_abc agent=pentester tool=Bash key="nmap -sV target" rule=restricted
[2026-04-15T10:30:10Z] BLOCK session=sess_abc agent=* tool=Bash key="git push --force origin main" rule=blocked
```

The compliance audit manifest structures the review of this trail.

### The manifest

Create `compliance-audit.mission.yaml`:

```yaml
version: 1
mission_id: compliance-audit-log-replay
description: "Replay trust firewall audit log from last pentest and validate policy adherence"
author: security-eng
pattern: pipeline
mission_ttl_hours: 8
agents:
  - role: security_hardener
    task: "Review audit.log for policy violations — decisions that should have been blocked but were allowed"
  - role: researcher
    task: "Verify every rule_id in audit.log maps to a real firewall rule, check for gaps in coverage"
  - role: auditor
scope:
  paths:
    - /home/user/colmena/config
  bash_patterns:
    extra_allow:
      - '^grep\b'
      - '^wc\b'
      - '^sort\b'
      - '^head\b'
      - '^tail\b'
      - '^cut\b'
      - '^awk\b'
except_paths:
  - "runtime-delegations.json"
  - "runtime-agent-overrides.json"
mission_gate: enforce
auditor_pool: ["auditor"]
budget:
  max_hours: 8
  max_agents: 6
acceptance_criteria:
  - "Every audit.log entry maps to a valid rule_id"
  - "No allowance without matching rule"
  - "All blocked decisions confirmed as correctly blocked"
  - "Coverage report: percentage of tool calls matched by rule"
metadata:
  audit_period: "2026-04-01..2026-04-30"
  standard: "SOC 2"
tags: [compliance, audit, soc2]
```

### Validate and spawn

```bash
colmena mission validate compliance-audit.mission.yaml
colmena mission spawn --from compliance-audit.mission.yaml
```

### What the run looks like

- **security_hardener** reads `audit.log`, groups by rule_id, checks that every ALLOW decision had a valid rule. Flags any entry where the tool used exceeds the rule's scope (e.g., `Bash` with `rm -rf` auto-approved).
- **researcher** cross-references rule_ids against `trust-firewall.yaml`. Validates regex patterns compiled correctly. Checks coverage: what percentage of tool calls matched a rule vs. fell through to the default action.
- **auditor** evaluates both reports. Scores Quality (did they check everything?), Precision (were the findings accurate?), Comprehensiveness (did they cover all edge cases?).

### Outcome

The auditor accepts the audit log as evidence. No manual report needed. The findings store contains the coverage analysis — every decision attributable to a rule, every rule exercised during the pentest. The compliance requirement is met with version-controlled YAML and append-only JSONL, not a hand-written document.

---

## Common operations across all use cases

### Manifest lifecycle

```bash
colmena mission init <slug> --for "description"      # Create a manifest
colmena mission init --from-history                   # Generate from audit log
colmena mission init --from-history --session <id>    # From a specific session
colmena mission validate <file>.mission.yaml          # Check schema + library refs
colmena mission spawn --from <file>.mission.yaml      # Create agents + delegations
colmena mission spawn --from <file>.mission.yaml --dry-run  # Preview first
colmena mission list                                  # Active missions
colmena mission status --id <id>                      # Detailed mission state
colmena mission deactivate --id <id>                  # Revoke all delegations
colmena mission abort --id <id>                       # Emergency stop
```

The `--from-history` flag reads your `config/audit.log`, finds Agent spawn calls, and generates a manifest that reproduces the mission. This is useful for standardizing workflows you ran ad-hoc — instead of documenting what you did, tell Colmena to derive the manifest from the log. The `--session` filter limits history to a specific CC session.

`mission status` shows the current state of each agent in a running mission: which agents have delegations active, which have submitted reviews, and which have pending evaluations. `mission abort` is the emergency stop — it kills all delegations immediately without waiting for review completion. Use `mission deactivate` for a clean shutdown that waits for in-flight reviews to complete.

### Trust and ELO

```bash
colmena elo show                          # Leaderboard with ratings
colmena calibrate show                    # Trust tiers per agent
colmena calibrate run                     # Apply ELO to firewall overrides
colmena calibrate reset                   # Clear all ELO-based overrides
```

### Findings and alerts (via MCP from inside Claude Code)

```
mcp__colmena__findings_query(severity="critical")
mcp__colmena__findings_query(mission_id="<mission-id>")
mcp__colmena__findings_list()

mcp__colmena__alerts_list(severity="high")
mcp__colmena__alerts_ack(alert_id="all")
```

### Session summary

```bash
colmena stats                               # Total savings
colmena stats --session <session-id>        # Per-session detail
```

Before ending a Claude Code session, ask for `mcp__colmena__session_stats` to print the value summary.

## When to use Colmena vs vanilla Claude Code

```bash
colmena suggest "fix a typo in the README"
# complexity=low, recommended_agents=1, verdict: use CC directly

colmena suggest "add rate limiting to the API with tests and review"
# complexity=medium, recommended_agents=3+, verdict: use Colmena

colmena suggest "refactor auth module, migrate database schema, update all consumers"
# complexity=high, recommended_agents=5+, verdict: use Colmena
```

The threshold is 3+ recommended agents. Below that, the orchestration overhead is not worth it. At 3+, the trust firewall, scoped permissions, auditor review, and ELO calibration start paying off.

## Where to go next

- `docs/user/getting-started.md` — install and first mission in 5 minutes
- `docs/guide.md` — deep dives into each subsystem
- `docs/install-mode-b.md` — let your Claude Code bootstrap Colmena
