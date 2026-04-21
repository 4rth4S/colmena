# Colmena

[![CI](https://github.com/4rth4S/colmena/actions/workflows/ci.yml/badge.svg)](https://github.com/4rth4S/colmena/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Version](https://img.shields.io/badge/version-0.11.1-blue.svg)](./Cargo.toml)

<p align="center">
  <img src="docs/colmena-banner.png" alt="Colmena — the hive defends the colony" width="400">
</p>

<p align="center"><strong>Deterministic governance for multi-agent Claude Code.</strong></p>

<p align="center">YAML rules + audit.log for every tool call. Multi-agent missions with peer review. ELO-calibrated trust per role.</p>

---

Colmena is a local-first governance layer for Claude Code. Every tool call is evaluated against YAML rules in under 15ms — zero LLM calls in the hot path, zero per-call cost, every decision written to `audit.log` and explainable by a rule ID. Beyond single-agent allow/ask/block, Colmena orchestrates multi-agent missions with mandatory peer review and ELO-calibrated trust per role. Your rules, your log, your team's history — all on disk, all yours.

## Which fits you?

| You are a... | Colmena gives you |
| --- | --- |
| **Pentester** | Scoped Caido-native web/API agents, `restricted` Bash by default, findings store for triage, audit trail that regulators can replay. |
| **Developer** | Auto-approve for `Read`, `cargo test`, `git log`; ask on `git push`; block on `--force`. A code reviewer agent that is genuinely read-only. |
| **DevOps** | Bash patterns for `kubectl`, `terraform`, `helm`, `docker` pre-wired. Secrets paths blocked. Delegations scoped per-session. |
| **SRE** | Runbook-friendly patterns (sequential, review-gated), alerts feed into findings, `journalctl`/`kubectl get` pre-approved, destructive ops gated. |

If you are none of the above but run agents in production, Colmena still gives you a deterministic audit trail and a way to hold each role accountable over time. Skip to [Install](#install).

## What problem this solves

Claude Code gives agents a lot of power. Out of the box, you approve every tool call by hand, or grant blanket permissions and hope for the best. Neither scales when multiple agents run in parallel and compliance or reliability matter.

- **Y-spam.** Answering "y" to every safe `Read` and `cargo test` is friction, not security.
- **Blanket allow.** Once you enable "allow all", you have no audit trail and no accountability.
- **Multi-agent chaos.** Spawning three agents in parallel with overlapping file scopes ends in conflicts and unreviewed work.
- **Opaque decisions.** When something goes wrong, you want to know *which rule* allowed it — not a probability score.

Colmena's position: **policy is code, review is mandatory, trust is earned.** Every decision is a rule you wrote, every artifact goes through peer review, every role accumulates an ELO that reflects how well it actually does the work.

## How it compares to Claude Code auto-mode

Anthropic's `--enable-auto-mode` (research preview) and Colmena solve different layers of the same problem. They are complementary, not competing.

| Dimension            | Claude Code auto-mode        | Colmena                                       |
| -------------------- | ---------------------------- | --------------------------------------------- |
| Decision model       | Probabilistic (LLM classifier) | Deterministic (YAML rules + regex)          |
| Per-call cost        | Model tokens per classification | Zero — no network, no LLM call             |
| Explainability       | Opaque classifier output     | `audit.log` line with the matching rule ID    |
| Scope                | Single-agent intent detection | Single + multi-agent with peer review        |
| Accountability       | Per tool call                | Per agent + per role, ELO over time           |
| Storage              | Cloud-side                   | Local filesystem (YAML / JSON / JSONL)        |

Auto-mode catches semantic intent the rule base can't — prompt injection attempts, mass-delete nudges, context the agent shouldn't have. Colmena enforces the policy you wrote and keeps a tamper-evident local record. **Use them together.**

## Install

Two ways to onboard. Both end up at the same place: hooks registered, MCP registered, `colmena doctor` green.

- **Mode A** — you install the binary and run `colmena setup`. Three paths below (crates.io, pre-built binary, from source).
- **Mode B** — you point your own Claude Code session at this repo and let it bootstrap everything. Validated with 4 power users (2026-04-16). See [docs/install-mode-b.md](docs/install-mode-b.md).

### Mode A — from crates.io (post v0.12.0)

```bash
cargo install colmena-cli colmena-mcp
colmena setup
colmena doctor
```

### Mode A — pre-built binary

Pick your platform from the [latest release](https://github.com/4rth4S/colmena/releases/latest), then verify the checksum:

```bash
curl -LO https://github.com/4rth4S/colmena/releases/download/vX.Y.Z/colmena-vX.Y.Z-x86_64-apple-darwin.tar.gz
curl -LO https://github.com/4rth4S/colmena/releases/download/vX.Y.Z/SHA256SUMS.txt
sha256sum -c SHA256SUMS.txt --ignore-missing
tar xzf colmena-vX.Y.Z-*.tar.gz
./colmena setup
./colmena doctor
```

Platform targets: `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin`, `aarch64-apple-darwin`, `x86_64-pc-windows-msvc`.

### Mode A — from source

```bash
git clone https://github.com/4rth4S/colmena
cd colmena
cargo build --workspace --release
./target/release/colmena setup
./target/release/colmena doctor
```

Two commands after the build. The firewall is active for every Claude Code session from now on.

## Your first mission in 30 seconds

After `colmena setup`, open Claude Code in any project and ask:

```
mcp__colmena__mission_suggest("review and harden the auth module with tests")
```

If the output says `recommended_agents: 3+`, spawn the squad:

```
mcp__colmena__mission_spawn(mission="review and harden the auth module with tests")
```

You get back scoped prompts for each agent with mission markers, time-limited delegations, and a pre-assigned reviewer. Paste the prompts into `Agent` tool calls. The `SubagentStop` hook blocks any worker from stopping until it submits for peer review; the auditor's scores feed ELO; your audit log grows one line per decision.

That's it. The rest of this README is reference.

## What a session looks like

```
# Agent reads a file → auto-approved
[tool_use] Read: src/main.rs
  → ALLOW: Read-only local operations

# Agent runs tests → auto-approved
[tool_use] Bash: cargo test --workspace
  → ALLOW: Build tools

# Agent tries to push → Colmena asks
[tool_use] Bash: git push origin feature-branch
  → ASK: Push requires human confirmation
  [y/n?]

# Agent tries force push → blocked, no prompt
[tool_use] Bash: git push --force origin main
  → BLOCK: Destructive operation
```

Every decision logged to `config/audit.log`.

## Use case vignettes

### 1. Pentest engagement (Caido-native)

You have a scoped target with a Caido project loaded. You want a pair of agents — one for the web surface (XSS, CSRF, CORS, IDOR, session mgmt) and one for the API surface (BOLA, mass assignment, rate limits) — coordinated by a security architect.

```
mcp__colmena__library_select(mission="bug bounty on the payments API and its admin dashboard")
# → caido-pentest pattern recommended (hierarchical, 3 agents)

mcp__colmena__mission_spawn(mission="bug bounty on the payments API and its admin dashboard",
                            pattern_id="caido-pentest")
```

Each agent gets `mcp__caido__*` scoped via role YAML, `Bash` restricted to nmap/curl/nuclei, findings auto-written to the store. When either pentester stops, they submit a findings artifact for peer review; the security architect evaluates. You get one structured report at the end, with every HTTP request in the audit log.

See [use-cases.md #pentest](docs/user/use-cases.md#1-pentest-engagement-caido-native-web--api) for the full walkthrough.

### 2. Dev team code review

You have a feature branch that needs systematic review, not a drive-by. The `code-review-cycle` pattern runs developer → code reviewer → auditor sequentially. The code reviewer is genuinely read-only (no `Write`, no `Edit`) — it cannot "helpfully" fix things and muddy the diff. The auditor scores each round via QPC (Quality + Precision + Comprehensiveness), and the scores feed back into per-role ELO.

```
mcp__colmena__mission_spawn(mission="review and harden error handling in the config loader")
```

Over time, reviewers that consistently catch real bugs climb to `Elevated` trust and get broader auto-approve; reviewers that rubber-stamp drop to `Probation`. Trust is earned, not declared.

See [use-cases.md #dev-review](docs/user/use-cases.md#2-dev-team-code-review-cycle) for the full walkthrough.

### 3. DevOps kubectl ops

Your CC session is going to touch `kubectl`, `helm`, `terraform`, and `aws`. Without Colmena, you approve every one by hand or grant blanket Bash. The `devops_engineer` role ships with those exact bash patterns pre-approved, secrets paths (`*.env`, `*credentials*`, `*.key`, `*.pem`) blocked by path rule, and destructive operations (`terraform destroy`, `kubectl delete ns`) routed to `ask`.

```bash
colmena delegate add --tool Bash --agent devops_engineer --session $SESSION_ID --ttl 4
# then in CC:
mcp__colmena__mission_spawn(mission="roll out the new helm chart to staging and watch for errors")
```

Every `kubectl apply` logs a line to `audit.log` with the rule ID that allowed it. If the chart rollout fails, the audit trail is the post-mortem.

See [use-cases.md #devops](docs/user/use-cases.md#3-devops-kubectl-ops) for the full walkthrough.

### 4. SRE runbook execution

An alert fires. You want an agent to walk a runbook — `kubectl get`, `journalctl`, `curl` against health endpoints, maybe a `systemctl status` — without ever touching production state. The `sre` role pre-approves the read-side of ops (`kubectl get`, `prometheus`, `dig`, `journalctl`, `systemctl status/show/list-units`) and routes anything that writes through `ask`.

```
mcp__colmena__mission_spawn(mission="investigate the 5xx spike on checkout-api and draft an incident note")
```

Findings accumulate as the agent works; alerts the agent raises are append-only (no agent can acknowledge its own alert). If you need to stop the investigation mid-flight, `colmena mission deactivate --id <id>` revokes all delegations instantly.

See [use-cases.md #sre](docs/user/use-cases.md#4-sre-runbook-execution) for the full walkthrough.

## Key features

**Runtime delegations.** Temporarily expand agent permissions without editing config. All delegations have mandatory TTL (max 24h) and optional agent/session scoping.

```bash
colmena delegate add --tool WebFetch --agent architect --ttl 4
```

**Multi-agent missions.** Spawn coordinated agent squads with one command. Colmena selects the pattern, maps roles, generates scoped prompts, creates time-limited delegations, and assigns a reviewer lead.

```bash
colmena suggest "refactor the auth module with tests and review"
# → complexity=medium, recommended_agents=3+, use Colmena
```

**ELO-based trust.** Agents earn trust through peer review. Five tiers: Uncalibrated → Standard → Elevated (auto-approve role tools) / Restricted / Probation. Trust calibrates automatically — good agents earn autonomy, bad ones get restricted.

**Output filtering.** Bash output passes through a 4-stage pipeline (ANSI strip → stderr-only → dedup → truncate) plus an optional prompt-injection heuristic before Claude processes it. Saves 30-50% tokens from noisy commands.

**Extensible library.** 15 built-in roles and 11 orchestration patterns ship out of the box. Create roles and patterns that match your domain — the engine is generic, the specialization is yours.

## Make it yours

Colmena's built-in library is a starting point. The real value comes when you create roles and patterns that fit your workflow.

```bash
colmena library create-role --id data_engineer \
  --description "ETL pipeline development and data quality validation" \
  --category development
```

This generates a complete role definition — YAML config with scoped tool permissions, a system prompt, and trust configuration. Edit `config/library/roles/data_engineer.yaml` to tighten scope:

```yaml
tools_allowed: [Read, Write, Edit, Bash, Glob, Grep]
permissions:
  bash_patterns:
    - '^python\b'
    - '^dbt\b'
    - '^sql\b'
  path_within:
    - '${MISSION_DIR}'
    - 'pipelines/'
```

Create a matching pattern:

```bash
colmena library create-pattern --id etl-review \
  --description "ETL pipeline development with data quality review" \
  --topology sequential
```

Your custom roles and patterns work with the full Colmena stack — trust firewall, scoped delegations, peer review, ELO ratings.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Workspace                         │
│                                                      │
│  ┌──────────────┐   ┌──────────────┐                │
│  │ colmena-core │   │colmena-filter│                │
│  │  (library)   │   │  (pipeline)  │                │
│  │              │   │              │                │
│  │ • firewall   │   │ • ANSI strip │                │
│  │ • config     │   │ • dedup      │                │
│  │ • delegate   │   │ • truncate   │                │
│  │ • ELO        │   │ • stats      │                │
│  │ • review     │   └──────┬───────┘                │
│  │ • library    │          │                         │
│  │ • missions   │          │                         │
│  └──────┬───────┘          │                         │
│         │                  │                         │
│  ┌──────┴──────────────────┴───┐  ┌──────────────┐  │
│  │      colmena-cli            │  │ colmena-mcp  │  │
│  │      (hook binary)          │  │ (MCP server) │  │
│  │                             │  │              │  │
│  │ • PreToolUse (evaluate)     │  │ • 27 tools   │  │
│  │ • PostToolUse (filter)      │  │ • stdio      │  │
│  │ • PermissionRequest (auto)  │  │ • rate limit │  │
│  │ • SubagentStop (review)     │  │              │  │
│  └─────────────────────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────┘
```

- **colmena-core** — business logic. Protocol-agnostic, zero platform deps.
- **colmena-cli** — hook binary invoked by Claude Code on every tool call.
- **colmena-filter** — output filtering pipeline.
- **colmena-mcp** — 27 tools exposed as native Claude Code tools via MCP.

Depth: [docs/dev/architecture.md](docs/dev/architecture.md).

## CLI reference

```
colmena setup                         # One-command onboarding
colmena doctor                        # Health check (7 categories)
colmena delegate add/list/revoke      # Manage trust delegations
colmena library list/show/select      # Browse roles and patterns
colmena library create-role/create-pattern   # Create your own
colmena review list/show              # Peer reviews
colmena elo show                      # ELO leaderboard
colmena calibrate run/show/reset      # Trust calibration
colmena mission list/deactivate       # Mission lifecycle
colmena suggest "<mission>"           # Complexity analysis
colmena stats                         # Session statistics
```

## Documentation

**For users:**
- [Getting Started](docs/user/getting-started.md) — zero to running in 5 minutes
- [Use Cases](docs/user/use-cases.md) — full tutorials for pentest, dev review, devops, SRE, refactor, docs
- [Install Mode B](docs/install-mode-b.md) — let your own CC bootstrap Colmena
- [User Guide](docs/guide.md) — detailed walkthrough with a payments API audit example

**For contributors:**
- [Architecture](docs/dev/architecture.md) — crates, data flows, trust model, MCP internals
- [Contributing](docs/dev/contributing.md) — dev setup, how to add rules/tools/roles, PR workflow
- [Internals](docs/dev/internals.md) — edge cases, dark corners, safety contracts

## Design principles

- **< 15ms** hook latency — Rust, pre-compiled regexes, no network calls
- **Safe fallback** — any hook failure returns `ask`, never `deny` or crash
- **Files over databases** — YAML config, JSON queue, JSONL logs, git-versionable
- **Build on CC, not around it** — hooks + MCP, no hacks
- **Domain-agnostic** — the engine is generic, the domain is in your templates
- **Human authority wins** — YAML overrides always beat ELO; you can revoke everything with `colmena calibrate reset`

## Security

See [SECURITY.md](./SECURITY.md) for the disclosure process. Colmena ships with a documented STRIDE/DREAD threat model (local reference) and every release goes through `cargo deny` and `cargo audit` in CI.

## License

Released under the [MIT License](./LICENSE).

## Contributors

See [CONTRIBUTORS.md](./CONTRIBUTORS.md) for acknowledgments.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) and [docs/dev/contributing.md](docs/dev/contributing.md).

---

<p align="center">built with ❤️‍🔥 by AppSec</p>
