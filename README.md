# Colmena

[![CI](https://github.com/4rth4S/colmena/actions/workflows/ci.yml/badge.svg)](https://github.com/4rth4S/colmena/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Version](https://img.shields.io/badge/version-0.14.0-blue.svg)](./Cargo.toml)

<p align="center">
  <img src="docs/colmena-banner.png" alt="Colmena — the hive defends the colony" width="400">
</p>

<p align="center"><strong>Deterministic governance for multi-agent Claude Code.</strong></p>

<p align="center">YAML rules + audit.log for every tool call. Multi-agent missions with centralized auditor review. ELO-calibrated trust per role.</p>

---

## Which fits you?

| You are a... | Colmena gives you |
|---|---|
| **Pentester** | Scoped Caido-native web/API agents, restricted Bash by default, findings store for triage, audit trail that regulators can replay. Start here: `docs/user/use-cases.md#1-pentest-engagement`. |
| **Developer** | Auto-approve for `Read`, `cargo test`, `git log`; ask on `git push`; block on `--force`. A code reviewer that is genuinely read-only. Start here: `docs/user/getting-started.md`. |
| **DevOps / SRE** | Bash patterns for `kubectl`, `terraform`, `helm`, `docker` pre-wired. Secrets paths blocked. Delegations scoped per-session. Start here: `docs/user/use-cases.md#3-incident-response`. |

If you are none of the above but run agents in production, Colmena gives you a deterministic audit trail and a way to hold each role accountable over time.

## Why Colmena

I built Colmena because I could not trust autonomous agents. Tools like OpenClaw or `--dangerous-skip-permissions` propose giving agents total control to stop them asking. That puts too much risk on the operator. Colmena gives agents freedom within their domain, with deterministic enforcement at the boundary. A Dark Factory in local — auditable, tuneable, trustable by the operator. Every firewall decision writes to the audit log with the matching rule ID. Any auditor can replay the log and explain why a call was allowed, asked, or blocked.

The problem is not unique to me. Every team running Claude Code hits the same wall: approve every tool call by hand, or grant blanket permissions and hope for the best. Neither scales when multiple agents run in parallel and compliance matters.

- **Y-spam.** Answering "y" to every safe `Read` and `cargo test` is friction, not security.
- **Blanket allow.** Once you enable "allow all", you have no audit trail and no accountability.
- **Multi-agent chaos.** Spawning three agents in parallel with overlapping file scopes ends in conflicts and unreviewed work.
- **Opaque decisions.** When something goes wrong, you want to know which rule allowed it — not a probability score.

Colmena's position: policy is code, review is mandatory, trust is earned. Every decision is a rule you wrote, every artifact goes through auditor review, every role accumulates an ELO that reflects how well it actually works.

### How it compares to Claude Code auto-mode

Anthropic's `--enable-auto-mode` (research preview) and Colmena solve different layers of the same problem. They are complementary, not competing.

| Dimension | Claude Code auto-mode | Colmena |
|---|---|---|
| Decision model | Probabilistic (LLM classifier) | Deterministic (YAML rules + regex) |
| Per-call cost | Model tokens per classification | Zero — no network, no LLM call |
| Explainability | Opaque classifier output | `audit.log` line with matching rule ID |
| Scope | Single-agent intent detection | Single + multi-agent with auditor review |
| Accountability | Per tool call | Per agent + per role, ELO over time |
| Storage | Cloud-side | Local filesystem (YAML / JSON / JSONL) |

Auto-mode catches semantic intent the rule base cannot — prompt injection attempts, mass-delete nudges, context the agent should not have. Colmena enforces the policy you wrote and keeps a tamper-evident local record. Use them together.

### What Colmena is not

Colmena is not an access control list. It is not a one-time config you set and forget. It is a runtime governance layer that adapts as your agents work. Every mission generates new delegations, every review adjusts ELO ratings, every audit.log entry is evidence you can replay.

Colmena is also not a SaaS platform. There is no cloud component, no telemetry, no remote API. Everything runs on your machine, everything stays on your disk. The config is YAML, the queue is JSON, the audit trail is JSONL. All of it is version-controllable and grep-able.

## Features

**Manifests (`.mission.yaml`).** Define missions as version-controlled YAML files. Declare roles, scope paths, bash patterns, acceptance criteria, and ELO buckets. `colmena mission validate` checks your schema, `colmena mission spawn --from <manifest>` creates the squad. `colmena mission init` scaffolds new manifests, `--from-history` generates one from your audit log.

**Chain-aware firewall.** Bash chains like `mkdir && cd && git clone && echo done` are evaluated piece by piece — each sub-command goes through the full rule set independently. Bare assignments (`KEY=value`) auto-approve as no-op. Subshells fall through to a safe default. Toggle with `chain_aware: true` in your config (on by default).

**Auto-elevate.** When you approve the same agent and the same command twice within a configurable window, Colmena creates a session-scoped delegation automatically. No more answering the same question three times.

**Runtime-agent-overrides.** Add or remove agent-specific rules without editing the main config file. Overrides live in `runtime-agent-overrides.json` — separate from `trust-firewall.yaml` so your version-controlled config stays clean. Useful for temporary scoping during active missions.

**Runtime delegations.** Temporarily expand agent permissions without editing config. All delegations have mandatory TTL (max 24h) and optional agent or session scoping.

```
colmena delegate add --tool WebFetch --agent architect --ttl 4
```

**Multi-agent missions.** Spawn coordinated agent squads from a manifest or a one-liner. Colmena selects the pattern, maps roles to topology slots, generates scoped prompts with mission markers, creates time-limited delegations, and assigns a reviewer.

```
colmena suggest "refactor auth module with tests and review"
colmena mission spawn --from my-mission.mission.yaml
```

**ELO-based trust.** Agents earn trust through auditor review. Five tiers: Uncalibrated > Standard > Elevated (auto-approve role tools) / Restricted / Probation. Trust calibrates automatically from review outcomes.

**Output filtering.** Bash output passes through a 4-stage pipeline (ANSI strip, stderr-only, dedup, truncate) plus an optional prompt-injection heuristic before Claude processes it. Saves 30-50% tokens from noisy commands.

**Extensible library.** 22 built-in roles and 13 orchestration patterns ship out of the box. Create your own with `colmena library create-role` and `colmena library create-pattern`.

### What a session looks like

Open Claude Code in any project after `colmena setup`. The firewall is live:

```
# Agent reads a file — auto-approved
[tool_use] Read: src/main.rs
  > ALLOW: Read-only local operations

# Agent runs tests — auto-approved
[tool_use] Bash: cargo test --workspace
  > ALLOW: Build tools

# Agent tries to push — Colmena asks
[tool_use] Bash: git push origin feature-branch
  > ASK: Push requires human confirmation
  [y/n?]

# Agent tries force push — blocked, no prompt
[tool_use] Bash: git push --force origin main
  > BLOCK: Destructive operation
```

Every decision is logged to `config/audit.log` with the matching rule ID.

A multi-agent mission adds another layer. Paste a `mission_spawn` prompt into CC and you get back scoped agent prompts with mission markers, time-limited delegations, and a pre-assigned auditor. The `SubagentStop` hook blocks any worker from stopping until it submits for review. The auditor's scores feed ELO. Your audit log grows one line per decision.

### How the trust tiers work

Every role starts at Uncalibrated or Standard trust. As the auditor evaluates artifacts, scores accumulate in the ELO log. The `calibrate run` command reads that log and adjusts trust:

- **Elevated.** Role tools are auto-approved in the PermissionRequest hook. Bash patterns from the role YAML apply. No "y" prompts for routine work.
- **Restricted.** The role's tool calls go through `ask` — human confirms every time. Used after consistently low scores.
- **Probation.** Same as Restricted, with an alert generated. Used after critical findings.

YAML `agent_overrides` always beat ELO — if you write a rule that says "developer is blocked from Write", no ELO rating overrides that. Human authority wins.

## Quick install

```bash
git clone https://github.com/4rth4S/colmena
cd colmena
cargo build --workspace --release
./target/release/colmena setup
./target/release/colmena doctor
```

Two commands after the build. The firewall is active for every Claude Code session from now on. See `docs/user/getting-started.md` for the full walkthrough.

For Mode B — let your own Claude Code bootstrap Colmena — see `docs/install-mode-b.md`.

## Make it yours

The built-in library is a starting point. Create roles and patterns that fit your domain:

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

Custom roles and patterns work with the full stack — trust firewall, scoped delegations, auditor review, ELO ratings.

For private or experimental roles that should stay out of the public repo, set `$COLMENA_PRIVATE_LIBRARY` to a directory outside the repo. Private entries with the same ID override public ones.

## Documentation

**For users:**
- `docs/user/getting-started.md` — zero to running in 5 minutes
- `docs/user/use-cases.md` — full tutorials for pentest, dev, incident response, compliance
- `docs/install-mode-b.md` — let your CC bootstrap Colmena
- `docs/guide.md` — detailed walkthrough of every subsystem

**For contributors:**
- `docs/dev/architecture.md` — crates, data flows, trust model, MCP internals
- `docs/dev/contributing.md` — dev setup, how to add rules, tools, roles
- `docs/dev/internals.md` — edge cases, safety contracts, gotchas

## CLI reference

```
colmena setup                         # One-command onboarding
colmena doctor                        # Health check (7 categories)
colmena delegate add/list/revoke      # Manage trust delegations
colmena library list/show/select      # Browse roles and patterns
colmena library create-role/pattern   # Create your own
colmena review list/show              # Auditor reviews
colmena elo show                      # ELO leaderboard
colmena calibrate run/show/reset      # Trust calibration
colmena mission init/validate/spawn   # Manifest-driven missions
colmena mission list/deactivate       # Mission lifecycle
colmena mission status/abort          # Monitor running missions
colmena suggest "<mission>"           # Complexity analysis
colmena stats                         # Session statistics
```

## Getting help

- Open a [GitHub Issue](https://github.com/4rth4S/colmena/issues) for bugs or feature requests.
- No Discord, Slack, or community channels yet. Issues only for now.

## Design principles

- **< 15ms** hook latency — Rust, pre-compiled regexes, no network calls.
- **Safe fallback** — any hook failure returns `ask`, never `deny` or crash.
- **Files over databases** — YAML config, JSON queue, JSONL logs, git-versionable.
- **Build on CC, not around it** — hooks + MCP, no hacks.
- **Domain-agnostic** — the engine is generic, the domain is in your templates.
- **Human authority wins** — YAML overrides always beat ELO; revoke everything with `colmena calibrate reset`.

## Security

See `SECURITY.md` for the disclosure process. Colmena ships with a documented STRIDE/DREAD threat model and every release goes through `cargo deny` and `cargo audit` in CI.

## License

Released under the [MIT License](./LICENSE).

## Contributors

See [CONTRIBUTORS.md](./CONTRIBUTORS.md).

---

<p align="center">built with ❤️‍🔥 by AppSec</p>
