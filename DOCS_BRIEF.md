# Colmena Docs Regeneration Brief

**Version:** 1.0
**For:** 2 technical writers (architect reviews output)
**Source of truth:** `/home/fr33m4n/colmena/CLAUDE.md` (codebase state, v0.14.0)
**Target docs (6):** `README.md`, `docs/user/getting-started.md`, `docs/user/use-cases.md`, `docs/guide.md`, `docs/install-mode-b.md`, `docs/presentation.html`

---

## 1. Voice and Tone

**Technical without being dry.** Active voice, one idea per paragraph. Short sentences.
- Write "The firewall evaluates" — not "The system performs evaluation of"
- Write "Run this command" — not "You should run the following command"

**First person for the origin story only.** The "Why Colmena" section in README opens with "I built Colmena because..." — then pivots to the universal problem statement. No other section uses first person.

**Second person for instructions.** "Install Colmena with `cargo build --workspace --release`." Not "Users can install..."

**No buzzwords.** Never use: revolutionary, game-changing, AI-powered, next-generation, paradigm shift, groundbreaking. Authentic beats polished. If a phrase sounds like marketing copy, rewrite it.

**Spanish-accented English is fine.** Coco is Latin American. The docs should sound like they were written by someone who builds things, not by a copywriter.

---

## 2. Canonical Terminology

| Use this | Not this |
|----------|----------|
| mission | task, job, run |
| agent instance | agent copy, worker instance |
| trust firewall | permission system, security layer |
| ELO rating | score, reputation, rank |
| manifest | config file, settings file (for `.mission.yaml`) |
| delegation | permission grant, access token |
| auditor | reviewer, checker |
| spawn | launch, start, create (for missions) |
| runtime-agent-overrides | dynamic rules, temporary permissions |
| auto-elevate | auto-approve, smart allow |

**Compound terms are hyphenated.** `runtime-agent-overrides`, `auto-elevate`, `chain-aware`, `trust-circle`.

**ELO is always capitalized.** It stands for Elo (the rating system named after Arpad Elo). Write "ELO" in all caps to distinguish from the name.

**Never use "simply", "just", "obviously".** These words hide complexity or assume reader knowledge. If something is straightforward, show it with a clear example, not a label.

---

## 3. Per-Doc Structure

### README.md (~400 lines)

The front door. Every reader starts here.

- Banner + badges (build, version, license)
- "Which fits you?" table — 3 profiles (pentester, dev, devops/SRE) with 1-line "start here" per profile
- **Why Colmena** — Opens first-person origin story: "I built Colmena because I couldn't trust autonomous agents. Tools like OpenClaw or `--dangerous-skip-permissions` propose giving agents total control to stop them asking. That's too much risk. Colmena gives agents freedom within their domain, with deterministic enforcement at the boundary. A Dark Factory in local — auditable, tuneable, trustable by the operator." Then pivots: "The problem isn't unique to me..." (universalizes)
- Features list (include v0.14.0 + M7.15: manifests, auto-elevate, runtime-agent-overrides, `--from-history`, chain-aware firewall)
- Quick install (2 commands: `cargo build --workspace --release && ./target/release/colmena setup`)
- Getting help (GitHub Issues, no Discord/Slack yet)
- Cross-reference: `docs/user/getting-started.md` for full install

### docs/user/getting-started.md (~350 lines)

Onboarding walkthrough. Reader runs every command.

- Prerequisites (Rust toolchain, git, Linux/macOS)
- Install: Mode A (source) — `git clone`, `cargo build`. Mode B referenced but body is in `install-mode-b.md`
- `colmena setup && colmena doctor` — explain what each does
- First manifest: `colmena mission init` creates a `.mission.yaml`
- First mission: `colmena mission spawn --from <manifest> --dry-run` — show the output, explain the agents, the auditor, the markers
- What just happened — walk the output: who is each agent, what is the auditor's role, where are the files
- Next steps: `colmena mission spawn --from <manifest>` (no dry-run), then `docs/user/use-cases.md` for real scenarios
- Cross-reference: `docs/guide.md` for subsystem deep dives, `docs/install-mode-b.md`

### docs/user/use-cases.md (~500 lines)

Four cases. Each case = problem + solution + manifest YAML + outcome.

**Case 1: Pentest BBP (Coinbase follow-up).** Problem: A wallet popup vulnerability scan generates 12 attack chains but triagers need reproducible evidence per chain, and the mission has to fit within a BBP scope. Solution: spawn a squad with 2 agents (bbp_pentester_web + bbp_pentester_api) + auditor. Each agent owns a subdomain and artifacts. Manifest includes `chain_aware: true` for Bash chains. Outcome: 8 ELO events generated, reproducible artifacts, triager accepted submission.

**Case 2: Dev refactor (Colmena self-dev).** Problem: A Rust workspace with 4 crates needs a refactor that touches all crates — trust-firewall rules, ELO algorithm, CLI subcommands. One human with one Claude cannot track cross-crate side effects. Solution: spawn 3 agents (developer + tester + architect) scoped via `workspace_scope: repo-wide`. Manifest uses `--code-paths` to scope each agent's `path_within`. Auditor reviews each PR artifact. Outcome: refactor lands in 2 hours, 12 reviews, zero regressions.

**Case 3: Incident response (SRE latency spike).** Problem: Production latency spikes at 3 AM. On-call SRE needs to investigate without exposing credentials to the agent. Solution: spawn an incident-response squad with `platform_engineer` + `sre` agents. Manifest delegates Bash with `bash_pattern: "(kubectl|curl|grep|awk) .*"` — agent can run diagnostics but cannot write files or access secrets. Outcome: root cause identified in 15 minutes, incident report filed, agent deactivated.

**Case 4: Compliance audit (log replay).** Problem: SOC 2 auditor asks "show me every decision the trust firewall made during last month's penetration test." Solution: replay `config/audit.log` through `colmena` — each line has matching rule ID, tool, agent, decision. Manifest validates the audit trail scope. Outcome: auditor accepts the log as evidence, no manual report needed.

**Each manifest MUST be valid YAML.** Copy-paste into `colmena mission validate` and it passes. Use real role IDs and tool names from the library. No pseudocode.

### docs/install-mode-b.md (~150 lines)

Concise. Mode B is "point your Claude Code at this repo."

- When to choose B over A (already using CC, want to bootstrap from within CC)
- `git clone git@github.com:4rth4S/colmena.git && cd colmena`
- `cargo build --workspace --release`
- `./target/release/colmena setup` (registers hooks + MCP)
- `colmena doctor` to verify
- That's it — CC reads CLAUDE.md and self-configures
- Cross-reference: `docs/user/getting-started.md` for first mission

### docs/guide.md (~1200 lines)

Reference by subsystem. Each section: what it is, how it works, CLI commands (copy-pastable), MCP tools, examples.

**Subsystems in order:**
1. **Firewall** — YAML rules, compile-time regex, chain-aware Bash eval, precedence (blocked > delegations > agent_overrides > ELO > restricted > chain_aware > chain_guard > mission_revocation > trust_circle > defaults). CLI: `colmena config check`.
2. **Delegations** — Role-scoped permissions with TTL, `--session` scoping, `bash_pattern` conditions. CLI: `colmena delegate add/list/revoke`. MCP: `delegate`, `delegate_list`, `delegate_revoke`.
3. **Missions** — Agents with governance, auditor role, ELO cycle. SubagentStop gate enforces review before stop. CLI: `colmena mission list/deactivate/init/spawn/validate/status/abort`. MCP: `mission_spawn`, `mission_deactivate`, `mission_suggest`.
4. **Manifests (v1)** — The `.mission.yaml` format. Structure: schema, agents, roles, tools, scope. Auto-elevate, runtime-agent-overrides, `--from-history`. `colmena mission init` scaffolds them, `colmena mission validate` checks them, `colmena mission spawn --from` runs them. `elo_bucket_for` maps roles to ELO buckets.
5. **ELO and Calibration** — Append-only JSONL log with temporal decay, trust tiers (Uncalibrated > Standard > Elevated/Restricted/Probation), min 3 reviews to calibrate. CLI: `colmena elo show`, `colmena calibrate run/show/reset`. MCP: `elo_ratings`, `calibrate_auditor`, `calibrate_auditor_feedback`.
6. **MCP Tools (27 total)** — Table: tool name, function, rate-limited?, restricted?. Grouped: Firewall (3), Library (6), Review (3), ELO/Findings (4), Alerts/Calibrate (4), Operations (3), Session (1). Every tool listed.
7. **Audit and Findings** — `config/audit.log` append-only, one line per firewall decision with matching rule ID. Findings store with severity enum and QPC framework. CLI: `colmena review list/show`. MCP: `review_submit`, `review_list`, `review_evaluate`, `findings_query`, `findings_list`.
8. **Security** — No LLM calls in the hot path, deterministic rules, tamper-evident audit log, path normalization, atomic writes, file permission checks.

### docs/presentation.html (~1200 lines)

Standalone HTML with inline CSS/JS. 10 slides. No external dependencies.

1. **Title** — Colmena: Trustable Multi-Agent Orchestration. Coco / 4rth4S.
2. **Problem** — Autonomous agents ask too often or not enough. Binary trust doesn't work.
3. **Approach** — Deterministic governance + ELO-calibrated trust + multi-agent accountability.
4. **Architecture** — 4 crates (core, cli, filter, mcp), 5 CC hook points, 27 MCP tools.
5. **Firewall** — YAML rules, chain-aware Bash eval, precedence diagram, `<15ms` latency.
6. **Missions** — Agent squad spawn, manifest-driven, auditor review cycle, SubagentStop gates.
7. **Manifests** — `.mission.yaml` format, `mission init` → `validate` → `spawn`, auto-elevate, runtime overrides.
8. **ELO** — Append-only log, temporal decay, 4 trust tiers, per-role calibration. ELO overrides in separate file.
9. **Metrics** — 622 tests, v0.14.0, 27 MCP tools, 56 prompts saved average per session, ~20% friction reduction (measured 2026-04), zero LLM calls in hot path.
10. **Get Started** — `git clone && cargo build && colmena setup`. Links to README and getting-started.

---

## 4. Cross-Reference Map

```
README ──┬─→ getting-started (#install)
          ├─→ use-cases
          └─→ install-mode-b

getting-started ──┬─→ use-cases (next steps)
                  ├─→ guide (deep dives)
                  └─→ install-mode-b

use-cases ──┬─→ guide (reference per subsystem)
            └─→ getting-started (first mission)

guide ──┬─→ getting-started
        └─→ use-cases

install-mode-b ──┬─→ getting-started
                 └─→ guide
```

Every doc links to at least one other doc. Readers should never dead-end.

---

## 5. What NOT to Do

- **No Rust types, file paths, or implementation details.** Do not mention `colmena_core::`, `serde`, `rmcp`, `Cargo.toml`, or internal module names. The reader does not care how the code is organized.
- **No features that don't exist yet.** If it isn't in v0.14.0, don't write it. Do not mention crates.io publish, web UI, SaaS, or "coming soon." No "TBD" or placeholder text.
- **No marketing language.** No "revolutionary", "game-changing", "AI-powered", "next-generation", or "paradigm shift." If a sentence would fit in a startup pitch deck, rewrite it.
- **No performance claims without data.** If you write "under 15ms", cite the measurement. If you write "20% friction reduction", cite the April 2026 measurement. Do not make up numbers.
- **No false precision.** "~20%" not "19.47%". "~400 lines" not "387 lines".
- **No "simply", "just", "obviously".** These words assume the reader shares your context. Delete them.
- **No "we" for the company.** Colmena has no company. "I" (Coco) or "you" (user). Never "we at Colmena."
- **No Discord, Slack, or community links.** Only GitHub Issues for now.

---

## 6. Origin Story (for the "Why" section)

Coco created Colmena because he couldn't trust autonomous agents. Tools like OpenClaw or Claude Code's `--dangerous-skip-permissions` propose giving agents total control to stop them asking. But that puts too much risk on the operator. Colmena's approach: give agents freedom within their domain, with deterministic enforcement at the boundary. A Dark Factory in local — auditable, tuneable, trustable by the operator. Every firewall decision writes to the audit log with the matching rule ID. Any auditor can replay the log and explain why a call was allowed, asked, or blocked.

---

## 7. Deliverables Checklist

Each writer produces one or more docs. Architect reviews against this brief before marking done.

- [ ] README.md: banner, profile table, origin story, features, install, links
- [ ] getting-started.md: prerequisites, install, setup+doctor, first manifest, first mission, walkthrough
- [ ] use-cases.md: 4 valid manifests, real scenarios, problem/solution/outcome per case
- [ ] guide.md: 8 subsystems, all 27 MCP tools, every CLI command copy-pastable
- [ ] install-mode-b.md: concise, clone→build→setup→done
- [ ] presentation.html: 10 slides, standalone HTML, no external deps
- [ ] Cross-references: every doc links to at least one other
- [ ] Terminology audit: no banned terms, no "simply/just/obviously", no missing features
