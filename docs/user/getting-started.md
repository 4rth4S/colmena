# Getting Started

Zero to a working trust firewall in 5 minutes, then your first multi-agent mission.

## Prerequisites

- **Claude Code** installed and working (the `claude` command is available).
- **Rust toolchain** (stable) via [rustup](https://rustup.rs/) — only needed if you build from source.
- **Linux or macOS.** Windows is not tested but may work under WSL2.
- A real `$HOME`. Colmena refuses to fall back to `/tmp` on purpose.

## Install

Two paths. Both end at `colmena doctor` green.

### Mode A — from source

```bash
git clone https://github.com/4rth4S/colmena.git
cd colmena
cargo build --workspace --release
./target/release/colmena setup
./target/release/colmena doctor
```

### Mode B — let your Claude Code bootstrap Colmena

If Claude Code is already your daily driver, point it at this repo and let it do the work. See `docs/install-mode-b.md` for the full walkthrough.

---

## What `colmena setup` does

One idempotent command. Run it again later — your edits are preserved, new defaults land in `.defaults/` for reference.

1. **Detects mode.** Repo mode if a Cargo workspace is nearby (config at `<project>/config/`), otherwise standalone (`~/.colmena/config/`).
2. **Creates config directories.** `library/roles`, `library/patterns`, `library/prompts`, `queue/pending`, `queue/decided`.
3. **Writes default config.** All defaults embedded in the binary — no downloads needed.

   | File | Purpose |
   |---|---|
   | `trust-firewall.yaml` | What to allow, ask, block |
   | `filter-config.yaml` | Output filter settings |
   | `review-config.yaml` | Auditor review thresholds |
   | `library/roles/*.yaml` | 22 built-in roles |
   | `library/patterns/*.yaml` | 13 orchestration patterns |
   | `library/prompts/*.md` | System prompts per role |

4. **Registers hooks** in `~/.claude/settings.json`:
   - `PreToolUse` — evaluates every tool call against the firewall
   - `PostToolUse` — filters noisy Bash output before Claude sees it
   - `PermissionRequest` — auto-approves tools within a role's scope
   - `SubagentStop` — blocks agents from stopping without submitting for auditor review
5. **Registers MCP** in `~/.mcp.json` so Claude Code sees the 31 Colmena tools natively.

Pass `--force` to overwrite custom files. Pass `--dry-run` to preview without writing.

## Verify the install

```bash
./target/release/colmena doctor
```

Seven categories: config validity, hook registration, MCP registration, library integrity, runtime state, file permissions, version consistency. All should be green.

## First run — the firewall in action

Open Claude Code in any project. The firewall is live from the first tool call.

**Read call** — auto-approved. No prompt. The file loads.

**`cargo test --workspace`** — auto-approved by the `build tools` rule in `trust_circle`.

**`rm -rf target/`** — the firewall matches a `restricted` rule:

```
[tool_use] Bash: rm -rf target/
  ASK: Potentially destructive system command
  Allow? [y/n]
```

**`git push --force origin main`** — blocked outright, no prompt, no override:

```
[tool_use] Bash: git push --force origin main
  BLOCK: Destructive operation
```

Every decision writes a line to `config/audit.log` with the matching rule ID.

## Your first manifest

Missions start with a manifest — a YAML file that defines the squad, their roles, their scope, and how they work together.

Create one with:

```bash
colmena mission init my-first-mission --for "review the auth module and improve test coverage"
```

This generates `my-first-mission.mission.yaml` in the current directory. Open it and see what a manifest looks like:

```yaml
version: 1
mission_id: my-first-mission
description: "review the auth module and improve test coverage"
author: operator
pattern: code-review-cycle
mission_ttl_hours: 8
agents:
  - role: developer
    task: "Add tests for auth module"
  - role: code_reviewer
    task: "Review auth module changes"
  - role: auditor
scope:
  paths:
    - /home/you/your-project
  bash_patterns:
    extra_allow:
      - '^cargo (build|test|check|clippy)\b'
      - '^git (diff|log|status)\b'
mission_gate: enforce
```

Every manifest has a `version`, a `mission_id`, a list of `agents` with roles and tasks, and a `scope` section that limits file paths and bash commands. The `auditor` role is mandatory — every mission has a reviewer.

### Validate the manifest

```bash
colmena mission validate my-first-mission.mission.yaml
```

This checks the schema, verifies role IDs exist in the library, and confirms the pattern is valid. A passing validation means the manifest is ready to spawn.

If you want to generate a manifest from past activity instead of a template:

```bash
colmena mission init --from-history
```

This reads your `audit.log`, finds Agent spawn calls, and generates a manifest that reproduces the mission. Useful for standardizing workflows you already ran ad-hoc.

## Your first mission

Now turn the manifest into a running mission. Start with a dry run to see what would happen:

```bash
colmena mission spawn --from my-first-mission.mission.yaml --dry-run
```

You will see:

- The selected pattern (`code-review-cycle` — sequential: developer > code_reviewer > auditor)
- Each topology slot mapped to a real role
- Scoped delegation commands that `mission spawn` would create
- The mission marker (`<!-- colmena:mission_id=my-first-mission -->`) that will be embedded in each agent's prompt

This is read-only. No files are written, no delegations are created.

### What the output shows

The dry run prints three sections:

**Pattern and topology.** The pattern determines the order agents work in. `code-review-cycle` is sequential — the developer works first, the code reviewer reviews the diff, the auditor evaluates both.

**Agent prompts (preview).** Each agent gets a prompt with:
- A role-specific system prompt from the library
- The task from your manifest
- The scope boundaries (which paths and bash commands are allowed)
- A mission marker that the firewall uses to enforce mission boundaries
- A pre-filled `review_submit` call so the agent knows exactly what to send before stopping

**Delegations (preview).** Each role gets time-limited permissions:
- `developer` — `Read`, `Write`, `Edit`, `Bash` (with cargo/git patterns)
- `code_reviewer` — `Read`, `Glob`, `Grep` (no `Write` or `Edit`)
- `auditor` — `mcp__colmena__review_evaluate`, `mcp__colmena__findings_query`

### Spawn for real

When the dry run looks correct:

```bash
colmena mission spawn --from my-first-mission.mission.yaml
```

This writes the agent prompts to `~/.claude/agents/<role>.md`, creates the time-limited delegations, and embeds the mission marker.

### What the spawn creates

Walk through what `mission spawn` created:

**Developer prompt.** The developer gets `Read`, `Write`, `Edit`, and `Bash` scoped to `cargo` and `git` patterns. Their prompt says: "Add tests for auth module" — the task from your manifest. It includes `<!-- colmena:mission_id=my-first-mission -->` so every tool call the developer makes is tagged with this mission. The prompt ends with: "Before stopping, call `mcp__colmena__review_submit` with your artifact path."

**Code reviewer prompt.** The code reviewer gets `Read`, `Glob`, and `Grep` — no `Write`, no `Edit`. The reviewer genuinely cannot modify files. Their task is to read the diff and file findings. They also get the mission marker and a pre-filled `review_submit` call.

**Auditor prompt.** The auditor gets `mcp__colmena__review_evaluate` and `mcp__colmena__findings_query`. The auditor does NOT get a `review_submit` call — the centralized reviewer is exempt from the review cycle. Their job is to score both agents using QPC and file findings.

**Delegations.** Each delegation has an 8-hour TTL (configurable with `--mission-ttl`). The developer's Bash delegations are scoped to `^cargo (build|test|check|clippy)` and `^git (diff|log|status)` — no blanket Bash auto-approve. The code reviewer has no Bash delegation at all.

**Subagent files.** The prompts are written to `~/.claude/agents/developer.md`, `~/.claude/agents/code_reviewer.md`, and `~/.claude/agents/auditor.md`. Open Claude Code and paste each prompt into a separate `Agent` tool call.

### Run the mission

In Claude Code, paste the developer prompt first. The developer reads the auth module, writes tests, runs them. When the developer tries to stop, the `SubagentStop` hook intercepts and says "submit for review first." The developer calls `mcp__colmena__review_submit` with the test file path.

Then paste the code reviewer prompt. The reviewer reads the diff, comments on test coverage, files findings. The reviewer also must submit before stopping.

Finally, paste the auditor prompt. The auditor reads both artifacts and evaluates:

```
mcp__colmena__review_evaluate(
  review_id="r_...",
  quality=8, precision=9, comprehensiveness=7,
  findings=[{ category="completeness", severity="low", ... }]
)
```

The scores feed ELO. If a score is low, an alert fires. The mission is complete.

## Mission enforcement during the run

- **SubagentStop hook.** When a worker calls `Stop`, the hook checks: does this agent have a pending `review_submit`? If not, the stop is blocked. The agent must submit the artifact first.
- **Reviewer gate.** When a reviewer calls `Stop`, the hook checks: does this agent have pending evaluations as a reviewer? If so, the stop is blocked until `review_evaluate` is called.
- **Auditor exemption.** The auditor role has `role_type: auditor` in its YAML definition. The SubagentStop hook skips the review check for auditors — the centralized reviewer does not submit its own work.
- **Mission deactivation.** `colmena mission deactivate --id my-first-mission` revokes every delegation for every agent in the mission. Even if Claude Code has learned to auto-approve certain tools via session rules, the mission revocation check in PreToolUse fires first and denies.
- **Stale review handling.** If you re-spawn a worker after tweaking its prompt, the prior pending review is auto-invalidated. The new review pairs with a fresh reviewer.
- **Every tool call is logged.** `config/audit.log` grows one line per decision.

## Customize the firewall

`config/trust-firewall.yaml` has three tiers evaluated in order. Here is the precedence:

```
blocked > delegations > agent_overrides (YAML) > ELO overrides > restricted >
chain_aware > chain_guard > mission_revocation > trust_circle > defaults
```

### Add a rule

Auto-approve `npm install`:

```yaml
trust_circle:
  - tools: [Bash]
    conditions:
      bash_pattern: '^npm install\b'
    action: auto-approve
    reason: 'Package installation'
```

### Tighten a rule

Block `curl` outright:

```yaml
blocked:
  - tools: [Bash]
    conditions:
      bash_pattern: '^curl\b'
    action: block
    reason: 'No network requests'
```

### Validate after editing

```bash
colmena config check
```

## The audit log

Every firewall decision looks like this:

```
[2026-04-15T10:30:00Z] ALLOW session=sess_abc agent=* tool=Read key="src/main.rs" rule=trust_circle
[2026-04-15T10:30:01Z] ALLOW session=sess_abc agent=* tool=Bash key="cargo test --workspace" rule=trust_circle
[2026-04-15T10:30:05Z] ASK   session=sess_abc agent=developer tool=Bash key="rm -rf target/" rule=restricted
[2026-04-15T10:30:10Z] BLOCK session=sess_abc agent=* tool=Bash key="git push --force origin main" rule=blocked
```

Rotates at 10MB. Aggregate stats:

```bash
colmena stats
colmena stats --session <session-id>
```

## Next steps

- `docs/user/use-cases.md` — full tutorials for pentest, dev, incident response, compliance audit
- `docs/install-mode-b.md` — let your Claude Code bootstrap Colmena from the repo
- `docs/guide.md` — deep dives into each subsystem: firewall, delegations, missions, manifests, ELO, MCP tools, audit, security
