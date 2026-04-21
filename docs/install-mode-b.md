# Install Mode B — let your Claude Code bootstrap Colmena

There are two equally supported ways to onboard.

- **Mode A** — classic. Clone (or download the binary), build, run `colmena setup`, register the MCP server, start using CC with the firewall active. See the [README](../README.md#install).
- **Mode B** — flip the direction. Point your own Claude Code session at this repository and let CC read `CLAUDE.md`, the library YAMLs, and the role prompts, then bootstrap everything for you — build, `colmena setup`, MCP registration, and a starter set of delegations.

Mode B was validated on 2026-04-16 with 4 power users (pentester, developer, devops, SRE). All four onboarded without reading `CLAUDE.md` directly — their CC read it for them and drove the install. If your CC is already a daily driver, Mode B is usually the faster path.

This page is the user-facing walkthrough. It also records the repo-side contract that makes Mode B safe.

## What Mode B is (and is not)

Mode B is **not** a magic installer. It is a design commitment: the files at the top of this repo — `CLAUDE.md`, `README.md`, `config/library/roles/*.yaml`, `config/library/prompts/*.md` — are structured to be read by a Claude Code agent and produce correct install steps, not just by humans.

Concretely:

- `CLAUDE.md` carries the full positioning, architecture, tech stack, conventions, CLI surface, MCP tool list, and security invariants. An agent can decide what to do next without guessing.
- Every role YAML declares its own `tools_allowed`, `bash_patterns`, `path_within`, trust level, and category. An agent can reason about scope by reading the file.
- Every role prompt is a self-contained mission brief. An agent can inspect what a role does without extra context.
- `colmena setup` is deterministic and idempotent — re-running is safe.

Mode B does **not** replace human review. You still approve the first `colmena setup`, the first delegations, and any mission gate activation. What it removes is the friction of reading onboarding docs yourself before your CC can be useful.

## Prerequisites

- Claude Code installed and working (CLI or IDE integration).
- A Rust toolchain (`rustc`, `cargo`, stable channel). No nightly required.
- SSH or HTTPS access to this repository.
- A real `$HOME`. Colmena refuses to fall back to `/tmp` on purpose.

No prior Colmena knowledge required.

## Step-by-step

### 1. Clone and open

```bash
git clone git@github.com:4rth4S/colmena.git
cd colmena
```

Open the directory in Claude Code. As soon as CC starts in this working directory, it autoloads `CLAUDE.md` per standard behavior. That file contains everything it needs.

### 2. Ask CC to set Colmena up

A prompt like this is enough:

> Read `CLAUDE.md` and set up Colmena on this machine. Build the binaries, run `colmena setup`, register the MCP server, and explain to me the default trust rules before I approve any delegation.

What CC typically does:

1. Reads `CLAUDE.md` to ground itself.
2. Runs `cargo build --workspace --release` — produces `target/release/colmena` and `target/release/colmena-mcp`.
3. Runs `./target/release/colmena setup` — writes default config, registers the four hooks in `~/.claude/settings.json` (PreToolUse, PostToolUse, PermissionRequest, SubagentStop), registers the MCP server in `~/.mcp.json` pointing at the local `colmena-mcp` binary.
4. Runs `./target/release/colmena doctor` — verifies config, hooks, MCP, library, runtime directories, and filesystem permissions are all green.
5. Reads `config/trust-firewall.yaml` and explains what is allowed / asked / blocked by default. Suggests the first delegations for your workflow — but never executes them unattended. The `delegate` MCP tools are read-only on purpose: they return the CLI command for you to run.

### 3. Let CC suggest your first mission

Once installed, CC can use the library tools directly:

- `mcp__colmena__library_list` — roles + patterns
- `mcp__colmena__library_select --mission "<your mission>"` — ranked pattern recommendations
- `mcp__colmena__mission_suggest "<your mission>"` — complexity analysis, Colmena vs vanilla CC
- `mcp__colmena__mission_spawn` — one-step pipeline (select → map → generate scoped prompts with mission markers)

A reasonable first prompt after install:

> Pick a small mission relevant to this repo (for example: write a short doc about how the trust firewall evaluates Bash calls). Use `mission_suggest` to decide whether it needs Colmena. If yes, use `mission_spawn` to create the squad, show me the generated prompts, and only then start agents.

### 4. Customize for your workflow

The built-in roles are a starting point, not a prescription. From here:

- Edit `config/trust-firewall.yaml` to match your domain.
- Tweak roles in `config/library/roles/*.yaml` — each role is a single file.
- Create new roles and patterns with `colmena library create-role` and `colmena library create-pattern`.

See the "Make it yours" section of the [README](../README.md#make-it-yours) for end-to-end examples.

## Mode A vs Mode B at a glance

|                      | Mode A (binary + manual setup) | Mode B (CC bootstraps from repo)               |
| -------------------- | ------------------------------ | ---------------------------------------------- |
| Who reads the docs   | The user                       | The user's CC                                  |
| Onboarding time      | 5–10 minutes                   | 2–3 minutes of prompting, build time in the background |
| Required knowledge   | What Colmena is, why           | Just what you want to accomplish               |
| Trust model          | Unchanged — user approves setup | Unchanged — user approves setup + delegations |
| Good for             | Solo users, CI environments    | Teams, anyone whose CC is already a daily driver |

Both modes end at the same place: `colmena setup` run, hooks registered, MCP registered, `colmena doctor` green, default firewall active.

## Tips

- Re-running `colmena setup` over an existing install is safe. Your custom files are preserved; new defaults are copied to `.defaults/` for reference.
- If your CC already has a mission running when you clone, it may try to spawn agents inside that mission — not what you want for a first install. Start a fresh CC session in the new working directory.
- For teams: one person does Mode A on shared infrastructure (CI, lab machines), the rest of the team does Mode B on their laptops. The trust rules live in version control either way.

## Troubleshooting

- **`colmena doctor` warns about world-writable config files.** Deliberate check on Unix. Tighten permissions on `config/trust-firewall.yaml` and `config/runtime-delegations.json`:
  ```bash
  chmod 600 config/trust-firewall.yaml config/runtime-delegations.json
  ```
- **Agents still prompt for permission after setup.** Check `~/.claude/settings.json` for the hook entries and re-run `colmena install` if they're missing. The `PermissionRequest` hook is what teaches CC session rules for role-delegated tools.
- **MCP server not visible in CC.** Confirm the absolute path in `~/.mcp.json` points to the built `target/release/colmena-mcp` binary and that the binary is executable.
- **`$HOME` not set.** Colmena refuses to fall back to `/tmp`. Set `HOME` explicitly and re-run.

## Related docs

- [README](../README.md) — positioning, install (Mode A), CLI reference, MCP tools
- [Getting Started](user/getting-started.md) — 5-minute install + first mission
- [Use Cases](user/use-cases.md) — full tutorials per persona
- [User Guide](guide.md) — detailed walkthrough with a payments API audit
- [CLAUDE.md](../CLAUDE.md) — the file your CC reads when you open the repo

---

built with ❤️‍🔥 by AppSec
