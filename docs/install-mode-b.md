# Install Mode B — let your Claude Code bootstrap Colmena

Mode B is the "point your Claude Code at this repo" path. Instead of reading the docs and running commands yourself, your CC reads `CLAUDE.md`, builds Colmena, runs `setup`, and registers the MCP server — all from a single prompt.

## When to choose Mode B

- You already use Claude Code daily and want to stay in the flow.
- You prefer to bootstrap without reading setup docs first.
- You trust your CC to run `cargo build`, `colmena setup`, and verify the result.

If you prefer to run each command yourself, use Mode A (see `docs/user/getting-started.md`). Both paths end in the same state: hooks registered, MCP registered, `colmena doctor` green.

## What Mode B is (and is not)

Mode B is not a magic installer. It is a design commitment: the files at the top of this repo are structured to be read by a Claude Code agent and produce correct install steps. Concretely:

- `CLAUDE.md` carries the full positioning, architecture, CLI surface, MCP tool list, and security invariants. An agent can decide what to do next without guessing.
- Every role YAML declares its own `tools_allowed`, `bash_patterns`, `path_within`, and trust level. An agent can reason about scope by reading the file.
- Every role prompt is a self-contained mission brief. An agent can inspect what a role does without extra context.
- `colmena setup` is deterministic and idempotent — re-running is safe.

Mode B does not replace human review. You still approve the first `colmena setup`, the first delegations, and any mission gate activation. What it removes is the friction of reading onboarding docs yourself before your CC can be useful.

## Prerequisites

- Claude Code installed and working (`claude` command available).
- A Rust toolchain (stable) via [rustup](https://rustup.rs/). No nightly required.
- SSH or HTTPS access to this repository.
- A real `$HOME`. Colmena refuses to fall back to `/tmp`.

No prior Colmena knowledge required.

## Step by step

### 1. Clone and open

```bash
git clone git@github.com:4rth4S/colmena.git
cd colmena
```

Open the directory in Claude Code. CC autoloads `CLAUDE.md` as soon as it starts in this working directory. That file contains everything it needs.

### 2. Ask CC to set Colmena up

A prompt like this is enough:

> Read CLAUDE.md and set up Colmena on this machine. Build the binaries, run colmena setup, register the MCP server, and explain the default trust rules before I approve any delegation.

CC will:

1. Read `CLAUDE.md` to understand positioning, architecture, CLI surface, and MCP tool list.
2. Run `cargo build --workspace --release` to produce `target/release/colmena` and `target/release/colmena-mcp`. The build takes 2-3 minutes on first run.
3. Run `./target/release/colmena setup` to write default config, register the four hooks (PreToolUse, PostToolUse, PermissionRequest, SubagentStop) in `~/.claude/settings.json`, and register the MCP server in `~/.mcp.json`.
4. Run `./target/release/colmena doctor` to verify all seven categories are green: config validity, hook registration, MCP registration, library integrity, runtime state, file permissions, version consistency.
5. Read `config/trust-firewall.yaml` and summarize what is allowed, asked, and blocked by default.
6. Suggest the first delegations for your workflow — but never execute them unattended. The `delegate` MCP tools are read-only: CC returns the CLI command for you to inspect and run.

### 3. Start your first mission

Once installed, CC can use the Colmena tools natively. A good first prompt:

> Use mission_suggest to see if this repo needs Colmena for a small doc task. If yes, use mission_spawn to create the squad.

CC will call `mcp__colmena__mission_suggest` to analyze the mission complexity, then `mcp__colmena__mission_spawn` to generate the agent prompts. You review and paste them into `Agent` tool calls.

If you prefer the CLI path, the same flow works from the terminal:

```bash
colmena suggest "write a short doc about how the trust firewall evaluates Bash calls"
# → complexity=low, recommended_agents=1, verdict: use CC directly
colmena suggest "review the auth module and harden error handling"
# → complexity=medium, recommended_agents=3+, verdict: use Colmena
colmena mission spawn --mission "review the auth module and harden error handling" --dry-run
```

### 4. Customize for your workflow

The built-in roles are a starting point, not a prescription. From here:

- Edit `config/trust-firewall.yaml` to match your domain.
- Tweak roles in `config/library/roles/*.yaml` — each role is a single file.
- Create new roles and patterns with `colmena library create-role` and `colmena library create-pattern`.

## Mode A vs Mode B

| | Mode A (binary + manual setup) | Mode B (CC bootstraps from repo) |
|---|---|---|
| Who reads the docs | The user | The user's CC |
| Onboarding time | 5-10 minutes | 2-3 minutes of prompting, build in background |
| Required knowledge | What Colmena is and why | Just what you want to accomplish |
| Trust model | Unchanged — user approves setup | Unchanged — user approves setup and delegations |
| Good for | Solo users, CI environments | Teams, daily CC drivers |

Both modes end at the same place: `colmena setup` run, hooks registered, MCP registered, `colmena doctor` green, default firewall active.

## Tips

- Re-running `colmena setup` over an existing install is safe. Custom files are preserved; new defaults are copied to `.defaults/` for reference.
- Start a fresh CC session in the cloned directory. If your CC already has a mission running, it may try to spawn agents inside that mission — not what you want for a first install.
- For teams: one person does Mode A on shared infrastructure (CI, lab machines). The rest use Mode B on their laptops. Trust rules live in version control either way.

## Troubleshooting

- **`colmena doctor` warns about world-writable config files.** Deliberate check on Unix. Tighten permissions: `chmod 600 config/trust-firewall.yaml config/runtime-delegations.json`.
- **Agents still prompt after setup.** Check `~/.claude/settings.json` for the hook entries and re-run `colmena install` if they are missing. The PermissionRequest hook is what teaches CC session rules for role-delegated tools.
- **MCP server not visible.** Confirm the absolute path in `~/.mcp.json` points to the built `target/release/colmena-mcp` binary and that the binary is executable.
- **`$HOME` not set.** Colmena refuses to fall back to `/tmp`. Set `HOME` explicitly and re-run.

## Related docs

- `docs/user/getting-started.md` — full onboarding walkthrough with first mission
- `docs/user/use-cases.md` — tutorials per persona with copy-pastable manifests
- `docs/guide.md` — subsystem deep dives: firewall, delegations, missions, ELO, MCP tools, audit
