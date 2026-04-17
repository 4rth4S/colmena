# Install Mode B: let your Claude Code configure itself from this repo

There are two ways to onboard Colmena.

- **Mode A** is the classic path: clone the repo, build the binary, run `colmena setup` by hand, register the MCP server, and then start using CC with the firewall active.
- **Mode B** flips the direction: you point your own Claude Code session at this repository and let CC read `CLAUDE.md`, the library YAMLs, and the role prompts, and then bootstrap everything for you — build, `colmena setup`, MCP registration, and an initial set of delegations.

Mode B was validated on 2026-04-16 with 4 power users (pentester, developer, devops, SRE). All four onboarded without reading `CLAUDE.md` directly — their CC read it for them and drove the install.

This document is the user-facing walkthrough for Mode B. It also records the contract this repo maintains so that an oriented CC can bootstrap a new user safely.

## What Mode B is (and isn't)

Mode B is **not** a magic installer. It is a design commitment: the files at the top of this repo (`CLAUDE.md`, `README.md`, `config/library/roles/*.yaml`, `config/library/prompts/*.md`) are structured to be read by a Claude Code agent and produce correct install steps, not just by humans.

In practice, this means:

- `CLAUDE.md` contains enough precise information about the project (architecture, tech stack, conventions, CLI subcommands, MCP tools, security invariants, and positioning) that an agent can decide what to do next without guessing.
- Every role YAML declares its own `tools_allowed`, `bash_patterns`, `path_within`, trust level, and category — an agent can read the file and reason about scope.
- Every role prompt is a self-contained mission brief, so an agent can inspect what the role does without additional context.
- The CLI has a deterministic `colmena setup` that performs all filesystem work (config files, hook registration, MCP registration) and is safe to re-run.

Mode B does **not** replace human review. The user still approves the first `colmena setup`, the first delegations, and any mission gate activation. What Mode B removes is the friction of reading onboarding docs as a human before your CC can be useful.

## Prerequisites

- Claude Code installed and working (CLI or IDE integration).
- A Rust toolchain (`rustc`, `cargo`, stable channel). No nightly required.
- SSH access to this repository if you intend to clone, or HTTPS if not.
- An existing `HOME` environment variable (Colmena refuses to fall back to `/tmp` on purpose).

Mode B does not require any prior Colmena knowledge from the user.

## Step-by-step

### 1. Clone the repository and open it in Claude Code

```bash
git clone git@github.com:4rth4S/colmena.git
cd colmena
```

Open the working directory with Claude Code as you would any repo. The moment CC starts in this directory, it will autoload `CLAUDE.md` as per standard behavior. That file contains the full positioning, architecture, conventions, and CLI/MCP surface area.

### 2. Ask CC to set Colmena up

A prompt like the following is enough:

> Read `CLAUDE.md` and set up Colmena on this machine. Build the binaries, run `colmena setup`, register the MCP server, and explain to me the default trust rules before I approve any delegation.

What CC will typically do at this point:

1. Read `CLAUDE.md` to ground itself on the project.
2. Run `cargo build --workspace --release` to produce `target/release/colmena` and `target/release/colmena-mcp`.
3. Run `./target/release/colmena setup` — this is the idempotent one-shot that writes the default config, registers the PreToolUse / PostToolUse / PermissionRequest / SubagentStop hooks in `~/.claude/settings.json`, and registers the MCP server in `~/.mcp.json` pointing at the local `colmena-mcp` binary.
4. Run `./target/release/colmena doctor` to verify that config, hooks, MCP, library, runtime directories, and filesystem permissions are all green.
5. Read `config/trust-firewall.yaml` to explain to you what is allowed / asked / blocked by default, and suggest the first delegations for your workflow (never execute delegations unattended — delegate MCP tools are read-only on purpose, they return the CLI command for you to run).

### 3. Let CC suggest your first mission

Once Colmena is installed, CC can use the library tools directly:

- `mcp__colmena__library_list` — list roles + patterns.
- `mcp__colmena__library_select --mission "<your mission>"` — get ranked pattern recommendations.
- `mcp__colmena__mission_suggest "<your mission>"` — decide whether a mission is complex enough to justify Colmena vs vanilla CC.
- `mcp__colmena__mission_spawn` — one-step pipeline to spawn a squad (select → map → generate scoped prompts with mission markers).

A reasonable first prompt after install:

> Pick a small mission relevant to this repo (for example: write a short doc about how the trust firewall evaluates Bash calls). Use `mission_suggest` to decide if it needs Colmena. If yes, use `mission_spawn` to create the squad, show me the generated prompts, and only then start agents.

### 4. Customize for your workflow

Mode B assumes the user will then edit `config/trust-firewall.yaml` for their own domain, add or tweak roles in `config/library/roles/*.yaml`, and create patterns that match their team's topology. The built-in roles are a starting point, not a prescription — see the "Make It Yours" section of the [README](../README.md) for `colmena library create-role` and `colmena library create-pattern`.

## Mode A vs Mode B at a glance

|                      | Mode A (binary + manual setup) | Mode B (CC bootstraps from repo)               |
| -------------------- | ------------------------------ | ---------------------------------------------- |
| Who reads the docs   | The user                       | The user's CC                                  |
| Onboarding time      | 5–10 minutes                   | 2–3 minutes of prompting, build time in the background |
| Required knowledge   | What Colmena is, why           | Just what you want to accomplish               |
| Trust model          | Unchanged — user approves setup | Unchanged — user approves setup and delegations |
| Good for             | Solo users, CI environments    | Teams, validated users, anyone whose CC is already a daily driver |

Both modes end at the same place: `colmena setup` run, hooks registered, MCP registered, `colmena doctor` green, default firewall active.

## Tips

- If you run Mode B on an existing Colmena install, `colmena setup` will preserve your custom files and copy any new defaults to `.defaults/` for reference. You can re-run it safely.
- If your CC already has a mission running when you clone, it may try to spawn agents inside that mission — not what you want for a first install. Start a fresh CC session in the new working directory.
- For teams: one person does Mode A on the shared infrastructure (CI, lab), the rest of the team does Mode B on their machines. The trust rules live in version control either way.

## Troubleshooting

- **`colmena doctor` warns about world-writable config files.** This is a deliberate check on Unix systems; tighten permissions on `config/trust-firewall.yaml` and `config/runtime-delegations.json`.
- **Agents still get permission prompts after setup.** Check `~/.claude/settings.json` for the hook entries and re-run `colmena install` if they are missing. The `PermissionRequest` hook is what teaches CC session rules for `role`-delegated tools.
- **MCP server not visible in CC.** Confirm the absolute path in `~/.mcp.json` points to the built `target/release/colmena-mcp` binary and that the binary is executable.

## Related docs

- [README](../README.md) — positioning, quick start (Mode A), CLI reference, MCP tools.
- [docs/guide.md](guide.md) — detailed walkthrough.
- [CLAUDE.md](../CLAUDE.md) — the file your CC reads when you open the repo.

---

built with ❤️‍🔥 by AppSec
