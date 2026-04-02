# Contributing to Colmena

## Prerequisites

- Rust toolchain (stable): `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- Git with SSH access to this repo

## Development Setup

```bash
git clone git@github.com:4rth4S/colmena.git
cd colmena
cargo build --workspace
cargo test --workspace
```

## Branching

Always work on a branch. Never commit directly to `main`.

| Prefix | Use |
|--------|-----|
| `feature/` | New functionality |
| `fix/` | Bug fixes |
| `chore/` | Dependencies, CI, cleanup |
| `docs/` | Documentation only |

```bash
git checkout -b feature/my-feature
```

## Making Changes

### Before you code

1. Read `CLAUDE.md` -- it has all conventions, architecture decisions, and invariants
2. Check existing patterns in the codebase before creating new abstractions
3. For non-trivial changes, discuss the approach first

### While coding

```bash
# Build
cargo build --workspace

# Test (must pass before PR)
cargo test --workspace

# Lint (must be clean before PR)
cargo clippy --workspace -- -W warnings
```

### Key conventions (from CLAUDE.md)

- Hook path must complete in < 100ms -- no network calls, no heavy I/O
- Any hook failure returns `ask` (safe fallback), never `deny`
- PostToolUse safe fallback: any error returns original output unchanged
- Error handling: `anyhow::Result` everywhere, never panic in the hook path
- Atomic file writes (temp + rename) for concurrent CC instances
- MCP delegate/revoke tools are read-only: return CLI commands, never execute directly
- Delegations always have TTL (max 24h)
- `blocked` rules can never be overridden by any mechanism

## Pull Requests

1. Create a PR against `main`
2. CI runs automatically: tests, clippy, release build
3. PR title should be descriptive: `feat: add role-bound permissions` not `update stuff`
4. If adding features, update:
   - `CHANGELOG.md` under `[Unreleased]`
   - `CLAUDE.md` if adding new conventions or invariants
   - `README.md` if adding CLI commands or MCP tools
   - `docs/guide.md` if user-facing behavior changes

## Versioning

Colmena uses [Semantic Versioning](https://semver.org/) with a single workspace version in `Cargo.toml`.

| Bump | When | Example |
|------|------|---------|
| Patch (0.2.x) | Bug fixes only | Fix regex false positive |
| Minor (0.x.0) | New milestone, new CLI/MCP tools, new optional config fields | M3 release |
| Major (x.0.0) | Breaking config schema, mandatory data migration, removed commands | Not yet |

The version in `Cargo.toml` applies to all 4 crates (workspace-level).

**Config schema version** (`version: 1` in `trust-firewall.yaml`) is separate from the package version. Only bump it when existing config files would break with new code.

## Releasing

### 1. Prepare the release

```bash
# Ensure you're on main with all changes merged
git checkout main
git pull

# Verify version in Cargo.toml matches your intended release
grep '^version' Cargo.toml
# version = "0.3.0"

# Ensure CHANGELOG.md has the release date
# Move [Unreleased] items into [0.3.0] - YYYY-MM-DD
```

### 2. Tag and push

```bash
git tag v0.3.0
git push origin v0.3.0
```

### 3. What happens automatically

The `release.yml` GitHub Action:
1. Runs tests + clippy (gate)
2. Verifies Cargo.toml version matches the tag
3. Extracts changelog notes for this version from CHANGELOG.md
4. Builds release binaries (`colmena` + `colmena-mcp`)
5. Creates a GitHub Release with binaries attached and changelog as body
6. Marks as prerelease if version < 1.0.0

### Retroactive tags

For past milestones that were never tagged:

```bash
git tag v0.1.0 <commit-hash>    # M0-M2.5 merge commit
git push origin v0.1.0
```

## Project Structure

```
colmena/
  Cargo.toml              # Workspace root (single version for all crates)
  CHANGELOG.md            # Version history (Keep a Changelog format)
  CLAUDE.md               # Development conventions + invariants
  CONTRIBUTING.md         # This file
  README.md               # Project overview + feature reference
  .github/workflows/
    ci.yml                # PR checks: test + clippy + build
    release.yml           # Tag-triggered: test + build + GitHub Release
  colmena-core/           # Shared library (config, firewall, delegate, calibrate, ...)
  colmena-cli/            # CLI binary (hook handler + subcommands)
  colmena-filter/         # Output filtering pipeline
  colmena-mcp/            # MCP server (rmcp + stdio)
  config/                 # Runtime config (YAML, JSON, library)
  docs/                   # User guide, specs, plans, security
```

## CI

GitHub Actions run on every PR to `main`:

| Job | What it checks |
|-----|---------------|
| **Test** | `cargo test --workspace` -- all tests pass |
| **Clippy** | `cargo clippy --workspace -- -W warnings` -- no warnings |
| **Build Release** | `cargo build --workspace --release` -- release profile compiles |

All three must pass before merge.

## Commit Messages

Use conventional commit style:

```
feat: add mission lifecycle management
fix: blocked regex false positive on branch names
chore: bump serde to 1.0.200
docs: update guide with calibration walkthrough
```

Commit trailers:

```
built with love by AppSec
Co-Authored-By: Claude <noreply@anthropic.com>
```

---

built with love by AppSec
