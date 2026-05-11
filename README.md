# Colmena

[![CI](https://github.com/4rth4S/colmena/actions/workflows/ci.yml/badge.svg)](https://github.com/4rth4S/colmena/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Version](https://img.shields.io/badge/version-0.14.3-blue.svg)](./Cargo.toml)
[![crates.io](https://img.shields.io/crates/v/colmena.svg)](https://crates.io/crates/colmena)

<p align="center">
  <img src="docs/colmena-banner.png" alt="Colmena — the hive defends the colony" width="400">
</p>

<p align="center"><strong>Deterministic governance for multi-agent Claude Code.</strong></p>

<p align="center">YAML rules + Rust firewall + audit.log for every tool call. Multi-agent missions with auditor review. ELO-calibrated trust per role.</p>

---

## 🎯 Which fits you?

| You are a... | Colmena gives you |
|---|---|
| **Pentester** 🛡️ | Scoped Caido-native agents, restricted Bash, findings store, replayable audit trail. [Start here →](https://docs.colmena.space/use-cases/pentest/) |
| **Developer** 💻 | Auto-approve `cargo test` & `git log`, ask on `git push`, block `--force`. Read-only reviewer. [Start here →](https://docs.colmena.space/use-cases/code-review/) |
| **DevOps / SRE** ⚙️ | Bash patterns for `kubectl`, `terraform`, `helm` pre-wired. Secrets blocked. Per-session delegations. [Start here →](https://docs.colmena.space/use-cases/incident-response/) |

If you run AI agents and care about auditability, Colmena gives you a deterministic trail and per-role accountability over time.

## 🚀 Quick install

```bash
# From crates.io
cargo install colmena
colmena setup
colmena doctor

# From source
git clone https://github.com/4rth4S/colmena
cd colmena && cargo build --workspace --release
./target/release/colmena setup && ./target/release/colmena doctor
```

Two commands after install. The firewall is live for every Claude Code session.

[Full installation guide →](https://docs.colmena.space/quickstart/getting-started/) · [Let Claude bootstrap Colmena →](https://docs.colmena.space/quickstart/install-mode-b/)

## 🧠 What Colmena does

Colmena sits between Claude Code and your filesystem. Every tool call — Bash, Write, WebFetch — passes through a **deterministic firewall** in <15ms. Zero LLM calls, zero per-call cost, zero cloud dependencies. Just YAML rules compiled to regex, evaluated in a fixed precedence chain with a tamper-evident audit trail.

**The three pillars:**

- 🔒 **Scoped autonomy.** Agents are free within their domain, blocked at the boundary. Policy is code — rules you wrote, not an LLM's best guess.
- ✅ **Mandatory review.** Every artifact goes through auditor evaluation. QPC scoring (Quality + Precision + Comprehensiveness). No review, no stop — the SubagentStop hook enforces it.
- 📈 **Earned trust.** ELO ratings calibrate over time from review outcomes. Five tiers. Trust is not declared — it's demonstrated.

[Read the concepts →](https://docs.colmena.space/concepts/scoped-autonomy/) · [Browse all features →](https://docs.colmena.space/reference/cli/)

## 📚 Documentation

All technical documentation lives at **[docs.colmena.space](https://docs.colmena.space)**:

| Section | What you'll find |
|---------|-----------------|
| [Quickstart](https://docs.colmena.space/quickstart/getting-started/) | Install, verify, first mission |
| [Core Concepts](https://docs.colmena.space/concepts/scoped-autonomy/) | Firewall, missions, ELO, scoped autonomy |
| [Use Cases](https://docs.colmena.space/use-cases/pentest/) | Pentest, code review, incident response, refactor |
| [Reference](https://docs.colmena.space/reference/cli/) | CLI commands, MCP tools, role YAML, manifest schema |
| [Architecture](https://docs.colmena.space/architecture/overview/) | System overview, hook pipeline, mission lifecycle |
| [Community](https://docs.colmena.space/community/contributing/) | Contributing guide, roadmap, security policy |

## 🏗️ Design principles

- **< 15ms** hook latency — Rust, pre-compiled regexes, no network calls.
- **Safe fallback** — any hook failure returns `ask`, never `deny` or crash.
- **Files over databases** — YAML config, JSON queue, JSONL logs, git-versionable.
- **Build on CC, not around it** — hooks + MCP, no hacks.
- **Domain-agnostic** — the engine is generic, the domain is in your templates.
- **Human authority wins** — YAML overrides always beat ELO; revoke everything with `colmena calibrate reset`.

## 🔒 Security

See [SECURITY.md](./SECURITY.md) for the disclosure process. Every release goes through `cargo deny` and `cargo audit` in CI.

## 📄 License

Released under the [MIT License](./LICENSE).

## ✨ Contributors

See [CONTRIBUTORS.md](./CONTRIBUTORS.md).

---

<p align="center">built with ❤️‍🔥 by AppSec</p>
