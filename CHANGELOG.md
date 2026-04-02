# Changelog

All notable changes to Colmena are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/).
Versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-04-01

### Added
- **Dynamic trust calibration (M3):** ELO scores now drive firewall rules automatically
  - `colmena calibrate run` -- applies ELO-based trust tiers as agent overrides
  - `colmena calibrate show` -- displays current trust tier per agent
  - `colmena calibrate reset` -- clears all ELO-based overrides instantly
  - Trust tiers: Uncalibrated, Elevated, Standard, Restricted, Probation
  - Warm-up period: agents need 3+ peer reviews before calibration applies
  - ELO overrides stored in `config/elo-overrides.json` (separate from YAML)
- **Mission lifecycle management:**
  - `colmena mission list` -- shows active missions with delegation counts
  - `colmena mission deactivate --id X` -- revokes all delegations for a mission
- **Role-bound permissions:** roles can define `permissions` block with `bash_patterns`, `path_within`, `path_not_match` for scoped auto-approve rules
- **Mission delegations:** `library_generate` now creates scoped delegations from role permissions, with optional session binding and 8h default TTL
- **Delegation conditions:** `RuntimeDelegation` supports `conditions` field for fine-grained matching (bash_pattern, path_within, path_not_match)
- **Delegation provenance:** `RuntimeDelegation.source` tracks origin ("human", "role", "elo") and `mission_id` links to missions for bulk revocation
- **Pre-Approved Operations section** in generated CLAUDE.md files -- agents know what they can do without asking
- **2 new MCP tools:** `mission_deactivate`, `calibrate` (22 tools total)
- **3 new audit events:** MISSION_ACTIVATE, MISSION_DEACTIVATE, CALIBRATION
- **New crate module:** `colmena-core/src/calibrate.rs` -- TrustThresholds, TrustTier, calibrate(), save/load overrides

### Changed
- Firewall evaluation precedence now includes ELO overrides: blocked > delegations > agent_overrides (YAML) > ELO overrides > restricted > trust_circle > defaults
- `evaluate()` has a new `evaluate_with_elo()` companion that accepts ELO-calibrated overrides
- Hook now loads `elo-overrides.json` at evaluation time (safe fallback: empty if missing)
- Role scaffold template includes documented `permissions` section (commented out)
- Prompt scaffold template includes "Tools Available" section

### Upgrade notes
- **Zero migration required.** Rebuild and the new features are available.
- Config `trust-firewall.yaml` (version: 1) unchanged -- no schema changes.
- `runtime-delegations.json` has new optional fields (`source`, `mission_id`, `conditions`) -- backward compatible via serde defaults.
- No need to re-run `colmena install` -- hook registration unchanged.

## [0.1.0] - 2026-03-30

### Added
- **Trust Firewall (M0):** declarative YAML rules with precedence (blocked > delegations > agent_overrides > restricted > trust_circle > defaults)
- **Approval Queue (M0):** pending items with priority, timestamps, and truncated inputs
- **Runtime Delegations (M0):** time-limited trust expansion with TTL (max 24h), per-agent and per-session scoping
- **Audit Log (M0):** append-only log for every firewall decision
- **Sound Notifications (M0):** macOS sound cues for different decision types
- **MCP Server (M0.5):** 6 trust management tools via rmcp + stdio transport
- **Wisdom Library (M1):** 4 security roles (pentester, auditor, researcher, security_architect) with ELO config and mentoring
- **Orchestration Patterns (M1):** 6 patterns (oracle-workers, plan-then-execute, debate, mentored-execution, pipeline, swarm-consensus)
- **Pattern Selector (M1):** keyword-based scoring with when_to_use/when_not_to_use/specializations matching
- **Mission Generator (M1):** creates per-agent CLAUDE.md files from role prompts + mission context
- **Role Scaffold (M1):** `library create-role` generates role YAML + prompt template
- **RRA Security Hardening (M1):** path traversal prevention, role ID validation, prompt containment
- **Peer Review Protocol (M2):** submit/assign/evaluate flow with 6 security invariants
- **ELO Engine (M2):** append-only JSONL event log, temporal decay (1.0/0.7/0.4/0.1), leaderboard
- **Trust Gate (M2):** auto-approve at score >= 7.0 with no critical findings, hardcoded floor at 5.0
- **Findings Store (M2):** persistent findings from reviews, queryable by role/category/severity/date/mission
- **Output Filtering (M2.5):** PostToolUse hook with 4-stage pipeline (ANSI strip, stderr-only, dedup, smart truncation)
- **Filter Statistics (M2.5):** JSONL token savings log with `colmena stats` summary
- **20 MCP tools** across M0.5, M1, M2
- **CLI** with hook, queue, delegate, config, install, library, review, elo, stats subcommands

---

built with love by AppSec
