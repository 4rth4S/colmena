# M7.15 Mission Manifest — Security Architect Review

**Author:** Security Architect (peer review, parallel with `colmena_architect` + SRE)
**Date:** 2026-05-01
**Scope:** Threat model, controls, and invariants for `mission-manifest.yaml` + `mission_spawn --manifest <file>`.
**Lens:** The manifest is a *new trust boundary*. It declaratively grants permissions to N agents from a single file. If the manifest lies, is tampered with, or is mis-validated, agents gain authority they shouldn't have.

---

## TL;DR — non-negotiable for v1

1. **The manifest is data, not code.** It can *request* permissions; it cannot *bypass* the global `blocked` tier or the hardcoded invariants in §12.
2. **Hash + audit on apply.** Every manifest application logs `MANIFEST_APPLY {path, sha256, mission_id, agents, delegations_created, agent_overrides_added}` to `audit.log`. Replayable.
3. **Caps are hardcoded.** TTL ≤ 24h, agent count ≤ 25, scope.paths max depth ≤ 6, regex compile budget ≤ 50 patterns total. Manifest cannot raise any cap.
4. **Read-only post-load.** Manifest file is hashed at apply-time. Mid-mission edits to the YAML are NOT re-applied. To change scope, deactivate + re-spawn.
5. **No ad-hoc auditor pools.** `auditor_pool` defaults to `["auditor"]`. Anything else requires `--allow-broad-auditor-pool` CLI flag (human ack).
6. **Agent_overrides expire with the mission.** Manifest-injected overrides are ephemeral, scoped via `mission_id`, and removed by `mission deactivate`. They never persist into `trust-firewall.yaml`.
7. **Acceptance criteria ≠ security gate.** Doc-only in v1. Mechanizing is M7.16. v1 surfaces criteria in the prompt + review template; auditor enforces verbally.

If any of those slip, do not ship M7.15.

---

## 1. Manifest as a trust boundary — STRIDE

The manifest takes the role that `mission_spawn` arguments + a chain of `delegate add` commands play today. Today's chain is reviewed by a human typing each command; the manifest collapses that into one file. That collapse is the threat.

### 1.1 Spoofing — "who says this manifest is yours?"

**Threat S-1.** An agent (or compromised process with FS write) authors `~/Downloads/mission.yaml`, calls `mission_spawn --manifest ~/Downloads/mission.yaml`, and grants itself elevated permissions.

**Today's analogue:** `delegate add` requires explicit human invocation and is logged with the user's session.

**Controls (P0):**

- `mission_spawn --manifest <path>` **must be a human-invoked CLI subcommand**, not an MCP tool callable from agents. The MCP surface area for manifest apply is read-only: `mission_manifest_show <path>` returns a parsed + validated view + the CLI command to apply. Same pattern as `delegate` MCP today (`returns CLI command, never executes`, per CLAUDE.md §"MCP Server").
- The CLI command requires the manifest path to be **inside an allowlisted dir** (`$COLMENA_HOME/missions/manifests/` by default, configurable). Manifests in `/tmp`, `~/Downloads`, or under agent-writable dirs are rejected with explicit error. This prevents drive-by manifests dropped by exfiltration.
- Manifest must declare an `author` field (free text, e.g. `coco`). Logged. Not authoritative — just provenance for audit.

**Why not crypto-signing?** v1 single-user assumption. Single-user attacker model is "compromised agent inside my CC", not "remote signed-manifest repo". Sign in v2 (M7.16) when manifests are shared via repo / CI.

**Cost:** ~1 day. **Invariant if omitted:** any agent with Write tool can self-spawn elevated swarm.

### 1.2 Tampering — mid-mission manifest edits

**Threat T-1.** Agent during a mission edits `manifests/active.yaml` to widen `scope.paths`, then waits for a re-application or restart. (Today's analogue: agent edits `runtime-delegations.json` — already blocked by `path_not_match` in trust_circle Write rule.)

**Threat T-2.** Manifest is loaded once at spawn; an attacker edits the file post-spawn and assumes a future read picks it up. This depends on whether Colmena re-reads.

**Controls (P0):**

- **Hash on load.** `mission_spawn --manifest` computes SHA-256, writes it to `config/missions/<mission_id>/manifest.sha256`, and stamps it into the `MANIFEST_APPLY` audit event. Subsequent operations (e.g. `mission deactivate`, `mission status`) verify the hash and warn loudly if drift is detected. They DO NOT re-apply.
- **Manifest file path added to `path_not_match` in the trust_circle Write rule.** Any agent (manifest-spawned or otherwise) attempting to Edit/Write the active manifest is blocked. Pattern: `*manifests/*.yaml`, `*manifest.sha256`. Costs nothing (regex is already compiled).
- **No live reload.** `mission_spawn --manifest` is a one-shot apply. Manifest changes require `mission deactivate <id>` + re-spawn with new manifest. This is the same model as `colmena install` today.

**Threat T-3 (subtle).** YAML aliases / anchors (`&` / `*`) used to obfuscate scope. e.g. defining a benign `&safe` and aliasing it where a reviewer expects literal paths.

**Control:** `MissionManifest::from_yaml` must reject YAML with anchors/merges (`<<:`, `&`, `*`) unless explicitly opted in. `serde_yml` honors them by default; we need a pre-pass that scans the raw text for `&`/`<<:` outside string contexts and bails. Cost: 1h. Without it, scope review is ambiguous.

### 1.3 Repudiation

**Threat R-1.** "I never authorized that scope" — operator sees an exfiltration in audit.log, manifest-driven mission was active, but the manifest content has been overwritten and the apply event is bare.

**Controls (P0):**

- Audit event `MANIFEST_APPLY` MUST capture: `manifest_path`, `manifest_sha256`, `mission_id`, `applied_by` (OS user via `whoami`), `applied_at`, `pattern_id`, `agent_count`, `roles[]` (list of role ids), `delegations_added` (count + tool names), `agent_overrides_added` (count + agent ids), `mission_gate_state` (enforce|warn|off), `auditor_pool`, `manifest_yaml_excerpt` (first 4KB redacted of secrets per §1.4).
- Audit event is appended to `audit.log` AND a copy of the full manifest YAML is snapshotted to `config/missions/<mission_id>/manifest.snapshot.yaml` (read-only, owned by the user). The snapshot makes replay possible even if the source path was deleted.
- `MANIFEST_DEACTIVATE` event when `mission deactivate` runs: counts delegations revoked + agent_overrides removed.

**Replay-ability test (acceptance criterion for the design):** given `mission_id`, run `colmena audit replay <mission_id>` → reconstruct the manifest as applied + the scope diff vs current `trust-firewall.yaml`. If you cannot, audit is incomplete.

### 1.4 Information disclosure — secrets in manifest

**Threat I-1.** Operator pastes an API key into `scope.bash_patterns.extra_allow: ['^curl.*-H "Authorization: Bearer eyJ...']` to allowlist a specific authenticated endpoint. Manifest is committed to repo or shared. Token leaks.

**Threat I-2.** Manifest snapshot in `config/missions/<id>/manifest.snapshot.yaml` is world-readable by default and contains `goal: "audit api with token sk_live_..."`.

**Controls (P0):**

- **Pre-load secret regex scan.** Before `MissionManifest::from_yaml` returns Ok, run a regex sweep against the *raw YAML text* matching:
  - JWTs: `eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`
  - AWS keys: `AKIA[0-9A-Z]{16}`, `aws_secret_access_key\s*[:=]`
  - Generic API key shapes: `sk_(live|test)_[A-Za-z0-9]{20,}`, `ghp_[A-Za-z0-9]{36}`, `xoxb-[0-9]+-[0-9]+-[A-Za-z0-9]+`
  - Bearer / Basic auth headers: `(?i)authorization\s*:\s*(bearer|basic)\s+[A-Za-z0-9_\-./=+]{16,}`
  - PEM blocks: `-----BEGIN [A-Z ]+PRIVATE KEY-----`
  - High-entropy strings inside `scope.bash_patterns.extra_allow` (Shannon entropy > 4.5 over a > 20-char alphanumeric run).
- On match: `bail!("manifest rejected: looks like a secret at line N — never embed credentials in manifest")`. Never log the matched substring.
- **Snapshot file mode `0600`** on Unix. Snapshot dir `0700`. Same pattern as `runtime-delegations.json` today.
- **Goal field max length 512 chars** to discourage operators from pasting full prompts (which may include secrets) into `goal:`.

**Cost:** ~half day for the secret patterns + tests. **Invariant if omitted:** Colmena becomes a credential-leak vector via manifest snapshots and shared YAML.

### 1.5 Denial of service

**Threat D-1.** Manifest with `agents: [{role: bbp_pentester_web, count: 1000}]` spawns 1000 subagent files + 1000 delegations + 1000 agent_overrides. CC chokes; firewall regex compile budget blows up; `~/.claude/agents/` is poisoned with hundreds of `bbp_pentester_web-001..1000.md`.

**Threat D-2.** `scope.bash_patterns.extra_allow` with 500 regex entries. Every Bash hook re-compiles all of them (or worse, the patterns are catastrophically backtrackable like `(a+)+$`). Hook latency blows past the <100ms contract.

**Threat D-3.** `scope.paths` with 10000 entries. Every Read/Write hook iterates the list.

**Controls (P0, hardcoded caps):**

- `agents[].count ≤ 5` per role; `sum(agents[].count) ≤ 25` total. Above 25, manifest is rejected. (For reference: `mission_suggest` already balks at >12. 25 is generous.)
- `scope.bash_patterns.extra_allow ≤ 20 regexes total across all roles`.
- Each regex compiled with `regex::RegexBuilder::size_limit(100_000)` and `dfa_size_limit(1_000_000)`. Catastrophic patterns are bounded by the regex crate's defaults; we tighten further. Pattern length limit: 256 chars per pattern.
- `scope.paths ≤ 32 entries`; each path absolute, max 256 chars.
- `scope.hosts ≤ 32 entries`.
- `acceptance_criteria ≤ 10 items`, each ≤ 200 chars.
- `mission_ttl_hours` already capped at 24 in `mission_manifest.rs:25` (`MAX_TTL_HOURS`). Keep.

**Threat D-4 (target-side DoS).** Manifest enables `bash_patterns.extra_allow: ['^curl https://victim\.com']` and a 12-agent swarm hammers `victim.com`. Colmena does not rate-limit outbound HTTP today. Out-of-scope for v1 (it's a target-side concern, not a manifest-trust issue), but document in the README that mission swarms can self-DoS targets and the operator is responsible. Future M7.x: optional `scope.rate_limit: {host: max_req_per_min}`.

### 1.6 Elevation of privilege — the worst case

**Threat E-1.** Manifest declares:
```yaml
roles:
  - name: developer
    bash_patterns:
      extra_allow: ['^.*$']
    paths: ['/']
```
…and the developer agent gets unrestricted root-shell-equivalent.

**Controls (P0, hardcoded invariants — see §12 for full list):**

- `extra_allow` regexes are **rejected if they match any of the always-blocked patterns** in §12. Pre-flight: for each `extra_allow` regex `R`, check if `R` matches any sentinel string from the blocklist (`rm -rf /`, `dd if=/dev/`, `:(){ :|:& };:`, `mkfs.`, `chmod 777 /`, `wget http://.*/-O /tmp/.*sh`, etc.). If yes, reject the manifest.
- Catch-all regex detection: `^.*$`, `.*`, `^.+$`, empty pattern → rejected. The intent of `extra_allow` is *narrow expansion*. Catch-alls defeat the purpose.
- `scope.paths` containing `/`, `/etc`, `/root`, `/home/<user>/.ssh`, `/var/log`, `~/.aws`, `~/.config/gcloud` → rejected.
- Manifest cannot list `Bash` in a role's `tools_allowed` and simultaneously omit `bash_patterns` for that role. **No bash without patterns.** This is already CLAUDE.md §"Security & Trust" policy ("Elevated trust without bash_patterns generates 'ask'"); the manifest must enforce at parse time, not at hook time.

**Threat E-2.** Manifest assigns `role: auditor` to a worker, exempting it from `SubagentStop` review gate (auditor `role_type` exempt per CLAUDE.md). Worker now never has to call `review_submit`.

**Control:** `role_type` is a property of the library role, NOT the manifest. Manifest cannot override it. The `MissionManifest::role(name)` resolver looks up the library role; library `role_type: auditor` flag is the only path to exemption. If a manifest tries to add `role_type:` inline, parser rejects with explicit error: "role_type is not a manifest field; defined in library YAML only".

---

## 2. Scope binding — the most sensitive field

Scope is the manifest's reason to exist. Get it wrong and everything else is wallpaper.

### 2.1 `scope.paths` — path traversal + cross-tenant access

**Threats:**
- Relative paths: `scope.paths: ['../../etc']` resolved at apply-time hits `/etc`.
- Tilde expansion side-effects: `~/.ssh` if `HOME` is mis-set or shell-evaluated.
- Symlink chase: `scope.paths: ['/home/coco/proj']` where `proj` is a symlink to `/`.
- Other-user homes: `/home/<other>/...` on multi-user systems (less relevant for Coco's single-user box, but relevant for SRE/CI use cases).

**Controls (P0):**

- **All paths must be absolute** (start with `/`), no `~`, no `$VAR` (manifest is data, not shell). Reject otherwise.
- **Canonicalize via `Path::canonicalize` at apply time** to resolve symlinks and `..`. If canonicalization fails (path doesn't exist), reject — manifest must reference real, present paths. (Edge case: `${MISSION_DIR}` substitution must happen *before* canonicalize; mission_dir is created first, then canonicalized.)
- **After canonicalize, enforce a "never-allow" prefix list** (see §12). Hardcoded.
- **Default deny outside `$COLMENA_HOME/missions/<id>/`.** Manifest must explicitly opt into wider scope by listing dirs. The implicit `${MISSION_DIR}` is always added; everything else is opt-in.
- **Whitelist not blacklist.** `scope.paths` is the allowlist. Operators can ALSO declare `scope.paths_forbidden` (manifest analogue of `path_not_match`), which is merged with the hardcoded never-allow list — never replaces it.

**Cost:** ~1 day. **Invariant if omitted:** path traversal CVE waiting to happen.

### 2.2 `scope.bash_patterns.extra_allow` — regex bypass surface

This is the riskiest field in the manifest. It expands `agent_overrides` for the listed roles, which already have precedence over `restricted` per the firewall precedence chain (`firewall.rs:100-128`). Loose regexes here neuter the global firewall.

**Threats:**
- Smuggling: `'^curl https://example\.com.*'` — looks innocent, but allows `curl https://example.com; rm -rf ~` (chain after dot-match-all).
- ReDoS: `'^(a+)+$'`.
- Always-on: `'^.*$'` or just `'.*'`.
- Backreference / lookaround abuse: regex crate doesn't support these, so we're safe there.

**Controls (P0):**

- **Pattern validation is layered.** For each `extra_allow` regex `R`:
  1. Compile under a strict size budget (§1.5 caps).
  2. Must have an `^` anchor at start. Patterns without `^` are rejected (forces the operator to think about the prefix).
  3. Must NOT match any sentinel from the always-blocked list (§12).
  4. Must NOT match common chain operators when combined with chain-aware evaluator. e.g. if `R` matches `curl https://x.com`, also test `R.is_match("curl https://x.com && rm -rf /")` — if true, the regex is overly greedy. Reject.
  5. Catch-all detection: refuse `^.*$`, `^.+$`, `.*`, `.+`, empty patterns.
- **Chain-aware evaluator (M7.10) still runs.** The manifest's `extra_allow` only auto-approves the *individual piece* of a chain that matches; the rest of the chain falls through to normal precedence. This is good — even if `extra_allow` is sloppy, M7.10 splits chains and re-evaluates each piece. Document this behavior.
- **`extra_allow` can ONLY be additive.** Manifest cannot REMOVE entries from `restricted` or `blocked`. `agent_overrides` injected from manifest are auto-approve rules; they cannot demote a `blocked` rule to `ask` or `auto`. Already true via firewall precedence (`blocked` is step 1, before `agent_overrides` at step 3).

**Threat — order of precedence collision:** YAML `agent_overrides` from `trust-firewall.yaml` are checked at step 3a, manifest-injected `agent_overrides` are also at 3a (they ARE YAML-equivalent overrides). If a YAML override says `ask` and a manifest override says `auto-approve`, who wins? **Recommendation:** YAML file overrides (curated by human, version-controlled) take precedence over manifest-injected (per-mission, ephemeral). Implementation: manifest-injected overrides are stored in a *separate* in-memory map merged AFTER `config.agent_overrides` is consulted; if YAML overrides have a hit, return that decision before checking manifest-injected. This preserves CLAUDE.md's "human always wins" invariant.

### 2.3 `scope.hosts` — SSRF + internal network pivot

**Threats:**
- `scope.hosts: ["169.254.169.254"]` — AWS/GCP metadata endpoint, IMDSv1 credential exfil.
- `scope.hosts: ["10.0.0.0/8"]` — pivot to internal network.
- `scope.hosts: ["localhost", "127.0.0.1"]` — local services (databases, dev servers with auth disabled).
- DNS rebinding: `scope.hosts: ["evil.com"]` where `evil.com` resolves to public IP at validation time and `127.0.0.1` at use time.

**Controls (P0):**

- **Hardcoded host blocklist** (§12) wins over any `scope.hosts` entry. Operator cannot allowlist `169.254.169.254`.
- **Hosts are a hint to bash_patterns, not an enforcement layer.** Today Colmena does not intercept network calls; it intercepts *commands* (Bash with `curl`, `wget`, etc.) via firewall rules. So `scope.hosts` is interpreted as: "when generating `extra_allow` regexes for `curl|wget|http`, restrict the URL portion to these hosts". It's a UX shortcut, not a network firewall. **Document this clearly in the manifest spec** — operators must not believe `scope.hosts` blocks SSRF; it shapes the bash regex.
- **Reject CIDR ranges in `scope.hosts`** for v1. Only fully-qualified hostnames or single IPs. CIDR semantics are too easy to misuse.
- **Reject `localhost`, `127.0.0.1`, `0.0.0.0`, RFC1918 ranges** unless `--allow-loopback` CLI flag is passed (operator ack).

### 2.4 Whitelist vs blacklist — recommendation

**Whitelist by default.** All scope fields are allowlists. Hardcoded blocklist (§12) is the floor that no manifest can lower. This matches the firewall's existing model (`blocked` > `agent_overrides` > `trust_circle` > defaults). Mixing models within the manifest would be confusing and error-prone.

---

## 3. Manifest tampering attack model

### 3.1 Local FS attacker (compromised agent or external malware)

**A-1: Pre-spawn rewrite.** Attacker writes `manifests/payment-audit.yaml` with `scope.paths: ['/']`, waits for operator to `mission_spawn --manifest payment-audit.yaml`.

**Mitigations:** §1.1 (allowlisted dir + secret scan + cap validation). The cap validation rejects the catch-all path before spawn.

**A-2: Mid-mission edit.** Manifest already applied, attacker edits `manifests/active.yaml`, hopes for re-application. Today: no re-application; hash drift detected on next CLI invocation involving the mission.

**Mitigations:**
- §1.2 (read-only post-load + hash verification + path_not_match Write block on `*manifests/*.yaml`).
- Add `~/.claude/agents/<role>.md` files generated by manifest spawn to `path_not_match` too (M7.3 already auto-generates these; M7.15 inherits the threat). Without this, an agent could edit its own subagent `.md` to add `tools` it shouldn't have.

**A-3: Snapshot tampering.** Attacker edits `config/missions/<id>/manifest.snapshot.yaml` to retroactively rewrite history.

**Mitigations:**
- Snapshot has `0600` mode, owned by user (best-effort, an attacker-as-user can still edit).
- Real defense: the SHA-256 in `audit.log` (which is append-only, world-readable, Write-protected via `path_not_match`) is the authoritative record. Snapshot is convenience; audit.log is truth. Replay tooling must verify snapshot hash against audit log hash and warn on mismatch.

### 3.2 Compromised agent during mission

**A-4: Agent uses Edit tool to widen its own scope** by editing the active manifest.

**Mitigations:**
- `path_not_match: ['*manifests/*.yaml', '*manifest.sha256', '*manifest.snapshot.yaml']` added to trust_circle Write rule.
- Even if Edit is allowed inside the mission scope, those files are excluded by the glob match.
- Defense in depth: the manifest is read once at apply; mid-mission edits don't take effect.

**A-5: Agent calls `mission_spawn --manifest` itself** to layer a new mission with broader scope on top.

**Mitigations:**
- `mission_spawn --manifest` is CLI-only; no MCP tool exposes it. Agents have no `Bash` access to `colmena mission_spawn` unless the operator explicitly delegates `^colmena mission_spawn` (which they shouldn't, and we should put it in `restricted` by default).
- Add `^colmena (mission_spawn|delegate add|install|setup)` to `blocked` for ALL agents (manifest-spawned or otherwise). These are operator commands. (Today, `colmena delegate add` is not explicitly blocked for agents; this is a gap M7.15 should close as a side effect.)

### 3.3 Manifest version pinning

**A-6: Manifest authored against Colmena v0.13 with `scope.bash_patterns.extra_allow` semantics; applied against future v0.20 where semantics changed and the regex is now interpreted as auto-approve for chains.**

**Mitigation (P1):** Add optional `colmena_min_version: "0.14.0"` field to the manifest. If current `colmena --version` is below, reject. If above, log a warning if the manifest schema version is older than the current schema. Cost: ~2h. Justification: forward-compat. Without it, schema drift can silently change semantics across upgrades.

---

## 4. Delegation auto-creation from manifest

The manifest is, in essence, a `delegate add` factory. This collides with several existing invariants.

### 4.1 TTL handling

- `mission_manifest.rs:93-99` already caps `mission_ttl_hours` at `MAX_TTL_HOURS` (24h). Good. Default 8h. Good.
- Manifest CANNOT extend an existing mission's delegations. Re-applying with a longer TTL on the same `mission_id` should `bail!` — operator must `mission deactivate` first.
- TTL is per-mission, not per-role. v1 should NOT support per-role TTL overrides; that's a future feature once we see real demand. Avoid feature creep that introduces "auditor TTL=24h, worker TTL=2h" footguns.

### 4.2 Auto-creation without human approval — the real question

Today: `delegate add` is a CLI command; the operator types it, sees the output, can audit. M7.15 collapses N `delegate add` calls into one `mission_spawn --manifest`.

**Is this acceptable?** **Yes, IF:**
- The CLI shows a clear "about to create N delegations + M agent_overrides for K agents" diff and prompts `[y/N]` for confirmation. `--yes` flag for non-interactive (CI). Default interactive.
- All caps in §1.5 are enforced before the prompt (operator never sees a 1000-delegation diff).
- Audit log captures the full delegation list (already covered in §1.3).

**Is this NOT acceptable if:**
- Manifest can be applied silently by a daemon / agent (out of scope per §1.1).
- The diff is hidden (e.g. spinner + done, no list). Operators must see what they're authorizing.

**Inheritance from M6.2.** Per CLAUDE.md, `delegate add` since M6.2 requires mandatory conditions (`bash_pattern` or `path_within`) for Bash delegations. **The manifest must inherit this.** Any role declaring Bash in `tools_allowed` MUST declare `bash_patterns` AND/OR `paths` in its scope. Manifest validation enforces. No empty-condition Bash delegations.

**`--session` scope.** Per CLAUDE.md, delegations without `--session` warn about global scope. Manifest delegations should be **session-scoped by default** (the session that ran `mission_spawn --manifest`). Operator opts out with `--global-scope` flag. This is more restrictive than today's `delegate add` default; appropriate because manifests bundle many delegations at once and the blast radius of "global by default" is larger.

### 4.3 Failure mode — manifest neutralizes restricted

**Scenario:** firewall has `restricted: [{tools: [Bash], conditions: {bash_pattern: 'curl.*-X (POST|PUT|DELETE)'}}]` (network mutation requires ask). Manifest declares `agents.bbp_pentester_web.bash_patterns.extra_allow: ['^curl.*coinbase\.com']`. The auto-approve is broader than the restricted ask.

**Today's precedence (`firewall.rs:100-128`):** `agent_overrides` (step 3) is checked BEFORE `restricted` (step 4). So `extra_allow` does neutralize `restricted` for the listed agent.

**Is this acceptable?** **Yes, with controls:**

- This is the *intended* purpose of agent-scoped overrides. The whole point is to expand a specific agent's scope without globally relaxing rules.
- BUT the operator must understand they're doing this. v1: when manifest is loaded, parser computes the diff between `extra_allow` patterns and `config.restricted` patterns; if any `extra_allow` regex would auto-approve a command currently in `restricted`, the CLI shows a **warning block** in the apply diff:

  ```
  WARNING: manifest auto-approves the following commands currently in 'restricted':
    - 'curl -X POST https://api.coinbase.com/...' (matched by extra_allow[0] for role bbp_pentester_web)
  Continue? [y/N]
  ```

- Without this UX, operators silently neuter restrictions and don't realize until incident review. With it, every `extra_allow` requires informed consent.

**Cost:** ~1 day (regex intersection check + UX). **Invariant if omitted:** silent firewall bypass.

---

## 5. Acceptance criteria — mechanized or doc-only?

### 5.1 The trap

Acceptance criteria sounds great. "PoC artifact exists at `./poc.html` AND review verdict is READY". Cute. Then:
- Agent creates `poc.html` with content `<!-- TODO -->`. Criterion satisfied.
- Auditor under time pressure writes verdict "READY" without reading the artifact. Criterion satisfied.

Mechanized criteria without semantic verification is theater. Worse, it gives a false sense of security: "the gate said ready, ship it".

### 5.2 Recommendation

**v1: doc-only.** `acceptance_criteria` is a list of strings rendered into:
1. The mission prompt to every agent (so they know what "done" means).
2. The auditor's review template (auditor must address each criterion explicitly in their `review_evaluate` reasoning).

The auditor is the criterion-checker, not the runtime. This matches the existing M2/M6.4 architecture: review is the gate.

**v2 (M7.16) — mechanized criteria.** Optional, narrow, non-bypassable predicates only:
- `artifact_exists: <glob>` — file exists, non-empty (`> 0 bytes`), MIME-type matches (e.g. `application/json`).
- `review_verdict: READY` — auditor's `review_evaluate` outcome equals expected value.
- `tests_pass: <command>` — run a fixed command, exit code 0. (DANGER: arbitrary command execution. Must be in a strict allowlist or run in a sandbox. Defer.)
- `min_findings_severity: <level>` — at least N findings of severity ≥ X.

The runtime hook would be `Pre-Stop` (we already have `SubagentStop`). On the auditor's Stop, if `acceptance_criteria_v2` is set, evaluate each predicate. If any fails: block Stop, return reason. Cost: ~1 week + a careful threat model on `tests_pass` (sandbox or allowlist).

**v1 honest answer:** doc-only for M7.15. Mechanized in M7.16 with sandboxing for `tests_pass`. Don't ship machine-checked criteria in v1 — the value is low (auditor already reads the prompt) and the failure mode (false-pass theater) is bad.

---

## 6. Auditor pool — invariants

CLAUDE.md is unambiguous: `available_roles: ["auditor"]` is the production-recommended pool. Centralized auditor invariant.

### 6.1 Threats

**T-1.** Manifest declares `auditor_pool: ["auditor", "developer", "code_reviewer"]`. Now `submit_review` randomly picks any of those. A worker (e.g. another developer) reviews the developer's work — same-tribe approval. Quality gate degrades, ELO becomes noise.

**T-2.** Manifest declares `auditor_pool: ["friendly_role"]` where `friendly_role` is a custom-created role (M6 library_create_role) with permissive evaluation defaults. Effectively self-approval.

### 6.2 Controls (P0)

- **Default `auditor_pool: ["auditor"]`** if unset. Always.
- **Validation:** every role in `auditor_pool` MUST have `role_type: auditor` in its library YAML. If any role does not, manifest is rejected unless `--allow-broad-auditor-pool` flag is passed (operator ack, logged).
- **Audit log captures the pool.** `MANIFEST_APPLY.auditor_pool` field is mandatory.
- **Anti-self-review:** `auditor_pool` must NOT contain any role listed in `agents[].role`. If the same role is both worker and auditor, reject.

### 6.3 Cross-mission anti-reciprocal scope (per M7.3.1 memory)

Per the open bug `project_review_reciprocal_cross_mission_bug.md`, the anti-reciprocal filter currently operates globally and blocks legitimate cross-mission auditor reuse. **M7.15 must not ship without M7.3.1 being fixed first**, OR M7.15 explicitly documents that manifest-spawned missions inherit the bug. Recommendation: hard-gate M7.15 on M7.3.1 landing. Otherwise, manifest-driven swarms with `auditor_pool: ["auditor"]` will hit "no eligible reviewer" after the auditor's first cross-mission pairing, which silently breaks the ELO loop the manifest is supposed to help close.

---

## 7. Multi-instance agent identity (`count: 3`, instances: [squad-a/b/c])

This is the most-likely-to-break-quietly part of the design.

### 7.1 The CC propagation problem

Per `project_elo_success_recipe.md` (15-day-old memory, but mechanism is current per CLAUDE.md):
- Each subagent file `~/.claude/agents/<role_id>.md` must have `name: <role_id>` matching the delegation `agent_id`.
- CC propagates `name` as `agent_id` OR `agent_type` in the hook payload. Firewall checks both (`firewall.rs:110-112`).
- Without exact match, ELO tracks the wrong identity → cycle breaks silently.

### 7.2 Multi-instance shape — what the manifest declares

```yaml
agents:
  - role: bbp_pentester_web
    count: 3
    instances: [squad-a, squad-b, squad-c]
```

This means: spawn 3 subagent files, each a copy of the `bbp_pentester_web` library role, with `name: squad-a`, `squad-b`, `squad-c`. Three distinct delegations. Three distinct ELO tracks.

### 7.3 Threats

**T-1.** `count: 3` without `instances:`. Auto-generate names? `bbp_pentester_web-1/2/3`? Conflict with future re-spawn (manifest applied twice gets `-1/2/3` again, name collision with prior delegations).

**T-2.** `instances:` count != `count:`. Inconsistency. Reject at parse time.

**T-3.** Two manifests with overlapping instance names (`squad-a` in mission X, `squad-a` in mission Y). Today's anti-reciprocal global filter would exacerbate the M7.3.1 bug.

**T-4.** Concurrent `review_submit` from `squad-a` and `squad-b` on the same `artifact_path`. Anti-reciprocal vs stale-hash interaction.

### 7.4 Controls (P0)

- **`instances` is mandatory when `count > 1`.** No auto-generation. Operator must name them explicitly. Forces awareness.
- **Instance names are namespaced by `mission_id`.** Effective agent_id = `<mission_id>:<instance_name>`. Subagent file: `~/.claude/agents/<mission_id>__<instance_name>.md` with `name: <mission_id>__<instance_name>`. This guarantees no cross-mission collision (and incidentally side-steps the M7.3.1 anti-reciprocal bug for manifest-spawned missions, because each mission's instances are unique strings).
- **Validation: instance names match `^[a-z][a-z0-9_-]{1,30}$`.** No spaces, no special chars, no path components.
- **Concurrency (T-4):** `review_submit` already has stale-hash invalidation per CLAUDE.md §"Security & Trust": if `squad-a` and `squad-b` both submit reviews for the same artifact, the later submission invalidates the earlier (per author). For DIFFERENT authors on the same artifact, both are valid concurrent reviews — that's actually the intended design. Document in the manifest spec: "if multiple instances share an artifact, each independently triggers review."

### 7.5 Subagent file generation — the security delta vs M7.3

M7.3 already auto-generates subagent files. M7.15 multiplies by N. The risks compound:
- N agent files in `~/.claude/agents/` increase the attack surface (each is mutable by any agent with Edit on `~/.claude/`).
- Cleanup: `mission deactivate` MUST remove these files, not orphan them.

**Control:** `mission deactivate` removes `~/.claude/agents/<mission_id>__*.md`. Audit event `MANIFEST_CLEANUP {mission_id, agents_removed: N}`. Without this, instance files leak past mission lifetime.

---

## 8. Audit + observability of manifest apply

### 8.1 Required audit events

- `MANIFEST_APPLY` — fields enumerated in §1.3.
- `MANIFEST_VALIDATION_REJECT` — when manifest fails parse/cap/secret-scan validation. Captures `manifest_path`, `manifest_sha256_partial` (to disambiguate without full hash if the file was deleted), `reason`.
- `MANIFEST_DEACTIVATE` — fields: `mission_id`, `delegations_revoked`, `agent_overrides_removed`, `instance_files_removed`.
- Existing `DELEGATE_CREATE`/`DELEGATE_REVOKE` events fire as before for each individual delegation. The `MANIFEST_APPLY` event is the *transactional* wrapper.

### 8.2 Replay test

Acceptance criterion for the design: given `mission_id`, the operator can run `colmena audit replay <mission_id>` and:
- Reconstruct the manifest content (from snapshot, verified against audit hash).
- List agents created and their final ELO.
- List delegations granted and whether they expired or were revoked.
- List `agent_overrides` injected and removed.
- Diff scope: what could the agents do that they couldn't have done without the manifest?

If you cannot answer those questions from `audit.log` + `manifest.snapshot.yaml`, audit is incomplete. This is the test the design must pass.

### 8.3 Statusline / session_stats integration

- `session_stats` should report active manifest-driven missions: `mission_id`, agent count, time remaining, scope summary (1-line).
- Statusline blip on `MANIFEST_APPLY` and `MANIFEST_DEACTIVATE` so the operator knows it happened (analogous to M7.11 SessionEnd value banner).

---

## 9. Kill switches

### 9.1 `mission deactivate` semantics

Today, `mission deactivate <id>` revokes delegations linked to `mission_id`. M7.15 adds two new artifacts that must also be cleaned:

1. **Manifest-injected `agent_overrides`.** These live in-memory (or in a session-scoped overlay file — see implementation discussion below). Must be removed.
2. **Auto-generated instance subagent files.** `~/.claude/agents/<mission_id>__*.md`. Removed on deactivate.

**Implementation question:** where do manifest-injected `agent_overrides` live?
- **Option A (in-memory only).** Reloaded on each hook invocation from `runtime-delegations.json`-style file. Simplest. But agent_overrides are richer (rules with conditions), so a separate file `runtime-agent-overrides.json` keyed by `mission_id` is probably needed.
- **Option B (write into `trust-firewall.yaml`).** STRONGLY DISCOURAGED. `trust-firewall.yaml` is human-curated, version-controlled. Manifest-injected entries pollute it and can survive `mission deactivate` if the cleanup misses them.

**Recommendation: Option A**, with a new file `runtime-agent-overrides.json` (mirror of `runtime-delegations.json` semantics: TTL-bound, mission-tagged, atomic write, locked). The firewall reads it at evaluation time and merges with `config.agent_overrides` (with YAML winning per §2.2 collision rule). `mission deactivate` removes entries by `mission_id`.

### 9.2 Survival post-deactivate

Without §9.1 cleanup, mission permissions can survive past `mission deactivate`. This is a **scope leak**. Hard rule for v1: every manifest-injected artifact (delegation, agent_override, subagent file) MUST be revocable by `mission deactivate <id>` AND by mission TTL expiry. Test: spawn manifest mission, wait for TTL, verify all three artifact types are gone.

### 9.3 Emergency disable

- **YAML flag `disable_manifest_spawn: true`** in `trust-firewall.yaml`. When set, `mission_spawn --manifest` exits 1 with an explicit error. Conservative operators or compromised-CC scenarios.
- **Env var `COLMENA_DISABLE_MANIFEST=1`.** Same semantics, runtime-controllable. Useful for CI sandboxing or quick disable without editing YAML.
- **Both should also disable mid-mission rollover:** if `disable` is set after a manifest mission spawned, the existing mission keeps running (don't trap agents) but no new manifest can be applied.

---

## 10. Compatibility with `auto-elevate after 2× yes` (M7.x feature request)

Per `project_firewall_auto_elevate_2x_yes.md`, Coco wants: same agent_type asked the same prompt 2x, both approved → auto-create session-scoped delegation.

### 10.1 Interaction with manifest

- If manifest declares `bash_patterns.extra_allow: ['^curl.*coinbase\.com']`, the auto-elevate trigger never fires for those commands — they're already auto-approved. Fine.
- If manifest does NOT declare them, operator approves 2x, auto-elevate creates a session delegation. Fine.
- **Collision:** auto-elevate writes to `runtime-delegations.json` with no `mission_id` (it's session-scoped, not mission-scoped). Manifest writes to `runtime-agent-overrides.json` with `mission_id`. No file collision.
- **Precedence:** manifest's `agent_overrides` (step 3 in firewall) take precedence over auto-elevate's runtime delegation (step 2). Wait — runtime delegations are step 2, agent_overrides are step 3. So delegations win first. Concrete: if auto-elevate creates a delegation that DENIES (which it shouldn't, but hypothetically), it would override the manifest's auto-approve. **Mitigation:** auto-elevate ONLY creates auto-approve delegations (per its design — "operator said yes 2x"). It cannot create deny. So the precedence collision is benign.

### 10.2 Recommendation

- Document the precedence: `runtime_delegations > manifest agent_overrides > YAML agent_overrides > restricted > trust_circle`.
- Auto-elevate should check before creating: if a manifest agent_override already covers the command, skip auto-elevate (no-op, save the disk write).
- Auto-elevate's session-scoped delegation expires with the session; manifest's agent_overrides expire with the mission. Different lifetimes, both bounded. No leak.

---

## 11. Threats not obvious

### 11.1 Manifest sharing — the leak surface

If Coco shares `manifest.yaml` (gist, public repo, blog post about Colmena), what does it leak?
- `mission_id` — generally safe but can hint at internal naming conventions or roadmap.
- `goal:` — operators may write sensitive info ("audit Coinbase 4337 dapp permissions"). Reveals targets.
- `scope.paths:` — reveals filesystem layout, project locations, possibly other clients' work.
- `scope.hosts:` — reveals targets (especially for pentest missions).
- `scope.bash_patterns.extra_allow:` — reveals attack patterns or tool usage.
- `acceptance_criteria:` — reveals what "done" looks like, sometimes proprietary methodology.
- `pattern: bbp-impact-chain` — reveals which Colmena patterns the operator uses.

**Control (P1):** `colmena manifest scrub <path>` command that:
- Replaces `goal:` with `[redacted]` (or operator-supplied generic).
- Replaces `scope.paths` with `[<N> paths]`.
- Replaces `scope.hosts` with `[<N> hosts]`.
- Strips `acceptance_criteria` content (keeps count).
- Outputs scrubbed YAML safe to share.

**Convention (P0):** README and CLAUDE.md must explicitly warn that manifests are not safe to share by default. They are configuration with potentially sensitive payload. Treat them like `.env` files.

### 11.2 Manifest in CI

If a future use case is "GitHub Actions runs `colmena mission_spawn --manifest .github/missions/nightly.yaml`", several issues:

- **Credentials:** what auth does CI need? Today: nothing (Colmena is local-only). M7.15 inherits this — manifests don't need auth. But if CI is the operator, the GitHub Action user has effective `--yes` on every prompt. So CI manifests must be doubly-validated.
- **Privilege creep in CI:** GitHub Actions runners have ambient permissions (repo write, secrets, etc.). If a manifest-driven mission grants Bash + extra_allow `curl.*github.com`, an agent could exfiltrate secrets via PR comments. Out-of-scope for v1 (Colmena isn't on CI yet) but flag for M8.
- **Recommendation:** v1 docs should say "do not run `mission_spawn --manifest` in CI". The threat model is single-user-local. CI hardening is M8+.

### 11.3 Manifest vs library_create_role/pattern injection

M6 added MCP tools for `library_create_role` / `library_create_pattern`. Per CLAUDE.md, these are in `restricted` (require human ack) to prevent library poisoning. **The manifest must inherit this.** Specifically:

- `pattern:` field references an existing library pattern. Manifest CANNOT inline-define a pattern. If the pattern doesn't exist in `library/`, manifest is rejected.
- Same for roles. `agents[].role:` references existing library roles.
- This forces all role/pattern creation to go through the audited `library_create_*` path. Manifest is composition only.

### 11.4 Manifest-driven ELO poisoning

If an attacker can spawn a manifest mission with friendly auditor + worker pair, write trivial artifacts, and cycle the auditor through 10 reviews of "10/10", they pump ELO for `worker_role` and trigger trust-tier elevation (Standard → Elevated), unlocking auto-approve for that role globally.

**Mitigations (already partly in place + new):**
- `auditor_pool` invariants (§6) prevent friendly auditors.
- ELO calibration uses temporal decay + min review count (per CLAUDE.md). 10 reviews in one mission don't dominate.
- **NEW (P1):** ELO events tagged with `mission_id` so calibration can detect "all events came from one mission" and de-weight or flag for manual review. Cost: ~1 day. Without it, ELO pumping is feasible.

---

## 12. Hardcoded security invariants — non-overridable

These are the floor. No manifest field, no CLI flag, no YAML override changes them.

### 12.1 Files always protected (Write/Edit blocked, regardless of scope.paths)

Inherits the trust_circle Write rule's `path_not_match`:

- `audit.log`, `*audit.log*`
- `trust-firewall.yaml`, `*trust-firewall*`
- `runtime-delegations.json`, `runtime-agent-overrides.json`, `*runtime-*`
- `elo-overrides.json`, `*elo-*`
- `revoked-missions.json`, `*revoked-missions*`
- `alerts.json`, `*alerts*`
- `reviews/`, `findings/`, `*reviews*`, `*findings*`
- `filter-config.yaml`, `*filter-config*`, `*filter-stats*`
- `settings.json`, `*settings.json`
- `colmena-errors*`
- **NEW for M7.15:** `*manifests/*.yaml`, `*manifest.sha256`, `*manifest.snapshot.yaml`, `~/.claude/agents/*.md`
- Universal secrets: `*.env`, `*credentials*`, `*secret*`, `*.key`, `*.pem`

### 12.2 Paths always blocked (regardless of scope.paths)

- `/etc/`, `/etc/shadow`, `/etc/passwd`, `/etc/sudoers`
- `/root/`
- `/home/<other_user>/` — implementable as "absolute path under `/home/` whose first component != current user". Best-effort on multi-user systems.
- `~/.ssh/`, `~/.aws/`, `~/.config/gcloud/`, `~/.docker/config.json`, `~/.npmrc`, `~/.pypirc`
- `/var/log/`, `/var/lib/`
- `/proc/`, `/sys/` (exfil surface for kernel info)
- `/dev/`, especially `/dev/mem`, `/dev/sd*`, `/dev/nvme*`

### 12.3 Hosts always blocked

- `169.254.169.254` (AWS/GCP metadata)
- `metadata.google.internal`, `metadata.azure.com`
- `127.0.0.1`, `localhost`, `0.0.0.0` (unless `--allow-loopback` operator flag)
- RFC1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (unless `--allow-private-net` operator flag)
- IPv6 link-local `fe80::/10`, ULA `fc00::/7`
- `file://` scheme in URLs (SSRF + local file read)

### 12.4 Bash patterns always blocked

Independent of `extra_allow`. Manifest validation must reject any `extra_allow` that would auto-approve these:

- `rm -rf /`, `rm -rf ~`, `rm -rf $HOME` (and obvious variants `--no-preserve-root`, `/*`).
- `dd if=/dev/zero of=/dev/`, `dd if=/dev/urandom of=/dev/`
- `mkfs.`, `:(){ :|:& };:` (fork bomb), `chmod 777 /`, `chmod -R 777 /`
- `wget|curl http(s)?://[^ ]+ \| (sh|bash|zsh)` (pipe-to-shell from network)
- `eval $(curl ...)`, `$(curl ...) | sh`
- `nc -e`, `bash -i >& /dev/tcp/` (reverse shell shapes)
- `:(){:|:&};:` already covered
- `find / -delete`, `find ~ -delete`
- `git push --force` to protected branches (already in current `blocked` per CLAUDE.md)
- `gh pr merge` (already blocked per CLAUDE.md "PRs are merged by human only")
- `colmena (mission_spawn|delegate add|install|setup)` (operator commands, never agent-callable)

### 12.5 Manifest fields never honored

These fields, if present in YAML, cause hard reject:

- `disable_audit_log`
- `disable_path_not_match`
- `override_blocked` / `unblock`
- `extend_ttl_beyond_max`
- `role_type` (overriding library `role_type`)
- `chain_aware: false` at manifest level (per `feedback_chain_aware_kill_switch.md`, this disables chain protection — never expose at manifest level; trust-firewall.yaml only)
- Anything starting with `_`, `internal_`, or matching a regex of "looks like a feature flag we forgot to remove".

### 12.6 Delegation invariants

- TTL absolute max 24h (`delegate.rs:10` `MAX_TTL_HOURS`).
- Bash delegations require `bash_pattern` OR `path_within` (M6.2 invariant). Manifest enforces at parse time.
- Source: `role` (manifest-spawned delegations match this; same as today's mission_spawn).
- All delegations carry `mission_id`. Used by `mission deactivate` for bulk revocation.

---

## 13. Recommendations — prioritized

### P0 (must ship for v1, otherwise do not ship)

| # | Control | Cost | Justification if omitted |
|---|---------|------|-------------------------|
| 1 | CLI-only `mission_spawn --manifest` (no MCP). Allowlisted manifest dir. | 1d | Self-spawn elevation (§1.1 S-1). |
| 2 | Hash + snapshot + audit on apply. | 1d | No replay-ability; repudiation. |
| 3 | Read-only post-load + path_not_match for `*manifests/*.yaml` + subagent files. | 0.5d | Mid-mission tampering (§3.2 A-4). |
| 4 | Caps: ≤25 agents, ≤20 regexes, ≤32 paths/hosts. Hardcoded. | 0.5d | DoS + hook latency blow-up (§1.5). |
| 5 | Secret regex scan on raw YAML. Reject + log without leaking match. | 0.5d | Credential leak via manifest (§1.4). |
| 6 | `extra_allow` validation: `^`-anchored, no catch-alls, must not match always-blocked sentinels, no chain-greedy. | 1d | Firewall bypass via sloppy regex (§2.2). |
| 7 | Path canonicalize + always-blocked path list. | 1d | Path traversal CVE (§2.1). |
| 8 | Hardcoded blocklist (§12) — files, paths, hosts, bash patterns, fields. | 1d | Manifest can otherwise grant root-equivalent. |
| 9 | Auditor pool defaults to `["auditor"]`; non-default requires `--allow-broad-auditor-pool` ack. | 0.5d | Same-tribe approval, ELO degradation (§6). |
| 10 | Multi-instance: `instances` mandatory when `count>1`; namespace by `mission_id`; cleanup on deactivate. | 1d | Identity collision, ELO breakage, file leak (§7). |
| 11 | Manifest-injected `agent_overrides` in separate `runtime-agent-overrides.json`, never in `trust-firewall.yaml`. Removed by `mission deactivate`. | 1d | Scope leak post-mission (§9.1). |
| 12 | Apply-time CLI diff + `[y/N]` prompt with `--yes` opt-out. Restricted-bypass warning (§4.3). | 1d | Silent firewall neuter (§4.3). |
| 13 | YAML anchor/alias rejection. | 2h | Scope obfuscation (§1.2 T-3). |
| 14 | Hard-gate on M7.3.1 (anti-reciprocal cross-mission fix). | (M7.3.1 cost) | Manifest swarms hit "no eligible reviewer" silently (§6.3). |

**P0 total estimate:** ~10 days of security-focused work. (Independent of the architect/SRE work — they have their own scopes.)

### P1 (should ship, defer if schedule slips)

| # | Control | Cost | Notes |
|---|---------|------|-------|
| 15 | `colmena_min_version` field + check. | 2h | Forward-compat; cheap. |
| 16 | `colmena manifest scrub` for safe sharing. | 0.5d | UX, not safety-critical. |
| 17 | ELO event tagging with `mission_id` for de-weighting single-mission pumping. | 1d | Anti-poisoning (§11.4). |
| 18 | Statusline / session_stats integration for active manifests. | 0.5d | Observability. |
| 19 | `disable_manifest_spawn` YAML flag + env var kill switch. | 2h | Emergency disable (§9.3). |

### P2 (later, M7.16+)

- Mechanized acceptance criteria (predicates, sandboxing).
- Per-role TTL.
- CIDR/network scope enforcement (real network firewall, not bash-pattern shaping).
- Manifest signing for sharing across users / CI.
- `colmena audit replay <mission_id>` reconstruction tool.

---

## 14. Insecure proposals in the starting shape — call-outs

The starting-point shape has the following issues to address explicitly in the unified `ARCHITECT_PLAN.md`:

1. **`scope.paths: [/home/fr33m4n/bugbounty/CoinBase, ${MISSION_DIR}]`** — must be canonicalized, must pass blocklist (§12.2). `/home/fr33m4n/...` is fine for Coco's box, but the example sets a precedent that absolute user-home paths are normal. They are, in this single-user model. Document that other models (multi-tenant) require additional controls not in M7.15.
2. **`scope.hosts: ["*.coinbase.com"]`** — wildcard hosts. Today's bash regex shaping handles `*.` poorly (it's a glob, not a regex; conversion is needed). v1 should accept `*.coinbase.com` and translate it to a bash regex like `https?://([a-z0-9-]+\.)+coinbase\.com`. Document the translation.
3. **`scope.bash_patterns.extra_allow: ['^curl.*coinbase\.com']`** — chain-greedy. `curl https://coinbase.com && rm -rf ~` would match. Recommend tighter: `^curl( -[A-Za-z]+)*( --[a-z-]+)*( https?://[a-z0-9.-]+\.coinbase\.com[/?][^ ;|&]*)$`. The validator in §2.2 catches the original; reject and require the tighter form.
4. **`budget: { max_hours: 8, max_agents: 12 }`** — `max_hours` aliases `mission_ttl_hours` (already capped 24h). `max_agents` must enforce against the §1.5 cap of 25; budget doesn't get to exceed it. If budget says `max_agents: 1000`, manifest is rejected.
5. **`auditor_pool: ["auditor"]`** — correct default; just enforce at parse.
6. **`mission_gate: enforce`** — good. v1 should make `enforce` the only honored value; `warn`/`off` are deferred until there's a real use case (per CLAUDE.md, Mission Gate is "ask, not deny" — manifest setting `off` would weaken that).
7. **`instances: [squad-a, squad-b, squad-c]`** — names lack mission namespace prefix. v1 should prefix internally with `<mission_id>__` per §7.4.
8. **`weaponizer` and `auditor` roles in `agents:` without count** — implicit `count: 1`. Fine, but explicit is better. Recommend manifest spec say `count` defaults to 1, with single-instance subagent file `<mission_id>__<role>.md`.

---

## 15. What this review does NOT cover (by lens)

Out of scope for Security Architect:
- Architectural cleanliness (layering, module boundaries, API design) → `colmena_architect`.
- Performance characteristics under load, hook latency budgets, concurrency → SRE.
- Library role / pattern design quality → already covered by M2/M6/M7 reviews.
- Mechanized acceptance criteria semantics (deferred to M7.16).
- Manifest signing / multi-user trust → M8+.
- DoS against external targets via swarm — flagged but operator-responsibility per §1.5 D-4.

---

## 16. Closing — invariants restated

The manifest is configuration. Configuration cannot grant authority that the runtime cannot revoke. Configuration cannot bypass the runtime's hardcoded floor.

If we ship M7.15 with the P0 list intact, the manifest collapses today's `delegate add` chain into one auditable, hash-verified, capped, secret-scanned file — without expanding the agents' authority beyond what the operator could have granted manually one-by-one. That's the bar.

If any P0 slips, the manifest becomes a privilege-escalation vector. Don't ship.

— Security Architect
