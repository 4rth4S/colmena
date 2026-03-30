# Colmena M0 — Dark Corners Analysis

> Edge cases, security gaps, and hidden assumptions in the current implementation.
> Generated: 2026-03-29

---

## Critical (must-fix before production)

### 1. Glob matching is broken — `*.env` matches `.env.old`

**File:** `src/firewall.rs:198-215` (`glob_match()`)

The `path_not_match` condition uses a hand-rolled glob that only supports `*`. The pattern `*.env` uses `ends_with(".env")`, which means:

- `project/.env` -> blocked (correct)
- `project/.env.production` -> blocked (incorrect — false positive)
- `project/my.env.backup` -> blocked (incorrect — false positive)

**Impact:** Users expect `*.env` to block `.env` files, not every file containing `.env` in its name. Could block legitimate writes or, worse, give false confidence that secrets are protected when they're not.

**Fix:** Replace `glob_match()` with the `glob` crate or implement proper glob semantics where `*` doesn't match path separators and anchors correctly.

---

### 2. Path traversal bypasses `path_within` check

**File:** `src/firewall.rs:150-160`

```rust
if !allowed_dirs.iter().any(|dir| p.starts_with(dir)) {
```

Simple string prefix match. No path normalization.

**Attack:** A tool call with `file_path: "/Users/fr33m4n/colmena/src/../../../etc/passwd"` passes the `path_within: ["/Users/fr33m4n/colmena"]` check because the string starts with the allowed prefix, even though the resolved path is outside the project.

**Impact:** Medium. The filesystem still enforces OS-level permissions, but the firewall rule is bypassed — auto-approving writes that should require human review.

**Fix:** Use `std::path::Path::canonicalize()` or at minimum `std::fs::canonicalize()` before comparing. Alternatively, normalize `..` segments manually for paths that don't exist yet.

---

### 3. Config and binary paths hardcoded to `~/colmena`

**Files:** `src/main.rs:280`, `src/install.rs:93,98`

```rust
// main.rs
fn default_config_dir() -> PathBuf {
    dirs_or_home().join("colmena/config")
}

// install.rs
format!("{home}/colmena/target/release/colmena")
format!("{home}/colmena/config/trust-firewall.yaml")
```

**Impact:** If colmena is cloned to any path other than `~/colmena` (e.g., `~/projects/colmena`, `/opt/colmena`), the hook fails silently and falls back to `ask` on every call, negating the entire tool.

**Fix:** Introduce `COLMENA_HOME` env var. Derive default paths from the actual binary location (`std::env::current_exe()`) or from `--config` parent directory. The install command should detect the actual project root.

---

### 4. Race condition on `runtime-delegations.json`

**File:** `src/main.rs:217`

```rust
let mut delegations = delegate::load_delegations(&delegations_path);
delegations.push(new_delegation);
std::fs::write(&delegations_path, json)?;
```

Read-modify-write without any locking.

**Scenario:** Two concurrent CC instances (or the human running `colmena delegate` while a hook is evaluating) can clobber each other's writes. The last writer wins, silently dropping delegations.

**Impact:** Lost delegations = unexpected `ask` prompts for operations the human already approved. Annoying but not dangerous (fails safe).

**Fix:** Write to a temp file then `rename()` (atomic on most filesystems). Or use `flock()` / `fcntl` advisory locks. For M0 with typically 1-2 concurrent instances, the risk is low but will grow with M2/M3 multi-agent scenarios.

---

### 5. Regex compiled at eval time, not load time

**File:** `src/firewall.rs:134-141`

```rust
match Regex::new(pattern) {
    Ok(re) => { if !re.is_match(command) { return false; } }
    Err(_) => return false, // bad regex = no match
}
```

**Two problems:**

1. **Performance:** Regex is recompiled on every hook call (~5ms for complex patterns). With 10+ agents making 50+ calls/session, this adds latency.

2. **Silent failures:** An invalid regex (e.g., `(?P<broken>`) silently makes the rule never match. The user's "blocked" rule becomes inert with no warning. A destructive command could slip through if the blocked pattern is malformed.

**Fix:** Compile all regexes in `config::load_config()` and cache them in the `Rule` struct (as `Option<Regex>`). Fail loudly at load time if any pattern is invalid. `config check` already validates patterns — but the hook path should too.

---

## High Priority (fix before multi-agent use)

### 6. Error handling masks all failures equally

**File:** `src/main.rs:95-100`

Any error in any subcommand (config parse failure, disk full, permission denied) produces the same output: `{"permissionDecision": "ask", "reason": "Colmena error: ..."}`. The error reason is in the JSON but CC may not surface it to the user.

**Impact:** Debugging is extremely difficult. The user sees normal `ask` prompts and doesn't know colmena is broken.

**Fix:** Write errors to a log file (`~/.colmena/colmena.log` or `config/colmena-errors.log`). Keep the safe `ask` fallback but make failures discoverable.

---

### 7. Queue write failures are silent

**File:** `src/main.rs:137`

```rust
let _ = queue::enqueue_pending(config_dir, &payload, &decision);
```

If disk is full, permissions are wrong, or the queue directory doesn't exist, the approval decision is lost from the audit trail. The hook still returns the correct decision, but there's no record of it.

**Fix:** Log the failure. Consider keeping a count of "dropped queue entries" that `queue list` can report.

---

### 8. Tool names are never validated

**Files:** `src/config.rs`, `src/delegate.rs`

Tool names in rules and delegations are `String` — any typo is silently accepted. `tools: [bash]` (lowercase) never matches `"Bash"`. `delegate --tool Raed` creates a delegation that never fires.

**Fix:** Define a `KnownTool` enum or a `VALID_TOOLS` set. Validate at config load time and delegation creation time. Warn on unknown tools.

---

### 9. No `queue decided/` lifecycle

**Files:** `src/queue.rs`

The spec mentions `queue/decided/` for audit trails, but no code ever writes there. Pending entries accumulate forever — no archival, no cleanup.

**Impact:** Over weeks of use, `queue/pending/` fills with hundreds of JSON files. `queue list` becomes slow and noisy.

**Fix:** Add `queue::move_to_decided()` (called externally or on a schedule). Add `queue prune --older-than 7d` CLI subcommand.

---

### 10. `install` doesn't verify the hook works

**File:** `src/install.rs`

After writing to `settings.json`, the command prints "Hook installed successfully" but never verifies:
- The binary exists at the installed path
- The binary is executable
- The config file exists
- A test payload produces valid output

**Fix:** Run a dry-run test payload through the installed hook command before declaring success.

---

## Medium Priority (M0.1 improvements)

### 11. No session-scoped delegations

The `session_id` field exists on `RuntimeDelegation` but is never enforced. All delegations apply globally. The spec says delegations should be "session-scoped by default."

### 12. No `delegate list` or `delegate revoke` commands

Users can add delegations but can't inspect or remove them without manually editing JSON.

### 13. `say` command not sanitized

**File:** `src/notify.rs:38`

Agent names are interpolated directly into the `say` command argument. Unusual names with quotes or special chars could cause unexpected behavior.

### 14. Notification config has no defaults

If the `notifications:` section is missing from YAML, notifications are silently disabled (Option is None). Users might expect them to be on by default.

### 15. No MCP tool pattern matching

Only 2 MCP tools are explicitly listed in `restricted`. All other MCP tools fall to default `ask`. Consider a wildcard rule: `tools: [mcp__*]` (requires implementing prefix matching in the rule engine).

### 16. No payload versioning

`HookPayload` has no version field. If CC changes the payload schema, colmena won't detect the incompatibility — it'll just fail to deserialize and fall back to `ask`.

---

## Low Priority (nice to have)

### 17. Regex compilation on every call

Even without the silent-failure issue, recompiling regexes per call is wasteful. Cache compiled patterns in a `HashMap<String, Regex>` or inside the `Rule` struct.

### 18. Filename collision in queue writes

`{timestamp_ms}-{tool_use_id}.json` could theoretically collide if two CC instances generate the same tool_use_id at the same millisecond. Extremely unlikely but not impossible.

### 19. macOS-only notifications

`afplay` and system sound paths are hardcoded to macOS. Will fail silently on Linux/Windows. Acceptable for M0 (macOS-only target).

### 20. Fire-and-forget notification spawns

Failed `afplay`/`say` spawns produce no error. Hard to debug if sounds stop working.

### 21. `install` already-installed check is substring-based

`c.contains("colmena")` could false-positive on paths like `~/.colmena-backup/hook`. Should use exact path match.

### 22. Delegation expiry uses `>` not `>=`

A delegation that expires at exactly the current time is pruned. Minor off-by-one, practically invisible.

---

## Security Considerations

| Vector | Status | Notes |
|--------|--------|-------|
| Path traversal via `..` | **Vulnerable** | `path_within` check uses string prefix, not normalized paths |
| Glob bypass | **Vulnerable** | `*.env` pattern doesn't work as expected |
| Command injection via `say` | Low risk | User controls agent names, not external input |
| Queue data exposure | Acceptable | Queue stores raw tool_input; readable only by the user |
| Delegation hijacking | Low risk | File permissions protect `runtime-delegations.json` |
| Config tampering | Acceptable | YAML is user-owned; no privilege escalation possible |
| Hook failure = open | By design | Safe fallback to `ask` — correct per spec |

---

## Recommended Fix Order

1. **Path traversal** (security) — canonicalize paths in `firewall.rs`
2. **Glob matching** (correctness) — replace hand-rolled glob with proper implementation
3. **Hardcoded paths** (usability) — introduce `COLMENA_HOME` or auto-detect
4. **Regex at load time** (correctness + performance) — compile and cache patterns
5. **Error logging** (debuggability) — log to file before safe fallback
6. **Tool name validation** (correctness) — catch typos at config load
7. **Delegation race condition** (reliability) — atomic file writes
8. **Install verification** (UX) — dry-run after hook registration
