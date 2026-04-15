# Colmena Internals

Edge cases, safety contracts, implementation details, and gotchas for contributors modifying the codebase.

---

## 1. Hook Protocol

### PreToolUse

**Input** (`HookPayload`, `hook.rs:8-22`):
```json
{
  "session_id": "sess_abc123", "hook_event_name": "PreToolUse",
  "tool_name": "Bash", "tool_input": {"command": "ls -la"},
  "tool_use_id": "tu_001", "agent_id": "pentester",
  "cwd": "/home/user/project"
}
```
Optional fields: `agent_id`, `agent_type`, `permission_mode`.

**Output** (`hook.rs:38-83`):
```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "allow",
    "permissionDecisionReason": "Read-only local operations"
  }
}
```
`permissionDecision`: `allow`, `deny`, or `ask`.

### PostToolUse

**Input**: Same as PreToolUse plus `tool_response`:
```json
"tool_response": {"stdout": "...", "stderr": "...", "interrupted": false}
```
CC sends `tool_response` (not `tool_output`) and `interrupted` (not `exitCode`). Source: `main.rs:590-594`.

**Output** (`hook.rs:87-120`): When modified, includes `"updatedMCPToolOutput": "filtered content"`. On passthrough, the field is absent entirely (`skip_serializing_if` None).

### PermissionRequest

**Output** (`hook.rs:123-198`):
```json
{
  "hookSpecificOutput": {
    "hookEventName": "PermissionRequest",
    "decision": {
      "behavior": "allow",
      "updatedPermissions": [{
        "type": "addRules",
        "rules": [{"toolName": "Read"}, {"toolName": "mcp__caido__*"}],
        "behavior": "allow", "destination": "session"
      }]
    }
  }
}
```
When denying or passing through: no JSON written to stdout. CC continues its default behavior.

### SubagentStop

**Input** (`SubagentStopPayload`, `hook.rs:202-211`): Different struct from tool events. No `tool_name`/`tool_input`.
```json
{"session_id": "sess_abc", "hook_event_name": "SubagentStop",
 "agent_id": "pentester", "cwd": "/home/user/project", "reason": "task_complete"}
```

**Output**: `{"decision": "approve"}` or `{"decision": "block", "systemMessage": "Submit review first..."}`

---

## 2. Safe Fallbacks (Safety Contracts)

Every hook type has a defined fallback behavior when errors occur. These are not guidelines — they are invariants.

| Hook | On Error | Rationale | Source |
|------|----------|-----------|--------|
| PreToolUse | Return `ask` | Never auto-deny a legitimate tool call. Let the human decide. | `main.rs:293-300` |
| PostToolUse | Passthrough (original output) | Never lose or corrupt tool output. A filter bug must not affect CC's processing. | `main.rs:557-566` |
| PermissionRequest | No output | CC continues to prompt the user. Same as if Colmena was not installed. | `main.rs:649-654` |
| SubagentStop | Return `approve` | Never trap an agent. A stuck agent is worse than a premature exit. | `main.rs:740-745` |

The filter pipeline has its own safety layer: each filter is wrapped in `catch_unwind` (`pipeline.rs:75-91`). A panicking filter is skipped — it never crashes the hook process.

---

## 3. Filter Pipeline Internals

### Why This Order?

1. **ANSI strip first** — escape sequences inflate char counts and confuse text-based filters. Regex compiled once via `OnceLock` (`filters/ansi.rs`).
2. **Stderr-only second** — on failure, discards stdout entirely. Running after dedup/truncate would waste work on discarded output.
3. **Dedup third** — collapses N+ consecutive identical lines. May reduce output enough that truncation becomes unnecessary.
4. **Truncate last** — hard cap at 150 lines / 30K chars (below CC's 50K internal limit). Preserves start + end, cuts from middle.

Source: `colmena-filter/src/pipeline.rs:33-48`.

### catch_unwind Safety

```rust
let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
    filter.filter(&current_stdout, &current_stderr, exit_code)
}));

match result {
    Ok(filter_result) => { /* apply if modified */ }
    Err(_) => { notes.push(format!("{filter_name}:PANICKED")); }
}
```

A panicking filter is logged as `"filter_name:PANICKED"` in the pipeline notes and skipped. The previous output is preserved. Source: `pipeline.rs:74-92`.

---

## 4. Concurrency

### Atomic File Writes

Shared state files (delegations, ELO overrides, alerts) use temp file + rename:

```rust
// colmena-core/src/delegate.rs:94-112
let temp_path = path.with_extension("json.tmp");
std::fs::write(&temp_path, json)?;
std::fs::rename(&temp_path, path)?;
```

This ensures readers see either the old or new version, never a partial write. Both the CLI hook and MCP server may write to these files.

### Race Condition

Two CC instances writing delegations simultaneously can race. The last writer wins. There is no file locking. This is a known limitation — accepted because:
- Delegation writes are infrequent (human-initiated or mission generation).
- The worst case is a lost delegation, which the human can re-add.

Queue entries avoid collisions by using unique filenames: `{timestamp_millis}-{tool_use_id}.json`. Source: `queue.rs:94`.

### Append-Only Files

`audit.log`, `elo-events.jsonl`, and `filter-stats.jsonl` are append-only. Multiple processes can safely append to the same file (kernel-level atomicity for small writes on most filesystems). 10MB rotation renames the file, which may cause a small window where an appending process writes to the old file handle.

---

## 5. ELO Implementation Details

### Append-Only, Calculate on Read

There is no stored "current rating." The ELO is recalculated from all events every time `calculate_rating()` is called. Each event's delta is multiplied by a temporal decay factor based on event age:

```rust
// colmena-core/src/elo.rs:88-99
pub fn decay_factor(event_ts: DateTime<Utc>, now: DateTime<Utc>) -> f64 {
    let age = now - event_ts;
    if age < Duration::days(7) { 1.0 }
    else if age < Duration::days(30) { 0.7 }
    else if age < Duration::days(90) { 0.4 }
    else { 0.1 }
}
```

This means the same agent's ELO changes over time even without new events, as old events decay.

### JSONL Format

Each event is a single JSON line:

```json
{"ts":"2026-04-15T10:30:00Z","agent":"pentester","event":"reviewed","delta":9,"reason":"Score 10.0","mission":"mission-1","review_id":"r_1713178200000_a1b2"}
```

### 10MB Rotation

When the log exceeds 10MB, the current file is renamed to `.jsonl.1` (overwriting any previous rotation). The next append creates a fresh file. Source: `elo.rs:107-113`.

Consequence: after rotation, the agent's rating is recalculated from only the events in the new (empty) file. Old events are effectively forgotten. This is intentional — very old history should not dominate current trust decisions.

---

## 6. Regex Compilation

### Config Patterns (Compile Once)

`compile_config()` (`config.rs:127-139`) compiles all `bash_pattern` regex patterns from the YAML config into a `CompiledPatterns` HashMap keyed by rule identifier (e.g., `trust_circle[0]`). This happens once per hook invocation at config load time.

Invalid regex patterns log a warning but do not crash. The rule simply won't match, which is a safe fallback (the tool call falls through to a less permissive rule or defaults to Ask).

### YAML Single-Quote Escaping

YAML double-quoted strings interpret escape sequences. `"\b"` becomes a backspace character, not a regex word boundary. Always use single quotes:

```yaml
# CORRECT
bash_pattern: '^(cat|head|tail)\b'

# WRONG — \b becomes backspace, regex won't match word boundaries
bash_pattern: "^(cat|head|tail)\b"
```

This applies to `trust-firewall.yaml` and any role/pattern YAML with regex patterns.

### ELO Override Patterns (Compile at Evaluation Time)

ELO overrides are loaded from `elo-overrides.json`, not from the YAML config. Their regex patterns are not compiled by `compile_config()`. Instead, they are compiled inside `evaluate_with_elo()` at evaluation time:

```rust
// colmena-core/src/firewall.rs:71-79
let mut all_patterns = patterns.clone();
for (agent_id, rules) in elo_overrides {
    let tier = format!("elo_override:{agent_id}");
    let _ = crate::config::compile_rules(rules, &tier, &mut all_patterns);
}
```

Invalid regex in ELO overrides is silently skipped — the rule won't match, falling back to Ask.

---

## 7. Path Handling

### Component-Based Normalization

`normalize_path()` (`firewall.rs:334-347`) resolves `.` and `..` segments without filesystem access, preventing traversal like `/project/src/../../etc/passwd` → `/etc/passwd`. Does not call `canonicalize()` (which would follow symlinks and require filesystem access).

### path_within: Component-Based Comparison

Uses `Path::starts_with()` instead of `String::starts_with()`. This is a security fix: `String::starts_with("/project")` would match `/project-evil/file` (sibling directory bypass). `Path::starts_with()` compares components. Source: `firewall.rs:304-316`.

### Glob Matching on Filename Only

`glob_match()` (`firewall.rs:390-406`) extracts the last path component before matching. `*.env` matches `foo.env` but NOT `foo.env.production`. Three forms: `*.ext` (extension), `prefix*` (prefix), `*contains*` (substring).

### Path Extraction per Tool

Read/Write/Edit use `tool_input.file_path`. Glob/Grep use `tool_input.path`. WebFetch uses `tool_input.url`. Other tools: no path extracted (path conditions skipped). Source: `firewall.rs:350-369`.

### cwd Validation

Before `${PROJECT_DIR}` expansion, cwd is validated (`config.rs:73-87`). Requires >= 2 normal path components. Rejects `/` and `/tmp` to prevent `${PROJECT_DIR}` from matching the entire filesystem.

---

## 8. Queue Uniqueness

Queue entry filenames use millisecond timestamps + tool_use_id: `{timestamp_millis}-{tool_use_id}.json`. Source: `queue.rs:94`.

Queue entries truncate `tool_input` for storage:
- Bash `command` field: first 200 characters + `...`
- Write `content` field: replaced with `[REDACTED]`
- Other string values: first 200 characters

Source: `colmena-core/src/queue.rs:30-50`.

---

## 9. Edge Cases & Gotchas

### Shell Chain Guard False Positives

The chain guard (`firewall.rs:380-386`) checks for `&&`, `||`, `;`, `$(`, and backtick anywhere in the command string — including inside quoted strings. For example:

```bash
echo "a;b"   # Triggers ask (false positive — semicolon is inside quotes)
```

This is by design. The comment in the source code explicitly states: "false positives only result in an extra human confirmation, never in a security bypass."

Plain pipes (`|`) are intentionally excluded. `cat file | grep pattern` matches the trust_circle piped-commands rule without triggering the chain guard.

### Delegations Without expires_at Are Silently Skipped

If someone manually edits `runtime-delegations.json` and adds a delegation without an `expires_at` field, it is silently skipped with a warning to stderr (`delegate.rs:76-82`). This prevents permanent delegations via JSON injection.

### ELO Rating Drifts Over Time

Because ELO is calculated at read time with temporal decay, the same agent's rating changes over time even without new events. An agent that was Elevated (1600+) can drift to Standard or below as their events age. This is intentional — recent performance matters more than historical.

### Concurrent CC Instances Can Race on Delegations

Two CC instances running `colmena delegate add` simultaneously write to the same `runtime-delegations.json`. Despite atomic temp+rename, the second writer overwrites the first. The first delegation is lost. Mitigation: delegation writes are infrequent and human-visible.

### PermissionRequest Teaches ALL Role Tools at Once

When the first PermissionRequest fires for a role, it does not just approve the single requested tool. It teaches CC session rules for ALL tools in that role's `tools_allowed` list. Subsequent calls for any of those tools go through CC's learned rules without hitting the hook. Source: `main.rs:714-732`.

This is efficient but means a single PermissionRequest hook invocation has side effects on all future tool calls for that role in the session.

### Mission Revocation Overrides CC Session Rules

If CC has learned to auto-approve tools via PermissionRequest, and then the mission is deactivated via `colmena mission deactivate`, the PreToolUse hook blocks the agent at the mission revocation step (step 6 in the evaluation chain) — BEFORE CC checks its learned rules. Source: `firewall.rs:138-147`.

The mechanism: PreToolUse fires before CC applies session rules. If the agent_id is in `revoked-missions.json`, the hook returns `deny`, and CC never reaches its learned auto-approve.

### PostToolUse Only Filters Bash

Non-Bash tools (Read, Write, Edit, Glob, Grep) pass through without filtering (`main.rs:571-575`). The filter pipeline is designed specifically for command output. If you need filtering for other tool types, you would need to modify the PostToolUse dispatch logic.

### ELO Override Regex Compiled at Evaluation Time

Unlike YAML config patterns (compiled once at load), ELO override patterns are compiled on every `evaluate_with_elo()` call (`firewall.rs:71-79`). This is because they come from JSON, not the YAML config pipeline. Invalid regex silently fails — the override rule won't match.

### Watchdog Kills the Process

A background thread starts a 5-second timer when the hook begins (`main.rs:306-327`). If stdin doesn't close within 5 seconds, the process logs a TIMEOUT event to audit.log and calls `std::process::exit(0)`. This prevents CC from hanging indefinitely if something blocks stdin.

### Reviewer Selection Is Random

`submit_review()` uses `rand::seq::SliceRandom` to pick the reviewer from eligible candidates (`review.rs:112-113`). This prevents deterministic assignment patterns that could enable collusion between specific agent pairs.

---

## 10. Security Invariants

These values are hardcoded. Config can raise thresholds but never below these floors.

| Invariant | Value | Location | Rationale |
|-----------|-------|----------|-----------|
| Trust gate floor | 5.0 | `review.rs:17` | Scores below 5.0 always require human review, regardless of config threshold |
| Max review score | 10 | `review.rs:24` | Prevents ELO inflation via absurdly large scores |
| Min score dimensions | 2 | `review.rs:20` | At least 2 scores required per review |
| Max delegation TTL | 24h | `delegate.rs:10` | No long-lived trust delegations |
| Min agents per pattern | 3 | `pattern_scaffold.rs:96-106` | Always 2+ workers + auditor |
| Watchdog timeout | 5s | `main.rs:313` | Hook process killed if stdin doesn't close |
| Stdin size limit | 10MB | `main.rs:330` | Prevents OOM from oversized payloads |
| Log rotation size | 10MB | `audit.rs:170`, `elo.rs:102`, `stats.rs:32` | Prevents disk exhaustion |
| Findings hard cap | 5000 | `findings.rs` | Prevents OOM on load |
| Shell chain operators | `&&`, `\|\|`, `;`, `$(`, `` ` `` | `firewall.rs:380-386` | Cannot be configured away |

### Review Invariants

These are enforced in `review.rs:85-139` and cannot be bypassed:
- Author cannot review their own work (`author != reviewer`)
- No reciprocal reviews in the same mission
- Hash verification: the review artifact hash at submission must match at evaluation
- Minimum 2 score dimensions per evaluation

### Self-Protecting Config

The Write/Edit trust_circle rule in `trust-firewall.yaml:64` includes `path_not_match` exclusions for Colmena's own config files:

```yaml
path_not_match: ['*trust-firewall*', '*runtime-delegations*', '*elo-*',
                 '*audit.log*', '*filter-config*', '*filter-stats*',
                 '*settings.json', '*revoked-missions*', '*alerts*']
```

An agent auto-approved for Write within the project directory cannot modify these files. If you add a new config file, add its pattern to this list.

### MCP Delegate Tools Are Read-Only by Design

`delegate`, `delegate_revoke`, and `mission_deactivate` MCP tools return CLI commands as strings. They never execute the commands. This is a deliberate security decision — agents cannot create or revoke delegations directly. A human must copy and run the command.

Arguments are escaped via `safe_cli_arg()` (`colmena-mcp/src/main.rs:19-25`) which single-quotes any argument containing special characters, preventing command injection.

---

## 11. Things That Will Bite You

### 1. Two Binaries, One Core

`colmena` and `colmena-mcp` are separate processes that share `colmena-core`. They read the same config files but have no inter-process communication. A delegation created by the CLI is visible to the MCP server on its next tool call (because both read `runtime-delegations.json`), but there is no notification mechanism.

### 2. Hook Path Is Synchronous

The CLI hook handler is synchronous. Only the MCP server uses tokio. The hook must complete in <100ms. Do not add network calls, heavy computation, or async to the hook path.

### 3. Binary Is Self-Contained

`colmena setup` does not download anything. All default files (YAML config, role definitions, prompt files) are compiled into the binary via `include_str!()` in `colmena-cli/src/defaults.rs`. If you add a new config file, you must embed it there for `setup` to install it.

### 4. path_within Is Not String Prefix

`Path::starts_with()` is component-aware. `/project` does NOT match `/project-evil/file`. If you change path comparison to string-based, you create a sibling-directory bypass vulnerability.

### 5. Action Enum Is Kebab-Case

In YAML and JSON: `auto-approve`, not `autoApprove`. If you add a new variant to `Action`, the serde rename attribute `#[serde(rename_all = "kebab-case")]` applies automatically. But remember that the hook JSON protocol uses `allow`/`deny`/`ask` (different values) for `permissionDecision`.

### 6. Finding Severity Is a Closed Enum

Only `"critical"`, `"high"`, `"medium"`, `"low"` are accepted. Anything else is rejected at validation. Source: `findings.rs:9-10`. If you need a new severity level, you must update the validation logic.

### 7. CC Hook JSON Field Names

The CC hook protocol uses camelCase (`hookEventName`, `permissionDecision`, `updatedMCPToolOutput`). Colmena's internal types use snake_case. The translation is handled by serde rename attributes in `hook.rs`. If you add a new field, match CC's naming convention with `#[serde(rename = "camelCase")]`.

### 8. PostToolUse Field Name Mismatch

CC sends `tool_response` (not `tool_output`) and `interrupted` (not `exitCode`). This mismatch was discovered during integration testing. If CC changes its protocol, `hook.rs` deserialization will break silently (fields become None).

### 9. Config File Permissions

On Unix, config loading checks for world-writable files and logs a warning. If critical config files (`trust-firewall.yaml`, `runtime-delegations.json`) are world-writable, the system still works but the warning indicates a security risk — any user could modify firewall rules.

### 10. Auditor Role Exemption

The auditor role has `role_type: auditor` in its YAML. This is the only mechanism that exempts a role from the SubagentStop review check. If you create a new role that should be exempt, add `role_type: auditor` to its YAML. There is no other exemption mechanism.

---

## See Also

- [Architecture](architecture.md) -- system overview, data flows, trust model, MCP internals
- [Contributing](contributing.md) -- dev setup, how to add rules/tools/roles, PR workflow
- [Getting Started](../user/getting-started.md) -- user-facing setup guide
