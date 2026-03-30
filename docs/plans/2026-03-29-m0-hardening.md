# M0 Hardening — Dark Corners Fix Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the 5 critical and 5 high-priority issues from `docs/dark-corners.md` so Colmena M0 is production-safe and shareable on GitHub.

**Architecture:** All fixes are surgical edits to existing modules. No new modules needed. The main structural change is adding a `CompiledRule` wrapper around `Rule` that caches compiled regexes at config load time. All path comparisons switch from string prefix to canonicalized `PathBuf` comparison.

**Tech Stack:** Rust, existing deps. No new crates needed — we already have `regex`, `anyhow`, `chrono`.

**Dark corners doc:** `docs/dark-corners.md`

---

### Task 1: Fix path traversal in `firewall.rs`

Path-based conditions use string prefix matching (`p.starts_with(dir)`), which is vulnerable to `../../` traversal. Fix by normalizing paths before comparison.

**Files:**
- Modify: `src/firewall.rs:125-174` (conditions_match, extract_path)
- Test: `src/firewall.rs` (inline tests)

- [ ] **Step 1: Write failing test for path traversal**

Add to `src/firewall.rs` test module:

```rust
#[test]
fn test_path_traversal_blocked() {
    let config = load_test_config();
    // Attempt to escape project dir with ../
    let payload = make_payload(
        "Write",
        json!({"file_path": "/Users/test/project/src/../../etc/passwd"}),
    );
    let decision = evaluate(&config, &[], &payload);
    // Should NOT be auto-approved — path escapes project dir
    assert_eq!(decision.action, Action::Ask);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test test_path_traversal_blocked -- --nocapture`
Expected: FAIL — currently returns `AutoApprove` because string starts with `/Users/test/project`

- [ ] **Step 3: Implement path normalization**

Add a `normalize_path` function and use it in `conditions_match`:

```rust
/// Normalize a path by resolving `.` and `..` segments without touching the filesystem.
/// This is needed because paths in hook payloads may not exist yet (e.g., Write to new file).
fn normalize_path(path: &str) -> String {
    use std::path::{Component, PathBuf};
    let mut normalized = PathBuf::new();
    for component in std::path::Path::new(path).components() {
        match component {
            Component::ParentDir => {
                normalized.pop();
            }
            Component::CurDir => {}
            other => normalized.push(other),
        }
    }
    normalized.to_string_lossy().to_string()
}
```

Then in `conditions_match`, wrap the extracted path:

```rust
let path = extract_path(payload).map(|p| normalize_path(&p));
```

- [ ] **Step 4: Run tests to verify fix + no regressions**

Run: `cargo test`
Expected: ALL pass including `test_path_traversal_blocked`

- [ ] **Step 5: Commit**

```bash
git add src/firewall.rs
git commit -m "fix: normalize paths to prevent ../ traversal bypass in path_within"
```

---

### Task 2: Fix glob matching in `firewall.rs`

The hand-rolled `glob_match` uses `ends_with` which causes false positives: `*.env` matches `.env.production`. Replace with proper filename-based matching.

**Files:**
- Modify: `src/firewall.rs:198-215` (glob_match)
- Test: `src/firewall.rs` (inline tests)

- [ ] **Step 1: Write failing tests for glob edge cases**

Add to `src/firewall.rs` test module:

```rust
#[test]
fn test_glob_match_exact_extension() {
    // *.env should match files ending in exactly ".env"
    assert!(glob_match("*.env", "/project/.env"));
    assert!(glob_match("*.env", "/project/local.env"));
    // Should NOT match files where .env is a prefix of the extension
    assert!(!glob_match("*.env", "/project/.env.production"));
    assert!(!glob_match("*.env", "/project/.env.backup"));
}

#[test]
fn test_glob_match_contains() {
    // *credentials* should match anywhere in filename
    assert!(glob_match("*credentials*", "/project/credentials.json"));
    assert!(glob_match("*credentials*", "/project/aws_credentials"));
    assert!(glob_match("*credentials*", "/project/my-credentials-file.txt"));
}

#[test]
fn test_glob_match_exact_filename() {
    // *.key should match .key extension
    assert!(glob_match("*.key", "/project/server.key"));
    assert!(!glob_match("*.key", "/project/server.keystore"));
}

#[test]
fn test_path_not_match_env_production() {
    let config = load_test_config();
    // .env.production should NOT be blocked — it doesn't end in exactly ".env"
    let payload = make_payload(
        "Write",
        json!({"file_path": "/Users/test/project/.env.production"}),
    );
    let decision = evaluate(&config, &[], &payload);
    // The *.env pattern should NOT match .env.production
    assert_eq!(decision.action, Action::AutoApprove);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test test_glob_match_exact -- --nocapture`
Expected: FAIL — `*.env` currently matches `.env.production`

- [ ] **Step 3: Rewrite glob_match with proper semantics**

Replace the `glob_match` function. The key insight: `*.env` should match the **filename** (last path component), and `*` matches any chars except nothing when at edges of the literal part.

```rust
/// Glob matching against the filename (last path component).
/// Supports: `*.ext` (extension match), `prefix*` (prefix match), `*contains*` (substring in filename).
fn glob_match(pattern: &str, value: &str) -> bool {
    // Extract just the filename for matching
    let filename = std::path::Path::new(value)
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or(value);

    if pattern.starts_with('*') && pattern.ends_with('*') && pattern.len() > 2 {
        // *contains* pattern — match substring in filename
        let needle = &pattern[1..pattern.len() - 1];
        filename.contains(needle)
    } else if pattern.starts_with('*') {
        // *suffix pattern — match end of filename
        let suffix = &pattern[1..];
        filename.ends_with(suffix)
    } else if pattern.ends_with('*') {
        // prefix* pattern — match start of filename
        let prefix = &pattern[..pattern.len() - 1];
        filename.starts_with(prefix)
    } else {
        // exact match on filename
        filename == pattern
    }
}
```

- [ ] **Step 4: Run all tests**

Run: `cargo test`
Expected: ALL pass

- [ ] **Step 5: Commit**

```bash
git add src/firewall.rs
git commit -m "fix: glob matching operates on filename, prevents false positives like .env.production"
```

---

### Task 3: Compile regexes at config load time

Regexes are compiled on every `evaluate()` call. Invalid patterns silently make rules inert. Fix by compiling at config load time — fail loudly with helpful errors, and cache for performance.

**Files:**
- Modify: `src/config.rs` (add `CompiledConfig` struct, `compile_config` fn)
- Modify: `src/firewall.rs` (use `CompiledConfig` instead of raw strings)
- Modify: `src/main.rs` (call `compile_config` after `load_config`)
- Test: `src/config.rs`, `src/firewall.rs`

- [ ] **Step 1: Write failing test for invalid regex detection**

Add to `src/config.rs` test module:

```rust
#[test]
fn test_compile_config_rejects_bad_regex() {
    let mut config = FirewallConfig {
        version: 1,
        defaults: Defaults { action: Action::Ask },
        trust_circle: vec![],
        restricted: vec![],
        blocked: vec![Rule {
            tools: vec!["Bash".to_string()],
            conditions: Some(Conditions {
                bash_pattern: Some("(?P<broken>".to_string()),
                path_within: None,
                path_not_match: None,
            }),
            action: Action::Block,
            reason: Some("test".to_string()),
        }],
        agent_overrides: HashMap::new(),
        notifications: None,
    };
    let result = compile_config(&mut config);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("blocked[0]"));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test test_compile_config_rejects_bad_regex`
Expected: FAIL — `compile_config` doesn't exist yet

- [ ] **Step 3: Add compiled regex storage to config.rs**

Add a `compiled_patterns` field and a `compile_config` function:

```rust
use regex::Regex;

/// Pre-compiled regex patterns for all rules. Keyed by "{tier}[{index}]".
pub type CompiledPatterns = HashMap<String, Regex>;

/// Compile and validate all regex patterns in the config.
/// Returns an error if any pattern is invalid, naming the exact rule.
pub fn compile_config(config: &FirewallConfig) -> Result<CompiledPatterns> {
    let mut patterns = HashMap::new();

    let compile_rules = |rules: &[Rule], tier: &str, patterns: &mut CompiledPatterns| -> Result<()> {
        for (i, rule) in rules.iter().enumerate() {
            if let Some(ref cond) = rule.conditions {
                if let Some(ref pat) = cond.bash_pattern {
                    let compiled = Regex::new(pat)
                        .with_context(|| format!("Invalid regex in {tier}[{i}]: {pat}"))?;
                    patterns.insert(format!("{tier}[{i}]"), compiled);
                }
            }
        }
        Ok(())
    };

    compile_rules(&config.blocked, "blocked", &mut patterns)?;
    compile_rules(&config.restricted, "restricted", &mut patterns)?;
    compile_rules(&config.trust_circle, "trust_circle", &mut patterns)?;

    for (agent_id, rules) in &config.agent_overrides {
        compile_rules(rules, &format!("agent_override:{agent_id}"), &mut patterns)?;
    }

    Ok(patterns)
}
```

- [ ] **Step 4: Update firewall.rs to use pre-compiled patterns**

Change `evaluate` signature to accept `&CompiledPatterns`:

```rust
pub fn evaluate(
    config: &FirewallConfig,
    patterns: &CompiledPatterns,
    delegations: &[RuntimeDelegation],
    payload: &HookPayload,
) -> Decision {
```

Change `check_rules` to accept and pass through patterns. In `conditions_match`, replace `Regex::new(pattern)` with a lookup:

```rust
fn conditions_match(conditions: &Conditions, payload: &HookPayload, rule_key: &str, patterns: &CompiledPatterns) -> bool {
    if let Some(ref _pattern) = conditions.bash_pattern {
        if payload.tool_name == "Bash" {
            let command = payload.tool_input.get("command").and_then(|v| v.as_str()).unwrap_or("");
            if let Some(re) = patterns.get(rule_key) {
                if !re.is_match(command) {
                    return false;
                }
            } else {
                return false; // pattern was supposed to be compiled but wasn't found
            }
        }
    }
    // ... rest unchanged
}
```

- [ ] **Step 5: Update main.rs to compile patterns**

In `run_hook`:
```rust
let cfg = config::load_config(&config_file, &payload.cwd)?;
let patterns = config::compile_config(&cfg)?;
// ...
let decision = firewall::evaluate(&cfg, &patterns, &delegations, &payload);
```

In `run_config_check`, replace the inline regex validation with `compile_config`:
```rust
match config::compile_config(&cfg) {
    Ok(_) => println!("\nConfig is valid."),
    Err(e) => {
        eprintln!("  ERROR: {e}");
        std::process::exit(1);
    }
}
```

- [ ] **Step 6: Update all tests for new evaluate signature**

Every call to `evaluate` and `check_rules` in tests needs `&patterns`. Load test patterns via:
```rust
fn load_test_config_and_patterns() -> (FirewallConfig, CompiledPatterns) {
    let config_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("config/trust-firewall.yaml");
    let config = load_config(&config_path, "/Users/test/project").unwrap();
    let patterns = compile_config(&config).unwrap();
    (config, patterns)
}
```

- [ ] **Step 7: Run all tests**

Run: `cargo test`
Expected: ALL pass

- [ ] **Step 8: Commit**

```bash
git add src/config.rs src/firewall.rs src/main.rs
git commit -m "fix: compile regexes at config load time, fail loudly on invalid patterns"
```

---

### Task 4: Introduce COLMENA_HOME for portable paths

Binary, config, and queue paths are hardcoded to `~/colmena`. Replace with auto-detection based on the actual binary location, with `COLMENA_HOME` env override.

**Files:**
- Modify: `src/main.rs:278-287` (default_config_dir, dirs_or_home)
- Modify: `src/install.rs:86-99` (settings_json_path, colmena_binary_path, colmena_config_path)
- Test: `tests/integration.rs`

- [ ] **Step 1: Write failing test**

Add to `tests/integration.rs`:

```rust
#[test]
fn test_hook_respects_colmena_home() {
    let tmp = tempfile::TempDir::new().unwrap();
    let config_dir = tmp.path().join("config");
    std::fs::create_dir_all(config_dir.join("queue/pending")).unwrap();

    // Copy trust-firewall.yaml to temp dir
    std::fs::copy(
        &config_path(),
        config_dir.join("trust-firewall.yaml"),
    ).unwrap();

    let payload = make_payload("Read", json!({"file_path": "/tmp/foo.txt"}));
    let input = serde_json::to_string(&payload).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_colmena"))
        .args(["hook"])
        .env("COLMENA_HOME", tmp.path())
        .env("HOME", "/tmp/colmena-test-home")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child.stdin.take().unwrap().write_all(input.as_bytes()).unwrap();
            child.wait_with_output()
        })
        .unwrap();

    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let resp: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(resp["hookSpecificOutput"]["permissionDecision"], "allow");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test test_hook_respects_colmena_home`
Expected: FAIL — `COLMENA_HOME` not recognized, falls back to `~/colmena/config`

- [ ] **Step 3: Replace hardcoded paths in main.rs**

Replace `default_config_dir` and `dirs_or_home`:

```rust
/// Resolve the colmena home directory.
/// Priority: COLMENA_HOME env > directory containing the running binary > ~/colmena fallback
fn colmena_home() -> PathBuf {
    if let Ok(home) = std::env::var("COLMENA_HOME") {
        return PathBuf::from(home);
    }
    if let Ok(exe) = std::env::current_exe() {
        // Binary is at <colmena_home>/target/{release,debug}/colmena
        if let Some(target_dir) = exe.parent() {
            if let Some(target) = target_dir.parent() {
                if let Some(project_root) = target.parent() {
                    if project_root.join("config/trust-firewall.yaml").exists() {
                        return project_root.to_path_buf();
                    }
                }
            }
        }
    }
    // Fallback
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    PathBuf::from(home).join("colmena")
}

fn default_config_dir() -> PathBuf {
    colmena_home().join("config")
}
```

- [ ] **Step 4: Update install.rs to use colmena_home**

Replace `colmena_binary_path` and `colmena_config_path`:

```rust
fn colmena_binary_path() -> String {
    // Use current exe path — install should be run from the built binary
    std::env::current_exe()
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            PathBuf::from(format!("{home}/colmena/target/release/colmena"))
        })
        .to_string_lossy()
        .to_string()
}

fn colmena_config_path() -> String {
    // Derive from binary location
    let exe = std::env::current_exe().unwrap_or_default();
    if let Some(target_dir) = exe.parent() {
        if let Some(target) = target_dir.parent() {
            if let Some(project_root) = target.parent() {
                let config = project_root.join("config/trust-firewall.yaml");
                if config.exists() {
                    return config.to_string_lossy().to_string();
                }
            }
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    format!("{home}/colmena/config/trust-firewall.yaml")
}
```

- [ ] **Step 5: Run all tests**

Run: `cargo test`
Expected: ALL pass

- [ ] **Step 6: Commit**

```bash
git add src/main.rs src/install.rs tests/integration.rs
git commit -m "fix: auto-detect project root, support COLMENA_HOME env for portable paths"
```

---

### Task 5: Atomic file writes for delegations

The delegation read-modify-write cycle has a race condition with concurrent CC instances. Fix by writing to a temp file then renaming atomically.

**Files:**
- Modify: `src/main.rs:192-231` (run_delegate)
- Modify: `src/delegate.rs` (add save_delegations fn)
- Test: `src/delegate.rs`

- [ ] **Step 1: Write a save_delegations function with atomic write**

Add to `src/delegate.rs`:

```rust
/// Save delegations atomically — write to temp file then rename.
pub fn save_delegations(path: &Path, delegations: &[RuntimeDelegation]) -> Result<()> {
    let json = serde_json::to_string_pretty(delegations)
        .context("Failed to serialize delegations")?;

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp_path = dir.join(".runtime-delegations.tmp");

    std::fs::write(&tmp_path, &json)
        .with_context(|| format!("Failed to write temp delegations file: {}", tmp_path.display()))?;

    std::fs::rename(&tmp_path, path)
        .with_context(|| format!("Failed to rename temp delegations file to {}", path.display()))?;

    Ok(())
}
```

- [ ] **Step 2: Write test for save_delegations**

```rust
#[test]
fn test_save_and_reload_delegations() {
    let tmp = tempfile::TempDir::new().unwrap();
    let path = tmp.path().join("delegations.json");

    let delegations = vec![RuntimeDelegation {
        tool: "Bash".to_string(),
        agent_id: None,
        action: Action::AutoApprove,
        created_at: Utc::now(),
        expires_at: Some(Utc::now() + Duration::hours(4)),
        session_id: None,
    }];

    save_delegations(&path, &delegations).unwrap();
    let reloaded = load_delegations(&path);
    assert_eq!(reloaded.len(), 1);
    assert_eq!(reloaded[0].tool, "Bash");
}
```

- [ ] **Step 3: Update main.rs run_delegate to use save_delegations**

Replace `std::fs::write(&delegations_path, json)?;` with:

```rust
delegate::save_delegations(&delegations_path, &delegations)?;
```

- [ ] **Step 4: Run all tests**

Run: `cargo test`
Expected: ALL pass

- [ ] **Step 5: Commit**

```bash
git add src/delegate.rs src/main.rs
git commit -m "fix: atomic file writes for runtime-delegations.json to prevent race conditions"
```

---

### Task 6: Error logging to file

All hook failures produce a generic `ask` fallback with the error as a reason string that CC may not surface. Add a log file so failures are discoverable.

**Files:**
- Modify: `src/main.rs:95-101` (error handler)
- Create: logging helper (inline in main.rs, no new module)
- Test: `tests/integration.rs`

- [ ] **Step 1: Add log_error helper to main.rs**

```rust
/// Best-effort append to colmena error log. Never panics.
fn log_error(msg: &str) {
    let log_path = colmena_home().join("colmena-errors.log");
    let timestamp = chrono::Utc::now().to_rfc3339();
    let line = format!("[{timestamp}] {msg}\n");
    // Append, don't truncate — ignore errors (we're already in error handling)
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .and_then(|mut f| {
            use std::io::Write;
            f.write_all(line.as_bytes())
        });
}
```

- [ ] **Step 2: Call log_error in the main error handler**

```rust
if let Err(e) = result {
    log_error(&format!("Hook error: {e:#}"));
    let fallback = hook::HookResponse::ask(format!("Colmena error: {e}"));
    let _ = serde_json::to_writer(std::io::stdout(), &fallback);
    std::process::exit(0);
}
```

- [ ] **Step 3: Also log queue write failures in run_hook**

Replace `let _ = queue::enqueue_pending(...)` with:

```rust
if let Err(e) = queue::enqueue_pending(config_dir, &payload, &decision) {
    log_error(&format!("Queue write failed: {e:#}"));
}
```

- [ ] **Step 4: Add colmena-errors.log to .gitignore**

Append to `.gitignore`:
```
/colmena-errors.log
```

- [ ] **Step 5: Run all tests**

Run: `cargo test`
Expected: ALL pass

- [ ] **Step 6: Commit**

```bash
git add src/main.rs .gitignore
git commit -m "fix: log hook errors to colmena-errors.log for debuggability"
```

---

### Task 7: Validate tool names in config and delegations

Typos in tool names silently create dead rules. Add validation of known tool names at config load time and delegation creation time.

**Files:**
- Modify: `src/config.rs` (add `validate_tool_names`, known tools list)
- Modify: `src/main.rs` (validate on delegate)
- Test: `src/config.rs`

- [ ] **Step 1: Write failing test for unknown tool warning**

Add to `src/config.rs` test module:

```rust
#[test]
fn test_validate_tool_names_catches_typos() {
    let config = FirewallConfig {
        version: 1,
        defaults: Defaults { action: Action::Ask },
        trust_circle: vec![Rule {
            tools: vec!["Raed".to_string()], // typo
            conditions: None,
            action: Action::AutoApprove,
            reason: None,
        }],
        restricted: vec![],
        blocked: vec![],
        agent_overrides: HashMap::new(),
        notifications: None,
    };
    let warnings = validate_tool_names(&config);
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("Raed"));
}

#[test]
fn test_validate_tool_names_accepts_known() {
    let config = FirewallConfig {
        version: 1,
        defaults: Defaults { action: Action::Ask },
        trust_circle: vec![Rule {
            tools: vec!["Read".to_string(), "Write".to_string(), "Bash".to_string()],
            conditions: None,
            action: Action::AutoApprove,
            reason: None,
        }],
        restricted: vec![],
        blocked: vec![],
        agent_overrides: HashMap::new(),
        notifications: None,
    };
    let warnings = validate_tool_names(&config);
    assert!(warnings.is_empty());
}

#[test]
fn test_validate_tool_names_allows_mcp_prefix() {
    let config = FirewallConfig {
        version: 1,
        defaults: Defaults { action: Action::Ask },
        trust_circle: vec![],
        restricted: vec![Rule {
            tools: vec!["mcp__claude_ai_Slack__slack_send_message".to_string()],
            conditions: None,
            action: Action::Ask,
            reason: None,
        }],
        blocked: vec![],
        agent_overrides: HashMap::new(),
        notifications: None,
    };
    let warnings = validate_tool_names(&config);
    assert!(warnings.is_empty());
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test test_validate_tool_names`
Expected: FAIL — function doesn't exist

- [ ] **Step 3: Implement validate_tool_names**

Add to `src/config.rs`:

```rust
/// Known Claude Code tool names. MCP tools (mcp__*) are always valid.
const KNOWN_TOOLS: &[&str] = &[
    "Agent", "Bash", "Edit", "Glob", "Grep", "Read", "Write",
    "WebFetch", "WebSearch", "NotebookEdit",
    "AskUserQuestion", "EnterPlanMode", "ExitPlanMode",
    "TaskCreate", "TaskUpdate", "SendMessage",
];

/// Check all tool names in the config against known tools.
/// Returns a list of warnings for unrecognized tool names.
/// MCP tools (prefixed with `mcp__`) are always accepted.
pub fn validate_tool_names(config: &FirewallConfig) -> Vec<String> {
    let mut warnings = Vec::new();

    let check_rules = |rules: &[Rule], tier: &str, warnings: &mut Vec<String>| {
        for (i, rule) in rules.iter().enumerate() {
            for tool in &rule.tools {
                if !tool.starts_with("mcp__") && !KNOWN_TOOLS.contains(&tool.as_str()) {
                    warnings.push(format!(
                        "Unknown tool '{}' in {tier}[{i}] — did you mean one of: {:?}?",
                        tool, KNOWN_TOOLS
                    ));
                }
            }
        }
    };

    check_rules(&config.trust_circle, "trust_circle", &mut warnings);
    check_rules(&config.restricted, "restricted", &mut warnings);
    check_rules(&config.blocked, "blocked", &mut warnings);
    for (agent_id, rules) in &config.agent_overrides {
        check_rules(rules, &format!("agent_override:{agent_id}"), &mut warnings);
    }

    warnings
}
```

- [ ] **Step 4: Surface warnings in config check and hook path**

In `main.rs` `run_config_check`, after compile_config:
```rust
let warnings = config::validate_tool_names(&cfg);
for w in &warnings {
    eprintln!("  WARNING: {w}");
}
```

In `main.rs` `run_hook`, after load_config (log warnings, don't fail):
```rust
let warnings = config::validate_tool_names(&cfg);
for w in &warnings {
    log_error(&format!("Config warning: {w}"));
}
```

In `main.rs` `run_delegate`, validate the tool:
```rust
let warnings = config::validate_tool_names_single(&tool);
for w in &warnings {
    eprintln!("WARNING: {w}");
}
```

Add the single-tool validator in config.rs:
```rust
pub fn validate_tool_names_single(tool: &str) -> Vec<String> {
    if !tool.starts_with("mcp__") && !KNOWN_TOOLS.contains(&tool) {
        vec![format!("Unknown tool '{}' — known tools: {:?}", tool, KNOWN_TOOLS)]
    } else {
        vec![]
    }
}
```

- [ ] **Step 5: Run all tests**

Run: `cargo test`
Expected: ALL pass

- [ ] **Step 6: Commit**

```bash
git add src/config.rs src/main.rs
git commit -m "fix: validate tool names in config and delegations, warn on typos"
```

---

### Task 8: Install command verification

`colmena install` declares success without checking that the hook actually works. Add a dry-run verification.

**Files:**
- Modify: `src/install.rs` (add verify step)
- Test: `tests/integration.rs`

- [ ] **Step 1: Add verification to install.rs**

After the "Hook installed successfully" message, add:

```rust
// Verify the binary exists and is executable
let binary = colmena_binary_path();
let binary_path = std::path::Path::new(&binary);
if !binary_path.exists() {
    eprintln!("WARNING: Binary not found at {binary}");
    eprintln!("  Run `cargo build --release` before using the hook.");
} else {
    // Dry-run with a test payload
    let test_payload = r#"{"session_id":"verify","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"/tmp/test"},"tool_use_id":"verify","cwd":"/tmp"}"#;
    let config = colmena_config_path();
    match std::process::Command::new(&binary)
        .args(["hook", "--config", &config])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write as _;
            child.stdin.take().unwrap().write_all(test_payload.as_bytes()).unwrap();
            child.wait_with_output()
        }) {
        Ok(output) if output.status.success() => {
            println!("  Verification: hook dry-run passed.");
        }
        Ok(output) => {
            eprintln!("WARNING: Hook dry-run failed (exit {}).", output.status.code().unwrap_or(-1));
        }
        Err(e) => {
            eprintln!("WARNING: Could not run hook verification: {e}");
        }
    }
}
```

- [ ] **Step 2: Also fix the already-installed check to use exact path**

Replace:
```rust
let already_installed = arr.iter().any(|entry| {
    entry.get("command").and_then(|c| c.as_str())
        .map_or(false, |c| c.contains("colmena"))
});
```

With:
```rust
let already_installed = arr.iter().any(|entry| {
    entry.get("command").and_then(|c| c.as_str())
        .map_or(false, |c| c.contains(&hook_command) || c.contains("colmena hook"))
});
```

- [ ] **Step 3: Run all tests**

Run: `cargo test`
Expected: ALL pass

- [ ] **Step 4: Commit**

```bash
git add src/install.rs
git commit -m "fix: verify hook works after install, exact match for already-installed check"
```

---

### Task 9: Integration tests for new behaviors

Add integration tests covering the new dark-corner fixes: path traversal, glob matching, error logging, COLMENA_HOME.

**Files:**
- Modify: `tests/integration.rs`

- [ ] **Step 1: Add path traversal integration test**

```rust
#[test]
fn test_hook_blocks_path_traversal_write() {
    let payload = make_payload(
        "Write",
        json!({"file_path": format!("{}/src/../../etc/passwd", env!("CARGO_MANIFEST_DIR"))}),
    );
    let (stdout, code) = colmena_hook(&payload, &config_path());
    assert_eq!(code, 0);
    let resp: Value = serde_json::from_str(&stdout).unwrap();
    // Path escapes project dir -> should NOT be auto-approved
    assert_eq!(resp["hookSpecificOutput"]["permissionDecision"], "ask");
}
```

- [ ] **Step 2: Add .env.production glob test**

```rust
#[test]
fn test_hook_allows_env_production_write() {
    let payload = make_payload(
        "Write",
        json!({"file_path": format!("{}/.env.production", env!("CARGO_MANIFEST_DIR"))}),
    );
    let (stdout, code) = colmena_hook(&payload, &config_path());
    assert_eq!(code, 0);
    let resp: Value = serde_json::from_str(&stdout).unwrap();
    // .env.production should NOT be caught by *.env pattern
    assert_eq!(resp["hookSpecificOutput"]["permissionDecision"], "allow");
}
```

- [ ] **Step 3: Add invalid config test**

```rust
#[test]
fn test_config_check_invalid_regex() {
    let tmp = tempfile::TempDir::new().unwrap();
    let bad_config = tmp.path().join("bad.yaml");
    std::fs::write(&bad_config, r#"
version: 1
defaults:
  action: ask
trust_circle: []
restricted: []
blocked:
  - tools: [Bash]
    conditions:
      bash_pattern: '(?P<broken>'
    action: block
agent_overrides: {}
"#).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_colmena"))
        .args(["config", "check", "--config", bad_config.to_str().unwrap()])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Invalid regex") || stderr.contains("ERROR"));
}
```

- [ ] **Step 4: Run all tests**

Run: `cargo test`
Expected: ALL pass

- [ ] **Step 5: Commit**

```bash
git add tests/integration.rs
git commit -m "test: add integration tests for path traversal, glob fixes, config validation"
```

---

### Task 10: Final verification + release build

Run full test suite, build release binary, run smoke tests.

- [ ] **Step 1: Run full test suite**

```bash
cargo test
```

Expected: ALL pass (should be 40+ tests)

- [ ] **Step 2: Run clippy**

```bash
cargo clippy -- -W warnings
```

Fix any warnings.

- [ ] **Step 3: Build release**

```bash
cargo build --release
```

- [ ] **Step 4: Smoke tests with release binary**

```bash
# Auto-approve read
echo '{"session_id":"smoke","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"/tmp/foo"},"tool_use_id":"tu1","cwd":"/tmp"}' | ./target/release/colmena hook --config config/trust-firewall.yaml

# Block force push
echo '{"session_id":"smoke","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git push --force origin main"},"tool_use_id":"tu2","cwd":"/tmp"}' | ./target/release/colmena hook --config config/trust-firewall.yaml

# Path traversal → ask
echo '{"session_id":"smoke","hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"/Users/fr33m4n/colmena/src/../../etc/passwd"},"tool_use_id":"tu3","cwd":"/Users/fr33m4n/colmena"}' | ./target/release/colmena hook --config config/trust-firewall.yaml

# Config check
./target/release/colmena config check --config config/trust-firewall.yaml
```

- [ ] **Step 5: Final commit**

```bash
git add -A
git commit -m "chore: M0 hardening complete — all dark corners addressed"
```
