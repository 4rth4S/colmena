use std::process::Command;

use serde_json::{json, Value};

fn colmena_hook(payload: &Value, config_path: &str) -> (String, i32) {
    let input = serde_json::to_string(payload).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_colmena"))
        .args(["hook", "--config", config_path])
        .env("HOME", "/tmp/colmena-test-home")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .take()
                .unwrap()
                .write_all(input.as_bytes())
                .unwrap();
            child.wait_with_output()
        })
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let code = output.status.code().unwrap_or(-1);
    (stdout, code)
}

fn workspace_root() -> String {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest.parent().unwrap().to_string_lossy().to_string()
}

fn config_path() -> String {
    format!("{}/config/trust-firewall.yaml", workspace_root())
}

fn make_payload(tool: &str, tool_input: Value) -> Value {
    json!({
        "session_id": "integration-test",
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": tool_input,
        "tool_use_id": "tu_integration",
        "cwd": workspace_root()
    })
}

#[test]
fn test_hook_auto_approve_read() {
    let payload = make_payload(
        "Read",
        json!({"file_path": format!("{}/colmena-core/src/lib.rs", workspace_root())}),
    );
    let (stdout, code) = colmena_hook(&payload, &config_path());

    assert_eq!(code, 0, "Exit code should be 0");
    let resp: Value = serde_json::from_str(&stdout).expect("Should return valid JSON");
    assert_eq!(resp["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn test_hook_auto_approve_safe_bash() {
    let payload = make_payload("Bash", json!({"command": "git status"}));
    let (stdout, code) = colmena_hook(&payload, &config_path());

    assert_eq!(code, 0);
    let resp: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(resp["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn test_hook_block_force_push() {
    let payload = make_payload("Bash", json!({"command": "git push --force origin main"}));
    let (stdout, code) = colmena_hook(&payload, &config_path());

    assert_eq!(code, 0);
    let resp: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(resp["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn test_hook_block_force_push_short_flag() {
    let payload = make_payload("Bash", json!({"command": "git push -f origin main"}));
    let (stdout, code) = colmena_hook(&payload, &config_path());

    assert_eq!(code, 0);
    let resp: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(resp["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn test_hook_block_reset_hard() {
    let payload = make_payload("Bash", json!({"command": "git reset --hard HEAD~1"}));
    let (stdout, code) = colmena_hook(&payload, &config_path());

    assert_eq!(code, 0);
    let resp: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(resp["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn test_hook_commit_message_with_force_not_blocked() {
    let payload = make_payload("Bash", json!({"command": "git commit -m 'removed --force flag'"}));
    let (stdout, code) = colmena_hook(&payload, &config_path());

    assert_eq!(code, 0);
    let resp: Value = serde_json::from_str(&stdout).unwrap();
    // --force inside a commit message should NOT trigger blocked rule
    assert_ne!(resp["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn test_hook_ask_unknown_tool() {
    let payload = make_payload("mcp__unknown__tool", json!({"arg": "value"}));
    let (stdout, code) = colmena_hook(&payload, &config_path());

    assert_eq!(code, 0);
    let resp: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(resp["hookSpecificOutput"]["permissionDecision"], "ask");
}

#[test]
fn test_hook_ask_restricted_bash() {
    let payload = make_payload("Bash", json!({"command": "rm -r /tmp/somedir"}));
    let (stdout, code) = colmena_hook(&payload, &config_path());

    assert_eq!(code, 0);
    let resp: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(resp["hookSpecificOutput"]["permissionDecision"], "ask");
}

#[test]
fn test_hook_auto_approve_web_search() {
    let payload = make_payload("WebSearch", json!({"query": "rust serde tutorial"}));
    let (stdout, code) = colmena_hook(&payload, &config_path());

    assert_eq!(code, 0);
    let resp: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(resp["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn test_hook_auto_approve_project_write() {
    let payload = make_payload(
        "Write",
        json!({"file_path": format!("{}/colmena-core/src/test_output.rs", workspace_root())}),
    );
    let (stdout, code) = colmena_hook(&payload, &config_path());

    assert_eq!(code, 0);
    let resp: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(resp["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn test_hook_ask_env_file_write() {
    let payload = make_payload(
        "Write",
        json!({"file_path": format!("{}/.env", workspace_root())}),
    );
    let (stdout, code) = colmena_hook(&payload, &config_path());

    assert_eq!(code, 0);
    let resp: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(resp["hookSpecificOutput"]["permissionDecision"], "ask");
}

#[test]
fn test_hook_malformed_input_returns_ask() {
    let output = Command::new(env!("CARGO_BIN_EXE_colmena"))
        .args(["hook", "--config", &config_path()])
        .env("HOME", "/tmp/colmena-test-home")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .take()
                .unwrap()
                .write_all(b"not valid json!!!")
                .unwrap();
            child.wait_with_output()
        })
        .unwrap();

    assert_eq!(output.status.code(), Some(0), "Should still exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let resp: Value = serde_json::from_str(&stdout).expect("Should return valid JSON fallback");
    assert_eq!(resp["hookSpecificOutput"]["permissionDecision"], "ask");
}

#[test]
fn test_config_check_valid() {
    let output = Command::new(env!("CARGO_BIN_EXE_colmena"))
        .args(["config", "check", "--config", &config_path()])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Config is valid"));
}

#[test]
fn test_hook_blocks_path_traversal_write() {
    let payload = make_payload(
        "Write",
        json!({"file_path": format!("{}/src/../../../etc/passwd", workspace_root())}),
    );
    let (stdout, code) = colmena_hook(&payload, &config_path());
    assert_eq!(code, 0);
    let resp: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(resp["hookSpecificOutput"]["permissionDecision"], "ask");
}

#[test]
fn test_hook_allows_env_production_write() {
    let payload = make_payload(
        "Write",
        json!({"file_path": format!("{}/.env.production", workspace_root())}),
    );
    let (stdout, code) = colmena_hook(&payload, &config_path());
    assert_eq!(code, 0);
    let resp: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(resp["hookSpecificOutput"]["permissionDecision"], "allow");
}

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

#[test]
fn test_hook_respects_colmena_home() {
    let tmp = tempfile::TempDir::new().unwrap();
    let config_dir = tmp.path().join("config");
    std::fs::create_dir_all(config_dir.join("queue/pending")).unwrap();

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

// ── Helpers for library tests ──────────────────────────────────────────────────

/// Recursively copy a directory from src to dst.
fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if src_path.is_dir() {
            copy_dir_recursive(&src_path, &dst_path);
        } else {
            std::fs::copy(&src_path, &dst_path).unwrap();
        }
    }
}

/// Build a temp COLMENA_HOME with trust-firewall.yaml + the library directory copied in.
fn make_colmena_home() -> tempfile::TempDir {
    let tmp = tempfile::TempDir::new().unwrap();
    let config_dir = tmp.path().join("config");
    std::fs::create_dir_all(config_dir.join("queue/pending")).unwrap();
    std::fs::copy(&config_path(), config_dir.join("trust-firewall.yaml")).unwrap();

    let src_library = std::path::Path::new(&workspace_root()).join("config/library");
    copy_dir_recursive(&src_library, &config_dir.join("library"));

    tmp
}

// ── Library integration tests ─────────────────────────────────────────────────

#[test]
fn test_library_list() {
    let tmp = make_colmena_home();

    let output = Command::new(env!("CARGO_BIN_EXE_colmena"))
        .args(["library", "list"])
        .env("COLMENA_HOME", tmp.path())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "library list should exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("pentester"), "should list pentester role");
    assert!(stdout.contains("security_architect"), "should list security_architect role");
    assert!(stdout.contains("oracle-workers"), "should list oracle-workers pattern");
    assert!(stdout.contains("pipeline"), "should list pipeline pattern");
}

#[test]
fn test_library_show_role() {
    let tmp = make_colmena_home();

    let output = Command::new(env!("CARGO_BIN_EXE_colmena"))
        .args(["library", "show", "pentester"])
        .env("COLMENA_HOME", tmp.path())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "library show pentester should exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Pentester"), "should show role name Pentester");
    assert!(stdout.contains("web_vulnerabilities"), "should show web_vulnerabilities specialization");
    assert!(stdout.contains("offensive") || stdout.contains("exploitation") || stdout.contains("Offensive"),
        "should contain offensive-related content; got: {}", stdout);
}

#[test]
fn test_library_show_pattern() {
    let tmp = make_colmena_home();

    let output = Command::new(env!("CARGO_BIN_EXE_colmena"))
        .args(["library", "show", "oracle-workers"])
        .env("COLMENA_HOME", tmp.path())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "library show oracle-workers should exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Oracle"), "should contain Oracle in pattern name");
    assert!(stdout.contains("hierarchical"), "should show hierarchical topology");
    assert!(stdout.contains("hub-and-spoke"), "should show hub-and-spoke communication");
}

#[test]
fn test_library_show_unknown() {
    let tmp = make_colmena_home();

    let output = Command::new(env!("CARGO_BIN_EXE_colmena"))
        .args(["library", "show", "nonexistent"])
        .env("COLMENA_HOME", tmp.path())
        .output()
        .unwrap();

    let is_nonzero = !output.status.success();
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        is_nonzero || stderr.contains("not found") || stdout.contains("not found"),
        "should fail or report not found; exit={:?}, stderr={}, stdout={}",
        output.status.code(),
        stderr,
        stdout,
    );
}

#[test]
fn test_library_create_role() {
    let tmp = make_colmena_home();

    let output = Command::new(env!("CARGO_BIN_EXE_colmena"))
        .args([
            "library",
            "create-role",
            "--id",
            "test-role",
            "--description",
            "test description",
        ])
        .env("COLMENA_HOME", tmp.path())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "library create-role should exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let role_yaml = tmp
        .path()
        .join("config/library/roles/test-role.yaml");
    assert!(
        role_yaml.exists(),
        "role yaml file should be created at {:?}",
        role_yaml
    );
}

#[test]
fn test_library_select() {
    let tmp = make_colmena_home();

    let output = Command::new(env!("CARGO_BIN_EXE_colmena"))
        .args(["library", "select", "--mission", "security audit of payments API"])
        .env("COLMENA_HOME", tmp.path())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child
                .stdin
                .take()
                .unwrap()
                .write_all(b"1\n")
                .unwrap();
            child.wait_with_output()
        })
        .unwrap();

    assert!(
        output.status.success(),
        "library select should exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Recommended") || stdout.contains("Oracle"),
        "output should mention Recommended or a pattern name like Oracle; got: {}",
        stdout
    );
}
