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

fn make_permission_request_payload(tool: &str, agent_id: Option<&str>) -> Value {
    let mut payload = json!({
        "session_id": "integration-test",
        "hook_event_name": "PermissionRequest",
        "tool_name": tool,
        "tool_input": {},
        "tool_use_id": "tu_perm_req",
        "cwd": workspace_root()
    });
    if let Some(agent) = agent_id {
        payload["agent_id"] = json!(agent);
    }
    payload
}

/// Build a temp COLMENA_HOME with a role delegation for PermissionRequest tests.
fn make_colmena_home_with_delegation(agent_id: &str) -> tempfile::TempDir {
    let tmp = make_colmena_home();
    let config_dir = tmp.path().join("config");

    // Create runtime-delegations.json with a role delegation
    // Action uses kebab-case: "auto-approve", not "allow"
    let delegations = json!([{
        "tool": "Read",
        "agent_id": agent_id,
        "action": "auto-approve",
        "created_at": "2099-01-01T00:00:00Z",
        "expires_at": "2099-12-31T23:59:59Z",
        "source": "role",
        "mission_id": "test-mission"
    }]);
    std::fs::write(
        config_dir.join("runtime-delegations.json"),
        serde_json::to_string_pretty(&delegations).unwrap(),
    )
    .unwrap();

    tmp
}

fn colmena_hook_with_env(payload: &Value, colmena_home: &std::path::Path) -> (String, i32) {
    let input = serde_json::to_string(payload).unwrap();
    let config_flag = colmena_home
        .join("config/trust-firewall.yaml")
        .to_string_lossy()
        .to_string();

    let output = Command::new(env!("CARGO_BIN_EXE_colmena"))
        .args(["hook", "--config", &config_flag])
        .env("COLMENA_HOME", colmena_home)
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

// ── PermissionRequest integration tests ──────────────────────────────────────

#[test]
fn test_hook_permission_request_with_active_mission() {
    // Agent "pentester" has a role delegation (source="role") and Read is in tools_allowed
    let tmp = make_colmena_home_with_delegation("pentester");
    let payload = make_permission_request_payload("Read", Some("pentester"));
    let (stdout, code) = colmena_hook_with_env(&payload, tmp.path());

    assert_eq!(code, 0, "Exit code should be 0");
    assert!(!stdout.is_empty(), "Should return JSON response, got empty stdout");

    let resp: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("Should return valid JSON: {e}, got: {stdout}"));

    // Check the PermissionRequest response format
    let decision = &resp["hookSpecificOutput"]["decision"];
    assert_eq!(decision["behavior"], "allow", "Should allow tool in role's tools_allowed");

    // Should include updatedPermissions that teach CC session rules
    let perms = decision["updatedPermissions"].as_array()
        .expect("updatedPermissions should be an array");
    assert!(!perms.is_empty(), "Should have at least one permission update");
    assert_eq!(perms[0]["type"], "addRules");
    assert_eq!(perms[0]["behavior"], "allow");
    assert_eq!(perms[0]["destination"], "session");
}

#[test]
fn test_hook_permission_request_without_mission() {
    // Agent has no role delegation — PermissionRequest should produce no output
    let tmp = make_colmena_home(); // No delegations
    let payload = make_permission_request_payload("Read", Some("pentester"));
    let (stdout, code) = colmena_hook_with_env(&payload, tmp.path());

    assert_eq!(code, 0, "Exit code should be 0");
    // No output = CC continues to prompt user (safe passthrough)
    assert!(
        stdout.trim().is_empty(),
        "Without role delegation, should produce no output; got: {stdout}"
    );
}

#[test]
fn test_hook_permission_request_tool_not_in_role() {
    // Agent "researcher" has role delegation but mcp__caido__replay is NOT in researcher's tools_allowed
    let tmp = make_colmena_home_with_delegation("researcher");
    let payload = make_permission_request_payload("mcp__caido__replay", Some("researcher"));
    let (stdout, code) = colmena_hook_with_env(&payload, tmp.path());

    assert_eq!(code, 0, "Exit code should be 0");
    // Tool not in role's tools_allowed → no output (CC prompts user)
    assert!(
        stdout.trim().is_empty(),
        "Tool not in role's tools_allowed should produce no output; got: {stdout}"
    );
}

// ── SubagentStop integration tests ───────────────────────────────────────────

fn make_subagent_stop_payload(agent_id: Option<&str>) -> Value {
    let mut payload = json!({
        "session_id": "integration-test",
        "hook_event_name": "SubagentStop",
        "cwd": workspace_root(),
        "reason": "Task completed"
    });
    if let Some(agent) = agent_id {
        payload["agent_id"] = json!(agent);
    }
    payload
}

/// Build a temp COLMENA_HOME with delegation + a submitted review for the agent.
fn make_colmena_home_with_review(agent_id: &str, mission_id: &str) -> tempfile::TempDir {
    let tmp = make_colmena_home_with_delegation(agent_id);
    let config_dir = tmp.path().join("config");

    // Create a review entry in pending/
    let review_dir = config_dir.join("reviews/pending");
    std::fs::create_dir_all(&review_dir).unwrap();
    let review = json!({
        "review_id": "r_9999999_abcd",
        "mission": mission_id,
        "author_role": agent_id,
        "reviewer_role": "auditor",
        "artifact_path": "/tmp/test-artifact.rs",
        "artifact_hash": "sha256:0000",
        "state": "pending",
        "created_at": "2099-01-01T00:00:00Z",
        "evaluated_at": null,
        "scores": null,
        "score_average": null,
        "finding_count": null,
        "evaluation_narrative": null
    });
    std::fs::write(
        review_dir.join("r_9999999_abcd.json"),
        serde_json::to_string_pretty(&review).unwrap(),
    )
    .unwrap();

    tmp
}

#[test]
fn test_hook_subagent_stop_no_agent_id() {
    // No agent_id → approve (main agent, not a subagent)
    let tmp = make_colmena_home();
    let payload = make_subagent_stop_payload(None);
    let (stdout, code) = colmena_hook_with_env(&payload, tmp.path());

    assert_eq!(code, 0);
    let parsed: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(parsed["decision"], "approve");
}

#[test]
fn test_hook_subagent_stop_no_mission() {
    // Agent exists but has no role delegation → approve
    let tmp = make_colmena_home();
    let payload = make_subagent_stop_payload(Some("random-agent"));
    let (stdout, code) = colmena_hook_with_env(&payload, tmp.path());

    assert_eq!(code, 0);
    let parsed: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(parsed["decision"], "approve");
}

#[test]
fn test_hook_subagent_stop_worker_without_review() {
    // Worker has role delegation but NO review submitted → block
    let tmp = make_colmena_home_with_delegation("pentester");
    let payload = make_subagent_stop_payload(Some("pentester"));
    let (stdout, code) = colmena_hook_with_env(&payload, tmp.path());

    assert_eq!(code, 0);
    let parsed: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(parsed["decision"], "block");
    assert!(
        parsed["systemMessage"].as_str().unwrap().contains("review_submit"),
        "Block message should tell agent to call review_submit"
    );
}

#[test]
fn test_hook_subagent_stop_worker_with_review() {
    // Worker has role delegation AND review submitted → approve
    let tmp = make_colmena_home_with_review("pentester", "test-mission");
    let payload = make_subagent_stop_payload(Some("pentester"));
    let (stdout, code) = colmena_hook_with_env(&payload, tmp.path());

    assert_eq!(code, 0);
    let parsed: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(parsed["decision"], "approve");
}

#[test]
fn test_hook_subagent_stop_auditor_exempt() {
    // Auditor role has role_type: "auditor" → approve without review
    let tmp = make_colmena_home_with_delegation("auditor");
    let payload = make_subagent_stop_payload(Some("auditor"));
    let (stdout, code) = colmena_hook_with_env(&payload, tmp.path());

    assert_eq!(code, 0);
    let parsed: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(parsed["decision"], "approve");
}
