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

    // Create mission directory (Finding #1 fix: source="role" delegations
    // require a valid mission directory to prevent injection attacks)
    let mission_dir = config_dir.join("missions").join("test-mission");
    std::fs::create_dir_all(&mission_dir).unwrap();

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
    let payload = make_payload(
        "Bash",
        json!({"command": "git commit -m 'removed --force flag'"}),
    );
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
    std::fs::write(
        &bad_config,
        r#"
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
"#,
    )
    .unwrap();

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

    std::fs::copy(config_path(), config_dir.join("trust-firewall.yaml")).unwrap();

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
            child
                .stdin
                .take()
                .unwrap()
                .write_all(input.as_bytes())
                .unwrap();
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
    std::fs::copy(config_path(), config_dir.join("trust-firewall.yaml")).unwrap();

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
    assert!(
        stdout.contains("security_architect"),
        "should list security_architect role"
    );
    assert!(
        stdout.contains("oracle-workers"),
        "should list oracle-workers pattern"
    );
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
    assert!(
        stdout.contains("Pentester"),
        "should show role name Pentester"
    );
    assert!(
        stdout.contains("web_vulnerabilities"),
        "should show web_vulnerabilities specialization"
    );
    assert!(
        stdout.contains("offensive")
            || stdout.contains("exploitation")
            || stdout.contains("Offensive"),
        "should contain offensive-related content; got: {}",
        stdout
    );
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
    assert!(
        stdout.contains("Oracle"),
        "should contain Oracle in pattern name"
    );
    assert!(
        stdout.contains("hierarchical"),
        "should show hierarchical topology"
    );
    assert!(
        stdout.contains("hub-and-spoke"),
        "should show hub-and-spoke communication"
    );
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

    let role_yaml = tmp.path().join("config/library/roles/test-role.yaml");
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
        .args([
            "library",
            "select",
            "--mission",
            "security audit of payments API",
        ])
        .env("COLMENA_HOME", tmp.path())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child.stdin.take().unwrap().write_all(b"1\n").unwrap();
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
    assert!(
        !stdout.is_empty(),
        "Should return JSON response, got empty stdout"
    );

    let resp: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("Should return valid JSON: {e}, got: {stdout}"));

    // Check the PermissionRequest response format
    let decision = &resp["hookSpecificOutput"]["decision"];
    assert_eq!(
        decision["behavior"], "allow",
        "Should allow tool in role's tools_allowed"
    );

    // Should include updatedPermissions that teach CC session rules
    let perms = decision["updatedPermissions"]
        .as_array()
        .expect("updatedPermissions should be an array");
    assert!(
        !perms.is_empty(),
        "Should have at least one permission update"
    );
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
        parsed["systemMessage"]
            .as_str()
            .unwrap()
            .contains("review_submit"),
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

/// Build a COLMENA_HOME where agent has both a submitted review (as author)
/// AND a pending evaluation (as reviewer) — tests that evaluation check takes priority.
fn make_colmena_home_with_pending_evaluation(
    agent_id: &str,
    mission_id: &str,
) -> tempfile::TempDir {
    let tmp = make_colmena_home_with_delegation(agent_id);
    let config_dir = tmp.path().join("config");

    let review_dir = config_dir.join("reviews/pending");
    std::fs::create_dir_all(&review_dir).unwrap();

    // Review where this agent is the REVIEWER (must evaluate)
    let eval_review = json!({
        "review_id": "r_8888888_eval",
        "mission": mission_id,
        "author_role": "some-other-agent",
        "reviewer_role": agent_id,
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
        review_dir.join("r_8888888_eval.json"),
        serde_json::to_string_pretty(&eval_review).unwrap(),
    )
    .unwrap();

    // Review where this agent is the AUTHOR (has submitted work)
    let author_review = json!({
        "review_id": "r_7777777_submit",
        "mission": mission_id,
        "author_role": agent_id,
        "reviewer_role": "auditor",
        "artifact_path": "/tmp/other-artifact.rs",
        "artifact_hash": "sha256:1111",
        "state": "pending",
        "created_at": "2099-01-01T00:00:00Z",
        "evaluated_at": null,
        "scores": null,
        "score_average": null,
        "finding_count": null,
        "evaluation_narrative": null
    });
    std::fs::write(
        review_dir.join("r_7777777_submit.json"),
        serde_json::to_string_pretty(&author_review).unwrap(),
    )
    .unwrap();

    tmp
}

#[test]
fn test_hook_subagent_stop_reviewer_with_pending_evaluation() {
    // Agent has submitted their own review AND has a pending evaluation to complete.
    // Should be blocked — pending evaluation check takes priority over review_submit.
    let tmp = make_colmena_home_with_pending_evaluation("pentester", "test-mission");
    let payload = make_subagent_stop_payload(Some("pentester"));
    let (stdout, code) = colmena_hook_with_env(&payload, tmp.path());

    assert_eq!(code, 0);
    let parsed: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(parsed["decision"], "block");
    assert!(
        parsed["systemMessage"]
            .as_str()
            .unwrap()
            .contains("review_evaluate"),
        "Block message should tell agent to call review_evaluate"
    );
}

// ── Mission Gate integration tests ──────────────────────────────────────────

fn make_colmena_home_with_enforce_missions() -> tempfile::TempDir {
    let tmp = make_colmena_home();
    // Modify config to enable enforce_missions
    let config_path = tmp.path().join("config/trust-firewall.yaml");
    let content = std::fs::read_to_string(&config_path).unwrap();
    let modified = content.replace("enforce_missions: false", "enforce_missions: true");
    std::fs::write(&config_path, modified).unwrap();
    tmp
}

/// Build a colmena home with a minimal trust-firewall.yaml containing
/// `enforce_missions: false` explicitly. Does NOT copy the workspace YAML —
/// guarantees independence from any global default the workspace may carry.
fn make_colmena_home_no_enforce() -> tempfile::TempDir {
    let tmp = tempfile::TempDir::new().unwrap();
    let config_dir = tmp.path().join("config");
    std::fs::create_dir_all(config_dir.join("queue/pending")).unwrap();

    // Minimal YAML: enforce_missions explicitly false, no rules beyond defaults.
    // Any hook-path evaluation will fall through to safe defaults ("ask").
    let minimal_yaml = r#"version: 1
enforce_missions: false
defaults:
  action: ask
trust_circle: []
restricted: []
blocked: []
"#;
    std::fs::write(config_dir.join("trust-firewall.yaml"), minimal_yaml).unwrap();

    let src_library = std::path::Path::new(&workspace_root()).join("config/library");
    copy_dir_recursive(&src_library, &config_dir.join("library"));

    tmp
}

#[test]
fn test_mission_gate_blocks_bare_agent_when_enforced() {
    let tmp = make_colmena_home_with_enforce_missions();
    // Agent call without mission marker
    let payload = json!({
        "session_id": "gate-test",
        "hook_event_name": "PreToolUse",
        "tool_name": "Agent",
        "tool_input": {"prompt": "Just do something without a mission"},
        "tool_use_id": "tu_gate_1",
        "cwd": workspace_root()
    });
    let (stdout, code) = colmena_hook_with_env(&payload, tmp.path());

    assert_eq!(code, 0);
    let parsed: Value = serde_json::from_str(stdout.trim()).unwrap();
    // Should be "ask" (not deny) — human can override
    assert!(
        parsed.get("decision").is_none() || parsed["decision"] != "deny",
        "Mission gate should ask, not deny"
    );
    // Response should contain mission gate message
    let response_str = stdout.to_lowercase();
    assert!(
        response_str.contains("mission") && response_str.contains("gate")
            || response_str.contains("mission_spawn")
            || response_str.contains("mission gate"),
        "Response should mention mission gate: {}",
        stdout
    );
}

#[test]
fn test_mission_gate_allows_agent_with_marker() {
    let tmp = make_colmena_home_with_enforce_missions();
    // Agent call WITH mission marker in prompt
    let prompt = format!(
        "{}test-mission-123 -->\n# Developer\nYou write code.",
        colmena_core::selector::MISSION_MARKER_PREFIX
    );
    let payload = json!({
        "session_id": "gate-test",
        "hook_event_name": "PreToolUse",
        "tool_name": "Agent",
        "tool_input": {"prompt": prompt},
        "tool_use_id": "tu_gate_2",
        "cwd": workspace_root()
    });
    let (stdout, code) = colmena_hook_with_env(&payload, tmp.path());

    assert_eq!(code, 0);
    let parsed: Value = serde_json::from_str(stdout.trim()).unwrap();
    // Should NOT trigger mission gate — passes through to normal Agent handling (ask from restricted)
    let response_str = serde_json::to_string(&parsed).unwrap().to_lowercase();
    assert!(
        !response_str.contains("mission gate"),
        "Agent with marker should not trigger mission gate: {}",
        stdout
    );
}

#[test]
fn test_mission_gate_inactive_when_not_enforced() {
    // Uses an inline config with enforce_missions: false explicit — does NOT depend
    // on whatever default the workspace YAML carries at the time.
    let tmp = make_colmena_home_no_enforce();
    let payload = json!({
        "session_id": "gate-test",
        "hook_event_name": "PreToolUse",
        "tool_name": "Agent",
        "tool_input": {"prompt": "bare agent without marker"},
        "tool_use_id": "tu_gate_3",
        "cwd": workspace_root()
    });
    let (stdout, code) = colmena_hook_with_env(&payload, tmp.path());

    assert_eq!(code, 0);
    let parsed: Value = serde_json::from_str(stdout.trim()).unwrap();
    // Should NOT mention mission gate
    let response_str = serde_json::to_string(&parsed).unwrap().to_lowercase();
    assert!(
        !response_str.contains("mission gate"),
        "Mission gate should not fire when enforce_missions=false: {}",
        stdout
    );
}

#[test]
fn test_mission_gate_skips_non_agent_tools() {
    let tmp = make_colmena_home_with_enforce_missions();
    // Read tool call — mission gate should not fire even with enforce_missions=true
    let payload = json!({
        "session_id": "gate-test",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": "/tmp/test.txt"},
        "tool_use_id": "tu_gate_4",
        "cwd": workspace_root()
    });
    let (stdout, code) = colmena_hook_with_env(&payload, tmp.path());

    assert_eq!(code, 0);
    let parsed: Value = serde_json::from_str(stdout.trim()).unwrap();
    let response_str = serde_json::to_string(&parsed).unwrap().to_lowercase();
    assert!(
        !response_str.contains("mission gate"),
        "Non-Agent tools should never trigger mission gate: {}",
        stdout
    );
}

// ── Finding #8 (DREAD 5.6): PermissionRequest revocation check ────────────

/// Build a COLMENA_HOME with a role delegation AND the agent in revoked-missions.json.
fn make_colmena_home_with_revoked_agent(agent_id: &str) -> tempfile::TempDir {
    let tmp = make_colmena_home_with_delegation(agent_id);
    let config_dir = tmp.path().join("config");

    // Add agent to revoked-missions.json
    let revoked: std::collections::HashSet<String> =
        vec![agent_id.to_string()].into_iter().collect();
    std::fs::write(
        config_dir.join("revoked-missions.json"),
        serde_json::to_string(&revoked).unwrap(),
    )
    .unwrap();

    tmp
}

#[test]
fn test_permission_request_blocks_revoked_agent() {
    // Agent has a role delegation but is in revoked-missions.json.
    // PermissionRequest should NOT teach session rules — should return no output.
    let tmp = make_colmena_home_with_revoked_agent("pentester");
    let payload = make_permission_request_payload("Read", Some("pentester"));
    let (stdout, code) = colmena_hook_with_env(&payload, tmp.path());

    assert_eq!(code, 0, "Exit code should be 0");
    // Revoked agent → no output (CC prompts user, session rules not taught)
    assert!(
        stdout.trim().is_empty(),
        "Revoked agent should get no output from PermissionRequest; got: {stdout}"
    );
}

// ── Finding #1 (DREAD 7.6): Delegation injection integration test ─────────

#[test]
fn test_delegation_injection_source_role_without_mission_dir() {
    // Create a COLMENA_HOME with a delegation that has source="role" but
    // the mission directory does NOT exist — simulates injection attack
    let tmp = make_colmena_home();
    let config_dir = tmp.path().join("config");

    // Injected delegation with source="role" and fake mission_id (no directory)
    let delegations = json!([{
        "tool": "Agent",
        "agent_id": "injected-agent",
        "action": "auto-approve",
        "created_at": "2099-01-01T00:00:00Z",
        "expires_at": "2099-12-31T23:59:59Z",
        "source": "role",
        "mission_id": "fake-mission-never-created"
    }]);
    std::fs::write(
        config_dir.join("runtime-delegations.json"),
        serde_json::to_string_pretty(&delegations).unwrap(),
    )
    .unwrap();

    // PermissionRequest for the injected agent — should produce no output
    // because the delegation should be filtered out at load time
    let payload = make_permission_request_payload("Agent", Some("injected-agent"));
    let (stdout, code) = colmena_hook_with_env(&payload, tmp.path());

    assert_eq!(code, 0);
    assert!(
        stdout.trim().is_empty(),
        "Injected delegation should be filtered; no session rules taught. Got: {stdout}"
    );
}

// ── M7.3 mission spawn tests ─────────────────────────────────────────────

#[test]
fn test_mission_spawn_dry_run_with_manifest() {
    let tmp = make_colmena_home();
    let agents_tmp = tempfile::TempDir::new().unwrap();
    let fixture =
        std::path::Path::new(&workspace_root()).join("tests/fixtures/missions/peer-2-roles.yaml");

    let output = Command::new(env!("CARGO_BIN_EXE_colmena"))
        .args(["mission", "spawn", "--from"])
        .arg(&fixture)
        .arg("--dry-run")
        .env("COLMENA_HOME", tmp.path())
        .env("COLMENA_AGENTS_DIR", agents_tmp.path())
        .output()
        .expect("binary should run");

    assert!(
        output.status.success(),
        "dry-run should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("test-peer-mission"), "stdout: {stdout}");
    assert!(stdout.contains("(dry-run)"), "must mark dry-run: {stdout}");

    // No delegations written
    let delegations_path = tmp.path().join("config/runtime-delegations.json");
    assert!(
        !delegations_path.exists()
            || std::fs::read_to_string(&delegations_path).unwrap().trim() == "[]",
        "dry-run must not persist delegations"
    );

    // M7.3 dry-run contract: nothing persisted to disk
    let mission_dir = tmp.path().join("config/missions/test-peer-mission");
    let date_prefixed = tmp
        .path()
        .join("config/missions")
        .read_dir()
        .ok()
        .and_then(|mut it| it.next().and_then(|e| e.ok()))
        .map(|e| e.path());
    assert!(
        !mission_dir.exists() && date_prefixed.is_none(),
        "dry-run must not create mission directories"
    );
}

#[test]
fn test_mission_spawn_rejects_nonexistent_role() {
    let tmp = make_colmena_home();
    let agents_tmp = tempfile::TempDir::new().unwrap();
    let fixture = std::path::Path::new(&workspace_root())
        .join("tests/fixtures/missions/invalid-nonexistent-role.yaml");

    let output = Command::new(env!("CARGO_BIN_EXE_colmena"))
        .args(["mission", "spawn", "--from"])
        .arg(&fixture)
        .env("COLMENA_HOME", tmp.path())
        .env("COLMENA_AGENTS_DIR", agents_tmp.path())
        .output()
        .expect("binary should run");

    assert!(!output.status.success(), "must fail for unknown role");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("nonexistent_role_xyz"),
        "error must mention the unknown role: {stderr}"
    );
    assert!(
        stderr.contains("create-role"),
        "error must suggest colmena library create-role: {stderr}"
    );
}

#[test]
fn test_mission_spawn_rejects_ttl_over_max() {
    let tmp = make_colmena_home();

    // Write a temp manifest with ttl = 25 (> MAX_TTL_HOURS = 24)
    let manifest_content = r#"
id: ttl-overflow
pattern: peer
mission_ttl_hours: 25
roles:
  - name: developer
    task: "x"
"#;
    let manifest_path = tmp.path().join("bad-ttl.yaml");
    std::fs::write(&manifest_path, manifest_content).unwrap();
    let agents_tmp = tempfile::TempDir::new().unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_colmena"))
        .args(["mission", "spawn", "--from"])
        .arg(&manifest_path)
        .env("COLMENA_HOME", tmp.path())
        .env("COLMENA_AGENTS_DIR", agents_tmp.path())
        .output()
        .expect("binary should run");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("MAX_TTL_HOURS"), "stderr: {stderr}");
}

#[test]
fn test_mission_spawn_persists_delegations_when_not_dry_run() {
    let tmp = make_colmena_home();
    let agents_tmp = tempfile::TempDir::new().unwrap();
    let fixture =
        std::path::Path::new(&workspace_root()).join("tests/fixtures/missions/peer-2-roles.yaml");

    let output = Command::new(env!("CARGO_BIN_EXE_colmena"))
        .args(["mission", "spawn", "--from"])
        .arg(&fixture)
        .env("COLMENA_HOME", tmp.path())
        .env("COLMENA_AGENTS_DIR", agents_tmp.path())
        .output()
        .expect("binary should run");

    assert!(
        output.status.success(),
        "real spawn should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Delegations file exists and contains role-source delegations
    let delegations_path = tmp.path().join("config/runtime-delegations.json");
    assert!(
        delegations_path.exists(),
        "delegations file must exist after real spawn"
    );
    let content = std::fs::read_to_string(&delegations_path).unwrap();
    assert!(
        content.contains("\"source\": \"role\""),
        "must have role-source delegations: {content}"
    );
    assert!(
        content.contains("\"developer\""),
        "must have developer delegations: {content}"
    );
    assert!(
        content.contains("mcp__colmena__review_submit"),
        "must bundle review_submit: {content}"
    );
}

// ── prompt-inject integration tests ──────────────────────────────────────────

#[test]
fn test_mission_prompt_inject_terse() {
    let tmp = make_colmena_home();
    let output = Command::new(env!("CARGO_BIN_EXE_colmena"))
        .args(["mission", "prompt-inject", "--mode", "terse"])
        .env("COLMENA_HOME", tmp.path())
        .output()
        .expect("binary should run");
    assert!(
        output.status.success(),
        "prompt-inject terse should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("INTER-AGENT PROTOCOL"));
    assert!(stdout.contains("Facts only"));
}

#[test]
fn test_mission_prompt_inject_unsupported_mode() {
    let tmp = make_colmena_home();
    let output = Command::new(env!("CARGO_BIN_EXE_colmena"))
        .args(["mission", "prompt-inject", "--mode", "verbose"])
        .env("COLMENA_HOME", tmp.path())
        .output()
        .expect("binary should run");
    // The CLI error handler converts all Err results to exit 0 (safe fallback for hooks).
    // For unsupported modes the error text is surfaced in stdout as JSON reason.
    assert_eq!(
        output.status.code(),
        Some(0),
        "CLI always exits 0 (hook safe-fallback)"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("unsupported mode"),
        "unsupported mode error should appear in stdout JSON; got: {stdout}"
    );
}

// ── mission deactivate subagent cleanup tests ─────────────────────────────────

#[test]
fn test_mission_deactivate_removes_auto_generated_subagent_files() {
    let tmp = make_colmena_home();

    // Isolated agents dir via env var
    let agents_dir = tmp.path().join("agents");
    std::fs::create_dir_all(&agents_dir).unwrap();

    // Seed: one auto-generated file, one manual file
    let auto_path = agents_dir.join("developer.md");
    std::fs::write(
        &auto_path,
        "---\nname: developer\ncolmena_auto_generated: true\ntools: []\n---\n\nbody\n",
    )
    .unwrap();

    let manual_path = agents_dir.join("architect.md");
    std::fs::write(
        &manual_path,
        "---\nname: architect\ntools: []\n---\n\nbody\n",
    )
    .unwrap();

    // Seed a mission directory (required by load_delegations for source: role validation)
    std::fs::create_dir_all(tmp.path().join("config/missions/m-x")).unwrap();

    // Seed runtime-delegations.json with 2 agents under mission "m-x"
    let delegations = serde_json::json!([
        {
            "tool": "Read",
            "agent_id": "developer",
            "action": "auto-approve",
            "created_at": "2099-01-01T00:00:00Z",
            "expires_at": "2099-12-31T23:59:59Z",
            "source": "role",
            "mission_id": "m-x"
        },
        {
            "tool": "Read",
            "agent_id": "architect",
            "action": "auto-approve",
            "created_at": "2099-01-01T00:00:00Z",
            "expires_at": "2099-12-31T23:59:59Z",
            "source": "role",
            "mission_id": "m-x"
        }
    ]);
    std::fs::write(
        tmp.path().join("config/runtime-delegations.json"),
        serde_json::to_string_pretty(&delegations).unwrap(),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_colmena"))
        .args(["mission", "deactivate", "--id", "m-x"])
        .env("COLMENA_HOME", tmp.path())
        .env("COLMENA_AGENTS_DIR", &agents_dir)
        .output()
        .expect("binary should run");

    assert!(
        output.status.success(),
        "mission deactivate should succeed, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Auto-generated file: gone
    assert!(!auto_path.exists(), "auto-generated file must be removed");
    // Manual file: preserved
    assert!(manual_path.exists(), "manual file must be preserved");
}

// ── M7.3 live-surface: border case enforce_missions=false + 3+ roles ──────────

#[test]
fn test_mission_spawn_aborts_on_false_enforce_with_3_roles() {
    let tmp = make_colmena_home_no_enforce(); // enforce_missions: false explicit
    let agents_dir = tmp.path().join("agents");
    std::fs::create_dir_all(&agents_dir).unwrap();

    // 3-role manifest triggers the border case
    let manifest = r#"
id: border-case-mission
pattern: peer
mission_ttl_hours: 2
roles:
  - name: developer
    task: "x"
  - name: auditor
    task: "y"
  - name: code_reviewer
    task: "z"
"#;
    let manifest_path = tmp.path().join("border.yaml");
    std::fs::write(&manifest_path, manifest).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_colmena"))
        .args(["mission", "spawn", "--from"])
        .arg(&manifest_path)
        .env("COLMENA_HOME", tmp.path())
        .env("COLMENA_AGENTS_DIR", &agents_dir)
        .output()
        .expect("binary should run");

    assert!(
        !output.status.success(),
        "must abort without --session-gate or --no-gate-confirmed"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("enforce_missions: false is explicit"),
        "stderr must mention the explicit flag: {stderr}"
    );
    assert!(
        stderr.contains("--session-gate"),
        "stderr must list option 1: {stderr}"
    );
    assert!(
        stderr.contains("--no-gate-confirmed"),
        "stderr must list option 3: {stderr}"
    );
}

#[test]
fn test_mission_spawn_proceeds_with_session_gate() {
    let tmp = make_colmena_home_no_enforce();
    let agents_dir = tmp.path().join("agents");
    std::fs::create_dir_all(&agents_dir).unwrap();

    let manifest = r#"
id: session-gate-mission
pattern: peer
mission_ttl_hours: 2
roles:
  - name: developer
    task: "x"
  - name: auditor
    task: "y"
  - name: code_reviewer
    task: "z"
"#;
    let manifest_path = tmp.path().join("sess.yaml");
    std::fs::write(&manifest_path, manifest).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_colmena"))
        .args(["mission", "spawn", "--from"])
        .arg(&manifest_path)
        .arg("--session-gate")
        .env("COLMENA_HOME", tmp.path())
        .env("COLMENA_AGENTS_DIR", &agents_dir)
        .output()
        .expect("binary should run");

    assert!(
        output.status.success(),
        "--session-gate must allow spawn, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
