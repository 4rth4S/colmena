use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Payload received from Claude Code via stdin on every tool invocation.
/// For PreToolUse: tool_response is absent.
/// For PostToolUse: tool_response contains the tool's output (stdout, stderr, interrupted).
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct HookPayload {
    pub session_id: String,
    pub hook_event_name: String,
    pub tool_name: String,
    pub tool_input: Value,
    pub tool_use_id: String,
    pub agent_id: Option<String>,
    pub agent_type: Option<String>,
    pub cwd: String,
    pub permission_mode: Option<String>,
    pub transcript_path: Option<String>,
    /// Present only for PostToolUse events (CC sends "tool_response", not "tool_output").
    pub tool_response: Option<Value>,
}

impl HookPayload {
    pub fn to_evaluation_input(&self) -> colmena_core::models::EvaluationInput {
        colmena_core::models::EvaluationInput {
            session_id: self.session_id.clone(),
            tool_name: self.tool_name.clone(),
            tool_input: self.tool_input.clone(),
            tool_use_id: self.tool_use_id.clone(),
            agent_id: self.agent_id.clone(),
            agent_type: self.agent_type.clone(),
            cwd: self.cwd.clone(),
        }
    }
}

/// Response sent back to Claude Code via stdout.
#[derive(Debug, Serialize)]
pub struct HookResponse {
    #[serde(rename = "hookSpecificOutput")]
    pub hook_specific_output: HookSpecificOutput,
}

#[derive(Debug, Serialize)]
pub struct HookSpecificOutput {
    #[serde(rename = "hookEventName")]
    pub hook_event_name: String,
    #[serde(rename = "permissionDecision")]
    pub permission_decision: String,
    #[serde(rename = "permissionDecisionReason")]
    pub permission_decision_reason: String,
}

impl HookResponse {
    pub fn allow(reason: impl Into<String>) -> Self {
        Self {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: "allow".to_string(),
                permission_decision_reason: reason.into(),
            },
        }
    }

    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: "deny".to_string(),
                permission_decision_reason: reason.into(),
            },
        }
    }

    pub fn ask(reason: impl Into<String>) -> Self {
        Self {
            hook_specific_output: HookSpecificOutput {
                hook_event_name: "PreToolUse".to_string(),
                permission_decision: "ask".to_string(),
                permission_decision_reason: reason.into(),
            },
        }
    }
}

/// Response for PostToolUse hooks — returns filtered output to CC.
#[derive(Debug, Serialize)]
pub struct PostToolUseResponse {
    #[serde(rename = "hookSpecificOutput")]
    pub hook_specific_output: PostToolUseOutput,
}

#[derive(Debug, Serialize)]
pub struct PostToolUseOutput {
    #[serde(rename = "hookEventName")]
    pub hook_event_name: String,
    #[serde(
        rename = "updatedMCPToolOutput",
        skip_serializing_if = "Option::is_none"
    )]
    pub updated_mcp_tool_output: Option<String>,
}

impl PostToolUseResponse {
    /// Return filtered output to CC (replaces original).
    pub fn with_output(output: String) -> Self {
        Self {
            hook_specific_output: PostToolUseOutput {
                hook_event_name: "PostToolUse".to_string(),
                updated_mcp_tool_output: Some(output),
            },
        }
    }

    /// Return no modification — CC keeps original output.
    pub fn passthrough() -> Self {
        Self {
            hook_specific_output: PostToolUseOutput {
                hook_event_name: "PostToolUse".to_string(),
                updated_mcp_tool_output: None,
            },
        }
    }
}

/// Response for PermissionRequest hooks — can teach CC persistent session rules.
/// CC fires PermissionRequest when it's about to prompt the user for permission.
/// Returning `allow` with `updatedPermissions` teaches CC to auto-approve future calls.
#[derive(Debug, Serialize)]
pub struct PermissionRequestResponse {
    #[serde(rename = "hookSpecificOutput")]
    pub hook_specific_output: PermissionRequestOutput,
}

#[derive(Debug, Serialize)]
pub struct PermissionRequestOutput {
    #[serde(rename = "hookEventName")]
    pub hook_event_name: String,
    pub decision: PermissionRequestDecision,
}

#[derive(Debug, Serialize)]
pub struct PermissionRequestDecision {
    pub behavior: String,
    #[serde(rename = "updatedPermissions", skip_serializing_if = "Option::is_none")]
    pub updated_permissions: Option<Vec<PermissionUpdate>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// A permission update that CC applies to its session context.
/// Corresponds to CC's internal PermissionUpdate type.
#[derive(Debug, Serialize)]
pub struct PermissionUpdate {
    #[serde(rename = "type")]
    pub update_type: String,
    pub rules: Vec<PermissionRule>,
    pub behavior: String,
    pub destination: String,
}

/// A single permission rule for a tool.
#[derive(Debug, Serialize)]
pub struct PermissionRule {
    #[serde(rename = "toolName")]
    pub tool_name: String,
}

impl PermissionRequestResponse {
    /// Allow the tool call and teach CC session rules.
    pub fn allow_with_updates(updates: Vec<PermissionUpdate>) -> Self {
        Self {
            hook_specific_output: PermissionRequestOutput {
                hook_event_name: "PermissionRequest".to_string(),
                decision: PermissionRequestDecision {
                    behavior: "allow".to_string(),
                    updated_permissions: if updates.is_empty() {
                        None
                    } else {
                        Some(updates)
                    },
                    message: None,
                },
            },
        }
    }

    /// Deny the tool call with a reason message.
    #[allow(dead_code)]
    pub fn deny(message: impl Into<String>) -> Self {
        Self {
            hook_specific_output: PermissionRequestOutput {
                hook_event_name: "PermissionRequest".to_string(),
                decision: PermissionRequestDecision {
                    behavior: "deny".to_string(),
                    updated_permissions: None,
                    message: Some(message.into()),
                },
            },
        }
    }
}

/// Payload for SubagentStop lifecycle events.
/// Unlike tool events (PreToolUse/PostToolUse), these have no tool_name/tool_input.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct SubagentStopPayload {
    pub session_id: String,
    pub hook_event_name: String,
    pub agent_id: Option<String>,
    pub cwd: String,
    pub reason: Option<String>,
    pub transcript_path: Option<String>,
}

/// Response for SubagentStop hooks — approve or block agent from stopping.
#[derive(Debug, Serialize)]
pub struct SubagentStopResponse {
    pub decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(rename = "systemMessage", skip_serializing_if = "Option::is_none")]
    pub system_message: Option<String>,
}

impl SubagentStopResponse {
    pub fn approve() -> Self {
        Self {
            decision: "approve".to_string(),
            reason: None,
            system_message: None,
        }
    }

    pub fn block(message: impl Into<String>) -> Self {
        Self {
            decision: "block".to_string(),
            reason: None,
            system_message: Some(message.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_deserialize_hook_payload() {
        let input = json!({
            "session_id": "abc123",
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": "/tmp/foo.txt"},
            "tool_use_id": "tu_001",
            "agent_id": "pentester",
            "agent_type": "general-purpose",
            "cwd": "/Users/fr33m4n/colmena",
            "permission_mode": "default"
        });

        let payload: HookPayload = serde_json::from_value(input).unwrap();
        assert_eq!(payload.tool_name, "Read");
        assert_eq!(payload.agent_id, Some("pentester".to_string()));
        assert_eq!(payload.cwd, "/Users/fr33m4n/colmena");
    }

    #[test]
    fn test_to_evaluation_input_forwards_agent_type() {
        // Regression: EvaluationInput must carry both agent_id (per-invocation)
        // and agent_type (stable class name) so the firewall can match
        // agent_overrides / delegations against either.
        let input = json!({
            "session_id": "abc123",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
            "tool_use_id": "tu_fwd",
            "agent_id": "aa0aae6b1f3568365",
            "agent_type": "cron-worker",
            "cwd": "/tmp"
        });

        let payload: HookPayload = serde_json::from_value(input).unwrap();
        let eval = payload.to_evaluation_input();
        assert_eq!(eval.agent_id.as_deref(), Some("aa0aae6b1f3568365"));
        assert_eq!(eval.agent_type.as_deref(), Some("cron-worker"));
    }

    #[test]
    fn test_deserialize_payload_optional_fields() {
        let input = json!({
            "session_id": "abc123",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la"},
            "tool_use_id": "tu_002",
            "cwd": "/tmp"
        });

        let payload: HookPayload = serde_json::from_value(input).unwrap();
        assert_eq!(payload.agent_id, None);
        assert_eq!(payload.agent_type, None);
        assert_eq!(payload.permission_mode, None);
    }

    #[test]
    fn test_serialize_allow_response() {
        let resp = HookResponse::allow("Read-only operation");
        let json = serde_json::to_value(&resp).unwrap();

        assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "allow");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecisionReason"],
            "Read-only operation"
        );
        assert_eq!(json["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    }

    #[test]
    fn test_serialize_deny_response() {
        let resp = HookResponse::deny("Destructive operation blocked");
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "deny");
    }

    #[test]
    fn test_serialize_ask_response() {
        let resp = HookResponse::ask("Needs human review");
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "ask");
    }

    #[test]
    fn test_deserialize_post_tool_use_payload() {
        let input = json!({
            "session_id": "abc123",
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "cargo build"},
            "tool_use_id": "tu_010",
            "cwd": "/tmp",
            "transcript_path": "/home/user/.claude/projects/test/abc123.jsonl",
            "tool_response": {
                "stdout": "Compiling...\nFinished",
                "stderr": "",
                "interrupted": false
            }
        });

        let payload: HookPayload = serde_json::from_value(input).unwrap();
        assert_eq!(payload.hook_event_name, "PostToolUse");
        assert!(payload.tool_response.is_some());
        let response = payload.tool_response.unwrap();
        assert_eq!(response["stdout"], "Compiling...\nFinished");
        assert_eq!(response["interrupted"], false);
    }

    #[test]
    fn test_serialize_post_tool_use_with_output() {
        let resp = PostToolUseResponse::with_output("filtered output".to_string());
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["hookSpecificOutput"]["hookEventName"], "PostToolUse");
        assert_eq!(
            json["hookSpecificOutput"]["updatedMCPToolOutput"],
            "filtered output"
        );
    }

    #[test]
    fn test_serialize_post_tool_use_passthrough() {
        let resp = PostToolUseResponse::passthrough();
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["hookSpecificOutput"]["hookEventName"], "PostToolUse");
        // updatedMCPToolOutput should be absent (skip_serializing_if None)
        assert!(!json["hookSpecificOutput"]
            .as_object()
            .unwrap()
            .contains_key("updatedMCPToolOutput"));
    }

    #[test]
    fn test_to_evaluation_input() {
        let input = json!({
            "session_id": "sess1",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
            "tool_use_id": "tu_003",
            "agent_id": "worker",
            "agent_type": "general-purpose",
            "cwd": "/tmp",
            "permission_mode": "default"
        });

        let payload: HookPayload = serde_json::from_value(input).unwrap();
        let eval = payload.to_evaluation_input();

        assert_eq!(eval.session_id, "sess1");
        assert_eq!(eval.tool_name, "Bash");
        assert_eq!(eval.tool_use_id, "tu_003");
        assert_eq!(eval.agent_id, Some("worker".to_string()));
        assert_eq!(eval.cwd, "/tmp");
    }

    // ── PermissionRequest response tests ────────────────────────────────────

    #[test]
    fn test_serialize_permission_request_allow() {
        let resp = PermissionRequestResponse::allow_with_updates(vec![]);
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(
            json["hookSpecificOutput"]["hookEventName"],
            "PermissionRequest"
        );
        assert_eq!(json["hookSpecificOutput"]["decision"]["behavior"], "allow");
        // No updatedPermissions when empty
        assert!(!json["hookSpecificOutput"]["decision"]
            .as_object()
            .unwrap()
            .contains_key("updatedPermissions"));
    }

    #[test]
    fn test_serialize_permission_request_with_updates() {
        let updates = vec![PermissionUpdate {
            update_type: "addRules".to_string(),
            rules: vec![
                PermissionRule {
                    tool_name: "Read".to_string(),
                },
                PermissionRule {
                    tool_name: "mcp__caido__*".to_string(),
                },
            ],
            behavior: "allow".to_string(),
            destination: "session".to_string(),
        }];

        let resp = PermissionRequestResponse::allow_with_updates(updates);
        let json = serde_json::to_value(&resp).unwrap();

        let decision = &json["hookSpecificOutput"]["decision"];
        assert_eq!(decision["behavior"], "allow");
        let perms = decision["updatedPermissions"].as_array().unwrap();
        assert_eq!(perms.len(), 1);
        assert_eq!(perms[0]["type"], "addRules");
        assert_eq!(perms[0]["behavior"], "allow");
        assert_eq!(perms[0]["destination"], "session");
        let rules = perms[0]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0]["toolName"], "Read");
        assert_eq!(rules[1]["toolName"], "mcp__caido__*");
    }

    #[test]
    fn test_serialize_permission_request_deny() {
        let resp = PermissionRequestResponse::deny("Mission revoked");
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["hookSpecificOutput"]["decision"]["behavior"], "deny");
        assert_eq!(
            json["hookSpecificOutput"]["decision"]["message"],
            "Mission revoked"
        );
    }

    // ── SubagentStop response tests ─────────────────────────────────────────

    #[test]
    fn test_subagent_stop_payload_deserialize() {
        let input = json!({
            "session_id": "sess_abc",
            "hook_event_name": "SubagentStop",
            "agent_id": "pentester",
            "cwd": "/home/user/project",
            "reason": "task_complete",
            "transcript_path": "/tmp/transcript.jsonl"
        });

        let payload: SubagentStopPayload = serde_json::from_value(input).unwrap();
        assert_eq!(payload.session_id, "sess_abc");
        assert_eq!(payload.hook_event_name, "SubagentStop");
        assert_eq!(payload.agent_id, Some("pentester".to_string()));
        assert_eq!(payload.cwd, "/home/user/project");
        assert_eq!(payload.reason, Some("task_complete".to_string()));
    }

    #[test]
    fn test_subagent_stop_payload_minimal() {
        // No tool_name, no tool_input — unlike HookPayload
        let input = json!({
            "session_id": "sess_xyz",
            "hook_event_name": "SubagentStop",
            "cwd": "/tmp"
        });

        let payload: SubagentStopPayload = serde_json::from_value(input).unwrap();
        assert_eq!(payload.agent_id, None);
        assert_eq!(payload.reason, None);
        assert_eq!(payload.transcript_path, None);
    }

    #[test]
    fn test_subagent_stop_response_approve() {
        let resp = SubagentStopResponse::approve();
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["decision"], "approve");
        // No systemMessage for approve
        assert!(!json.as_object().unwrap().contains_key("systemMessage"));
        assert!(!json.as_object().unwrap().contains_key("reason"));
    }

    #[test]
    fn test_subagent_stop_response_block() {
        let resp = SubagentStopResponse::block("Submit review first");
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["decision"], "block");
        assert_eq!(json["systemMessage"], "Submit review first");
    }
}
