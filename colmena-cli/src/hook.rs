use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Payload received from Claude Code via stdin on every tool invocation.
/// For PreToolUse: tool_output is absent.
/// For PostToolUse: tool_output contains the tool's output (stdout, stderr, exitCode).
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
    /// Present only for PostToolUse events.
    pub tool_output: Option<Value>,
}

impl HookPayload {
    pub fn to_evaluation_input(&self) -> colmena_core::models::EvaluationInput {
        colmena_core::models::EvaluationInput {
            session_id: self.session_id.clone(),
            tool_name: self.tool_name.clone(),
            tool_input: self.tool_input.clone(),
            tool_use_id: self.tool_use_id.clone(),
            agent_id: self.agent_id.clone(),
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
    #[serde(rename = "updatedMCPToolOutput", skip_serializing_if = "Option::is_none")]
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

        assert_eq!(
            json["hookSpecificOutput"]["permissionDecision"],
            "allow"
        );
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecisionReason"],
            "Read-only operation"
        );
        assert_eq!(
            json["hookSpecificOutput"]["hookEventName"],
            "PreToolUse"
        );
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
            "tool_output": {
                "stdout": "Compiling...\nFinished",
                "stderr": "",
                "exitCode": 0
            }
        });

        let payload: HookPayload = serde_json::from_value(input).unwrap();
        assert_eq!(payload.hook_event_name, "PostToolUse");
        assert!(payload.tool_output.is_some());
        let output = payload.tool_output.unwrap();
        assert_eq!(output["stdout"], "Compiling...\nFinished");
        assert_eq!(output["exitCode"], 0);
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
}
