use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Protocol-agnostic evaluation input.
/// Both the CLI (HookPayload) and MCP server map their inputs to this type.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EvaluationInput {
    pub session_id: String,
    pub tool_name: String,
    pub tool_input: Value,
    pub tool_use_id: String,
    pub agent_id: Option<String>,
    pub cwd: String,
}
