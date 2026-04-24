use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Protocol-agnostic evaluation input.
/// Both the CLI (HookPayload) and MCP server map their inputs to this type.
///
/// `agent_id` and `agent_type` semantics:
/// - `agent_id` is the per-invocation identifier Claude Code assigns to a
///   spawned subagent (may be an ephemeral hash in recent CC versions, or the
///   stable role id when Colmena `mission_spawn` generated the delegation).
/// - `agent_type` is the stable agent class name — the `name:` field from the
///   subagent `.md` frontmatter, e.g. `cron-worker`, `pentester`. It does
///   not change across spawns of the same agent.
///
/// The firewall treats either field as a valid match key for
/// `agent_overrides` / runtime delegations so that single-agent scoped
/// permissions (via `agent_type`) coexist with mission-driven delegations
/// (via `agent_id`).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EvaluationInput {
    pub session_id: String,
    pub tool_name: String,
    pub tool_input: Value,
    pub tool_use_id: String,
    pub agent_id: Option<String>,
    #[serde(default)]
    pub agent_type: Option<String>,
    pub cwd: String,
}
