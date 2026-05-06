//! Detect Agent spawn patterns from audit.log for `mission init --from-history`.
//!
//! Parses audit.log lines in both JSONL and the native key=value format.
//! See `crate::audit` for the canonical event format used by the rest of Colmena.

use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Detected spawn activity from audit.log analysis.
#[derive(Debug, Clone)]
pub struct SpawnHistory {
    /// Detected role IDs from Agent tool spawns.
    pub roles: Vec<String>,
    /// Paths observed in spawn context.
    pub paths: Vec<String>,
    /// Frequent bash commands extracted from agent activity.
    pub frequent_commands: Vec<String>,
    /// Count of spawn events detected.
    pub total_spawns: usize,
    /// Sessions with spawn activity.
    pub sessions: Vec<String>,
}

impl SpawnHistory {
    /// Parse audit.log and detect Agent tool spawn patterns.
    ///
    /// Handles two log formats:
    /// - JSONL (one JSON object per line): expected fields: `tool`, `agent_type`,
    ///   `session_id`, `tool_input` (with `command` and path fields)
    /// - Native key=value format (`[ts] EVENT key1=val1 key2=val2 ...`):
    ///   parsed from DECISION and DELEGATE_EXPIRE events with `tool=Agent`
    ///   or delegation agent information.
    pub fn from_audit_log(audit_log_path: &Path, session_id: Option<&str>) -> Result<Self> {
        if !audit_log_path.exists() {
            return Ok(Self {
                roles: vec![],
                paths: vec![],
                frequent_commands: vec![],
                total_spawns: 0,
                sessions: vec![],
            });
        }

        let content = std::fs::read_to_string(audit_log_path)
            .with_context(|| format!("Failed to read {}", audit_log_path.display()))?;

        let mut roles: HashSet<String> = HashSet::new();
        let mut paths: HashSet<String> = HashSet::new();
        let mut commands: HashMap<String, usize> = HashMap::new();
        let mut sessions: HashSet<String> = HashSet::new();
        let mut total_spawns = 0;

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            // Try JSONL first
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(trimmed) {
                parse_jsonl_line(
                    &parsed,
                    session_id,
                    &mut roles,
                    &mut sessions,
                    &mut paths,
                    &mut commands,
                    &mut total_spawns,
                );
                continue;
            }

            // Fall back to native key=value audit format
            parse_kv_line(
                trimmed,
                session_id,
                &mut roles,
                &mut sessions,
                &mut paths,
                &mut commands,
                &mut total_spawns,
            );
        }

        let mut cmd_vec: Vec<(String, usize)> = commands.into_iter().collect();
        cmd_vec.sort_by_key(|b| std::cmp::Reverse(b.1));
        let frequent_commands: Vec<String> = cmd_vec
            .into_iter()
            .take(10)
            .map(|(cmd, count)| format!("{}  # observed {}x", cmd, count))
            .collect();

        Ok(Self {
            roles: {
                let mut v: Vec<String> = roles.into_iter().collect();
                v.sort();
                v
            },
            paths: {
                let mut v: Vec<String> = paths.into_iter().collect();
                v.sort();
                v
            },
            frequent_commands,
            total_spawns,
            sessions: {
                let mut v: Vec<String> = sessions.into_iter().collect();
                v.sort();
                v
            },
        })
    }
}

/// Parse a JSONL audit log line and extract Agent spawn information.
fn parse_jsonl_line(
    parsed: &serde_json::Value,
    session_id: Option<&str>,
    roles: &mut HashSet<String>,
    sessions: &mut HashSet<String>,
    paths: &mut HashSet<String>,
    commands: &mut HashMap<String, usize>,
    total_spawns: &mut usize,
) {
    let tool = parsed.get("tool").and_then(|v| v.as_str()).unwrap_or("");
    if tool != "Agent" {
        return;
    }

    if let Some(sid) = session_id {
        let event_session = parsed
            .get("session_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if event_session != sid {
            return;
        }
    }

    *total_spawns += 1;

    if let Some(agent_type) = parsed.get("agent_type").and_then(|v| v.as_str()) {
        if !agent_type.is_empty() {
            roles.insert(agent_type.to_string());
        }
    }
    if let Some(sid) = parsed.get("session_id").and_then(|v| v.as_str()) {
        if !sid.is_empty() {
            sessions.insert(sid.to_string());
        }
    }

    if let Some(tool_input) = parsed.get("tool_input").and_then(|v| v.as_object()) {
        for key in &["path", "file_path", "cwd", "paths"] {
            if let Some(p) = tool_input.get(*key).and_then(|v| v.as_str()) {
                if !p.is_empty() && p.starts_with('/') {
                    paths.insert(p.to_string());
                }
            }
        }
        if let Some(cmd) = tool_input.get("command").and_then(|v| v.as_str()) {
            if !cmd.is_empty() {
                let skeleton = extract_command_skeleton(cmd);
                *commands.entry(skeleton).or_insert(0) += 1;
            }
        }
    }
}

/// Split a line of key=value pairs (audit log format) into (key, value) tuples.
/// Handles quoted values with spaces: `key="value with spaces" other_key=simple`.
fn split_kv_pairs(line: &str) -> Vec<(&str, &str)> {
    let mut pairs: Vec<(&str, &str)> = Vec::new();
    let mut pos = 0;
    let bytes = line.as_bytes();

    while pos < bytes.len() {
        // Skip whitespace
        while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
            pos += 1;
        }
        if pos >= bytes.len() {
            break;
        }

        // Find `key=`
        let eq_pos = match line[pos..].find('=') {
            Some(p) => pos + p,
            None => break,
        };
        let key = &line[pos..eq_pos];
        pos = eq_pos + 1; // skip '='

        if pos >= bytes.len() {
            break;
        }

        // Check for quoted value
        if bytes[pos] == b'"' {
            // Find closing quote (handles escaped quotes)
            pos += 1;
            let start = pos;
            while pos < bytes.len() {
                if bytes[pos] == b'\\' && pos + 1 < bytes.len() {
                    pos += 2; // skip escaped char
                    continue;
                }
                if bytes[pos] == b'"' {
                    let value = &line[start..pos];
                    pairs.push((key, value));
                    pos += 1; // skip closing quote
                    break;
                }
                pos += 1;
            }
        } else {
            // Unquoted value: ends at whitespace or end of line
            let start = pos;
            while pos < bytes.len() && !bytes[pos].is_ascii_whitespace() {
                pos += 1;
            }
            let value = &line[start..pos];
            pairs.push((key, value));
        }
    }

    pairs
}

/// Parse a native key=value audit log line and extract Agent spawn information.
///
/// Format: `[timestamp] EVENT_TYPE key1=val1 key2=val2 ...`
///
/// Recognised events:
/// - All DECISION types (ALLOW/ASK/DENY) with `tool=Agent`
/// - DELEGATE_EXPIRE with `tool=Agent` (agent is the role name)
fn parse_kv_line(
    line: &str,
    session_id: Option<&str>,
    roles: &mut HashSet<String>,
    sessions: &mut HashSet<String>,
    paths: &mut HashSet<String>,
    commands: &mut HashMap<String, usize>,
    total_spawns: &mut usize,
) {
    // Strip timestamp prefix: [2026-05-06T...]
    let rest = match line.find("] ") {
        Some(pos) => {
            let after = &line[pos + 2..];
            after.trim_start()
        }
        None => return,
    };

    // The event type is the first whitespace-delimited token, then key=value pairs
    let (event_type, rest_kv) = {
        let rest_trimmed = rest.trim_start();
        let skip = rest.len() - rest_trimmed.len();
        let first_space = rest_trimmed
            .find(char::is_whitespace)
            .unwrap_or(rest_trimmed.len());
        let event = &rest_trimmed[..first_space];
        // Rest of line after event type
        let kv_raw = &rest[skip + first_space..];
        (event, kv_raw)
    };

    // Extract key=value pairs
    let rest = rest_kv.trim();
    let pairs = split_kv_pairs(rest);

    // Build a quick-lookup map
    let mut map: HashMap<&str, Vec<&str>> = HashMap::new();
    for (k, v) in &pairs {
        map.entry(k).or_default().push(v);
    }

    let tool = map
        .get("tool")
        .and_then(|v| v.first())
        .copied()
        .unwrap_or("");

    // Check for Agent tool events in DECISION events or DELEGATE_EXPIRE
    let is_agent_event = tool == "Agent"
        && (event_type == "ALLOW"
            || event_type == "ASK"
            || event_type == "DENY"
            || event_type == "DELEGATE_EXPIRE");

    if !is_agent_event {
        return;
    }

    let event_session = map
        .get("session")
        .and_then(|v| v.first())
        .copied()
        .unwrap_or("");

    if let Some(sid) = session_id {
        if event_session != sid {
            return;
        }
    }

    *total_spawns += 1;

    // Extract agent/role info
    let agent = map
        .get("agent")
        .and_then(|v| v.first())
        .copied()
        .unwrap_or("");
    if !agent.is_empty() && agent != "*" {
        roles.insert(agent.to_string());
    }

    if !event_session.is_empty() {
        sessions.insert(event_session.to_string());
    }

    // For DECISION events, the key field contains the task description or command
    if let Some(key_values) = map.get("key") {
        for value in key_values {
            if value.starts_with('/') {
                paths.insert(value.to_string());
            } else if !value.is_empty() {
                let skeleton = extract_command_skeleton(value);
                if !skeleton.is_empty() {
                    *commands.entry(skeleton).or_insert(0) += 1;
                }
            }
        }
    }
}

/// Reduce a command to its first two words to build a skeleton for grouping.
fn extract_command_skeleton(command: &str) -> String {
    let parts: Vec<&str> = command.split_whitespace().collect();
    if parts.is_empty() {
        return String::new();
    }
    if parts.len() >= 2 {
        format!("{} {}", parts[0], parts[1])
    } else {
        parts[0].to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_audit_log() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("empty.log");
        std::fs::write(&path, "").unwrap();
        let history = SpawnHistory::from_audit_log(&path, None).unwrap();
        assert_eq!(history.total_spawns, 0);
        assert!(history.roles.is_empty());
    }

    #[test]
    fn test_detects_agent_spawns_jsonl() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("audit.log");
        std::fs::write(
            &path,
            r#"{"tool":"Agent","agent_type":"bbp_pentester_web","session_id":"sess-1","tool_input":{"command":"curl https://api.coinbase.com/v2/accounts"}}
{"tool":"Agent","agent_type":"auditor","session_id":"sess-1","tool_input":{}}
{"tool":"Bash","agent_type":"bbp_pentester_web","session_id":"sess-1","tool_input":{"command":"cargo test"}}
{"tool":"Agent","agent_type":"developer","session_id":"sess-2","tool_input":{"command":"cargo build --release","path":"/home/user/colmena"}}
"#,
        )
        .unwrap();
        let history = SpawnHistory::from_audit_log(&path, None).unwrap();
        assert_eq!(history.total_spawns, 3);
        assert_eq!(history.roles.len(), 3);
        assert!(history.roles.contains(&"bbp_pentester_web".to_string()));
        assert!(history.roles.contains(&"auditor".to_string()));
        assert!(history.roles.contains(&"developer".to_string()));
        assert!(!history.frequent_commands.is_empty());
    }

    #[test]
    fn test_session_filter_jsonl() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("audit.log");
        std::fs::write(
            &path,
            r#"{"tool":"Agent","agent_type":"role-a","session_id":"sess-1","tool_input":{}}
{"tool":"Agent","agent_type":"role-b","session_id":"sess-2","tool_input":{}}
"#,
        )
        .unwrap();
        let history = SpawnHistory::from_audit_log(&path, Some("sess-1")).unwrap();
        assert_eq!(history.total_spawns, 1);
        assert!(history.roles.contains(&"role-a".to_string()));
    }

    #[test]
    fn test_detects_agent_spawns_native_format() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("audit.log");
        std::fs::write(
            &path,
            r#"[2026-05-06T14:20:51Z] ASK   session=ses-1 agent=bbp_pentester_web tool=Agent key="Recon subdomain scan" rule=restricted[0]
[2026-05-06T14:34:43Z] ASK   session=ses-1 agent=auditor tool=Agent key="Code review" rule=restricted[0]
[2026-05-06T15:00:00Z] ALLOW session=ses-1 agent=* tool=Bash key="cargo test" rule=trust_circle[0]
[2026-05-06T16:00:00Z] ASK   session=ses-2 agent=developer tool=Agent key="Implement feature" rule=restricted[0]
"#,
        )
        .unwrap();
        let history = SpawnHistory::from_audit_log(&path, None).unwrap();
        assert_eq!(history.total_spawns, 3);
        assert!(history.roles.contains(&"bbp_pentester_web".to_string()));
        assert!(history.roles.contains(&"auditor".to_string()));
        assert!(history.roles.contains(&"developer".to_string()));
        assert_eq!(history.sessions.len(), 2);
    }

    #[test]
    fn test_native_format_session_filter() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("audit.log");
        std::fs::write(
            &path,
            r#"[2026-05-06T14:20:51Z] ASK   session=ses-1 agent=role-a tool=Agent key="Task A" rule=restricted[0]
[2026-05-06T15:00:00Z] ASK   session=ses-2 agent=role-b tool=Agent key="Task B" rule=restricted[0]
"#,
        )
        .unwrap();
        let history = SpawnHistory::from_audit_log(&path, Some("ses-1")).unwrap();
        assert_eq!(history.total_spawns, 1);
        assert!(history.roles.contains(&"role-a".to_string()));
    }

    #[test]
    fn test_delegate_expire_provides_role_names() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("audit.log");
        std::fs::write(
            &path,
            r#"[2026-05-06T14:28:44Z] DELEGATE_EXPIRE tool=Agent agent=colmena_architect source=role
[2026-05-06T14:28:44Z] DELEGATE_EXPIRE tool=Agent agent=bbp_pentester_web source=role
[2026-05-06T14:28:44Z] DELEGATE_EXPIRE tool=Bash agent=colmena_architect source=role
"#,
        )
        .unwrap();
        let history = SpawnHistory::from_audit_log(&path, None).unwrap();
        assert_eq!(history.total_spawns, 2);
        assert!(history.roles.contains(&"colmena_architect".to_string()));
        assert!(history.roles.contains(&"bbp_pentester_web".to_string()));
    }

    #[test]
    fn test_extract_command_skeleton() {
        assert_eq!(
            extract_command_skeleton("cargo test --workspace"),
            "cargo test"
        );
        assert_eq!(extract_command_skeleton("kubectl get pods"), "kubectl get");
        assert_eq!(extract_command_skeleton("curl"), "curl");
    }
}
