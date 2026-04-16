use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::firewall::{Decision, Priority};
use crate::models::EvaluationInput;

/// Maximum length for tool_input command fields in queue entries.
const MAX_COMMAND_LEN: usize = 200;

/// An entry in the approval queue.
#[derive(Debug, Serialize, Deserialize)]
pub struct QueueEntry {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub agent_id: Option<String>,
    pub tool: String,
    pub input: serde_json::Value,
    pub rule_matched: Option<String>,
    pub priority: String,
    pub reason: String,
}

/// Truncate tool_input for queue storage (Fix 16).
/// - command: first MAX_COMMAND_LEN chars
/// - file_path: keep the path, redact content fields
/// - other string values: first MAX_COMMAND_LEN chars
fn truncate_input(tool_name: &str, input: &serde_json::Value) -> serde_json::Value {
    let mut truncated = input.clone();
    if let Some(obj) = truncated.as_object_mut() {
        match tool_name {
            "Bash" => {
                if let Some(cmd) = obj.get_mut("command") {
                    if let Some(s) = cmd.as_str() {
                        if s.len() > MAX_COMMAND_LEN {
                            *cmd =
                                serde_json::Value::String(format!("{}...", &s[..MAX_COMMAND_LEN]));
                        }
                    }
                }
            }
            "Write" => {
                // Keep file_path, redact content
                if obj.contains_key("content") {
                    obj.insert(
                        "content".to_string(),
                        serde_json::Value::String("[REDACTED]".to_string()),
                    );
                }
            }
            "Edit" => {
                // Keep file_path, redact old_string and new_string
                for key in &["old_string", "new_string"] {
                    if let Some(v) = obj.get_mut(*key) {
                        if let Some(s) = v.as_str() {
                            if s.len() > MAX_COMMAND_LEN {
                                *v = serde_json::Value::String(format!(
                                    "{}...",
                                    &s[..MAX_COMMAND_LEN]
                                ));
                            }
                        }
                    }
                }
            }
            _ => {
                // Generic: truncate any long string values
                for v in obj.values_mut() {
                    if let Some(s) = v.as_str() {
                        if s.len() > MAX_COMMAND_LEN {
                            *v = serde_json::Value::String(format!("{}...", &s[..MAX_COMMAND_LEN]));
                        }
                    }
                }
            }
        }
    }
    truncated
}

/// Write a pending approval entry to disk.
/// Filename: {timestamp_ms}-{tool_use_id}.json for uniqueness across concurrent CC instances.
pub fn enqueue_pending(
    config_dir: &Path,
    payload: &EvaluationInput,
    decision: &Decision,
) -> Result<PathBuf> {
    let pending_dir = config_dir.join("queue/pending");
    std::fs::create_dir_all(&pending_dir)
        .with_context(|| format!("Failed to create pending dir: {}", pending_dir.display()))?;

    let now = Utc::now();
    let timestamp_ms = now.timestamp_millis();
    let filename = format!("{}-{}.json", timestamp_ms, payload.tool_use_id);
    let filepath = pending_dir.join(&filename);

    let priority_str = match decision.priority {
        Priority::Low => "low",
        Priority::Medium => "medium",
        Priority::High => "high",
    };

    let entry = QueueEntry {
        id: format!("{}-{}", timestamp_ms, payload.tool_use_id),
        timestamp: now,
        agent_id: payload.agent_id.clone(),
        tool: payload.tool_name.clone(),
        input: truncate_input(&payload.tool_name, &payload.tool_input),
        rule_matched: decision.matched_rule.clone(),
        priority: priority_str.to_string(),
        reason: decision.reason.clone(),
    };

    let json = serde_json::to_string_pretty(&entry).context("Failed to serialize queue entry")?;
    std::fs::write(&filepath, json)
        .with_context(|| format!("Failed to write queue entry: {}", filepath.display()))?;

    Ok(filepath)
}

/// List all pending approval entries, sorted by timestamp (oldest first).
/// Auto-prunes entries older than 30 days.
pub fn list_pending(config_dir: &Path) -> Result<Vec<QueueEntry>> {
    let pending_dir = config_dir.join("queue/pending");
    if !pending_dir.exists() {
        return Ok(Vec::new());
    }

    // Auto-prune entries older than 30 days
    let _ = prune_old_entries(config_dir, Duration::days(30));

    let mut entries = Vec::new();
    for entry in std::fs::read_dir(&pending_dir)
        .with_context(|| format!("Failed to read pending dir: {}", pending_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let contents = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read queue file: {}", path.display()))?;
        match serde_json::from_str::<QueueEntry>(&contents) {
            Ok(qe) => entries.push(qe),
            Err(_) => continue, // skip malformed entries
        }
    }

    entries.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    Ok(entries)
}

/// Prune queue entries older than the given duration.
/// Moves them to queue/decided/ for archival.
pub fn prune_old_entries(config_dir: &Path, max_age: Duration) -> Result<usize> {
    let pending_dir = config_dir.join("queue/pending");
    if !pending_dir.exists() {
        return Ok(0);
    }

    let decided_dir = config_dir.join("queue/decided");
    std::fs::create_dir_all(&decided_dir)
        .with_context(|| format!("Failed to create decided dir: {}", decided_dir.display()))?;

    let cutoff = Utc::now() - max_age;
    let mut pruned = 0;

    for entry in std::fs::read_dir(&pending_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }

        let contents = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let qe: QueueEntry = match serde_json::from_str(&contents) {
            Ok(q) => q,
            Err(_) => continue,
        };

        if qe.timestamp < cutoff {
            let dest = decided_dir.join(entry.file_name());
            let _ = std::fs::rename(&path, &dest);
            pruned += 1;
        }
    }

    Ok(pruned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Action;
    use serde_json::json;
    use tempfile::TempDir;

    fn make_test_payload() -> EvaluationInput {
        EvaluationInput {
            session_id: "test-session".to_string(),
            tool_name: "Bash".to_string(),
            tool_input: json!({"command": "nmap -sV target"}),
            tool_use_id: "tu_001".to_string(),
            agent_id: Some("pentester".to_string()),
            cwd: "/tmp".to_string(),
        }
    }

    fn make_test_decision() -> Decision {
        Decision {
            action: Action::Ask,
            reason: "Potentially destructive".to_string(),
            matched_rule: Some("restricted[0]".to_string()),
            priority: Priority::Medium,
        }
    }

    #[test]
    fn test_enqueue_and_list() {
        let tmp = TempDir::new().unwrap();
        let config_dir = tmp.path();
        std::fs::create_dir_all(config_dir.join("queue/pending")).unwrap();

        let payload = make_test_payload();
        let decision = make_test_decision();

        let path = enqueue_pending(config_dir, &payload, &decision).unwrap();
        assert!(path.exists());

        let entries = list_pending(config_dir).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].tool, "Bash");
        assert_eq!(entries[0].agent_id, Some("pentester".to_string()));
        assert_eq!(entries[0].priority, "medium");
    }

    #[test]
    fn test_list_empty_queue() {
        let tmp = TempDir::new().unwrap();
        let entries = list_pending(tmp.path()).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_truncate_input_bash_long_command() {
        let long_cmd = "x".repeat(300);
        let input = json!({"command": long_cmd});
        let truncated = truncate_input("Bash", &input);
        let cmd = truncated["command"].as_str().unwrap();
        assert!(cmd.len() <= MAX_COMMAND_LEN + 3); // +3 for "..."
        assert!(cmd.ends_with("..."));
    }

    #[test]
    fn test_truncate_input_write_redacts_content() {
        let input = json!({"file_path": "/src/main.rs", "content": "very long content here"});
        let truncated = truncate_input("Write", &input);
        assert_eq!(truncated["file_path"], "/src/main.rs");
        assert_eq!(truncated["content"], "[REDACTED]");
    }

    #[test]
    fn test_truncate_input_short_command_unchanged() {
        let input = json!({"command": "ls -la"});
        let truncated = truncate_input("Bash", &input);
        assert_eq!(truncated["command"], "ls -la");
    }

    #[test]
    fn test_prune_old_entries() {
        let tmp = TempDir::new().unwrap();
        let config_dir = tmp.path();
        let pending_dir = config_dir.join("queue/pending");
        std::fs::create_dir_all(&pending_dir).unwrap();

        // Create an old entry (timestamp 40 days ago)
        let old_entry = QueueEntry {
            id: "old-entry".to_string(),
            timestamp: Utc::now() - Duration::days(40),
            agent_id: None,
            tool: "Bash".to_string(),
            input: json!({"command": "ls"}),
            rule_matched: None,
            priority: "low".to_string(),
            reason: "test".to_string(),
        };
        let old_path = pending_dir.join("old-entry.json");
        std::fs::write(&old_path, serde_json::to_string(&old_entry).unwrap()).unwrap();

        // Create a recent entry
        let new_entry = QueueEntry {
            id: "new-entry".to_string(),
            timestamp: Utc::now(),
            agent_id: None,
            tool: "Bash".to_string(),
            input: json!({"command": "ls"}),
            rule_matched: None,
            priority: "low".to_string(),
            reason: "test".to_string(),
        };
        let new_path = pending_dir.join("new-entry.json");
        std::fs::write(&new_path, serde_json::to_string(&new_entry).unwrap()).unwrap();

        let pruned = prune_old_entries(config_dir, Duration::days(30)).unwrap();
        assert_eq!(pruned, 1);

        // Old entry moved to decided/
        assert!(!old_path.exists());
        assert!(config_dir.join("queue/decided/old-entry.json").exists());

        // New entry still in pending/
        assert!(new_path.exists());
    }
}
