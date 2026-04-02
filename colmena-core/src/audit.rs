use std::io::Write;
use std::path::Path;

use chrono::Utc;

/// Audit event types for the append-only log.
#[derive(Debug)]
pub enum AuditEvent<'a> {
    /// Firewall decision: ALLOW, ASK, or DENY
    Decision {
        action: &'a str,
        session_id: &'a str,
        agent_id: Option<&'a str>,
        tool: &'a str,
        /// Key field from tool_input (e.g. command or file_path), truncated
        key_field: &'a str,
        rule: &'a str,
    },
    /// Delegation created
    DelegateCreate {
        tool: &'a str,
        agent: Option<&'a str>,
        ttl: &'a str,
        source: &'a str,
    },
    /// Delegation matched during evaluation
    DelegateMatch {
        tool: &'a str,
        agent: Option<&'a str>,
    },
    /// Delegation expired (pruned)
    DelegateExpire {
        tool: &'a str,
        agent: Option<&'a str>,
    },
    /// Delegation revoked
    DelegateRevoke {
        tool: &'a str,
        agent: Option<&'a str>,
    },
    /// Review submitted for cross-review
    ReviewSubmit {
        review_id: &'a str,
        author_role: &'a str,
        artifact_path: &'a str,
        mission: &'a str,
    },
    /// Review evaluated with scores and findings
    ReviewEvaluate {
        review_id: &'a str,
        reviewer_role: &'a str,
        score_avg: f64,
        finding_count: usize,
    },
    /// Review completed (auto-approved or human-reviewed)
    ReviewCompleted {
        review_id: &'a str,
        outcome: &'a str,
    },
    /// Mission activated with role-bound delegations
    MissionActivate {
        mission_id: &'a str,
        agent_count: usize,
        delegation_count: usize,
    },
    /// Mission deactivated (all delegations revoked)
    MissionDeactivate {
        mission_id: &'a str,
        revoked: usize,
    },
    /// ELO calibration changed an agent's trust tier
    Calibration {
        agent: &'a str,
        old_tier: &'a str,
        new_tier: &'a str,
        elo: i32,
    },
}

/// Format an audit event as a single log line.
fn format_event(event: &AuditEvent) -> String {
    let ts = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    match event {
        AuditEvent::Decision { action, session_id, agent_id, tool, key_field, rule } => {
            let agent = agent_id.unwrap_or("*");
            // Truncate key_field to 120 chars for log readability
            let truncated = if key_field.len() > 120 {
                format!("{}...", &key_field[..117])
            } else {
                key_field.to_string()
            };
            format!("[{ts}] {action:<5} session={session_id} agent={agent} tool={tool} key=\"{truncated}\" rule={rule}")
        }
        AuditEvent::DelegateCreate { tool, agent, ttl, source } => {
            let agent = agent.unwrap_or("*");
            format!("[{ts}] DELEGATE_CREATE tool={tool} agent={agent} ttl={ttl} source={source}")
        }
        AuditEvent::DelegateMatch { tool, agent } => {
            let agent = agent.unwrap_or("*");
            format!("[{ts}] DELEGATE_MATCH tool={tool} agent={agent}")
        }
        AuditEvent::DelegateExpire { tool, agent } => {
            let agent = agent.unwrap_or("*");
            format!("[{ts}] DELEGATE_EXPIRE tool={tool} agent={agent}")
        }
        AuditEvent::DelegateRevoke { tool, agent } => {
            let agent = agent.unwrap_or("*");
            format!("[{ts}] DELEGATE_REVOKE tool={tool} agent={agent}")
        }
        AuditEvent::ReviewSubmit { review_id, author_role, artifact_path, mission } => {
            format!("[{ts}] REVIEW_SUBMIT review={review_id} author={author_role} artifact={artifact_path} mission={mission}")
        }
        AuditEvent::ReviewEvaluate { review_id, reviewer_role, score_avg, finding_count } => {
            format!("[{ts}] REVIEW_EVALUATE review={review_id} reviewer={reviewer_role} score_avg={score_avg:.1} findings={finding_count}")
        }
        AuditEvent::ReviewCompleted { review_id, outcome } => {
            format!("[{ts}] REVIEW_COMPLETED review={review_id} outcome={outcome}")
        }
        AuditEvent::MissionActivate { mission_id, agent_count, delegation_count } => {
            format!("[{ts}] MISSION_ACTIVATE mission={mission_id} agents={agent_count} delegations={delegation_count}")
        }
        AuditEvent::MissionDeactivate { mission_id, revoked } => {
            format!("[{ts}] MISSION_DEACTIVATE mission={mission_id} revoked={revoked}")
        }
        AuditEvent::Calibration { agent, old_tier, new_tier, elo } => {
            format!("[{ts}] CALIBRATION agent={agent} old_tier={old_tier} new_tier={new_tier} elo={elo}")
        }
    }
}

/// Append an audit event to the audit log file.
/// Best-effort: never panics, never fails the caller. Returns Ok/Err for testing.
pub fn log_event(audit_log: &Path, event: &AuditEvent) -> std::io::Result<()> {
    let line = format_event(event);
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(audit_log)?;
    writeln!(file, "{}", line)?;
    Ok(())
}

/// Extract a key field from tool_input for audit logging.
/// Returns a short summary (command, file_path, or first key).
pub fn extract_key_field(tool_name: &str, tool_input: &serde_json::Value) -> String {
    match tool_name {
        "Bash" => tool_input
            .get("command")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        "Read" | "Write" | "Edit" => tool_input
            .get("file_path")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        "Glob" | "Grep" => tool_input
            .get("pattern")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        _ => {
            // Return first string value, or empty
            if let Some(obj) = tool_input.as_object() {
                obj.values()
                    .find_map(|v| v.as_str())
                    .unwrap_or("")
                    .to_string()
            } else {
                String::new()
            }
        }
    }
}

/// Session-level statistics parsed from the audit log.
#[derive(Debug, Default)]
pub struct SessionStats {
    pub total_decisions: usize,
    pub allow_count: usize,
    pub ask_count: usize,
    pub deny_count: usize,
    pub unique_agents: usize,
    pub unique_tools: usize,
    pub delegation_matches: usize,
}

/// Parse audit log and compute stats for a specific session (or all sessions if None).
pub fn session_stats(audit_log: &Path, session_id: Option<&str>) -> SessionStats {
    let contents = match std::fs::read_to_string(audit_log) {
        Ok(c) => c,
        Err(_) => return SessionStats::default(),
    };

    let mut stats = SessionStats::default();
    let mut agents = std::collections::HashSet::new();
    let mut tools = std::collections::HashSet::new();

    for line in contents.lines() {
        // Filter by session if provided
        if let Some(sid) = session_id {
            if !line.contains(&format!("session={sid}")) {
                // Also count non-session lines like DELEGATE_MATCH
                if line.contains("DELEGATE_MATCH") {
                    stats.delegation_matches += 1;
                }
                continue;
            }
        }

        if line.contains("] ALLOW ") {
            stats.allow_count += 1;
            stats.total_decisions += 1;
        } else if line.contains("] ASK ") || line.contains("] ASK  ") {
            stats.ask_count += 1;
            stats.total_decisions += 1;
        } else if line.contains("] DENY ") {
            stats.deny_count += 1;
            stats.total_decisions += 1;
        } else if line.contains("DELEGATE_MATCH") {
            stats.delegation_matches += 1;
            continue;
        } else {
            continue;
        }

        // Extract agent
        if let Some(start) = line.find("agent=") {
            let rest = &line[start + 6..];
            let agent = rest.split_whitespace().next().unwrap_or("*");
            if agent != "*" {
                agents.insert(agent.to_string());
            }
        }

        // Extract tool
        if let Some(start) = line.find("tool=") {
            let rest = &line[start + 5..];
            let tool = rest.split_whitespace().next().unwrap_or("");
            if !tool.is_empty() {
                tools.insert(tool.to_string());
            }
        }
    }

    stats.unique_agents = agents.len();
    stats.unique_tools = tools.len();
    stats
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    #[test]
    fn test_log_decision_event() {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("audit.log");

        let event = AuditEvent::Decision {
            action: "ALLOW",
            session_id: "sess_123",
            agent_id: Some("pentester"),
            tool: "Read",
            key_field: "/src/main.rs",
            rule: "trust_circle[0]",
        };

        log_event(&log_path, &event).unwrap();

        let contents = std::fs::read_to_string(&log_path).unwrap();
        assert!(contents.contains("ALLOW"));
        assert!(contents.contains("sess_123"));
        assert!(contents.contains("pentester"));
        assert!(contents.contains("Read"));
        assert!(contents.contains("trust_circle[0]"));
    }

    #[test]
    fn test_log_delegate_create_event() {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("audit.log");

        let event = AuditEvent::DelegateCreate {
            tool: "Bash",
            agent: None,
            ttl: "4h",
            source: "cli",
        };

        log_event(&log_path, &event).unwrap();

        let contents = std::fs::read_to_string(&log_path).unwrap();
        assert!(contents.contains("DELEGATE_CREATE"));
        assert!(contents.contains("tool=Bash"));
        assert!(contents.contains("agent=*"));
        assert!(contents.contains("ttl=4h"));
    }

    #[test]
    fn test_log_delegate_match_event() {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("audit.log");

        let event = AuditEvent::DelegateMatch {
            tool: "Bash",
            agent: Some("pentester"),
        };

        log_event(&log_path, &event).unwrap();

        let contents = std::fs::read_to_string(&log_path).unwrap();
        assert!(contents.contains("DELEGATE_MATCH"));
        assert!(contents.contains("agent=pentester"));
    }

    #[test]
    fn test_log_append_only() {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("audit.log");

        let event1 = AuditEvent::Decision {
            action: "ALLOW",
            session_id: "s1",
            agent_id: None,
            tool: "Read",
            key_field: "file1",
            rule: "trust_circle[0]",
        };
        let event2 = AuditEvent::Decision {
            action: "ASK",
            session_id: "s1",
            agent_id: None,
            tool: "Bash",
            key_field: "rm -r /tmp",
            rule: "restricted[0]",
        };

        log_event(&log_path, &event1).unwrap();
        log_event(&log_path, &event2).unwrap();

        let contents = std::fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("ALLOW"));
        assert!(lines[1].contains("ASK"));
    }

    #[test]
    fn test_extract_key_field_bash() {
        let input = json!({"command": "ls -la"});
        assert_eq!(extract_key_field("Bash", &input), "ls -la");
    }

    #[test]
    fn test_extract_key_field_read() {
        let input = json!({"file_path": "/src/main.rs"});
        assert_eq!(extract_key_field("Read", &input), "/src/main.rs");
    }

    #[test]
    fn test_extract_key_field_unknown_tool() {
        let input = json!({"url": "https://example.com"});
        assert_eq!(extract_key_field("WebFetch", &input), "https://example.com");
    }

    #[test]
    fn test_key_field_truncation() {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("audit.log");

        let long_key = "x".repeat(200);
        let event = AuditEvent::Decision {
            action: "ALLOW",
            session_id: "s1",
            agent_id: None,
            tool: "Bash",
            key_field: &long_key,
            rule: "trust_circle[0]",
        };

        log_event(&log_path, &event).unwrap();
        let contents = std::fs::read_to_string(&log_path).unwrap();
        // Should be truncated with ...
        assert!(contents.contains("..."));
        assert!(!contents.contains(&long_key));
    }

    #[test]
    fn test_delegate_revoke_event() {
        let tmp = TempDir::new().unwrap();
        let log_path = tmp.path().join("audit.log");

        let event = AuditEvent::DelegateRevoke {
            tool: "WebFetch",
            agent: Some("researcher"),
        };

        log_event(&log_path, &event).unwrap();

        let contents = std::fs::read_to_string(&log_path).unwrap();
        assert!(contents.contains("DELEGATE_REVOKE"));
        assert!(contents.contains("tool=WebFetch"));
        assert!(contents.contains("agent=researcher"));
    }
}
