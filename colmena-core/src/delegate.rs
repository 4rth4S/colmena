use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::config::Action;

/// Maximum TTL for any delegation: 24 hours.
pub const MAX_TTL_HOURS: i64 = 24;

/// Default TTL for delegations: 4 hours.
pub const DEFAULT_TTL_HOURS: i64 = 4;

/// Conditions that scope a delegation's applicability.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DelegationConditions {
    /// Regex pattern matched against Bash tool_input["command"].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bash_pattern: Option<String>,
    /// File path must start with one of these directories.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_within: Option<Vec<String>>,
    /// File path must NOT match any of these glob patterns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_not_match: Option<Vec<String>>,
}

/// A runtime trust delegation added by the human during a session,
/// or auto-generated from role permissions at mission creation time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeDelegation {
    pub tool: String,
    pub agent_id: Option<String>,
    pub action: Action,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub session_id: Option<String>,
    /// Provenance: "human" (CLI), "role" (mission generation), "elo" (calibration)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Links this delegation to a specific mission for bulk revocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mission_id: Option<String>,
    /// Optional conditions that scope when this delegation matches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<DelegationConditions>,
}

/// Load runtime delegations from a JSON file, pruning any that have expired.
/// Returns expired delegations separately for audit logging.
/// Returns an empty vec if the file doesn't exist or can't be parsed.
pub fn load_delegations(path: &Path) -> Vec<RuntimeDelegation> {
    let (active, _expired) = load_delegations_with_expired(path);
    active
}

/// Load delegations, returning (active, expired) for audit logging of expirations.
pub fn load_delegations_with_expired(
    path: &Path,
) -> (Vec<RuntimeDelegation>, Vec<RuntimeDelegation>) {
    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return (Vec::new(), Vec::new()),
    };

    let delegations: Vec<RuntimeDelegation> = match serde_json::from_str(&contents) {
        Ok(d) => d,
        Err(_) => return (Vec::new(), Vec::new()),
    };

    // Resolve the config_dir from the delegations file path for mission validation
    let config_dir = path.parent().map(PathBuf::from);

    let now = Utc::now();
    let mut active = Vec::new();
    let mut expired = Vec::new();

    for d in delegations {
        // Fix #8: reject delegations without expires_at (TTL is mandatory)
        if d.expires_at.is_none() {
            eprintln!(
                "[colmena] WARNING: skipping delegation for tool '{}' without expires_at (TTL required)",
                d.tool
            );
            continue;
        }

        // Fix Finding #1 (DREAD 7.6): validate source="role" delegations have a valid
        // mission_id corresponding to an actual mission directory. Prevents JSON injection
        // where an agent writes delegations with source="role" that PermissionRequest treats
        // as legitimate missions.
        if d.source.as_deref() == Some("role") {
            if let Some(ref mission_id) = d.mission_id {
                if let Some(ref cfg_dir) = config_dir {
                    let mission_dir = cfg_dir.join("missions").join(mission_id);
                    if !mission_dir.is_dir() {
                        eprintln!(
                            "[colmena] WARNING: skipping delegation for tool '{}' with source='role' \
                             — mission directory '{}' not found (possible injection)",
                            d.tool, mission_dir.display()
                        );
                        continue;
                    }
                }
            } else {
                eprintln!(
                    "[colmena] WARNING: skipping delegation for tool '{}' with source='role' \
                     but no mission_id (injection prevented)",
                    d.tool
                );
                continue;
            }
        }

        match d.expires_at {
            Some(exp) if exp <= now => expired.push(d),
            _ => active.push(d),
        }
    }

    (active, expired)
}

/// Save delegations atomically — write to temp file then rename.
/// Validates all delegations before persisting (e.g., Bash scope check).
///
/// Fix Finding #2 (DREAD 5.0): Uses advisory file locking to prevent TOCTOU
/// race where two CC instances read→modify→save simultaneously, losing delegations.
pub fn save_delegations(path: &Path, delegations: &[RuntimeDelegation]) -> Result<()> {
    for d in delegations {
        validate_bash_delegation(d)?;
    }

    let json =
        serde_json::to_string_pretty(delegations).context("Failed to serialize delegations")?;

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let lock_path = dir.join(".runtime-delegations.lock");

    // Advisory lock: create exclusive lock file, hold for duration of write
    let _lock = acquire_file_lock(&lock_path)?;

    let tmp_path = dir.join(".runtime-delegations.tmp");

    std::fs::write(&tmp_path, &json).with_context(|| {
        format!(
            "Failed to write temp delegations file: {}",
            tmp_path.display()
        )
    })?;

    std::fs::rename(&tmp_path, path).with_context(|| {
        format!(
            "Failed to rename temp delegations file to {}",
            path.display()
        )
    })?;

    // Lock released on drop
    Ok(())
}

/// Advisory file lock using platform-specific locking.
/// Falls back to no-op on platforms that don't support flock.
struct FileLock {
    _file: std::fs::File,
}

impl Drop for FileLock {
    fn drop(&mut self) {
        // Lock released when file handle is closed on drop
    }
}

/// Acquire an advisory file lock. Returns a guard that releases on drop.
/// Best-effort: returns Ok even if locking is not supported on the platform.
fn acquire_file_lock(lock_path: &Path) -> Result<FileLock> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(lock_path)
        .with_context(|| format!("Failed to open lock file: {}", lock_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = file.as_raw_fd();
        // LOCK_EX = exclusive lock, blocks until acquired
        let ret = unsafe { libc::flock(fd, libc::LOCK_EX) };
        if ret != 0 {
            // Best-effort: log but continue without lock
            eprintln!(
                "[colmena] WARNING: failed to acquire file lock (flock returned {})",
                ret
            );
        }
    }

    Ok(FileLock { _file: file })
}

/// Validate that Bash delegations have at least one scope condition.
/// Unscoped Bash delegations are extremely dangerous as they auto-approve ALL commands.
pub fn validate_bash_delegation(delegation: &RuntimeDelegation) -> Result<()> {
    if delegation.tool != "Bash" {
        return Ok(());
    }
    match &delegation.conditions {
        Some(conditions) => {
            if conditions.bash_pattern.is_none() && conditions.path_within.is_none() {
                anyhow::bail!(
                    "Bash delegations require at least one scope condition: \
                     --bash-pattern or --path-within. \
                     Unscoped Bash delegations auto-approve ALL commands."
                )
            }
            // Validate bash_pattern regex compiles (prevent silently inactive delegations)
            if let Some(ref pattern) = conditions.bash_pattern {
                if regex::Regex::new(pattern).is_err() {
                    anyhow::bail!(
                        "Invalid bash_pattern regex '{}' in Bash delegation. Pattern must be a valid regex.",
                        pattern
                    );
                }
            }
            Ok(())
        }
        None => {
            anyhow::bail!(
                "Bash delegations require at least one scope condition: \
                 --bash-pattern or --path-within. \
                 Unscoped Bash delegations auto-approve ALL commands."
            )
        }
    }
}

/// Validate TTL hours: must be between 1 and MAX_TTL_HOURS.
pub fn validate_ttl(hours: i64) -> Result<Duration> {
    if !(1..=MAX_TTL_HOURS).contains(&hours) {
        anyhow::bail!(
            "TTL must be between 1 and {} hours, got {}",
            MAX_TTL_HOURS,
            hours
        );
    }
    Ok(Duration::hours(hours))
}

/// Revoke delegations matching tool and optional agent.
/// Returns the number of delegations revoked.
pub fn revoke_delegations(path: &Path, tool: &str, agent: Option<&str>) -> Result<usize> {
    let delegations = load_delegations(path);
    let before = delegations.len();

    let remaining: Vec<RuntimeDelegation> = delegations
        .into_iter()
        .filter(|d| {
            if d.tool != tool {
                return true; // keep — different tool
            }
            match agent {
                Some(a) => d.agent_id.as_deref() != Some(a), // keep if agent doesn't match
                None => false,                               // revoke all for this tool
            }
        })
        .collect();

    let revoked = before - remaining.len();
    save_delegations(path, &remaining)?;
    Ok(revoked)
}

/// Revoke all delegations associated with a specific mission.
/// Returns the number of delegations revoked.
pub fn revoke_by_mission(path: &Path, mission_id: &str) -> Result<usize> {
    let delegations = load_delegations(path);
    let before = delegations.len();

    let remaining: Vec<RuntimeDelegation> = delegations
        .into_iter()
        .filter(|d| d.mission_id.as_deref() != Some(mission_id))
        .collect();

    let revoked = before - remaining.len();
    save_delegations(path, &remaining)?;
    Ok(revoked)
}

/// List active delegations with formatted output.
pub fn list_delegations(path: &Path) -> Vec<RuntimeDelegation> {
    load_delegations(path)
}

// ── Mission revocation tracking ─────────────────────────────────────────────

/// Load the set of revoked mission IDs for the mid-session kill switch.
/// File: config/revoked-missions.json (JSON array of mission_id strings).
/// Returns an empty set if the file doesn't exist or can't be parsed.
pub fn load_revoked_missions(config_dir: &Path) -> std::collections::HashSet<String> {
    let path = config_dir.join("revoked-missions.json");
    match std::fs::read_to_string(&path) {
        Ok(contents) => serde_json::from_str(&contents).unwrap_or_default(),
        Err(_) => std::collections::HashSet::new(),
    }
}

/// Extract agent IDs from delegations belonging to a mission.
/// Used during revocation to identify which agents to block.
pub fn agents_for_mission(delegations: &[RuntimeDelegation], mission_id: &str) -> Vec<String> {
    delegations
        .iter()
        .filter(|d| d.mission_id.as_deref() == Some(mission_id))
        .filter_map(|d| d.agent_id.clone())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect()
}

/// Mark a mission's agents as revoked for the mid-session kill switch.
/// Appends agent IDs to config/revoked-missions.json so the PreToolUse hook
/// can deny their tool calls even if CC has learned session rules.
///
/// Fix Finding #7 (DREAD 5.2): Uses atomic write (tmp+rename) to prevent
/// corrupted JSON on crash, which would cause load_revoked_missions to return
/// an empty set (revoked agents recovering permissions).
pub fn mark_mission_agents_revoked(config_dir: &Path, agent_ids: &[String]) -> Result<()> {
    let path = config_dir.join("revoked-missions.json");
    let mut revoked = load_revoked_missions(config_dir);
    for agent_id in agent_ids {
        revoked.insert(agent_id.clone());
    }
    let json =
        serde_json::to_string_pretty(&revoked).context("Failed to serialize revoked missions")?;

    let tmp_path = config_dir.join(".revoked-missions.tmp");
    std::fs::write(&tmp_path, &json).with_context(|| {
        format!(
            "Failed to write temp revoked missions file: {}",
            tmp_path.display()
        )
    })?;
    std::fs::rename(&tmp_path, &path).with_context(|| {
        format!(
            "Failed to rename temp revoked missions file to {}",
            path.display()
        )
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use serde_json::json;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn make_delegation(tool: &str, hours_until_expiry: Option<i64>) -> serde_json::Value {
        let now = Utc::now();
        let mut d = json!({
            "tool": tool,
            "agent_id": null,
            "action": "auto-approve",
            "created_at": now.to_rfc3339(),
        });
        if let Some(hours) = hours_until_expiry {
            d["expires_at"] = json!((now + Duration::hours(hours)).to_rfc3339());
        }
        d
    }

    #[test]
    fn test_load_delegations_empty_file() {
        let result = load_delegations(Path::new("/nonexistent/path.json"));
        assert!(result.is_empty());
    }

    #[test]
    fn test_load_delegations_valid() {
        let delegations = json!([
            make_delegation("WebFetch", Some(4)),
            make_delegation("Bash", Some(4)),
        ]);

        let mut tmp = NamedTempFile::new().unwrap();
        write!(tmp, "{}", delegations).unwrap();

        let result = load_delegations(tmp.path());
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].tool, "WebFetch");
        assert_eq!(result[1].tool, "Bash");
    }

    #[test]
    fn test_load_delegations_prunes_expired() {
        let delegations = json!([
            make_delegation("WebFetch", Some(-1)), // expired 1 hour ago
            make_delegation("Bash", Some(4)),      // still valid
        ]);

        let mut tmp = NamedTempFile::new().unwrap();
        write!(tmp, "{}", delegations).unwrap();

        let result = load_delegations(tmp.path());
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].tool, "Bash");
    }

    #[test]
    fn test_load_delegations_with_expired_returns_both() {
        let delegations = json!([
            make_delegation("WebFetch", Some(-1)),
            make_delegation("Bash", Some(4)),
        ]);

        let mut tmp = NamedTempFile::new().unwrap();
        write!(tmp, "{}", delegations).unwrap();

        let (active, expired) = load_delegations_with_expired(tmp.path());
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].tool, "Bash");
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].tool, "WebFetch");
    }

    #[test]
    fn test_save_and_reload_delegations() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("delegations.json");

        let delegations = vec![RuntimeDelegation {
            tool: "Bash".to_string(),
            agent_id: None,
            action: Action::AutoApprove,
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + Duration::hours(4)),
            session_id: None,
            source: None,
            mission_id: None,
            conditions: Some(DelegationConditions {
                bash_pattern: Some("^cargo test".to_string()),
                path_within: None,
                path_not_match: None,
            }),
        }];

        save_delegations(&path, &delegations).unwrap();
        let reloaded = load_delegations(&path);
        assert_eq!(reloaded.len(), 1);
        assert_eq!(reloaded[0].tool, "Bash");
    }

    #[test]
    fn test_delegation_serde_roundtrip() {
        let d = RuntimeDelegation {
            tool: "Read".to_string(),
            agent_id: Some("pentester".to_string()),
            action: Action::AutoApprove,
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + Duration::hours(4)),
            session_id: Some("sess_123".to_string()),
            source: None,
            mission_id: None,
            conditions: None,
        };

        let json = serde_json::to_string(&d).unwrap();
        let parsed: RuntimeDelegation = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.tool, "Read");
        assert_eq!(parsed.agent_id, Some("pentester".to_string()));
    }

    #[test]
    fn test_validate_ttl_valid() {
        assert!(validate_ttl(1).is_ok());
        assert!(validate_ttl(4).is_ok());
        assert!(validate_ttl(24).is_ok());
    }

    #[test]
    fn test_validate_ttl_invalid() {
        assert!(validate_ttl(0).is_err());
        assert!(validate_ttl(-1).is_err());
        assert!(validate_ttl(25).is_err());
        assert!(validate_ttl(100).is_err());
    }

    #[test]
    fn test_revoke_delegations() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("delegations.json");

        let delegations = vec![
            RuntimeDelegation {
                tool: "Read".to_string(),
                agent_id: None,
                action: Action::AutoApprove,
                created_at: Utc::now(),
                expires_at: Some(Utc::now() + Duration::hours(4)),
                session_id: None,
                source: None,
                mission_id: None,
                conditions: None,
            },
            RuntimeDelegation {
                tool: "WebFetch".to_string(),
                agent_id: Some("researcher".to_string()),
                action: Action::AutoApprove,
                created_at: Utc::now(),
                expires_at: Some(Utc::now() + Duration::hours(4)),
                session_id: None,
                source: None,
                mission_id: None,
                conditions: None,
            },
        ];

        save_delegations(&path, &delegations).unwrap();

        // Revoke Read (all agents)
        let revoked = revoke_delegations(&path, "Read", None).unwrap();
        assert_eq!(revoked, 1);

        let remaining = load_delegations(&path);
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].tool, "WebFetch");
    }

    #[test]
    fn test_revoke_delegations_by_agent() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("delegations.json");

        let delegations = vec![
            RuntimeDelegation {
                tool: "Bash".to_string(),
                agent_id: Some("pentester".to_string()),
                action: Action::AutoApprove,
                created_at: Utc::now(),
                expires_at: Some(Utc::now() + Duration::hours(4)),
                session_id: None,
                source: None,
                mission_id: None,
                conditions: Some(DelegationConditions {
                    bash_pattern: Some("^cargo".to_string()),
                    path_within: None,
                    path_not_match: None,
                }),
            },
            RuntimeDelegation {
                tool: "Bash".to_string(),
                agent_id: Some("auditor".to_string()),
                action: Action::AutoApprove,
                created_at: Utc::now(),
                expires_at: Some(Utc::now() + Duration::hours(4)),
                session_id: None,
                source: None,
                mission_id: None,
                conditions: Some(DelegationConditions {
                    bash_pattern: Some("^cargo".to_string()),
                    path_within: None,
                    path_not_match: None,
                }),
            },
        ];

        save_delegations(&path, &delegations).unwrap();

        // Revoke only pentester's Bash delegation
        let revoked = revoke_delegations(&path, "Bash", Some("pentester")).unwrap();
        assert_eq!(revoked, 1);

        let remaining = load_delegations(&path);
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].agent_id, Some("auditor".to_string()));
    }

    #[test]
    fn test_revoke_nonexistent_returns_zero() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("delegations.json");

        save_delegations(&path, &[]).unwrap();
        let revoked = revoke_delegations(&path, "Read", None).unwrap();
        assert_eq!(revoked, 0);
    }

    #[test]
    fn test_validate_bash_delegation_without_conditions_fails() {
        let d = RuntimeDelegation {
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
        let result = validate_bash_delegation(&d);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("scope condition"));

        // Also test with empty conditions (both fields None)
        let d2 = RuntimeDelegation {
            tool: "Bash".to_string(),
            agent_id: None,
            action: Action::AutoApprove,
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + Duration::hours(4)),
            session_id: None,
            source: None,
            mission_id: None,
            conditions: Some(DelegationConditions {
                bash_pattern: None,
                path_within: None,
                path_not_match: None,
            }),
        };
        let result2 = validate_bash_delegation(&d2);
        assert!(result2.is_err());
    }

    #[test]
    fn test_validate_bash_delegation_rejects_invalid_regex() {
        let d = RuntimeDelegation {
            tool: "Bash".to_string(),
            agent_id: Some("test".to_string()),
            action: Action::AutoApprove,
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + Duration::hours(4)),
            session_id: None,
            source: Some("test".to_string()),
            mission_id: None,
            conditions: Some(DelegationConditions {
                bash_pattern: Some("(?P<broken>".to_string()),
                path_within: None,
                path_not_match: None,
            }),
        };
        let result = validate_bash_delegation(&d);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid bash_pattern regex"));
    }

    #[test]
    fn test_validate_bash_delegation_with_pattern_succeeds() {
        let d = RuntimeDelegation {
            tool: "Bash".to_string(),
            agent_id: None,
            action: Action::AutoApprove,
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + Duration::hours(4)),
            session_id: None,
            source: None,
            mission_id: None,
            conditions: Some(DelegationConditions {
                bash_pattern: Some("^cargo test".to_string()),
                path_within: None,
                path_not_match: None,
            }),
        };
        assert!(validate_bash_delegation(&d).is_ok());

        // Also test with path_within
        let d2 = RuntimeDelegation {
            tool: "Bash".to_string(),
            agent_id: None,
            action: Action::AutoApprove,
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + Duration::hours(4)),
            session_id: None,
            source: None,
            mission_id: None,
            conditions: Some(DelegationConditions {
                bash_pattern: None,
                path_within: Some(vec!["/home/user/project".to_string()]),
                path_not_match: None,
            }),
        };
        assert!(validate_bash_delegation(&d2).is_ok());
    }

    #[test]
    fn test_validate_non_bash_delegation_without_conditions_succeeds() {
        let d = RuntimeDelegation {
            tool: "Read".to_string(),
            agent_id: None,
            action: Action::AutoApprove,
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + Duration::hours(4)),
            session_id: None,
            source: None,
            mission_id: None,
            conditions: None,
        };
        assert!(validate_bash_delegation(&d).is_ok());
    }

    #[test]
    fn test_load_delegations_skips_missing_expires_at() {
        // Simulate a manually-injected delegation without expires_at
        let delegations = json!([
            {
                "tool": "WebFetch",
                "agent_id": null,
                "action": "auto-approve",
                "created_at": Utc::now().to_rfc3339(),
                "expires_at": null
            },
            make_delegation("Read", Some(4)),
        ]);

        let mut tmp = NamedTempFile::new().unwrap();
        write!(tmp, "{}", delegations).unwrap();

        let (active, _expired) = load_delegations_with_expired(tmp.path());
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].tool, "Read");
    }

    // ── Mission revocation tests ────────────────────────────────────────────

    #[test]
    fn test_load_revoked_missions_missing_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let revoked = load_revoked_missions(tmp.path());
        assert!(revoked.is_empty());
    }

    #[test]
    fn test_mark_and_load_revoked_missions() {
        let tmp = tempfile::TempDir::new().unwrap();
        mark_mission_agents_revoked(
            tmp.path(),
            &["pentester".to_string(), "researcher".to_string()],
        )
        .unwrap();

        let revoked = load_revoked_missions(tmp.path());
        assert_eq!(revoked.len(), 2);
        assert!(revoked.contains("pentester"));
        assert!(revoked.contains("researcher"));

        // Mark another — should add, not replace
        mark_mission_agents_revoked(tmp.path(), &["auditor".to_string()]).unwrap();
        let revoked = load_revoked_missions(tmp.path());
        assert_eq!(revoked.len(), 3);
        assert!(revoked.contains("auditor"));
        assert!(revoked.contains("pentester"));
    }

    #[test]
    fn test_agents_for_mission() {
        let delegations = vec![
            RuntimeDelegation {
                tool: "Read".to_string(),
                agent_id: Some("pentester".to_string()),
                action: Action::AutoApprove,
                created_at: Utc::now(),
                expires_at: Some(Utc::now() + Duration::hours(4)),
                session_id: None,
                source: Some("role".to_string()),
                mission_id: Some("mission-1".to_string()),
                conditions: None,
            },
            RuntimeDelegation {
                tool: "Grep".to_string(),
                agent_id: Some("researcher".to_string()),
                action: Action::AutoApprove,
                created_at: Utc::now(),
                expires_at: Some(Utc::now() + Duration::hours(4)),
                session_id: None,
                source: Some("role".to_string()),
                mission_id: Some("mission-1".to_string()),
                conditions: None,
            },
            RuntimeDelegation {
                tool: "Read".to_string(),
                agent_id: Some("other-agent".to_string()),
                action: Action::AutoApprove,
                created_at: Utc::now(),
                expires_at: Some(Utc::now() + Duration::hours(4)),
                session_id: None,
                source: Some("role".to_string()),
                mission_id: Some("mission-2".to_string()),
                conditions: None,
            },
        ];

        let mut agents = agents_for_mission(&delegations, "mission-1");
        agents.sort();
        assert_eq!(agents, vec!["pentester", "researcher"]);

        let agents2 = agents_for_mission(&delegations, "mission-2");
        assert_eq!(agents2, vec!["other-agent"]);

        let agents3 = agents_for_mission(&delegations, "nonexistent");
        assert!(agents3.is_empty());
    }

    // ── Finding #1 (DREAD 7.6): Delegation injection prevention tests ──────

    #[test]
    fn test_load_delegations_skips_role_delegation_without_mission_id() {
        // A delegation with source="role" but no mission_id should be rejected
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("runtime-delegations.json");
        let delegations = json!([
            {
                "tool": "Read",
                "agent_id": "injected-agent",
                "action": "auto-approve",
                "created_at": Utc::now().to_rfc3339(),
                "expires_at": (Utc::now() + Duration::hours(4)).to_rfc3339(),
                "source": "role"
            },
            {
                "tool": "Write",
                "agent_id": null,
                "action": "auto-approve",
                "created_at": Utc::now().to_rfc3339(),
                "expires_at": (Utc::now() + Duration::hours(4)).to_rfc3339(),
                "source": "human"
            }
        ]);
        std::fs::write(&path, serde_json::to_string(&delegations).unwrap()).unwrap();

        let result = load_delegations(&path);
        // The source="role" without mission_id should be filtered out
        assert_eq!(result.len(), 1, "Should only keep the human delegation");
        assert_eq!(result[0].tool, "Write");
    }

    #[test]
    fn test_load_delegations_skips_role_delegation_with_nonexistent_mission() {
        // A delegation with source="role" and a mission_id that doesn't have a
        // corresponding directory should be rejected (injection attempt)
        let tmp = tempfile::TempDir::new().unwrap();
        let config_dir = tmp.path();
        let path = config_dir.join("runtime-delegations.json");

        // Note: no missions/ directory created — the mission_id is fake
        let delegations = json!([
            {
                "tool": "Agent",
                "agent_id": "injected-agent",
                "action": "auto-approve",
                "created_at": Utc::now().to_rfc3339(),
                "expires_at": (Utc::now() + Duration::hours(4)).to_rfc3339(),
                "source": "role",
                "mission_id": "fake-mission-id"
            }
        ]);
        std::fs::write(&path, serde_json::to_string(&delegations).unwrap()).unwrap();

        let result = load_delegations(&path);
        assert!(
            result.is_empty(),
            "Delegation with nonexistent mission directory should be rejected"
        );
    }

    #[test]
    fn test_load_delegations_allows_role_delegation_with_valid_mission() {
        // A delegation with source="role" and a valid mission directory should pass
        let tmp = tempfile::TempDir::new().unwrap();
        let config_dir = tmp.path();
        let path = config_dir.join("runtime-delegations.json");

        // Create a real mission directory
        let mission_dir = config_dir.join("missions").join("real-mission");
        std::fs::create_dir_all(&mission_dir).unwrap();

        let delegations = json!([
            {
                "tool": "Read",
                "agent_id": "pentester",
                "action": "auto-approve",
                "created_at": Utc::now().to_rfc3339(),
                "expires_at": (Utc::now() + Duration::hours(4)).to_rfc3339(),
                "source": "role",
                "mission_id": "real-mission"
            }
        ]);
        std::fs::write(&path, serde_json::to_string(&delegations).unwrap()).unwrap();

        let result = load_delegations(&path);
        assert_eq!(
            result.len(),
            1,
            "Valid role delegation with real mission dir should be kept"
        );
        assert_eq!(result[0].tool, "Read");
    }

    #[test]
    fn test_load_delegations_human_source_not_validated() {
        // Delegations with source="human" should not undergo mission_id validation
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("runtime-delegations.json");

        let delegations = json!([
            {
                "tool": "Read",
                "agent_id": null,
                "action": "auto-approve",
                "created_at": Utc::now().to_rfc3339(),
                "expires_at": (Utc::now() + Duration::hours(4)).to_rfc3339(),
                "source": "human"
            }
        ]);
        std::fs::write(&path, serde_json::to_string(&delegations).unwrap()).unwrap();

        let result = load_delegations(&path);
        assert_eq!(
            result.len(),
            1,
            "Human delegations should not require mission_id"
        );
    }

    // ── Finding #7 (DREAD 5.2): Atomic write for revoked-missions ──────────

    #[test]
    fn test_mark_revoked_missions_atomic_write() {
        // Verify that mark_mission_agents_revoked creates a valid JSON file
        // and that no tmp file is left behind
        let tmp = tempfile::TempDir::new().unwrap();
        mark_mission_agents_revoked(tmp.path(), &["agent-1".to_string()]).unwrap();

        let path = tmp.path().join("revoked-missions.json");
        assert!(path.exists(), "revoked-missions.json should exist");

        let tmp_path = tmp.path().join(".revoked-missions.tmp");
        assert!(
            !tmp_path.exists(),
            "temp file should be cleaned up after rename"
        );

        // Verify the JSON is valid
        let contents = std::fs::read_to_string(&path).unwrap();
        let parsed: std::collections::HashSet<String> = serde_json::from_str(&contents).unwrap();
        assert!(parsed.contains("agent-1"));
    }

    // ── Finding #2 (DREAD 5.0): File locking tests ────────────────────────

    #[test]
    fn test_save_delegations_creates_lock_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("delegations.json");

        let delegations = vec![RuntimeDelegation {
            tool: "Read".to_string(),
            agent_id: None,
            action: Action::AutoApprove,
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + Duration::hours(4)),
            session_id: None,
            source: None,
            mission_id: None,
            conditions: None,
        }];

        save_delegations(&path, &delegations).unwrap();

        // Verify delegations were saved correctly
        let reloaded = load_delegations(&path);
        assert_eq!(reloaded.len(), 1);
        assert_eq!(reloaded[0].tool, "Read");

        // Lock file should exist (it persists, the lock is released on handle drop)
        let lock_path = tmp.path().join(".runtime-delegations.lock");
        assert!(lock_path.exists(), "lock file should be created");
    }
}

/// Outcome of comparing a candidate delegation with the existing store.
#[derive(Debug, Clone, PartialEq)]
pub enum MergeDecision {
    /// No matching existing delegation — safe to insert.
    Insert,
    /// Existing delegation covers this one with TTL ≥ mission_end. Skip insert.
    SkipRespected {
        existing_expires_at: DateTime<Utc>,
    },
    /// Existing delegation expires BEFORE mission_end. Caller must decide
    /// to abort (default) or extend via `--extend-existing`.
    TtlTooShort {
        existing_expires_at: DateTime<Utc>,
        needed_until: DateTime<Utc>,
    },
}

/// Decide how to merge a candidate delegation into the existing store.
///
/// Matching key: (tool, agent_id). Conditions are not part of the key — if
/// a user has a custom `bash_pattern` delegation and the mission wants a
/// different one, the user's wins (returns SkipRespected with a TTL check).
///
/// `mission_end_at` is the time when the mission TTL ends. If the existing
/// delegation expires AFTER that, we respect the user (SkipRespected). If
/// BEFORE, we return TtlTooShort so the caller can either abort or extend.
pub fn decide_merge(
    candidate: &RuntimeDelegation,
    existing: &[RuntimeDelegation],
    mission_end_at: DateTime<Utc>,
) -> MergeDecision {
    for e in existing {
        if e.tool == candidate.tool && e.agent_id == candidate.agent_id {
            if let Some(exp) = e.expires_at {
                if exp >= mission_end_at {
                    return MergeDecision::SkipRespected {
                        existing_expires_at: exp,
                    };
                } else {
                    return MergeDecision::TtlTooShort {
                        existing_expires_at: exp,
                        needed_until: mission_end_at,
                    };
                }
            }
            // No expires_at on existing shouldn't happen (load_delegations drops those)
            // but treat defensively as short.
            return MergeDecision::TtlTooShort {
                existing_expires_at: Utc::now(),
                needed_until: mission_end_at,
            };
        }
    }
    MergeDecision::Insert
}

#[cfg(test)]
mod merge_tests {
    use super::*;

    fn make_delegation(tool: &str, agent: &str, expires: DateTime<Utc>) -> RuntimeDelegation {
        RuntimeDelegation {
            tool: tool.to_string(),
            agent_id: Some(agent.to_string()),
            action: Action::AutoApprove,
            created_at: Utc::now(),
            expires_at: Some(expires),
            session_id: None,
            source: Some("role".to_string()),
            mission_id: Some("m-test".to_string()),
            conditions: None,
        }
    }

    #[test]
    fn test_decide_merge_insert_when_no_match() {
        let candidate = make_delegation("Read", "developer", Utc::now() + Duration::hours(8));
        let existing = vec![];
        let end = Utc::now() + Duration::hours(8);
        assert_eq!(
            decide_merge(&candidate, &existing, end),
            MergeDecision::Insert
        );
    }

    #[test]
    fn test_decide_merge_skip_when_ttl_covers() {
        let end = Utc::now() + Duration::hours(8);
        let existing = vec![make_delegation(
            "Read",
            "developer",
            Utc::now() + Duration::hours(24),
        )];
        let candidate = make_delegation("Read", "developer", end);
        let dec = decide_merge(&candidate, &existing, end);
        match dec {
            MergeDecision::SkipRespected { .. } => {}
            other => panic!("expected SkipRespected, got {:?}", other),
        }
    }

    #[test]
    fn test_decide_merge_ttl_too_short() {
        let end = Utc::now() + Duration::hours(8);
        let existing = vec![make_delegation(
            "Read",
            "developer",
            Utc::now() + Duration::hours(2),
        )];
        let candidate = make_delegation("Read", "developer", end);
        let dec = decide_merge(&candidate, &existing, end);
        match dec {
            MergeDecision::TtlTooShort { .. } => {}
            other => panic!("expected TtlTooShort, got {:?}", other),
        }
    }

    #[test]
    fn test_decide_merge_different_agent_inserts() {
        let end = Utc::now() + Duration::hours(8);
        let existing = vec![make_delegation(
            "Read",
            "developer",
            end + Duration::hours(16),
        )];
        let candidate = make_delegation("Read", "auditor", end);
        assert_eq!(
            decide_merge(&candidate, &existing, end),
            MergeDecision::Insert
        );
    }

    #[test]
    fn test_decide_merge_different_tool_inserts() {
        let end = Utc::now() + Duration::hours(8);
        let existing = vec![make_delegation(
            "Read",
            "developer",
            end + Duration::hours(16),
        )];
        let candidate = make_delegation("Write", "developer", end);
        assert_eq!(
            decide_merge(&candidate, &existing, end),
            MergeDecision::Insert
        );
    }
}
