use std::path::Path;

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
pub fn load_delegations_with_expired(path: &Path) -> (Vec<RuntimeDelegation>, Vec<RuntimeDelegation>) {
    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return (Vec::new(), Vec::new()),
    };

    let delegations: Vec<RuntimeDelegation> = match serde_json::from_str(&contents) {
        Ok(d) => d,
        Err(_) => return (Vec::new(), Vec::new()),
    };

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
        match d.expires_at {
            Some(exp) if exp <= now => expired.push(d),
            _ => active.push(d),
        }
    }

    (active, expired)
}

/// Save delegations atomically — write to temp file then rename.
/// Validates all delegations before persisting (e.g., Bash scope check).
pub fn save_delegations(path: &Path, delegations: &[RuntimeDelegation]) -> Result<()> {
    for d in delegations {
        validate_bash_delegation(d)?;
    }

    let json = serde_json::to_string_pretty(delegations)
        .context("Failed to serialize delegations")?;

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp_path = dir.join(".runtime-delegations.tmp");

    std::fs::write(&tmp_path, &json)
        .with_context(|| format!("Failed to write temp delegations file: {}", tmp_path.display()))?;

    std::fs::rename(&tmp_path, path)
        .with_context(|| format!("Failed to rename temp delegations file to {}", path.display()))?;

    Ok(())
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
            MAX_TTL_HOURS, hours
        );
    }
    Ok(Duration::hours(hours))
}

/// Revoke delegations matching tool and optional agent.
/// Returns the number of delegations revoked.
pub fn revoke_delegations(
    path: &Path,
    tool: &str,
    agent: Option<&str>,
) -> Result<usize> {
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
                None => false, // revoke all for this tool
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
            make_delegation("Bash", Some(4)),       // still valid
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
                source: None, mission_id: None, conditions: None,
            },
            RuntimeDelegation {
                tool: "WebFetch".to_string(),
                agent_id: Some("researcher".to_string()),
                action: Action::AutoApprove,
                created_at: Utc::now(),
                expires_at: Some(Utc::now() + Duration::hours(4)),
                session_id: None,
                source: None, mission_id: None, conditions: None,
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
                source: None, mission_id: None,
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
                source: None, mission_id: None,
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
        assert!(result.unwrap_err().to_string().contains("Invalid bash_pattern regex"));
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
}
