use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::config::Action;

/// Maximum TTL for any delegation: 24 hours.
pub const MAX_TTL_HOURS: i64 = 24;

/// Default TTL for delegations: 4 hours.
pub const DEFAULT_TTL_HOURS: i64 = 4;

/// A runtime trust delegation added by the human during a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeDelegation {
    pub tool: String,
    pub agent_id: Option<String>,
    pub action: Action,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub session_id: Option<String>,
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
        match d.expires_at {
            Some(exp) if exp <= now => expired.push(d),
            _ => active.push(d),
        }
    }

    (active, expired)
}

/// Save delegations atomically — write to temp file then rename.
pub fn save_delegations(path: &Path, delegations: &[RuntimeDelegation]) -> Result<()> {
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
                tool: "Bash".to_string(),
                agent_id: None,
                action: Action::AutoApprove,
                created_at: Utc::now(),
                expires_at: Some(Utc::now() + Duration::hours(4)),
                session_id: None,
            },
            RuntimeDelegation {
                tool: "WebFetch".to_string(),
                agent_id: Some("researcher".to_string()),
                action: Action::AutoApprove,
                created_at: Utc::now(),
                expires_at: Some(Utc::now() + Duration::hours(4)),
                session_id: None,
            },
        ];

        save_delegations(&path, &delegations).unwrap();

        // Revoke Bash (all agents)
        let revoked = revoke_delegations(&path, "Bash", None).unwrap();
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
            },
            RuntimeDelegation {
                tool: "Bash".to_string(),
                agent_id: Some("auditor".to_string()),
                action: Action::AutoApprove,
                created_at: Utc::now(),
                expires_at: Some(Utc::now() + Duration::hours(4)),
                session_id: None,
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
        let revoked = revoke_delegations(&path, "Bash", None).unwrap();
        assert_eq!(revoked, 0);
    }
}
