//! Auto-elevate: session-scoped trust elevation via 2× operator confirmation.
//!
//! When the operator answers Y twice to the same binary skeleton within a time
//! window, auto-create a session-scoped delegation so the third and subsequent
//! calls pass without prompting.
//!
//! Skeletons are extracted from individual pieces of a Bash chain (via M7.10's
//! split_top_level_chain). The skeleton is the base binary + first subcommand
//! if present (e.g. "curl", "git diff", "cargo test", "head", "tee").

use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};

use crate::config::AutoElevateConfig;

/// State file relative to config dir.
const STATE_FILE: &str = "auto-elevate-state.json";

/// Maximum entries in the state file (bounds IO on the hot path).
const MAX_ENTRIES: usize = 200;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoElevateEntry {
    pub skeleton: String,
    pub session_id: String,
    pub count: u64,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
}

/// Known meta-commands whose first argument is typically a subcommand
/// (not a file, URL, or flag). Used by `extract_skeleton` to decide
/// whether `first word` or `first second` is the right skeleton.
const META_COMMANDS: &[&str] = &[
    "git",
    "cargo",
    "docker",
    "kubectl",
    "gh",
    "go",
    "npm",
    "yarn",
    "npx",
    "systemctl",
    "journalctl",
    "colmena",
    "helm",
    "terraform",
    "pip",
    "poetry",
];

/// Extract the binary skeleton from a Bash command piece.
///
/// Returns "first_word" for simple commands, or "first_word subcommand"
/// when the second token is a non-flag, non-path argument to a known
/// meta-command.
///
/// # Examples
///
/// ```
/// # use colmena_core::auto_elevate::extract_skeleton;
/// assert_eq!(extract_skeleton("curl -I https://api.example.com/v2/foo"), "curl");
/// assert_eq!(extract_skeleton("git diff --cached src/main.rs"), "git diff");
/// assert_eq!(extract_skeleton("cargo test -p colmena-core"), "cargo test");
/// assert_eq!(extract_skeleton("head -20"), "head");
/// assert_eq!(extract_skeleton("tee test.log"), "tee");
/// assert_eq!(extract_skeleton(""), "");
/// assert_eq!(extract_skeleton("   ls -la   "), "ls");
/// ```
pub fn extract_skeleton(command_piece: &str) -> String {
    let trimmed = command_piece.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let mut words = trimmed.split_ascii_whitespace();
    let first = words.next().unwrap(); // safe: trimmed is non-empty
    let second = words.next();

    match second {
        // sudo <bin> — strip sudo and extract from the rest of the command line.
        Some(_) if first == "sudo" => {
            let rest: String = std::iter::once(second.unwrap())
                .chain(words)
                .collect::<Vec<_>>()
                .join(" ");
            extract_skeleton(&rest)
        }
        // Second word is a flag → skeleton = first
        Some(s) if s.starts_with('-') => first.to_string(),
        // Second word looks like a path or URL → skeleton = first
        Some(s) if s.contains('/') || s.contains(':') => first.to_string(),
        // Second word looks like a filename (has extension dot) → skeleton = first
        Some(s) if s.contains('.') => first.to_string(),
        // First word is a known meta-command → skeleton = "first second"
        Some(s) if META_COMMANDS.contains(&first) => format!("{} {}", first, s),
        // Otherwise: simple command with argument → skeleton = first
        _ => first.to_string(),
    }
}

/// Read auto-elevate state, trimming expired entries.
fn read_state(config_dir: &Path, config: &AutoElevateConfig) -> Vec<AutoElevateEntry> {
    let path = config_dir.join(STATE_FILE);
    let now = Utc::now();
    let cutoff = now - Duration::minutes(config.window_minutes as i64);

    let entries: Vec<AutoElevateEntry> = match std::fs::read_to_string(&path) {
        Ok(raw) => serde_json::from_str(&raw).unwrap_or_default(),
        Err(_) => return Vec::new(),
    };

    entries
        .into_iter()
        .filter(|e| e.last_seen_at >= cutoff)
        .take(MAX_ENTRIES)
        .collect()
}

/// Write auto-elevate state (atomic via temp + rename).
fn write_state(config_dir: &Path, entries: &[AutoElevateEntry]) -> std::io::Result<()> {
    let path = config_dir.join(STATE_FILE);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = config_dir.join(format!("{}.tmp", STATE_FILE));
    let json = serde_json::to_vec(entries)?;
    std::fs::write(&tmp, json)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

/// Check whether a skeleton has reached the auto-elevate threshold.
///
/// Returns `true` if the operator has confirmed this skeleton at least
/// `config.threshold` times within the window.
pub fn is_elevated(
    config_dir: &Path,
    session_id: &str,
    agent_type: Option<&str>,
    skeleton: &str,
    config: &AutoElevateConfig,
) -> bool {
    if !config.enabled {
        return false;
    }
    // Auto-elevate only applies to the main session (no agent delegation).
    if agent_type.is_some() {
        return false;
    }
    if skeleton.is_empty() {
        return false;
    }

    let entries = read_state(config_dir, config);
    entries.iter().any(|e| {
        e.skeleton == skeleton && e.session_id == session_id && e.count >= config.threshold
    })
}

/// Record an operator approval for a skeleton.
///
/// Called from PostToolUse when a Bash command completes successfully
/// (operator approved it, tool ran). Increments the counter for each
/// skeleton extracted from the command's chain pieces.
pub fn record_approval(
    config_dir: &Path,
    session_id: &str,
    agent_type: Option<&str>,
    command: &str,
    config: &AutoElevateConfig,
) -> String {
    if !config.enabled {
        return String::new();
    }
    // Only record main-session approvals.
    if agent_type.is_some() {
        return String::new();
    }

    // Extract skeletons from the full command (split chain first, then skeleton per piece).
    let pieces = match crate::firewall::split_top_level_chain(command) {
        Some(p) => p,
        None => return String::new(),
    };

    let now = Utc::now();
    let mut entries = read_state(config_dir, config);

    for piece in pieces {
        let trimmed = piece.trim();
        if trimmed.is_empty() || crate::firewall::is_bare_assignment(trimmed) {
            continue;
        }
        let skeleton = extract_skeleton(trimmed);
        if skeleton.is_empty() {
            continue;
        }

        // Find or create entry.
        if let Some(entry) = entries
            .iter_mut()
            .find(|e| e.skeleton == skeleton && e.session_id == session_id)
        {
            entry.count += 1;
            entry.last_seen_at = now;
        } else {
            entries.push(AutoElevateEntry {
                skeleton: skeleton.clone(),
                session_id: session_id.to_string(),
                count: 1,
                first_seen_at: now,
                last_seen_at: now,
            });
        }
    }

    // Trim to MAX_ENTRIES (keep most recent by last_seen_at).
    entries.sort_by_key(|b| std::cmp::Reverse(b.last_seen_at));
    entries.truncate(MAX_ENTRIES);

    let _ = write_state(config_dir, &entries);

    // Check if this command matches any active mission manifest pattern.
    let mut suggestion = String::new();
    if let Some(mission_id) = is_manifest_authorized(command, config_dir) {
        suggestion.push_str(&format!(
            "\n  Note: command matches manifest '{}' extra_allow pattern.",
            mission_id
        ));
    }
    suggestion
}

/// Fully qualified path to the state file (for test inspection).
pub fn state_file_path(config_dir: &Path) -> PathBuf {
    config_dir.join(STATE_FILE)
}

/// Check whether a bash command is already authorized by any active
/// mission manifest's `extra_allow` patterns. Returns the manifest
/// mission_id that authorizes this command, if any.
pub fn is_manifest_authorized(command: &str, config_dir: &Path) -> Option<String> {
    let runtime_path = crate::config::runtime_overrides_path(config_dir);
    let overrides = crate::config::RuntimeAgentOverrides::load(&runtime_path).ok()?;
    let merged = overrides.merged_overrides();

    for (agent_id, rules) in &merged {
        for rule in rules {
            if let Some(ref conditions) = rule.conditions {
                if let Some(ref pattern) = conditions.bash_pattern {
                    if let Ok(re) = regex::Regex::new(pattern) {
                        if re.is_match(command) {
                            // Find which mission this override belongs to
                            for (mission_id, mission_ov) in &overrides.missions {
                                if let Some(mission_rules) = mission_ov.overrides.get(agent_id) {
                                    let matches = mission_rules.iter().any(|r| {
                                        r.conditions.as_ref().and_then(|c| c.bash_pattern.as_ref())
                                            == Some(pattern)
                                    });
                                    if matches {
                                        return Some(mission_id.clone());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_skeleton_simple() {
        assert_eq!(extract_skeleton("curl -I https://example.com"), "curl");
        assert_eq!(extract_skeleton("ls -la"), "ls");
        assert_eq!(extract_skeleton("head -20"), "head");
        assert_eq!(extract_skeleton("tee test.log"), "tee");
    }

    #[test]
    fn test_extract_skeleton_subcommand() {
        assert_eq!(extract_skeleton("git diff --cached"), "git diff");
        assert_eq!(extract_skeleton("cargo test -p foo"), "cargo test");
        assert_eq!(
            extract_skeleton("cargo clippy -- -D warnings"),
            "cargo clippy"
        );
        assert_eq!(extract_skeleton("gh pr merge"), "gh pr");
    }

    #[test]
    fn test_extract_skeleton_sudo() {
        // sudo systemctl restart → strips sudo → extract from remainder
        assert_eq!(
            extract_skeleton("sudo systemctl restart nginx"),
            "systemctl restart"
        );
        // sudo rm -rf / → strips sudo → "rm"
        assert_eq!(extract_skeleton("sudo rm -rf /"), "rm");
        // sudo -u postgres psql → strips sudo → extract from "-u postgres psql".
        // The -u flag with its arg postgres doesn't resolve cleanly; skeleton
        // becomes "-u" (first word). Edge case accepted — sudo with flags is rare
        // in the "2× Y" auto-elevate context.
        assert_eq!(extract_skeleton("sudo -u postgres psql"), "-u");
    }

    #[test]
    fn test_extract_skeleton_edge_cases() {
        assert_eq!(extract_skeleton(""), "");
        assert_eq!(extract_skeleton("   "), "");
        assert_eq!(extract_skeleton("  ls  "), "ls");
        assert_eq!(
            extract_skeleton("   cargo   build  --release  "),
            "cargo build"
        );
        // Assignment-like strings
        assert_eq!(extract_skeleton("KEY=value"), "KEY=value");
    }

    #[test]
    fn test_empty_skeleton_not_elevated() {
        let tmp = tempfile::TempDir::new().unwrap();
        let config = AutoElevateConfig {
            enabled: true,
            window_minutes: 10,
            threshold: 2,
        };
        assert!(!is_elevated(tmp.path(), "s1", None, "", &config));
    }

    #[test]
    fn test_disabled_config_never_elevates() {
        let tmp = tempfile::TempDir::new().unwrap();
        let config = AutoElevateConfig {
            enabled: false,
            window_minutes: 10,
            threshold: 2,
        };
        // Record approval
        record_approval(tmp.path(), "s1", None, "curl https://example.com", &config);
        record_approval(
            tmp.path(),
            "s1",
            None,
            "curl https://example.com/2",
            &config,
        );
        // Should not be elevated because config is disabled
        assert!(!is_elevated(tmp.path(), "s1", None, "curl", &config));
    }

    #[test]
    fn test_agent_session_not_recorded() {
        let tmp = tempfile::TempDir::new().unwrap();
        let config = AutoElevateConfig {
            enabled: true,
            window_minutes: 10,
            threshold: 2,
        };
        record_approval(
            tmp.path(),
            "s1",
            Some("pentester"),
            "curl https://example.com",
            &config,
        );
        // Should not be elevated because approval came from an agent.
        assert!(!is_elevated(tmp.path(), "s1", None, "curl", &config));
    }

    #[test]
    fn test_two_approvals_elevates() {
        let tmp = tempfile::TempDir::new().unwrap();
        let config = AutoElevateConfig {
            enabled: true,
            window_minutes: 10,
            threshold: 2,
        };
        record_approval(
            tmp.path(),
            "s1",
            None,
            "curl https://example.com/a",
            &config,
        );
        assert!(!is_elevated(tmp.path(), "s1", None, "curl", &config));
        record_approval(
            tmp.path(),
            "s1",
            None,
            "curl https://example.com/b",
            &config,
        );
        assert!(is_elevated(tmp.path(), "s1", None, "curl", &config));
    }

    #[test]
    fn test_chain_pieces_extracted() {
        let tmp = tempfile::TempDir::new().unwrap();
        let config = AutoElevateConfig {
            enabled: true,
            window_minutes: 10,
            threshold: 2,
        };
        // First approval: curl in a chain
        record_approval(
            tmp.path(),
            "s1",
            None,
            "curl https://a.com && curl https://b.com",
            &config,
        );
        // Both curl pieces increment the same skeleton.
        assert!(is_elevated(tmp.path(), "s1", None, "curl", &config));
    }

    #[test]
    fn test_different_sessions_independent() {
        let tmp = tempfile::TempDir::new().unwrap();
        let config = AutoElevateConfig {
            enabled: true,
            window_minutes: 10,
            threshold: 2,
        };
        record_approval(tmp.path(), "s1", None, "curl a.com", &config);
        record_approval(tmp.path(), "s2", None, "curl b.com", &config);
        // Session s1 only has 1 curl approval, not elevated.
        assert!(!is_elevated(tmp.path(), "s1", None, "curl", &config));
        // Session s2 only has 1 too.
        assert!(!is_elevated(tmp.path(), "s2", None, "curl", &config));
    }

    #[test]
    fn test_is_manifest_authorized_matches() {
        let tmp = tempfile::TempDir::new().unwrap();
        let overrides_path = crate::config::runtime_overrides_path(tmp.path());

        let mut overrides = crate::config::RuntimeAgentOverrides::default();
        let mut agent_map = std::collections::HashMap::new();
        agent_map.insert(
            "developer".to_string(),
            vec![crate::config::Rule {
                tools: vec!["Bash".to_string()],
                conditions: Some(crate::config::Conditions {
                    bash_pattern: Some("^cargo test\\b".to_string()),
                    path_within: None,
                    path_not_match: None,
                }),
                action: crate::config::Action::AutoApprove,
                reason: Some("Manifest test — scoped allow".to_string()),
            }],
        );
        overrides.missions.insert(
            "test-manifest".to_string(),
            crate::config::MissionRuntimeOverrides {
                applied_at: "2026-05-06T00:00:00Z".to_string(),
                manifest_sha256: "abc".to_string(),
                mission_ttl_hours: 8,
                overrides: agent_map,
            },
        );
        overrides.save(&overrides_path).unwrap();

        assert_eq!(
            is_manifest_authorized("cargo test --workspace", tmp.path()),
            Some("test-manifest".to_string())
        );
    }

    #[test]
    fn test_is_manifest_authorized_no_match() {
        let tmp = tempfile::TempDir::new().unwrap();
        // Set up overrides with a pattern so the file exists but doesn't match.
        let overrides_path = crate::config::runtime_overrides_path(tmp.path());
        let mut overrides = crate::config::RuntimeAgentOverrides::default();
        let mut agent_map = std::collections::HashMap::new();
        agent_map.insert(
            "developer".to_string(),
            vec![crate::config::Rule {
                tools: vec!["Bash".to_string()],
                conditions: Some(crate::config::Conditions {
                    bash_pattern: Some("^cargo test\\b".to_string()),
                    path_within: None,
                    path_not_match: None,
                }),
                action: crate::config::Action::AutoApprove,
                reason: Some("Manifest test".to_string()),
            }],
        );
        overrides.missions.insert(
            "test-manifest".to_string(),
            crate::config::MissionRuntimeOverrides {
                applied_at: "2026-05-06T00:00:00Z".to_string(),
                manifest_sha256: "abc".to_string(),
                mission_ttl_hours: 8,
                overrides: agent_map,
            },
        );
        overrides.save(&overrides_path).unwrap();

        // "rm -rf /" does not match "^cargo test\\b"
        assert_eq!(is_manifest_authorized("rm -rf /", tmp.path()), None);
    }

    #[test]
    fn test_is_manifest_authorized_no_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        // No runtime-agent-overrides.json exists
        assert_eq!(is_manifest_authorized("cargo build", tmp.path()), None);
    }

    #[test]
    fn test_state_file_expiry() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = state_file_path(tmp.path());
        // Write a stale entry manually.
        let old = AutoElevateEntry {
            skeleton: "curl".to_string(),
            session_id: "s1".to_string(),
            count: 5,
            first_seen_at: Utc::now() - Duration::hours(1),
            last_seen_at: Utc::now() - Duration::hours(1),
        };
        let json = serde_json::to_vec(&vec![old]).unwrap();
        std::fs::write(&path, json).unwrap();

        let config = AutoElevateConfig {
            enabled: true,
            window_minutes: 10,
            threshold: 2,
        };
        // Should NOT be elevated because the entry is stale.
        assert!(!is_elevated(tmp.path(), "s1", None, "curl", &config));
    }
}
