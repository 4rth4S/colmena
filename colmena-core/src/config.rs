use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Action to take when a rule matches.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    AutoApprove,
    Ask,
    Block,
}

/// Sentinel structure persisted to `<config_dir>/session-gate.json` when the
/// operator passes `--session-gate` to `mission spawn`. Honored by
/// `is_mission_gate_active` as a runtime override when
/// `enforce_missions: Some(false)` is explicit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionGateOverride {
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Conditions that must all be satisfied for a rule to match.
#[derive(Debug, Clone, Deserialize)]
pub struct Conditions {
    /// Regex pattern matched against Bash tool_input["command"].
    pub bash_pattern: Option<String>,
    /// File path must start with one of these directories.
    pub path_within: Option<Vec<String>>,
    /// File path must NOT match any of these glob patterns.
    pub path_not_match: Option<Vec<String>>,
}

/// A single firewall rule.
#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub tools: Vec<String>,
    pub conditions: Option<Conditions>,
    pub action: Action,
    pub reason: Option<String>,
}

/// Default action configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct Defaults {
    pub action: Action,
}

/// Notification settings.
#[derive(Debug, Clone, Deserialize)]
pub struct NotificationsConfig {
    pub enabled: bool,
}

/// Queue lifecycle configuration (M7.14).
///
/// All fields are optional with defaults so existing `trust-firewall.yaml` files
/// that omit the `queue:` block deserialize correctly with zero diff.
#[derive(Debug, Clone, Deserialize)]
pub struct QueueConfig {
    /// TTL in seconds for stale-GC (pending entries older than this are moved to decided/).
    /// Default: 600s (10 min). Clamped to [60, 3600] at runtime.
    #[serde(default = "default_pending_ttl_seconds")]
    pub retention_pending_seconds: u64,
    /// Retention in hours for decided/ entries before automatic purge.
    /// Default: 24h. Clamped to [1, 720] at runtime.
    #[serde(default = "default_decided_retention_hours")]
    pub retention_decided_hours: u64,
}

fn default_pending_ttl_seconds() -> u64 {
    600
}
fn default_decided_retention_hours() -> u64 {
    24
}

impl Default for QueueConfig {
    fn default() -> Self {
        Self {
            retention_pending_seconds: default_pending_ttl_seconds(),
            retention_decided_hours: default_decided_retention_hours(),
        }
    }
}

impl QueueConfig {
    /// Return clamped retention_pending_seconds, logging a warning if out of range.
    pub fn effective_pending_ttl(&self) -> u64 {
        let raw = self.retention_pending_seconds;
        let clamped = raw.clamp(60, 3600);
        if clamped != raw {
            eprintln!(
                "colmena config: queue.retention_pending_seconds={raw} is out of range [60, 3600]; \
                 using {clamped}"
            );
        }
        clamped
    }

    /// Return clamped retention_decided_hours, logging a warning if out of range.
    pub fn effective_decided_retention(&self) -> u64 {
        let raw = self.retention_decided_hours;
        let clamped = raw.clamp(1, 720);
        if clamped != raw {
            eprintln!(
                "colmena config: queue.retention_decided_hours={raw} is out of range [1, 720]; \
                 using {clamped}"
            );
        }
        clamped
    }
}

/// Top-level firewall configuration loaded from trust-firewall.yaml.
#[derive(Debug, Clone, Deserialize)]
pub struct FirewallConfig {
    pub version: u32,
    pub defaults: Defaults,
    #[serde(default)]
    pub trust_circle: Vec<Rule>,
    #[serde(default)]
    pub restricted: Vec<Rule>,
    #[serde(default)]
    pub blocked: Vec<Rule>,
    #[serde(default)]
    pub agent_overrides: HashMap<String, Vec<Rule>>,
    pub notifications: Option<NotificationsConfig>,
    /// Mission Gate policy:
    /// - `None` (unset in YAML) → auto-activate when mission delegations are live (M7.3)
    /// - `Some(true)` → always active
    /// - `Some(false)` → explicit opt-out (operator decision, respected always)
    #[serde(default)]
    pub enforce_missions: Option<bool>,
    /// Queue lifecycle settings (M7.14). Optional — defaults apply when absent.
    #[serde(default)]
    pub queue: QueueConfig,
}

/// Validate the cwd before using it as ${PROJECT_DIR}.
///
/// H3: A crafted cwd (e.g. "/") would expand path_within to match the entire filesystem.
/// Require at least 2 normal path components so "/" and "/tmp" are rejected.
fn validate_cwd(cwd: &str) -> Result<()> {
    use std::path::Component;
    let normal_count = std::path::Path::new(cwd)
        .components()
        .filter(|c| matches!(c, Component::Normal(_)))
        .count();
    if normal_count < 2 {
        anyhow::bail!(
            "cwd '{}' is too shallow ({} components) — possible ${{PROJECT_DIR}} injection",
            cwd,
            normal_count
        );
    }
    Ok(())
}

/// Load and parse the firewall config from a YAML file.
/// Resolves `${PROJECT_DIR}` placeholders in path_within values against the given `cwd`.
pub fn load_config(path: &Path, cwd: &str) -> Result<FirewallConfig> {
    // H3: Validate cwd depth before substituting into path_within rules.
    // If cwd is "/" or "/tmp" the path_within rules become trivially bypassable.
    validate_cwd(cwd).with_context(|| format!("Rejecting unsafe cwd '{cwd}'"))?;

    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config file: {}", path.display()))?;

    let mut config: FirewallConfig = serde_yml::from_str(&contents)
        .with_context(|| format!("Failed to parse config file: {}", path.display()))?;

    resolve_project_dir(&mut config, cwd);
    Ok(config)
}

/// Pre-compiled regex patterns for all rules. Keyed by "{tier}[{index}]".
pub type CompiledPatterns = HashMap<String, Regex>;

/// Compile regex patterns (bash_pattern) for a slice of rules into the patterns map.
/// Keys are formatted as `"{tier_prefix}[{index}]"` matching the format used by `check_rules`.
/// Returns an error if any pattern is invalid, naming the exact rule.
pub fn compile_rules(
    rules: &[Rule],
    tier_prefix: &str,
    patterns: &mut CompiledPatterns,
) -> Result<()> {
    for (i, rule) in rules.iter().enumerate() {
        if let Some(ref cond) = rule.conditions {
            if let Some(ref pat) = cond.bash_pattern {
                let compiled = Regex::new(pat)
                    .with_context(|| format!("Invalid regex in {tier_prefix}[{i}]: {pat}"))?;
                patterns.insert(format!("{tier_prefix}[{i}]"), compiled);
            }
        }
    }
    Ok(())
}

/// Compile and validate all regex patterns in the config.
/// Returns an error if any pattern is invalid, naming the exact rule.
pub fn compile_config(config: &FirewallConfig) -> Result<CompiledPatterns> {
    let mut patterns = CompiledPatterns::new();

    compile_rules(&config.blocked, "blocked", &mut patterns)?;
    compile_rules(&config.restricted, "restricted", &mut patterns)?;
    compile_rules(&config.trust_circle, "trust_circle", &mut patterns)?;

    for (agent_id, rules) in &config.agent_overrides {
        compile_rules(rules, &format!("agent_override:{agent_id}"), &mut patterns)?;
    }

    Ok(patterns)
}

/// Known Claude Code tool names. MCP tools (mcp__*) are always valid.
const KNOWN_TOOLS: &[&str] = &[
    "Agent",
    "Bash",
    "Edit",
    "Glob",
    "Grep",
    "Read",
    "Write",
    "WebFetch",
    "WebSearch",
    "NotebookEdit",
    "AskUserQuestion",
    "EnterPlanMode",
    "ExitPlanMode",
    "EnterWorktree",
    "ExitWorktree",
    "TaskCreate",
    "TaskUpdate",
    "TaskGet",
    "TaskList",
    "TaskOutput",
    "TaskStop",
    "SendMessage",
    "Skill",
    "ToolSearch",
];

/// Check all tool names in the config against known tools.
/// Returns a list of warnings for unrecognized tool names.
/// MCP tools (prefixed with `mcp__`) are always accepted.
pub fn validate_tool_names(config: &FirewallConfig) -> Vec<String> {
    let mut warnings = Vec::new();

    let check_rules = |rules: &[Rule], tier: &str, warnings: &mut Vec<String>| {
        for (i, rule) in rules.iter().enumerate() {
            for tool in &rule.tools {
                if !tool.starts_with("mcp__") && !KNOWN_TOOLS.contains(&tool.as_str()) {
                    warnings.push(format!(
                        "Unknown tool '{}' in {tier}[{i}] — known tools: {:?}",
                        tool, KNOWN_TOOLS
                    ));
                }
            }
        }
    };

    check_rules(&config.trust_circle, "trust_circle", &mut warnings);
    check_rules(&config.restricted, "restricted", &mut warnings);
    check_rules(&config.blocked, "blocked", &mut warnings);
    for (agent_id, rules) in &config.agent_overrides {
        check_rules(rules, &format!("agent_override:{agent_id}"), &mut warnings);
    }

    warnings
}

/// Validate a single tool name. Returns warnings if unknown.
pub fn validate_tool_name_single(tool: &str) -> Vec<String> {
    if !tool.starts_with("mcp__") && !KNOWN_TOOLS.contains(&tool) {
        vec![format!(
            "Unknown tool '{}' — known tools: {:?}",
            tool, KNOWN_TOOLS
        )]
    } else {
        vec![]
    }
}

/// Replace `${PROJECT_DIR}` with the actual cwd in all path_within values.
fn resolve_project_dir(config: &mut FirewallConfig, cwd: &str) {
    let resolve_rules = |rules: &mut [Rule]| {
        for rule in rules.iter_mut() {
            if let Some(ref mut conditions) = rule.conditions {
                if let Some(ref mut paths) = conditions.path_within {
                    for p in paths.iter_mut() {
                        *p = p.replace("${PROJECT_DIR}", cwd);
                    }
                }
            }
        }
    };

    resolve_rules(&mut config.trust_circle);
    resolve_rules(&mut config.restricted);
    resolve_rules(&mut config.blocked);

    for rules in config.agent_overrides.values_mut() {
        resolve_rules(rules);
    }
}

/// Best-effort check: warn if config files are world-writable.
/// Only checks on Unix. Returns warning messages (empty vec if OK).
#[cfg(unix)]
pub fn check_config_permissions(config_dir: &std::path::Path) -> Vec<String> {
    use std::os::unix::fs::PermissionsExt;
    let mut warnings = Vec::new();
    let critical_files = [
        "trust-firewall.yaml",
        "runtime-delegations.json",
        "elo-overrides.json",
        "audit.log",
    ];
    for name in &critical_files {
        let path = config_dir.join(name);
        if let Ok(meta) = std::fs::metadata(&path) {
            let mode = meta.permissions().mode();
            if mode & 0o002 != 0 {
                warnings.push(format!(
                    "Security: {} is world-writable (mode {:o}). Consider: chmod 600 {}",
                    name,
                    mode & 0o777,
                    path.display()
                ));
            }
        }
    }
    warnings
}

#[cfg(not(unix))]
pub fn check_config_permissions(_config_dir: &std::path::Path) -> Vec<String> {
    Vec::new()
}

impl FirewallConfig {
    /// Decide whether the Mission Gate applies to this call, given the live
    /// runtime delegations.
    ///
    /// Rules (M7.3):
    /// - If `enforce_missions` is explicit (`Some`), honor it literally.
    /// - If unset (`None`), auto-activate when there is at least one
    ///   delegation with `source: "role"` — i.e., a mission is live.
    /// - Otherwise (unset + no mission delegations), the gate is inactive.
    pub fn is_mission_gate_active(
        &self,
        delegations: &[crate::delegate::RuntimeDelegation],
        session_override: bool,
    ) -> bool {
        if session_override {
            return true;
        }
        match self.enforce_missions {
            Some(v) => v,
            None => delegations
                .iter()
                .any(|d| d.source.as_deref() == Some("role")),
        }
    }
}

/// Check whether a live session-gate override sentinel exists and hasn't expired.
/// Reads `<config_dir>/session-gate.json`. Returns false on any error (safe fallback).
pub fn session_gate_override_active(config_dir: &std::path::Path) -> bool {
    let path = config_dir.join("session-gate.json");
    if !path.exists() {
        return false;
    }
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let sentinel: SessionGateOverride = match serde_json::from_str(&content) {
        Ok(s) => s,
        Err(_) => return false,
    };
    sentinel.expires_at > chrono::Utc::now()
}

/// Write the session-gate override sentinel. Called by CLI when `--session-gate`
/// is passed. Atomic via temp+rename.
pub fn write_session_gate_override(
    config_dir: &std::path::Path,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> anyhow::Result<()> {
    let path = config_dir.join("session-gate.json");
    let sentinel = SessionGateOverride { expires_at };
    let json = serde_json::to_string_pretty(&sentinel).context("serializing sentinel")?;
    std::fs::create_dir_all(config_dir)
        .with_context(|| format!("creating config dir {}", config_dir.display()))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &json).with_context(|| format!("writing temp {}", tmp.display()))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("renaming to {}", path.display()))?;
    Ok(())
}

/// Remove the session-gate override sentinel. No-op if absent.
pub fn clear_session_gate_override(config_dir: &std::path::Path) -> anyhow::Result<()> {
    let path = config_dir.join("session-gate.json");
    if path.exists() {
        std::fs::remove_file(&path)
            .with_context(|| format!("removing sentinel {}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_deserialize_kebab_case() {
        let yaml = "auto-approve";
        let action: Action = serde_yml::from_str(yaml).unwrap();
        assert_eq!(action, Action::AutoApprove);

        let yaml = "ask";
        let action: Action = serde_yml::from_str(yaml).unwrap();
        assert_eq!(action, Action::Ask);

        let yaml = "block";
        let action: Action = serde_yml::from_str(yaml).unwrap();
        assert_eq!(action, Action::Block);
    }

    #[test]
    fn test_rule_deserialize() {
        let yaml = r#"
tools: [Read, Glob, Grep]
action: auto-approve
reason: "Read-only operations"
"#;
        let rule: Rule = serde_yml::from_str(yaml).unwrap();
        assert_eq!(rule.tools, vec!["Read", "Glob", "Grep"]);
        assert_eq!(rule.action, Action::AutoApprove);
        assert!(rule.conditions.is_none());
        assert_eq!(rule.reason, Some("Read-only operations".to_string()));
    }

    #[test]
    fn test_rule_with_conditions() {
        let yaml = r#"
tools: [Write, Edit]
conditions:
  path_within: ["${PROJECT_DIR}"]
  path_not_match: ["*.env", "*credentials*"]
action: auto-approve
"#;
        let rule: Rule = serde_yml::from_str(yaml).unwrap();
        let cond = rule.conditions.unwrap();
        assert_eq!(cond.path_within, Some(vec!["${PROJECT_DIR}".to_string()]));
        assert_eq!(
            cond.path_not_match,
            Some(vec!["*.env".to_string(), "*credentials*".to_string()])
        );
    }

    #[test]
    fn test_load_config_from_file() {
        let config_path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../config/trust-firewall.yaml");
        let config = load_config(&config_path, "/Users/test/project").unwrap();

        assert_eq!(config.version, 1);
        assert_eq!(config.defaults.action, Action::Ask);
        assert!(!config.trust_circle.is_empty());
        assert!(!config.restricted.is_empty());
        assert!(!config.blocked.is_empty());
    }

    #[test]
    fn test_compile_config_rejects_bad_regex() {
        let config = FirewallConfig {
            version: 1,
            defaults: Defaults {
                action: Action::Ask,
            },
            trust_circle: vec![],
            restricted: vec![],
            blocked: vec![Rule {
                tools: vec!["Bash".to_string()],
                conditions: Some(Conditions {
                    bash_pattern: Some("(?P<broken>".to_string()),
                    path_within: None,
                    path_not_match: None,
                }),
                action: Action::Block,
                reason: Some("test".to_string()),
            }],
            agent_overrides: HashMap::new(),
            notifications: None,
            enforce_missions: Some(false),
            queue: Default::default(),
        };
        let result = compile_config(&config);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("blocked[0]"));
    }

    #[test]
    fn test_validate_tool_names_catches_typos() {
        let config = FirewallConfig {
            version: 1,
            defaults: Defaults {
                action: Action::Ask,
            },
            trust_circle: vec![Rule {
                tools: vec!["Raed".to_string()],
                conditions: None,
                action: Action::AutoApprove,
                reason: None,
            }],
            restricted: vec![],
            blocked: vec![],
            agent_overrides: HashMap::new(),
            notifications: None,
            enforce_missions: Some(false),
            queue: Default::default(),
        };
        let warnings = validate_tool_names(&config);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("Raed"));
    }

    #[test]
    fn test_validate_tool_names_accepts_known() {
        let config = FirewallConfig {
            version: 1,
            defaults: Defaults {
                action: Action::Ask,
            },
            trust_circle: vec![Rule {
                tools: vec!["Read".to_string(), "Write".to_string(), "Bash".to_string()],
                conditions: None,
                action: Action::AutoApprove,
                reason: None,
            }],
            restricted: vec![],
            blocked: vec![],
            agent_overrides: HashMap::new(),
            notifications: None,
            enforce_missions: Some(false),
            queue: Default::default(),
        };
        let warnings = validate_tool_names(&config);
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_validate_tool_names_allows_mcp_prefix() {
        let config = FirewallConfig {
            version: 1,
            defaults: Defaults {
                action: Action::Ask,
            },
            trust_circle: vec![],
            restricted: vec![Rule {
                tools: vec!["mcp__claude_ai_Slack__slack_send_message".to_string()],
                conditions: None,
                action: Action::Ask,
                reason: None,
            }],
            blocked: vec![],
            agent_overrides: HashMap::new(),
            notifications: None,
            enforce_missions: Some(false),
            queue: Default::default(),
        };
        let warnings = validate_tool_names(&config);
        assert!(warnings.is_empty());
    }

    // ── H3: cwd validation tests ─────────────────────────────────────────────

    #[test]
    fn test_cwd_root_rejected() {
        let config_path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../config/trust-firewall.yaml");
        // "/" has 0 normal components — must be rejected to prevent PROJECT_DIR injection
        let result = load_config(&config_path, "/");
        assert!(result.is_err(), "cwd '/' must be rejected");
    }

    #[test]
    fn test_cwd_shallow_rejected() {
        let config_path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../config/trust-firewall.yaml");
        // "/tmp" has 1 normal component — must be rejected
        let result = load_config(&config_path, "/tmp");
        assert!(result.is_err(), "cwd '/tmp' must be rejected");
    }

    #[test]
    fn test_cwd_valid_accepted() {
        let config_path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../config/trust-firewall.yaml");
        // "/home/edgar" has 2 normal components — must be accepted
        let result = load_config(&config_path, "/home/edgar");
        assert!(
            result.is_ok(),
            "cwd '/home/edgar' must be accepted: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_project_dir_resolution() {
        let config_path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../config/trust-firewall.yaml");
        let config = load_config(&config_path, "/Users/test/myproject").unwrap();

        // Find the Write/Edit rule with path_within
        let write_rule = config
            .trust_circle
            .iter()
            .find(|r| r.tools.contains(&"Write".to_string()))
            .expect("Should have a Write rule in trust_circle");

        let cond = write_rule.conditions.as_ref().unwrap();
        let paths = cond.path_within.as_ref().unwrap();
        assert!(paths.contains(&"/Users/test/myproject".to_string()));
        assert!(!paths.iter().any(|p| p.contains("${PROJECT_DIR}")));
    }

    #[test]
    #[cfg(unix)]
    fn test_check_config_permissions_no_warnings_on_safe_files() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("trust-firewall.yaml");
        std::fs::write(&file_path, "version: 1").unwrap();
        std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let warnings = check_config_permissions(dir.path());
        assert!(warnings.is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn test_check_config_permissions_warns_world_writable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("trust-firewall.yaml");
        std::fs::write(&file_path, "version: 1").unwrap();
        std::fs::set_permissions(&file_path, std::fs::Permissions::from_mode(0o666)).unwrap();
        let warnings = check_config_permissions(dir.path());
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("world-writable"));
        assert!(warnings[0].contains("trust-firewall.yaml"));
    }

    // ── enforce_missions tests ──────────────────────────────────────────────

    #[test]
    fn test_enforce_missions_default_none() {
        let yaml = r#"
version: 1
defaults:
  action: ask
"#;
        let config: FirewallConfig = serde_yml::from_str(yaml).unwrap();
        assert!(
            config.enforce_missions.is_none(),
            "enforce_missions should default to None (unset)"
        );
    }

    #[test]
    fn test_enforce_missions_parses_true() {
        let yaml = r#"
version: 1
defaults:
  action: ask
enforce_missions: true
"#;
        let config: FirewallConfig = serde_yml::from_str(yaml).unwrap();
        assert_eq!(
            config.enforce_missions,
            Some(true),
            "enforce_missions should parse as Some(true)"
        );
    }

    #[test]
    fn test_enforce_missions_from_real_config() {
        let config_path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../config/trust-firewall.yaml");
        let config = load_config(&config_path, "/home/test/project").unwrap();
        // Real config has `enforce_missions: false` explicitly set
        assert_eq!(
            config.enforce_missions,
            Some(false),
            "Real config should have enforce_missions=Some(false)"
        );
    }

    // ── is_mission_gate_active tests ────────────────────────────────────────

    fn make_role_delegation() -> crate::delegate::RuntimeDelegation {
        crate::delegate::RuntimeDelegation {
            tool: "Read".to_string(),
            agent_id: Some("developer".to_string()),
            action: crate::config::Action::AutoApprove,
            created_at: chrono::Utc::now(),
            expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
            session_id: None,
            source: Some("role".to_string()),
            mission_id: Some("m-42".to_string()),
            conditions: None,
        }
    }

    fn make_firewall_config(enforce: Option<bool>) -> FirewallConfig {
        FirewallConfig {
            version: 1,
            defaults: Defaults {
                action: Action::Ask,
            },
            trust_circle: vec![],
            restricted: vec![],
            blocked: vec![],
            agent_overrides: HashMap::new(),
            notifications: None,
            enforce_missions: enforce,
            queue: Default::default(),
        }
    }

    #[test]
    fn test_is_mission_gate_active_explicit_true() {
        let config = make_firewall_config(Some(true));
        assert!(config.is_mission_gate_active(&[], false));
    }

    #[test]
    fn test_is_mission_gate_active_explicit_false_respected() {
        let config = make_firewall_config(Some(false));
        let d = make_role_delegation();
        assert!(
            !config.is_mission_gate_active(&[d], false),
            "explicit false honored even when role delegation is live"
        );
    }

    #[test]
    fn test_is_mission_gate_active_unset_activates_with_role_delegation() {
        let config = make_firewall_config(None);
        let d = make_role_delegation();
        assert!(config.is_mission_gate_active(&[d], false));
    }

    #[test]
    fn test_is_mission_gate_active_unset_inactive_without_delegations() {
        let config = make_firewall_config(None);
        assert!(!config.is_mission_gate_active(&[], false));
    }

    #[test]
    fn test_is_mission_gate_active_session_override_wins_over_explicit_false() {
        let config = make_firewall_config(Some(false));
        let d = make_role_delegation();
        // session_override: true should flip gate ON even when YAML says Some(false)
        assert!(
            config.is_mission_gate_active(&[d], true),
            "--session-gate must activate gate despite explicit false"
        );
    }

    #[test]
    fn test_is_mission_gate_active_session_override_with_unset_still_true() {
        let config = make_firewall_config(None);
        // No delegations, but override true → gate on
        assert!(config.is_mission_gate_active(&[], true));
    }

    // ── session-gate sentinel helper tests ───────────────────────────────────

    #[test]
    fn test_session_gate_override_absent_when_no_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        assert!(!session_gate_override_active(tmp.path()));
    }

    #[test]
    fn test_session_gate_override_active_when_unexpired() {
        let tmp = tempfile::TempDir::new().unwrap();
        let expires = chrono::Utc::now() + chrono::Duration::hours(1);
        write_session_gate_override(tmp.path(), expires).unwrap();
        assert!(session_gate_override_active(tmp.path()));
    }

    #[test]
    fn test_session_gate_override_inactive_when_expired() {
        let tmp = tempfile::TempDir::new().unwrap();
        let expired = chrono::Utc::now() - chrono::Duration::hours(1);
        write_session_gate_override(tmp.path(), expired).unwrap();
        assert!(!session_gate_override_active(tmp.path()));
    }

    #[test]
    fn test_clear_session_gate_override_removes_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let expires = chrono::Utc::now() + chrono::Duration::hours(1);
        write_session_gate_override(tmp.path(), expires).unwrap();
        assert!(tmp.path().join("session-gate.json").exists());
        clear_session_gate_override(tmp.path()).unwrap();
        assert!(!tmp.path().join("session-gate.json").exists());
    }

    // ── S6: QueueConfig tests (M7.14) ───────────────────────────────────────

    #[test]
    fn test_queue_config_defaults_when_absent() {
        // YAML without `queue:` block must yield defaults
        let yaml = r#"
version: 1
defaults:
  action: ask
"#;
        let config: FirewallConfig = serde_yml::from_str(yaml).unwrap();
        assert_eq!(config.queue.retention_pending_seconds, 600);
        assert_eq!(config.queue.retention_decided_hours, 24);
    }

    #[test]
    fn test_queue_config_clamp_below_range() {
        // Value below minimum (60s) → clamped to 60
        let cfg = QueueConfig {
            retention_pending_seconds: 10,
            retention_decided_hours: 24,
        };
        assert_eq!(cfg.effective_pending_ttl(), 60);
    }

    #[test]
    fn test_queue_config_clamp_above_range() {
        // Value above maximum (3600s / 720h) → clamped to max
        let cfg = QueueConfig {
            retention_pending_seconds: 9999,
            retention_decided_hours: 9999,
        };
        assert_eq!(cfg.effective_pending_ttl(), 3600);
        assert_eq!(cfg.effective_decided_retention(), 720);
    }

    #[test]
    fn test_queue_config_within_range_unchanged() {
        let cfg = QueueConfig {
            retention_pending_seconds: 600,
            retention_decided_hours: 48,
        };
        assert_eq!(cfg.effective_pending_ttl(), 600);
        assert_eq!(cfg.effective_decided_retention(), 48);
    }

    #[test]
    fn test_queue_config_parses_from_yaml() {
        let yaml = r#"
version: 1
defaults:
  action: ask
queue:
  retention_pending_seconds: 300
  retention_decided_hours: 48
"#;
        let config: FirewallConfig = serde_yml::from_str(yaml).unwrap();
        assert_eq!(config.queue.retention_pending_seconds, 300);
        assert_eq!(config.queue.retention_decided_hours, 48);
    }
}
