use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

// ── Role types ────────────────────────────────────────────────────────────────

/// Optional permissions block for role-bound firewall delegations.
/// When a mission uses this role, these become scoped auto-approve rules.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct RolePermissions {
    /// Regex patterns for auto-approved Bash commands (e.g. `^uv (run|pip)`)
    #[serde(default)]
    pub bash_patterns: Vec<String>,
    /// Allowed directories for file operations (supports `${MISSION_DIR}`)
    #[serde(default)]
    pub path_within: Vec<String>,
    /// Excluded file patterns (e.g. `*.env`, `*credentials*`)
    #[serde(default)]
    pub path_not_match: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Role {
    pub name: String,
    pub id: String,
    pub icon: String,
    pub description: String,
    pub system_prompt_ref: String,
    pub default_trust_level: String,
    pub tools_allowed: Vec<String>,
    pub specializations: Vec<String>,
    #[serde(default)]
    pub permissions: Option<RolePermissions>,
    pub elo: EloConfig,
    pub mentoring: MentoringConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EloConfig {
    pub initial: u32,
    #[serde(default)]
    pub categories: HashMap<String, u32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MentoringConfig {
    #[serde(default)]
    pub can_mentor: Vec<String>,
    #[serde(default)]
    pub mentored_by: Vec<String>,
}

// ── Pattern types ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct Pattern {
    pub name: String,
    pub id: String,
    pub source: Option<String>,
    pub description: String,
    pub topology: String,
    pub communication: String,
    pub when_to_use: Vec<String>,
    #[serde(default)]
    pub when_not_to_use: Vec<String>,
    pub pros: Vec<String>,
    pub cons: Vec<String>,
    pub estimated_token_cost: String,
    pub estimated_agents: String,
    pub roles_suggested: RolesSuggested,
    #[serde(default)]
    pub elo_lead_selection: bool,
}

/// Flexible roles_suggested: values can be a single string or a list of strings.
/// Example YAML:
///   roles_suggested:
///     oracle: security_architect
///     workers: [pentester, auditor, researcher]
#[derive(Debug, Clone, Deserialize)]
#[serde(transparent)]
pub struct RolesSuggested(pub HashMap<String, RoleSlot>);

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum RoleSlot {
    Single(String),
    Multiple(Vec<String>),
}

impl RoleSlot {
    pub fn as_vec(&self) -> Vec<String> {
        match self {
            RoleSlot::Single(s) => vec![s.clone()],
            RoleSlot::Multiple(v) => v.clone(),
        }
    }
}

impl RolesSuggested {
    /// Get all role IDs from all slots
    pub fn all_role_ids(&self) -> Vec<String> {
        self.0.values().flat_map(|slot| slot.as_vec()).collect()
    }
}

// ── Loaders ───────────────────────────────────────────────────────────────────

/// Load all role templates from library_dir/roles/*.yaml
pub fn load_roles(library_dir: &Path) -> Result<Vec<Role>> {
    load_yaml_dir(&library_dir.join("roles"))
}

/// Load all pattern templates from library_dir/patterns/*.yaml
pub fn load_patterns(library_dir: &Path) -> Result<Vec<Pattern>> {
    load_yaml_dir(&library_dir.join("patterns"))
}

/// Load a system prompt markdown file
pub fn load_prompt(library_dir: &Path, prompt_ref: &str) -> Result<String> {
    let path = library_dir.join(prompt_ref);

    // Normalize to prevent ../ traversal without requiring the file to exist
    let normalized = normalize_path(&path);
    let library_normalized = normalize_path(library_dir);

    if !normalized.starts_with(&library_normalized) {
        anyhow::bail!(
            "Prompt path traversal detected: '{}' escapes library directory",
            prompt_ref
        );
    }

    std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read prompt: {}", path.display()))
}

/// Normalize a path by resolving `.` and `..` segments without filesystem access.
fn normalize_path(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                normalized.pop();
            }
            Component::CurDir => {}
            other => normalized.push(other),
        }
    }
    normalized
}

/// Generic YAML directory loader — reads all *.yaml files, deserializes each
fn load_yaml_dir<T: serde::de::DeserializeOwned>(dir: &Path) -> Result<Vec<T>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut items = Vec::new();
    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("Failed to read directory: {}", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("yaml") {
            continue;
        }
        let contents = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read: {}", path.display()))?;
        let item: T = serde_yml::from_str(&contents)
            .with_context(|| format!("Failed to parse: {}", path.display()))?;
        items.push(item);
    }
    Ok(items)
}

/// Default library directory
pub fn default_library_dir() -> PathBuf {
    crate::paths::colmena_home().join("config/library")
}

// ── Validation ────────────────────────────────────────────────────────────────

/// Cross-validate library: check role references in patterns, tool names, prompt files
pub fn validate_library(roles: &[Role], patterns: &[Pattern], library_dir: &Path) -> Vec<String> {
    let mut warnings = Vec::new();
    let role_ids: Vec<&str> = roles.iter().map(|r| r.id.as_str()).collect();

    // Check pattern role references
    for pattern in patterns {
        for role_id in pattern.roles_suggested.all_role_ids() {
            if !role_ids.contains(&role_id.as_str()) {
                warnings.push(format!(
                    "Pattern '{}' references unknown role '{}'",
                    pattern.id, role_id
                ));
            }
        }
    }

    // Check tool names in roles
    for role in roles {
        for tool in &role.tools_allowed {
            let tool_warnings = crate::config::validate_tool_name_single(tool);
            for w in tool_warnings {
                warnings.push(format!("Role '{}': {}", role.id, w));
            }
        }
    }

    // Check prompt files exist
    for role in roles {
        let prompt_path = library_dir.join(&role.system_prompt_ref);
        if !prompt_path.exists() {
            warnings.push(format!(
                "Role '{}' references missing prompt: {}",
                role.id, role.system_prompt_ref
            ));
        }
    }

    warnings
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as IoWrite;

    // ── helpers ───────────────────────────────────────────────────────────────

    fn sample_role_yaml() -> &'static str {
        r#"
name: Security Architect
id: security_architect
icon: "🔒"
description: Designs and reviews security posture
system_prompt_ref: prompts/security_architect.md
default_trust_level: high
tools_allowed:
  - Read
  - Grep
  - Bash
specializations:
  - threat_modeling
  - code_review
elo:
  initial: 1200
  categories:
    code_review: 1250
    threat_modeling: 1300
mentoring:
  can_mentor:
    - pentester
  mentored_by:
    - ciso
"#
    }

    fn sample_pattern_yaml() -> &'static str {
        r#"
name: Oracle + Workers
id: oracle_workers
description: One oracle coordinates multiple specialist workers
topology: star
communication: hub_and_spoke
when_to_use:
  - Large, parallelisable tasks
  - Tasks with specialist subtasks
when_not_to_use:
  - Simple single-step tasks
pros:
  - High parallelism
  - Clear delegation
cons:
  - Oracle is a bottleneck
estimated_token_cost: high
estimated_agents: "3-6"
roles_suggested:
  oracle: security_architect
  workers:
    - pentester
    - researcher
elo_lead_selection: true
"#
    }

    // ── 1. Role YAML deserialization ──────────────────────────────────────────

    #[test]
    fn test_deserialize_role() {
        let role: Role = serde_yml::from_str(sample_role_yaml()).expect("should parse role");

        assert_eq!(role.id, "security_architect");
        assert_eq!(role.name, "Security Architect");
        assert_eq!(role.default_trust_level, "high");
        assert_eq!(role.tools_allowed, vec!["Read", "Grep", "Bash"]);
        assert_eq!(role.specializations, vec!["threat_modeling", "code_review"]);
        assert_eq!(role.elo.initial, 1200);
        assert_eq!(role.elo.categories["code_review"], 1250);
        assert_eq!(role.elo.categories["threat_modeling"], 1300);
        assert_eq!(role.mentoring.can_mentor, vec!["pentester"]);
        assert_eq!(role.mentoring.mentored_by, vec!["ciso"]);
    }

    // ── 2. Pattern YAML deserialization (mixed roles_suggested) ──────────────

    #[test]
    fn test_deserialize_pattern_mixed_roles_suggested() {
        let pattern: Pattern =
            serde_yml::from_str(sample_pattern_yaml()).expect("should parse pattern");

        assert_eq!(pattern.id, "oracle_workers");
        assert_eq!(pattern.topology, "star");
        assert!(pattern.elo_lead_selection);

        // oracle → Single slot
        let oracle_slot = pattern.roles_suggested.0.get("oracle").expect("oracle key");
        assert_eq!(oracle_slot.as_vec(), vec!["security_architect"]);

        // workers → Multiple slot
        let workers_slot = pattern.roles_suggested.0.get("workers").expect("workers key");
        let workers = workers_slot.as_vec();
        assert!(workers.contains(&"pentester".to_string()));
        assert!(workers.contains(&"researcher".to_string()));
    }

    // ── 3. RolesSuggested.all_role_ids ───────────────────────────────────────

    #[test]
    fn test_all_role_ids() {
        let pattern: Pattern =
            serde_yml::from_str(sample_pattern_yaml()).expect("should parse pattern");

        let mut ids = pattern.roles_suggested.all_role_ids();
        ids.sort();

        assert_eq!(ids, vec!["pentester", "researcher", "security_architect"]);
    }

    // ── 4. validate_library catches unknown role references ───────────────────

    #[test]
    fn test_validate_library_catches_unknown_role_references() {
        let role: Role = serde_yml::from_str(sample_role_yaml()).unwrap();
        let pattern: Pattern = serde_yml::from_str(sample_pattern_yaml()).unwrap();

        // Only provide the oracle role — workers (pentester, researcher) are missing
        let roles = vec![role];
        let patterns = vec![pattern];

        // Use a temp dir — prompt file won't exist, triggering a separate warning
        let tmp = tempfile::tempdir().unwrap();
        let warnings = validate_library(&roles, &patterns, tmp.path());

        // Should warn about at least pentester and researcher
        let role_ref_warnings: Vec<_> = warnings
            .iter()
            .filter(|w| w.contains("references unknown role"))
            .collect();

        assert!(
            role_ref_warnings.iter().any(|w| w.contains("pentester")),
            "expected warning for pentester, got: {warnings:?}"
        );
        assert!(
            role_ref_warnings.iter().any(|w| w.contains("researcher")),
            "expected warning for researcher, got: {warnings:?}"
        );

        // oracle (security_architect) IS in the roles list — no warning for it
        assert!(
            !role_ref_warnings
                .iter()
                .any(|w| w.contains("security_architect")),
            "security_architect should NOT trigger a role-ref warning"
        );
    }

    // ── 5. load_yaml_dir with empty / nonexistent directory ──────────────────

    #[test]
    fn test_load_yaml_dir_nonexistent_returns_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let nonexistent = tmp.path().join("does_not_exist");
        let result: Vec<Role> = super::load_yaml_dir(&nonexistent).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_load_yaml_dir_empty_dir_returns_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let empty_dir = tmp.path().join("empty");
        std::fs::create_dir(&empty_dir).unwrap();
        let result: Vec<Role> = super::load_yaml_dir(&empty_dir).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_load_roles_from_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let roles_dir = tmp.path().join("roles");
        std::fs::create_dir(&roles_dir).unwrap();

        // Write a valid role YAML
        let role_path = roles_dir.join("security_architect.yaml");
        let mut f = std::fs::File::create(&role_path).unwrap();
        f.write_all(sample_role_yaml().as_bytes()).unwrap();

        // Also write a non-YAML file that should be ignored
        std::fs::write(roles_dir.join("ignore_me.txt"), "not yaml").unwrap();

        let roles = load_roles(tmp.path()).unwrap();
        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].id, "security_architect");
    }

    #[test]
    fn test_load_patterns_from_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let patterns_dir = tmp.path().join("patterns");
        std::fs::create_dir(&patterns_dir).unwrap();

        let pattern_path = patterns_dir.join("oracle_workers.yaml");
        let mut f = std::fs::File::create(&pattern_path).unwrap();
        f.write_all(sample_pattern_yaml().as_bytes()).unwrap();

        let patterns = load_patterns(tmp.path()).unwrap();
        assert_eq!(patterns.len(), 1);
        assert_eq!(patterns[0].id, "oracle_workers");
    }

    // ── 6. load_prompt path traversal ────────────────────────────────────────

    #[test]
    fn test_load_prompt_blocks_path_traversal() {
        let tmp = tempfile::tempdir().unwrap();
        let library_dir = tmp.path();
        std::fs::create_dir_all(library_dir.join("prompts")).unwrap();
        std::fs::write(library_dir.join("prompts/safe.md"), "# Safe").unwrap();

        // Normal load works
        let result = load_prompt(library_dir, "prompts/safe.md");
        assert!(result.is_ok(), "safe prompt load failed: {:?}", result);

        // Path traversal is blocked
        let result = load_prompt(library_dir, "../../../etc/passwd");
        assert!(result.is_err(), "traversal should have been blocked");
        assert!(
            result.unwrap_err().to_string().contains("traversal"),
            "error message should mention traversal"
        );
    }
}
