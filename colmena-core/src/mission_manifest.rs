//! Parse and validate a mission manifest YAML.
//!
//! Example (minimal):
//! ```yaml
//! id: m73-core-impl
//! pattern: peer
//! mission_ttl_hours: 8
//! roles:
//!   - name: developer
//!     scope:
//!       owns: ["colmena-core/src/selector.rs"]
//!       forbidden: []
//!     task: "Implement mission_spawn auto-closure"
//!   - name: auditor
//!     scope:
//!       owns: []
//!       forbidden: []
//!     task: "Evaluate developer artifacts with QPC"
//! ```

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::delegate::MAX_TTL_HOURS;
use crate::selector::DEFAULT_MISSION_TTL_HOURS;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissionManifest {
    /// Mission id. Used as the mission_id stamped into delegations and prompts.
    pub id: String,
    /// Library pattern id (e.g. "peer", "hierarchical", "caido-pentest").
    pub pattern: String,
    /// TTL in hours. Default 8 if unset. Capped at `MAX_TTL_HOURS`.
    #[serde(default = "default_ttl_hours")]
    pub mission_ttl_hours: i64,
    /// Per-role scope + task.
    pub roles: Vec<ManifestRole>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestRole {
    /// Role id matching a library role (`colmena library list`).
    pub name: String,
    #[serde(default)]
    pub scope: ManifestScope,
    #[serde(default)]
    pub task: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ManifestScope {
    #[serde(default)]
    pub owns: Vec<String>,
    #[serde(default)]
    pub forbidden: Vec<String>,
}

fn default_ttl_hours() -> i64 {
    DEFAULT_MISSION_TTL_HOURS
}

impl MissionManifest {
    pub fn from_yaml(yaml: &str) -> Result<Self> {
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
        if self.id.trim().is_empty() {
            bail!("manifest.id cannot be empty");
        }
        if self.pattern.trim().is_empty() {
            bail!("manifest.pattern cannot be empty");
        }
        if self.roles.is_empty() {
            bail!("manifest.roles cannot be empty");
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
        for (i, r) in self.roles.iter().enumerate() {
            if r.name.trim().is_empty() {
                bail!("manifest.roles[{}].name cannot be empty", i);
            }
        }
        Ok(())
    }

    /// Find a role by its name (library id). Returns None if absent.
    pub fn role(&self, name: &str) -> Option<&ManifestRole> {
        self.roles.iter().find(|r| r.name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
id: m73-test
pattern: peer
mission_ttl_hours: 4
roles:
  - name: developer
    scope:
      owns: ["Cargo.toml"]
      forbidden: []
    task: "Bump version"
  - name: auditor
    scope:
      owns: []
      forbidden: []
    task: "Evaluate"
"#;

    #[test]
    fn test_from_yaml_valid() {
        let m = MissionManifest::from_yaml(VALID).unwrap();
        assert_eq!(m.id, "m73-test");
        assert_eq!(m.pattern, "peer");
        assert_eq!(m.mission_ttl_hours, 4);
        assert_eq!(m.roles.len(), 2);
        assert_eq!(m.role("developer").unwrap().scope.owns, vec!["Cargo.toml"]);
    }

    #[test]
    fn test_default_ttl_is_8() {
        let yaml = r#"
id: x
pattern: p
roles:
  - name: developer
"#;
        let m = MissionManifest::from_yaml(yaml).unwrap();
        assert_eq!(m.mission_ttl_hours, DEFAULT_MISSION_TTL_HOURS);
    }

    #[test]
    fn test_rejects_empty_id() {
        let yaml = r#"
id: ""
pattern: p
roles:
  - name: developer
"#;
        let err = MissionManifest::from_yaml(yaml).unwrap_err().to_string();
        assert!(err.contains("id cannot be empty"));
    }

    #[test]
    fn test_rejects_ttl_over_max() {
        let yaml = format!(
            r#"
id: x
pattern: p
mission_ttl_hours: {}
roles:
  - name: developer
"#,
            MAX_TTL_HOURS + 1
        );
        let err = MissionManifest::from_yaml(&yaml).unwrap_err().to_string();
        assert!(err.contains("exceeds MAX_TTL_HOURS"));
    }

    #[test]
    fn test_rejects_empty_roles() {
        let yaml = r#"
id: x
pattern: p
roles: []
"#;
        let err = MissionManifest::from_yaml(yaml).unwrap_err().to_string();
        assert!(err.contains("roles cannot be empty"));
    }
}
