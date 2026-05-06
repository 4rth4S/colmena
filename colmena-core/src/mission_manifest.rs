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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum MissionGate {
    Enforce,
    Observe,
    Off,
}

impl Default for MissionGate {
    fn default() -> Self { MissionGate::Enforce }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum InterAgentProtocol {
    Terse,
    Verbose,
}

impl Default for InterAgentProtocol {
    fn default() -> Self { InterAgentProtocol::Terse }
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
        Self { max_hours: 8, max_agents: 12 }
    }
}

fn default_ttl_hours() -> i64 { DEFAULT_MISSION_TTL_HOURS }
fn default_count() -> u8 { 1 }
fn default_auditor_pool() -> Vec<String> { vec!["auditor".to_string()] }
fn default_max_hours() -> u8 { 8 }
fn default_max_agents() -> u8 { 12 }

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
        if self.version != 1 {
            bail!("manifest.version must be 1 (got {})", self.version);
        }
        if self.mission_id.trim().is_empty() {
            bail!("manifest.mission_id cannot be empty");
        }
        if !self.mission_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            bail!("manifest.mission_id must be ASCII alphanumeric + hyphens (got '{}')", self.mission_id);
        }
        if self.description.trim().is_empty() {
            bail!("manifest.description cannot be empty");
        }
        if self.description.len() > 512 {
            bail!("manifest.description exceeds 512 chars (got {})", self.description.len());
        }
        if self.author.trim().is_empty() {
            bail!("manifest.author cannot be empty");
        }
        if self.mission_ttl_hours <= 0 {
            bail!("manifest.mission_ttl_hours must be > 0 (got {})", self.mission_ttl_hours);
        }
        if self.mission_ttl_hours > MAX_TTL_HOURS {
            bail!("manifest.mission_ttl_hours exceeds MAX_TTL_HOURS ({} > {})", self.mission_ttl_hours, MAX_TTL_HOURS);
        }
        if self.agents.is_empty() {
            bail!("manifest.agents cannot be empty");
        }
        if self.budget.max_hours > 24 {
            bail!("manifest.budget.max_hours exceeds 24 (got {})", self.budget.max_hours);
        }
        if self.budget.max_agents > 25 {
            bail!("manifest.budget.max_agents exceeds 25 (got {})", self.budget.max_agents);
        }
        if self.acceptance_criteria.len() > 10 {
            bail!("manifest.acceptance_criteria exceeds 10 items (got {})", self.acceptance_criteria.len());
        }
        for (i, ac) in self.acceptance_criteria.iter().enumerate() {
            if ac.len() > 200 {
                bail!("manifest.acceptance_criteria[{}] exceeds 200 chars (got {})", i, ac.len());
            }
        }
        if self.scope.paths.len() > 32 {
            bail!("manifest.scope.paths exceeds 32 entries (got {})", self.scope.paths.len());
        }
        for (i, p) in self.scope.paths.iter().enumerate() {
            if p.len() > 256 {
                bail!("manifest.scope.paths[{}] exceeds 256 chars (got {})", i, p.len());
            }
        }
        if self.scope.bash_patterns.extra_allow.len() > 20 {
            bail!("manifest.scope.bash_patterns.extra_allow exceeds 20 regexes (got {})", self.scope.bash_patterns.extra_allow.len());
        }
        for (i, p) in self.scope.bash_patterns.extra_allow.iter().enumerate() {
            if p.len() > 256 {
                bail!("manifest.scope.bash_patterns.extra_allow[{}] exceeds 256 chars (got {})", i, p.len());
            }
        }
        if self.scope.bash_patterns.extra_deny.len() > 50 {
            bail!("manifest.scope.bash_patterns.extra_deny exceeds 50 regexes (got {})", self.scope.bash_patterns.extra_deny.len());
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
                bail!("manifest.agents[{}].count exceeds 5 (got {})", i, agent.count);
            }
            if agent.count > 1 && agent.instances.len() != agent.count as usize {
                bail!("manifest.agents[{}]: count={} but instances has {} entries (must match)", i, agent.count, agent.instances.len());
            }
            total_agents += agent.count as u32;
            if agent.role == "auditor" {
                auditor_count += agent.count as u32;
            }
        }
        if total_agents > self.budget.max_agents as u32 {
            bail!("manifest total agents {} exceeds budget.max_agents {}", total_agents, self.budget.max_agents);
        }
        if total_agents > 25 {
            bail!("manifest total agents {} exceeds hard cap 25", total_agents);
        }
        if auditor_count > 1 {
            bail!("manifest has {} auditor instances — only 1 auditor allowed", auditor_count);
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
