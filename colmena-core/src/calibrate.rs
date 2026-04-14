use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::{Action, Rule, Conditions};
use crate::elo::AgentRating;
use crate::library::Role;

// ── Thresholds ───────────────────────────────────────────────────────────────

/// Configurable thresholds for ELO-based trust calibration.
#[derive(Debug, Clone)]
pub struct TrustThresholds {
    /// ELO >= this → Elevated tier (auto-approve role's tools_allowed)
    pub elevate_elo: i32,
    /// ELO >= this → Standard tier (no overrides, default rules)
    pub restrict_elo: i32,
    /// ELO >= this → Restricted tier (ask for everything)
    /// Below this → Probation tier (block dangerous tools)
    pub floor_elo: i32,
    /// Minimum peer reviews before ELO calibration applies
    pub min_reviews_to_calibrate: u32,
}

impl Default for TrustThresholds {
    fn default() -> Self {
        Self {
            elevate_elo: 1600,
            restrict_elo: 1300,
            floor_elo: 1100,
            min_reviews_to_calibrate: 3,
        }
    }
}

// ── Trust tiers ──────────────────────────────────────────────────────────────

/// Trust tier assigned to an agent based on ELO score and review count.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustTier {
    /// Not enough reviews yet — use default firewall rules
    Uncalibrated,
    /// ELO >= elevate_elo + enough reviews — auto-approve role's tools
    Elevated,
    /// ELO between restrict_elo and elevate_elo — default rules
    Standard,
    /// ELO between floor_elo and restrict_elo — ask for everything
    Restricted,
    /// ELO < floor_elo — block dangerous tools
    Probation,
}

impl TrustTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            TrustTier::Uncalibrated => "uncalibrated",
            TrustTier::Elevated => "elevated",
            TrustTier::Standard => "standard",
            TrustTier::Restricted => "restricted",
            TrustTier::Probation => "probation",
        }
    }
}

/// Determine the trust tier for an agent given their rating and thresholds.
pub fn determine_tier(
    rating: &AgentRating,
    thresholds: &TrustThresholds,
) -> TrustTier {
    if rating.review_count < thresholds.min_reviews_to_calibrate {
        return TrustTier::Uncalibrated;
    }
    if rating.elo >= thresholds.elevate_elo {
        TrustTier::Elevated
    } else if rating.elo >= thresholds.restrict_elo {
        TrustTier::Standard
    } else if rating.elo >= thresholds.floor_elo {
        TrustTier::Restricted
    } else {
        TrustTier::Probation
    }
}

// ── Calibration output ───────────────────────────────────────────────────────

/// A change in trust tier for a single agent.
#[derive(Debug, Clone)]
pub struct CalibrationChange {
    pub agent: String,
    pub old_tier: TrustTier,
    pub new_tier: TrustTier,
    pub elo: i32,
    pub reason: String,
}

/// Result of running calibration across all agents.
#[derive(Debug)]
pub struct CalibratedOverrides {
    pub agent_overrides: HashMap<String, Vec<Rule>>,
    pub changes: Vec<CalibrationChange>,
}

// ── Core calibration ─────────────────────────────────────────────────────────

/// Generate firewall agent_overrides from ELO ratings and role definitions.
///
/// - Elevated: auto-approve role's tools_allowed (with bash_pattern conditions if defined)
/// - Standard: no overrides (empty rules — agent uses default firewall path)
/// - Restricted: ask for all tools
/// - Probation: block Bash + WebFetch, ask for everything else
/// - Uncalibrated: no overrides (warm-up period)
pub fn calibrate(
    ratings: &[AgentRating],
    roles: &[Role],
    thresholds: &TrustThresholds,
    previous_overrides: &HashMap<String, Vec<Rule>>,
) -> CalibratedOverrides {
    let role_map: HashMap<&str, &Role> = roles.iter().map(|r| (r.id.as_str(), r)).collect();
    let mut overrides = HashMap::new();
    let mut changes = Vec::new();

    for rating in ratings {
        let new_tier = determine_tier(rating, thresholds);

        // Determine old tier from previous overrides
        let old_tier = infer_tier_from_overrides(
            previous_overrides.get(rating.agent.as_str()),
        );

        if new_tier != old_tier {
            changes.push(CalibrationChange {
                agent: rating.agent.clone(),
                old_tier: old_tier.clone(),
                new_tier: new_tier.clone(),
                elo: rating.elo,
                reason: format!(
                    "ELO {} with {} reviews",
                    rating.elo, rating.review_count
                ),
            });
        }

        let rules = match new_tier {
            TrustTier::Uncalibrated | TrustTier::Standard => {
                // No overrides — agent uses default firewall rules
                continue;
            }
            TrustTier::Elevated => {
                generate_elevated_rules(&rating.agent, &role_map)
            }
            TrustTier::Restricted => {
                generate_restricted_rules()
            }
            TrustTier::Probation => {
                generate_probation_rules()
            }
        };

        if !rules.is_empty() {
            overrides.insert(rating.agent.clone(), rules);
        }
    }

    // Clean orphan overrides: remove agent_ids not present in role_map
    let orphan_ids: Vec<String> = overrides.keys()
        .filter(|agent_id| !role_map.contains_key(agent_id.as_str()))
        .cloned()
        .collect();
    for orphan_id in &orphan_ids {
        changes.push(CalibrationChange {
            agent: orphan_id.clone(),
            old_tier: infer_tier_from_overrides(previous_overrides.get(orphan_id.as_str())),
            new_tier: TrustTier::Standard,
            elo: 0,
            reason: "Orphan override removed: role not in library".to_string(),
        });
    }
    overrides.retain(|agent_id, _| role_map.contains_key(agent_id.as_str()));

    CalibratedOverrides { agent_overrides: overrides, changes }
}

/// Generate auto-approve rules for an elevated agent based on their role.
fn generate_elevated_rules(
    agent_id: &str,
    role_map: &HashMap<&str, &Role>,
) -> Vec<Rule> {
    let mut rules = Vec::new();

    if let Some(role) = role_map.get(agent_id) {
        // Separate Bash from other tools
        let non_bash: Vec<String> = role.tools_allowed.iter()
            .filter(|t| *t != "Bash")
            .cloned()
            .collect();

        // Auto-approve non-Bash tools
        if !non_bash.is_empty() {
            rules.push(Rule {
                tools: non_bash,
                conditions: None,
                action: Action::AutoApprove,
                reason: Some(format!("Elevated trust for role '{}'", role.id)),
            });
        }

        // Bash: if role has bash_patterns, create one rule per pattern
        // Otherwise, auto-approve all Bash
        if role.tools_allowed.contains(&"Bash".to_string()) {
            if let Some(ref perms) = role.permissions {
                if !perms.bash_patterns.is_empty() {
                    for pattern in &perms.bash_patterns {
                        rules.push(Rule {
                            tools: vec!["Bash".to_string()],
                            conditions: Some(Conditions {
                                bash_pattern: Some(pattern.clone()),
                                path_within: None,
                                path_not_match: None,
                            }),
                            action: Action::AutoApprove,
                            reason: Some(format!(
                                "Elevated trust: Bash pattern '{}' for role '{}'",
                                pattern, role.id
                            )),
                        });
                    }
                } else {
                    rules.push(Rule {
                        tools: vec!["Bash".to_string()],
                        conditions: None,
                        action: Action::Ask,
                        reason: Some(format!("Elevated trust: Bash requires patterns for auto-approve (role '{}')", role.id)),
                    });
                }
            } else {
                rules.push(Rule {
                    tools: vec!["Bash".to_string()],
                    conditions: None,
                    action: Action::Ask,
                    reason: Some(format!("Elevated trust: Bash requires patterns for auto-approve (role '{}')", role.id)),
                });
            }
        }
    }

    rules
}

/// Generate ask-for-everything rules for a restricted agent.
fn generate_restricted_rules() -> Vec<Rule> {
    vec![Rule {
        tools: vec![
            "Bash".to_string(), "Write".to_string(), "Edit".to_string(),
            "WebFetch".to_string(), "WebSearch".to_string(), "Agent".to_string(),
        ],
        conditions: None,
        action: Action::Ask,
        reason: Some("Restricted trust: ELO below threshold".to_string()),
    }]
}

/// Generate probation rules: block dangerous tools, ask for others.
fn generate_probation_rules() -> Vec<Rule> {
    vec![
        Rule {
            tools: vec!["Bash".to_string(), "WebFetch".to_string()],
            conditions: None,
            action: Action::Block,
            reason: Some("Probation: dangerous tools blocked due to low ELO".to_string()),
        },
        Rule {
            tools: vec![
                "Write".to_string(), "Edit".to_string(),
                "WebSearch".to_string(), "Agent".to_string(),
            ],
            conditions: None,
            action: Action::Ask,
            reason: Some("Probation: all other tools require approval".to_string()),
        },
    ]
}

/// Infer what tier an agent was in based on their existing overrides.
fn infer_tier_from_overrides(rules: Option<&Vec<Rule>>) -> TrustTier {
    match rules {
        None => TrustTier::Standard, // no overrides = standard or uncalibrated
        Some(rules) if rules.is_empty() => TrustTier::Standard,
        Some(rules) => {
            // Check if any rule is Block → Probation
            if rules.iter().any(|r| r.action == Action::Block) {
                TrustTier::Probation
            } else if rules.iter().all(|r| r.action == Action::Ask) {
                TrustTier::Restricted
            } else {
                TrustTier::Elevated
            }
        }
    }
}

// ── Persistence ──────────────────────────────────────────────────────────────

/// Serializable wrapper for agent overrides stored as JSON.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct StoredOverrides {
    pub agent_overrides: HashMap<String, Vec<StoredRule>>,
}

/// A rule suitable for JSON serialization (mirrors config::Rule).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredRule {
    pub tools: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<StoredConditions>,
    pub action: Action,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredConditions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bash_pattern: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_within: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_not_match: Option<Vec<String>>,
}

impl From<&Rule> for StoredRule {
    fn from(rule: &Rule) -> Self {
        StoredRule {
            tools: rule.tools.clone(),
            conditions: rule.conditions.as_ref().map(|c| StoredConditions {
                bash_pattern: c.bash_pattern.clone(),
                path_within: c.path_within.clone(),
                path_not_match: c.path_not_match.clone(),
            }),
            action: rule.action.clone(),
            reason: rule.reason.clone(),
        }
    }
}

impl From<&StoredRule> for Rule {
    fn from(stored: &StoredRule) -> Self {
        Rule {
            tools: stored.tools.clone(),
            conditions: stored.conditions.as_ref().map(|c| Conditions {
                bash_pattern: c.bash_pattern.clone(),
                path_within: c.path_within.clone(),
                path_not_match: c.path_not_match.clone(),
            }),
            action: stored.action.clone(),
            reason: stored.reason.clone(),
        }
    }
}

/// Save calibrated overrides to a JSON file (atomic write).
pub fn save_overrides(path: &Path, overrides: &CalibratedOverrides) -> Result<()> {
    let stored = StoredOverrides {
        agent_overrides: overrides.agent_overrides.iter()
            .map(|(agent, rules)| {
                (agent.clone(), rules.iter().map(StoredRule::from).collect())
            })
            .collect(),
    };

    let json = serde_json::to_string_pretty(&stored)
        .context("Failed to serialize ELO overrides")?;

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp_path = dir.join(".elo-overrides.tmp");

    std::fs::write(&tmp_path, &json)
        .with_context(|| format!("Failed to write temp overrides file: {}", tmp_path.display()))?;

    std::fs::rename(&tmp_path, path)
        .with_context(|| format!("Failed to rename temp overrides file to {}", path.display()))?;

    Ok(())
}

/// Load calibrated overrides from a JSON file.
/// Returns empty map if file doesn't exist or can't be parsed.
pub fn load_overrides(path: &Path) -> HashMap<String, Vec<Rule>> {
    let contents = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return HashMap::new(),
    };

    let stored: StoredOverrides = match serde_json::from_str(&contents) {
        Ok(s) => s,
        Err(_) => return HashMap::new(),
    };

    stored.agent_overrides.iter()
        .map(|(agent, rules)| {
            (agent.clone(), rules.iter().map(Rule::from).collect())
        })
        .collect()
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::{EloConfig, MentoringConfig, RolePermissions};

    fn make_rating(agent: &str, elo: i32, review_count: u32) -> AgentRating {
        AgentRating {
            agent: agent.to_string(),
            elo,
            trend_7d: 0,
            review_count,
            last_active: None,
        }
    }

    fn make_role(id: &str, tools: Vec<&str>, bash_patterns: Option<Vec<&str>>) -> Role {
        Role {
            id: id.to_string(),
            name: id.to_string(),
            icon: "🔧".to_string(),
            description: format!("{} role", id),
            system_prompt_ref: format!("prompts/{}.md", id),
            default_trust_level: "ask".to_string(),
            tools_allowed: tools.into_iter().map(|s| s.to_string()).collect(),
            specializations: vec![],
            permissions: bash_patterns.map(|bp| RolePermissions {
                bash_patterns: bp.into_iter().map(|s| s.to_string()).collect(),
                path_within: vec![],
                path_not_match: vec![],
            }),
            role_type: None,
            elo: EloConfig { initial: 1500, categories: Default::default() },
            mentoring: MentoringConfig { can_mentor: vec![], mentored_by: vec![] },
        }
    }

    #[test]
    fn test_determine_tier_uncalibrated() {
        let rating = make_rating("newbie", 1500, 2); // only 2 reviews
        let thresholds = TrustThresholds::default();
        assert_eq!(determine_tier(&rating, &thresholds), TrustTier::Uncalibrated);
    }

    #[test]
    fn test_determine_tier_elevated() {
        let rating = make_rating("star", 1650, 5);
        let thresholds = TrustThresholds::default();
        assert_eq!(determine_tier(&rating, &thresholds), TrustTier::Elevated);
    }

    #[test]
    fn test_determine_tier_standard() {
        let rating = make_rating("average", 1400, 5);
        let thresholds = TrustThresholds::default();
        assert_eq!(determine_tier(&rating, &thresholds), TrustTier::Standard);
    }

    #[test]
    fn test_determine_tier_restricted() {
        let rating = make_rating("weak", 1200, 5);
        let thresholds = TrustThresholds::default();
        assert_eq!(determine_tier(&rating, &thresholds), TrustTier::Restricted);
    }

    #[test]
    fn test_determine_tier_probation() {
        let rating = make_rating("bad", 1050, 5);
        let thresholds = TrustThresholds::default();
        assert_eq!(determine_tier(&rating, &thresholds), TrustTier::Probation);
    }

    #[test]
    fn test_calibrate_elevated_with_bash_patterns() {
        let ratings = vec![make_rating("pentester", 1700, 5)];
        let roles = vec![make_role(
            "pentester",
            vec!["Bash", "Read", "Write"],
            Some(vec!["^nmap ", "^nikto "]),
        )];
        let thresholds = TrustThresholds::default();
        let result = calibrate(&ratings, &roles, &thresholds, &HashMap::new());

        let rules = result.agent_overrides.get("pentester").unwrap();
        // Should have: 1 rule for Read+Write (auto-approve) + 2 rules for Bash patterns
        assert_eq!(rules.len(), 3);
        assert!(rules.iter().any(|r| r.tools == vec!["Read", "Write"]));
        assert!(rules.iter().any(|r| {
            r.tools == vec!["Bash"]
                && r.conditions.as_ref().map(|c| c.bash_pattern.as_deref()) == Some(Some("^nmap "))
        }));
    }

    #[test]
    fn test_calibrate_elevated_no_bash_patterns() {
        let ratings = vec![make_rating("auditor", 1700, 5)];
        let roles = vec![make_role("auditor", vec!["Bash", "Read"], None)];
        let thresholds = TrustThresholds::default();
        let result = calibrate(&ratings, &roles, &thresholds, &HashMap::new());

        let rules = result.agent_overrides.get("auditor").unwrap();
        // Should have: 1 rule for Read (auto-approve) + 1 rule for Bash (ask, no patterns)
        assert_eq!(rules.len(), 2);
        let bash_rule = rules.iter().find(|r| r.tools == vec!["Bash"] && r.conditions.is_none()).unwrap();
        // Without bash_patterns, Bash must NOT be auto-approved (security: DREAD 5.6)
        assert_eq!(bash_rule.action, Action::Ask);
    }

    #[test]
    fn test_calibrate_standard_no_overrides() {
        let ratings = vec![make_rating("average", 1400, 5)];
        let roles = vec![make_role("average", vec!["Read"], None)];
        let thresholds = TrustThresholds::default();
        let result = calibrate(&ratings, &roles, &thresholds, &HashMap::new());

        assert!(!result.agent_overrides.contains_key("average"));
    }

    #[test]
    fn test_calibrate_probation_blocks_bash() {
        let ratings = vec![make_rating("bad", 1050, 5)];
        let roles = vec![make_role("bad", vec!["Bash", "Read"], None)];
        let thresholds = TrustThresholds::default();
        let result = calibrate(&ratings, &roles, &thresholds, &HashMap::new());

        let rules = result.agent_overrides.get("bad").unwrap();
        assert!(rules.iter().any(|r| r.tools.contains(&"Bash".to_string()) && r.action == Action::Block));
    }

    #[test]
    fn test_calibrate_tracks_changes() {
        let ratings = vec![make_rating("agent", 1700, 5)];
        let roles = vec![make_role("agent", vec!["Read"], None)];
        let thresholds = TrustThresholds::default();
        let result = calibrate(&ratings, &roles, &thresholds, &HashMap::new());

        assert_eq!(result.changes.len(), 1);
        assert_eq!(result.changes[0].new_tier, TrustTier::Elevated);
    }

    #[test]
    fn test_save_and_load_overrides() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("elo-overrides.json");

        let overrides = CalibratedOverrides {
            agent_overrides: HashMap::from([(
                "pentester".to_string(),
                vec![Rule {
                    tools: vec!["Read".to_string()],
                    conditions: None,
                    action: Action::AutoApprove,
                    reason: Some("test".to_string()),
                }],
            )]),
            changes: vec![],
        };

        save_overrides(&path, &overrides).unwrap();
        let loaded = load_overrides(&path);

        assert!(loaded.contains_key("pentester"));
        assert_eq!(loaded["pentester"].len(), 1);
        assert_eq!(loaded["pentester"][0].action, Action::AutoApprove);
    }

    #[test]
    fn test_load_overrides_nonexistent_returns_empty() {
        let loaded = load_overrides(Path::new("/nonexistent/path.json"));
        assert!(loaded.is_empty());
    }

    #[test]
    fn test_calibrate_cleans_orphan_overrides() {
        // "ghost" has low ELO → Probation tier, which generates generic rules
        // without checking role_map. Since "ghost" has no role in the library,
        // it should be cleaned out as an orphan override.
        let ratings = vec![
            make_rating("ghost", 1050, 5),    // Probation, no role
            make_rating("pentester", 1050, 5), // Probation, has role
        ];
        // Only "pentester" has a role; "ghost" does not.
        let roles = vec![make_role("pentester", vec!["Bash", "Read"], None)];
        let thresholds = TrustThresholds::default();
        let result = calibrate(&ratings, &roles, &thresholds, &HashMap::new());

        // "ghost" should NOT be in agent_overrides (orphan removed)
        assert!(
            !result.agent_overrides.contains_key("ghost"),
            "orphan agent 'ghost' should be removed from overrides"
        );

        // "pentester" should still be present (has a matching role)
        assert!(
            result.agent_overrides.contains_key("pentester"),
            "pentester with matching role should remain"
        );

        // There should be a CalibrationChange for "ghost" with orphan reason
        let orphan_change = result.changes.iter().find(|c| c.agent == "ghost" && c.reason.contains("Orphan"));
        assert!(
            orphan_change.is_some(),
            "should log a CalibrationChange for orphan removal"
        );
        let change = orphan_change.unwrap();
        assert_eq!(change.new_tier, TrustTier::Standard);
        assert_eq!(change.elo, 0);
    }
}
