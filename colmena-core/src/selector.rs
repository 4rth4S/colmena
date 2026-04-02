use crate::config::Action;
use crate::delegate::{DelegationConditions, RuntimeDelegation};
use crate::library::{Role, Pattern};
use chrono::Utc;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use anyhow::{Context, Result};

// ── Public types ──────────────────────────────────────────────────────────────

/// A pattern recommendation with score and details
#[derive(Debug, Clone)]
pub struct Recommendation {
    pub pattern_id: String,
    pub pattern_name: String,
    pub score: f64,
    pub matched_criteria: Vec<String>,
    pub anti_matched: Vec<String>,
    pub role_assignments: Vec<RoleAssignment>,
}

#[derive(Debug, Clone)]
pub struct RoleAssignment {
    pub slot: String,
    pub role_id: String,
    pub role_name: String,
    pub icon: String,
}

/// Default TTL for mission-generated delegations: 8 hours.
pub const DEFAULT_MISSION_TTL_HOURS: i64 = 8;

/// Generated mission configuration
#[derive(Debug)]
pub struct MissionConfig {
    pub mission_dir: PathBuf,
    pub agent_configs: Vec<AgentConfig>,
    /// Auto-generated delegations from role permissions
    pub delegations: Vec<RuntimeDelegation>,
}

#[derive(Debug)]
pub struct AgentConfig {
    pub role_id: String,
    pub role_name: String,
    pub claude_md_path: PathBuf,
}

// ── Tokenizer ─────────────────────────────────────────────────────────────────

/// Stop words to filter from mission text
const STOP_WORDS: &[&str] = &[
    "the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for",
    "of", "with", "by", "from", "is", "are", "was", "were", "be", "been",
    "being", "have", "has", "had", "do", "does", "did", "will", "would",
    "could", "should", "may", "might", "can", "this", "that", "these",
    "those", "it", "its",
];

/// Tokenize text into lowercase words, filtering stop words
fn tokenize(text: &str) -> Vec<String> {
    text.to_lowercase()
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|w| w.len() > 2 && !STOP_WORDS.contains(w))
        .map(|w| w.to_string())
        .collect()
}

/// Count keyword overlap between two token sets
fn keyword_overlap(tokens_a: &[String], tokens_b: &[String]) -> usize {
    tokens_a.iter().filter(|t| tokens_b.contains(t)).count()
}

// ── Pattern Scoring ───────────────────────────────────────────────────────────

/// Select and rank patterns for a mission
pub fn select_patterns(
    mission: &str,
    patterns: &[Pattern],
    roles: &[Role],
) -> Vec<Recommendation> {
    let mission_tokens = tokenize(mission);
    if mission_tokens.is_empty() {
        return Vec::new();
    }

    let role_map: HashMap<&str, &Role> = roles.iter().map(|r| (r.id.as_str(), r)).collect();

    let mut recommendations: Vec<Recommendation> = patterns
        .iter()
        .filter_map(|pattern| {
            // Score when_to_use matches
            let mut when_hits = Vec::new();
            for criterion in &pattern.when_to_use {
                let criterion_tokens = tokenize(criterion);
                let overlap = keyword_overlap(&mission_tokens, &criterion_tokens);
                if overlap > 0 {
                    when_hits.push(criterion.clone());
                }
            }

            // Score when_not_to_use matches
            let mut anti_hits = Vec::new();
            for criterion in &pattern.when_not_to_use {
                let criterion_tokens = tokenize(criterion);
                let overlap = keyword_overlap(&mission_tokens, &criterion_tokens);
                if overlap > 0 {
                    anti_hits.push(criterion.clone());
                }
            }

            // Score role specialization matches
            let mut spec_hits = 0usize;
            for role_id in pattern.roles_suggested.all_role_ids() {
                if let Some(role) = role_map.get(role_id.as_str()) {
                    let spec_tokens: Vec<String> = role.specializations.iter()
                        .flat_map(|s| tokenize(s))
                        .collect();
                    spec_hits += keyword_overlap(&mission_tokens, &spec_tokens);
                }
            }

            let score = (when_hits.len() as f64) * 2.0
                + (spec_hits as f64) * 1.5
                - (anti_hits.len() as f64) * 3.0;

            if score <= 0.0 {
                return None;
            }

            // Build role assignments
            let role_assignments = build_role_assignments(&pattern.roles_suggested, &role_map);

            Some(Recommendation {
                pattern_id: pattern.id.clone(),
                pattern_name: pattern.name.clone(),
                score,
                matched_criteria: when_hits,
                anti_matched: anti_hits,
                role_assignments,
            })
        })
        .collect();

    recommendations.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
    recommendations.truncate(3);
    recommendations
}

fn build_role_assignments(
    roles_suggested: &crate::library::RolesSuggested,
    role_map: &HashMap<&str, &Role>,
) -> Vec<RoleAssignment> {
    let mut assignments = Vec::new();
    for (slot, role_slot) in &roles_suggested.0 {
        for role_id in role_slot.as_vec() {
            let (name, icon) = role_map
                .get(role_id.as_str())
                .map(|r| (r.name.clone(), r.icon.clone()))
                .unwrap_or_else(|| (role_id.clone(), "?".to_string()));
            assignments.push(RoleAssignment {
                slot: slot.clone(),
                role_id,
                role_name: name,
                icon,
            });
        }
    }
    assignments
}

// ── Role Gap Detection ────────────────────────────────────────────────────────

/// Detect mission keywords that don't match any role specialization
pub fn detect_role_gaps(mission: &str, roles: &[Role]) -> Vec<String> {
    let mission_tokens = tokenize(mission);
    let all_specs: Vec<String> = roles.iter()
        .flat_map(|r| r.specializations.iter())
        .flat_map(|s| tokenize(s))
        .collect();

    // Common security keywords that might indicate a missing role
    let domain_keywords = [
        "cloud", "aws", "gcp", "azure", "kubernetes", "k8s", "docker",
        "mobile", "ios", "android", "flutter", "react", "frontend",
        "blockchain", "smart_contract", "defi", "infrastructure",
        "network", "wireless", "iot", "firmware", "hardware",
        "social_engineering", "phishing", "red_team",
    ];

    mission_tokens
        .iter()
        .filter(|t| {
            domain_keywords.contains(&t.as_str()) && !all_specs.contains(t)
        })
        .cloned()
        .collect::<Vec<_>>()
        .into_iter()
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect()
}

// ── Mission Config Generator ──────────────────────────────────────────────────

/// Generate a mission directory with CLAUDE.md per agent and role-bound delegations.
///
/// If `session_id` is provided, all generated delegations are scoped to that session.
pub fn generate_mission(
    mission: &str,
    recommendation: &Recommendation,
    roles: &[Role],
    library_dir: &Path,
    missions_dir: &Path,
    session_id: Option<&str>,
) -> Result<MissionConfig> {
    let role_map: HashMap<&str, &Role> = roles.iter().map(|r| (r.id.as_str(), r)).collect();

    // Create mission directory with date prefix
    let date = Utc::now().format("%Y-%m-%d");
    let mission_slug: String = mission
        .to_lowercase()
        .split_whitespace()
        .take(4)
        .collect::<Vec<_>>()
        .join("-")
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    let mission_slug = if mission_slug.is_empty() {
        "unnamed-mission".to_string()
    } else {
        mission_slug
    };
    let mission_name = format!("{}-{}", date, mission_slug);
    let mission_dir = missions_dir.join(&mission_name);
    let agents_dir = mission_dir.join("agents");

    std::fs::create_dir_all(&agents_dir)
        .with_context(|| format!("Failed to create mission dir: {}", mission_dir.display()))?;

    // Write mission.yaml
    let mission_yaml = format!(
        "mission: \"{}\"\npattern: {}\npattern_name: \"{}\"\ncreated: {}\nagents:\n{}",
        mission.replace('"', "\\\""),
        recommendation.pattern_id,
        recommendation.pattern_name,
        Utc::now().to_rfc3339(),
        recommendation.role_assignments.iter()
            .map(|a| format!("  - role: {}\n    slot: {}", a.role_id, a.slot))
            .collect::<Vec<_>>()
            .join("\n")
    );
    std::fs::write(mission_dir.join("mission.yaml"), &mission_yaml)?;

    // Generate CLAUDE.md per agent + role-bound delegations
    let mut agent_configs = Vec::new();
    let mut delegations = Vec::new();
    let now = Utc::now();
    let ttl = chrono::Duration::hours(DEFAULT_MISSION_TTL_HOURS);

    for assignment in &recommendation.role_assignments {
        let agent_dir = agents_dir.join(&assignment.role_id);
        std::fs::create_dir_all(&agent_dir)?;

        let role = role_map.get(assignment.role_id.as_str())
            .ok_or_else(|| anyhow::anyhow!(
                "Pattern '{}' references undefined role '{}'. Add it with: colmena library create-role --id {} --description \"...\"",
                recommendation.pattern_id, assignment.role_id, assignment.role_id
            ))?;

        // Generate delegations from role's tools_allowed + permissions
        let role_delegations = generate_role_delegations(
            role,
            &mission_name,
            &mission_dir,
            session_id,
            now,
            ttl,
        );
        delegations.extend(role_delegations);

        // Load the system prompt
        let system_prompt = crate::library::load_prompt(library_dir, &role.system_prompt_ref)
            .with_context(|| format!("Failed to load prompt for role '{}'", assignment.role_id))?;

        // Build pre-approved operations section
        let pre_approved = format_pre_approved_ops(role);

        // Build CLAUDE.md combining role prompt + mission context + permissions
        let claude_md = format!(
            "{}\n\n---\n\n## Mission\n\n{}\n\n## Your Role in This Mission\n\n\
            You are the **{}** ({}) in a **{}** pattern.\n\
            Your slot: **{}**\n\n\
            ## Team\n\n{}\n\n## Trust Level\n\n{}\n\n{}\n",
            system_prompt,
            mission,
            assignment.role_name,
            assignment.icon,
            recommendation.pattern_name,
            assignment.slot,
            recommendation.role_assignments.iter()
                .map(|a| format!("- {} {} ({})", a.icon, a.role_name, a.slot))
                .collect::<Vec<_>>()
                .join("\n"),
            role.default_trust_level,
            pre_approved,
        );

        let claude_md_path = agent_dir.join("CLAUDE.md");
        std::fs::write(&claude_md_path, &claude_md)?;

        agent_configs.push(AgentConfig {
            role_id: assignment.role_id.clone(),
            role_name: assignment.role_name.clone(),
            claude_md_path,
        });
    }

    Ok(MissionConfig {
        mission_dir,
        agent_configs,
        delegations,
    })
}

/// Generate RuntimeDelegations from a role's tools_allowed and permissions.
fn generate_role_delegations(
    role: &Role,
    mission_id: &str,
    mission_dir: &Path,
    session_id: Option<&str>,
    now: chrono::DateTime<Utc>,
    ttl: chrono::Duration,
) -> Vec<RuntimeDelegation> {
    let mut delegations = Vec::new();
    let mission_dir_str = mission_dir.to_string_lossy().to_string();

    // File-based tools that support path_within scoping
    let file_tools: &[&str] = &["Read", "Write", "Edit", "Glob", "Grep"];

    for tool in &role.tools_allowed {
        if tool == "Bash" {
            // Bash: if role has bash_patterns, create one delegation per pattern
            if let Some(ref perms) = role.permissions {
                if !perms.bash_patterns.is_empty() {
                    for pattern in &perms.bash_patterns {
                        delegations.push(RuntimeDelegation {
                            tool: "Bash".to_string(),
                            agent_id: Some(role.id.clone()),
                            action: Action::AutoApprove,
                            created_at: now,
                            expires_at: Some(now + ttl),
                            session_id: session_id.map(|s| s.to_string()),
                            source: Some("role".to_string()),
                            mission_id: Some(mission_id.to_string()),
                            conditions: Some(DelegationConditions {
                                bash_pattern: Some(pattern.clone()),
                                path_within: None,
                                path_not_match: None,
                            }),
                        });
                    }
                    continue; // bash_patterns defined, don't add a blanket Bash delegation
                }
            }
            // No bash_patterns: auto-approve all Bash for this agent
            delegations.push(RuntimeDelegation {
                tool: "Bash".to_string(),
                agent_id: Some(role.id.clone()),
                action: Action::AutoApprove,
                created_at: now,
                expires_at: Some(now + ttl),
                session_id: session_id.map(|s| s.to_string()),
                source: Some("role".to_string()),
                mission_id: Some(mission_id.to_string()),
                conditions: None,
            });
        } else {
            // Non-Bash tool: check if it supports path scoping
            let conditions = if file_tools.contains(&tool.as_str()) {
                // Apply path_within from role permissions if defined
                role.permissions.as_ref().and_then(|perms| {
                    if perms.path_within.is_empty() && perms.path_not_match.is_empty() {
                        None
                    } else {
                        let path_within = if perms.path_within.is_empty() {
                            None
                        } else {
                            Some(perms.path_within.iter()
                                .map(|p| p.replace("${MISSION_DIR}", &mission_dir_str))
                                .collect())
                        };
                        Some(DelegationConditions {
                            bash_pattern: None,
                            path_within,
                            path_not_match: if perms.path_not_match.is_empty() {
                                None
                            } else {
                                Some(perms.path_not_match.clone())
                            },
                        })
                    }
                })
            } else {
                None
            };

            delegations.push(RuntimeDelegation {
                tool: tool.clone(),
                agent_id: Some(role.id.clone()),
                action: Action::AutoApprove,
                created_at: now,
                expires_at: Some(now + ttl),
                session_id: session_id.map(|s| s.to_string()),
                source: Some("role".to_string()),
                mission_id: Some(mission_id.to_string()),
                conditions,
            });
        }
    }

    delegations
}

/// Format a "Pre-Approved Operations" section for CLAUDE.md
fn format_pre_approved_ops(role: &Role) -> String {
    let mut lines = vec!["## Pre-Approved Operations".to_string()];
    lines.push(String::new());
    lines.push("The following operations are pre-approved for your role in this mission:".to_string());

    for tool in &role.tools_allowed {
        if tool == "Bash" {
            if let Some(ref perms) = role.permissions {
                if !perms.bash_patterns.is_empty() {
                    let patterns: Vec<String> = perms.bash_patterns.iter()
                        .map(|p| format!("`{}`", p))
                        .collect();
                    lines.push(format!("- **Bash**: commands matching {}", patterns.join(", ")));
                    continue;
                }
            }
            lines.push("- **Bash**: all commands".to_string());
        } else {
            let scope = if let Some(ref perms) = role.permissions {
                if !perms.path_within.is_empty() && ["Read", "Write", "Edit", "Glob", "Grep"].contains(&tool.as_str()) {
                    format!(" (within: {})", perms.path_within.join(", "))
                } else {
                    String::new()
                }
            } else {
                String::new()
            };
            lines.push(format!("- **{}**{}", tool, scope));
        }
    }

    lines.push(String::new());
    lines.push("Blocked operations (always require human approval):".to_string());
    lines.push("- Force push, destructive filesystem operations, etc.".to_string());

    lines.join("\n")
}

// ── Role Scaffold Generator ───────────────────────────────────────────────────

/// Create a new role scaffold in the library
pub fn scaffold_role(id: &str, description: &str, library_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    // Validate role ID
    if id.is_empty() || id.len() > 64 {
        anyhow::bail!("Role ID must be 1-64 characters, got {}", id.len());
    }
    if !id.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
        anyhow::bail!(
            "Role ID '{}' contains invalid characters — only alphanumeric, dash, underscore allowed",
            id
        );
    }

    let role_path = library_dir.join("roles").join(format!("{}.yaml", id));
    let prompt_path = library_dir.join("prompts").join(format!("{}.md", id));

    if role_path.exists() {
        anyhow::bail!(
            "Role '{}' already exists at {}. Remove it first to recreate.",
            id,
            role_path.display()
        );
    }

    std::fs::create_dir_all(library_dir.join("roles"))?;
    std::fs::create_dir_all(library_dir.join("prompts"))?;

    let role_yaml = format!(
        r#"name: {name}
id: {id}
icon: "🔧"
description: "{description}"

system_prompt_ref: prompts/{id}.md

default_trust_level: ask
tools_allowed: [Read, Glob, Grep, WebFetch, WebSearch]

specializations: []

# Firewall permissions — auto-generated as delegations when a mission uses this role.
# Uncomment and customize to define what this role can do without asking.
# permissions:
#   bash_patterns: []
#   path_within: ['${{MISSION_DIR}}']
#   path_not_match: ['*.env', '*credentials*', '*.key']

elo:
  initial: 1500
  categories: {{}}

mentoring:
  can_mentor: []
  mentored_by: [security_architect]
"#,
        name = id.replace(['_', '-'], " "),
        id = id,
        description = description.replace('"', "\\\""),
    );

    let name = id.replace(['_', '-'], " ");
    let prompt_md = format!(
        "# {name}\n\n{description}\n\n\
        ## Tools Available\n\n\
        The following tools are pre-approved for your role:\n\
        - Read, Glob, Grep — codebase exploration\n\
        - WebFetch, WebSearch — external research\n\n\
        Customize this list in `roles/{id}.yaml` under `tools_allowed`.\n\
        Add `permissions.bash_patterns` to define auto-approved Bash commands.\n\n\
        ## Output Format\n\n\
        TODO: Define expected output format.\n",
    );

    std::fs::write(&role_path, role_yaml)?;
    std::fs::write(&prompt_path, prompt_md)?;

    Ok((role_path, prompt_path))
}

// ── Formatting ────────────────────────────────────────────────────────────────

/// Format recommendations as a human-readable string
pub fn format_recommendations(recommendations: &[Recommendation]) -> String {
    if recommendations.is_empty() {
        return "No matching patterns found for this mission.".to_string();
    }

    let mut output = String::from("Recommended patterns:\n\n");
    for (i, rec) in recommendations.iter().enumerate() {
        let label = if i == 0 { " [RECOMMENDED]" } else { "" };
        output.push_str(&format!("  {}. {}{}\n", i + 1, rec.pattern_name, label));

        // Group assignments by slot
        for assignment in &rec.role_assignments {
            output.push_str(&format!(
                "     {} {} {}: {}\n",
                assignment.icon,
                assignment.role_name,
                if assignment.slot.contains("worker")
                    || assignment.slot.contains("executor")
                    || assignment.slot.contains("explorer")
                    || assignment.slot.contains("stage")
                    || assignment.slot.contains("debater")
                {
                    "(worker)"
                } else {
                    "(lead)"
                },
                assignment.slot
            ));
        }

        output.push_str(&format!("     Score: {:.1}\n", rec.score));
        if !rec.matched_criteria.is_empty() {
            for m in &rec.matched_criteria {
                output.push_str(&format!("     ✓ {}\n", m));
            }
        }
        output.push('\n');
    }
    output
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── helpers ───────────────────────────────────────────────────────────────

    fn make_role(id: &str, name: &str, specializations: Vec<&str>) -> Role {
        use crate::library::{EloConfig, MentoringConfig};
        Role {
            id: id.to_string(),
            name: name.to_string(),
            icon: "🔧".to_string(),
            description: format!("{} role", name),
            system_prompt_ref: format!("prompts/{}.md", id),
            default_trust_level: "ask".to_string(),
            tools_allowed: vec!["Read".to_string()],
            specializations: specializations.into_iter().map(|s| s.to_string()).collect(),
            elo: EloConfig {
                initial: 1500,
                categories: Default::default(),
            },
            permissions: None,
            mentoring: MentoringConfig {
                can_mentor: vec![],
                mentored_by: vec![],
            },
        }
    }

    fn make_pattern(
        id: &str,
        name: &str,
        when_to_use: Vec<&str>,
        when_not_to_use: Vec<&str>,
        roles: Vec<(&str, &str)>,
    ) -> Pattern {
        use crate::library::{RolesSuggested, RoleSlot};
        let mut slots = std::collections::HashMap::new();
        for (slot, role_id) in roles {
            slots.insert(slot.to_string(), RoleSlot::Single(role_id.to_string()));
        }
        Pattern {
            id: id.to_string(),
            name: name.to_string(),
            source: None,
            description: format!("{} pattern", name),
            topology: "star".to_string(),
            communication: "hub_and_spoke".to_string(),
            when_to_use: when_to_use.into_iter().map(|s| s.to_string()).collect(),
            when_not_to_use: when_not_to_use.into_iter().map(|s| s.to_string()).collect(),
            pros: vec![],
            cons: vec![],
            estimated_token_cost: "medium".to_string(),
            estimated_agents: "2-4".to_string(),
            roles_suggested: RolesSuggested(slots),
            elo_lead_selection: false,
        }
    }

    // ── 1. select_patterns: audit mission ────────────────────────────────────

    #[test]
    fn test_select_patterns_audit_mission() {
        let roles = vec![
            make_role("security_architect", "Security Architect", vec!["audit", "compliance", "pci"]),
            make_role("auditor", "Auditor", vec!["audit", "compliance", "pci_dss", "payments"]),
            make_role("researcher", "Researcher", vec!["research", "analysis"]),
        ];

        let patterns = vec![
            make_pattern(
                "oracle_workers",
                "Oracle + Workers",
                vec![
                    "Large parallelisable audit tasks",
                    "Compliance checks with multiple specialists",
                ],
                vec!["Simple single-step tasks"],
                vec![
                    ("oracle", "security_architect"),
                    ("worker1", "auditor"),
                ],
            ),
            make_pattern(
                "plan_then_execute",
                "Plan Then Execute",
                vec![
                    "Tasks requiring upfront planning",
                    "Compliance and audit workflows",
                ],
                vec![],
                vec![
                    ("planner", "security_architect"),
                    ("executor", "auditor"),
                ],
            ),
            make_pattern(
                "single_agent",
                "Single Agent",
                vec!["Simple research tasks"],
                vec![],
                vec![("agent", "researcher")],
            ),
        ];

        let mission = "audit PCI-DSS compliance of payments API";
        let recs = select_patterns(mission, &patterns, &roles);

        assert!(!recs.is_empty(), "should have at least one recommendation");
        // oracle_workers or plan_then_execute should rank at top
        let top_id = &recs[0].pattern_id;
        assert!(
            top_id == "oracle_workers" || top_id == "plan_then_execute",
            "expected oracle_workers or plan_then_execute at top, got: {}",
            top_id
        );
        // score should be positive
        assert!(recs[0].score > 0.0);
    }

    // ── 2. select_patterns: empty mission ────────────────────────────────────

    #[test]
    fn test_select_patterns_empty_mission() {
        let roles = vec![make_role("auditor", "Auditor", vec!["audit"])];
        let patterns = vec![make_pattern(
            "oracle_workers",
            "Oracle + Workers",
            vec!["audit tasks"],
            vec![],
            vec![("oracle", "auditor")],
        )];

        let recs = select_patterns("", &patterns, &roles);
        assert!(recs.is_empty(), "empty mission should return empty vec");
    }

    // ── 3. detect_role_gaps ───────────────────────────────────────────────────

    #[test]
    fn test_detect_role_gaps() {
        // Roles have no cloud/aws specializations
        let roles = vec![
            make_role("security_architect", "Security Architect", vec!["threat_modeling", "code_review"]),
            make_role("auditor", "Auditor", vec!["compliance", "pci_dss"]),
        ];

        let mission = "audit cloud AWS infrastructure security";
        let mut gaps = detect_role_gaps(mission, &roles);
        gaps.sort();

        // "cloud" and "aws" should be detected as gaps
        assert!(gaps.contains(&"cloud".to_string()), "expected 'cloud' in gaps, got: {:?}", gaps);
        assert!(gaps.contains(&"aws".to_string()), "expected 'aws' in gaps, got: {:?}", gaps);
    }

    // ── 4. scaffold_role ─────────────────────────────────────────────────────

    #[test]
    fn test_scaffold_role() {
        let tmp = tempfile::tempdir().unwrap();
        let library_dir = tmp.path();

        let (role_path, prompt_path) = scaffold_role(
            "cloud_engineer",
            "Manages cloud infrastructure and deployments",
            library_dir,
        )
        .expect("scaffold_role should succeed");

        // Files should exist
        assert!(role_path.exists(), "role yaml should exist at {:?}", role_path);
        assert!(prompt_path.exists(), "prompt md should exist at {:?}", prompt_path);

        // role yaml should be valid YAML that deserializes as a Role
        let yaml_contents = std::fs::read_to_string(&role_path).unwrap();
        assert!(yaml_contents.contains("cloud_engineer"));
        assert!(yaml_contents.contains("Manages cloud infrastructure"));

        // prompt md should contain the id
        let md_contents = std::fs::read_to_string(&prompt_path).unwrap();
        assert!(md_contents.contains("cloud engineer"));
    }

    // ── 5. generate_mission ───────────────────────────────────────────────────

    #[test]
    fn test_generate_mission() {
        let tmp = tempfile::tempdir().unwrap();
        let library_dir = tmp.path().join("library");
        let missions_dir = tmp.path().join("missions");
        std::fs::create_dir_all(library_dir.join("prompts")).unwrap();
        std::fs::create_dir_all(&missions_dir).unwrap();

        // Write prompt files required by Fix 4 (fail fast on undefined roles)
        std::fs::write(
            library_dir.join("prompts/security_architect.md"),
            "# Security Architect\n\nSystem prompt.",
        )
        .unwrap();
        std::fs::write(
            library_dir.join("prompts/auditor.md"),
            "# Auditor\n\nSystem prompt.",
        )
        .unwrap();

        let roles = vec![
            make_role("security_architect", "Security Architect", vec!["audit"]),
            make_role("auditor", "Auditor", vec!["compliance"]),
        ];

        let rec = Recommendation {
            pattern_id: "oracle_workers".to_string(),
            pattern_name: "Oracle + Workers".to_string(),
            score: 4.5,
            matched_criteria: vec!["Compliance tasks".to_string()],
            anti_matched: vec![],
            role_assignments: vec![
                RoleAssignment {
                    slot: "oracle".to_string(),
                    role_id: "security_architect".to_string(),
                    role_name: "Security Architect".to_string(),
                    icon: "🔒".to_string(),
                },
                RoleAssignment {
                    slot: "worker1".to_string(),
                    role_id: "auditor".to_string(),
                    role_name: "Auditor".to_string(),
                    icon: "📋".to_string(),
                },
            ],
        };

        let mission_config = generate_mission(
            "audit PCI-DSS compliance",
            &rec,
            &roles,
            &library_dir,
            &missions_dir,
            None,
        )
        .expect("generate_mission should succeed");

        // Mission dir should exist
        assert!(
            mission_config.mission_dir.exists(),
            "mission dir should exist"
        );

        // mission.yaml should exist
        let mission_yaml = mission_config.mission_dir.join("mission.yaml");
        assert!(mission_yaml.exists(), "mission.yaml should exist");
        let yaml_contents = std::fs::read_to_string(&mission_yaml).unwrap();
        assert!(yaml_contents.contains("oracle_workers"));

        // Agent CLAUDE.md files should be created
        assert_eq!(mission_config.agent_configs.len(), 2, "should have 2 agent configs");
        for agent in &mission_config.agent_configs {
            assert!(
                agent.claude_md_path.exists(),
                "CLAUDE.md should exist for {}",
                agent.role_id
            );
            let contents = std::fs::read_to_string(&agent.claude_md_path).unwrap();
            assert!(
                contents.contains("Oracle + Workers"),
                "CLAUDE.md should mention the pattern name"
            );
            assert!(
                contents.contains("audit PCI-DSS compliance"),
                "CLAUDE.md should contain the mission"
            );
        }
    }

    // ── 6. Security: mission slug sanitization (Fix 2) ───────────────────────

    #[test]
    fn test_generate_mission_sanitizes_slug() {
        // The mission slug must not contain .. or special filesystem chars
        let mission = "test ../../../etc hack";
        let slug: String = mission
            .to_lowercase()
            .split_whitespace()
            .take(4)
            .collect::<Vec<_>>()
            .join("-")
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
            .collect();
        assert!(!slug.contains(".."), "slug should not contain '..'");
        assert!(!slug.contains('/'), "slug should not contain '/'");
    }

    // ── 7. Security: scaffold_role ID validation (Fix 3) ─────────────────────

    #[test]
    fn test_scaffold_role_rejects_invalid_id() {
        let tmp = tempfile::tempdir().unwrap();

        // Newline injection
        let result = scaffold_role("evil\nid: hacked", "desc", tmp.path());
        assert!(result.is_err(), "newline in ID should be rejected");

        // Path traversal
        let result = scaffold_role("../../../etc/passwd", "desc", tmp.path());
        assert!(result.is_err(), "path traversal in ID should be rejected");

        // Empty
        let result = scaffold_role("", "desc", tmp.path());
        assert!(result.is_err(), "empty ID should be rejected");

        // Valid ID works
        let result = scaffold_role("cloud-security", "Cloud specialist", tmp.path());
        assert!(result.is_ok(), "valid ID should succeed: {:?}", result);
    }

    // ── 8. Security: scaffold overwrite protection (Fix 5) ───────────────────

    #[test]
    fn test_scaffold_role_rejects_existing() {
        let tmp = tempfile::tempdir().unwrap();

        // First create succeeds
        let result = scaffold_role("test-role", "Test", tmp.path());
        assert!(result.is_ok(), "first scaffold should succeed: {:?}", result);

        // Second create fails (already exists)
        let result = scaffold_role("test-role", "Test", tmp.path());
        assert!(result.is_err(), "second scaffold should fail");
        assert!(
            result.unwrap_err().to_string().contains("already exists"),
            "error should mention 'already exists'"
        );
    }

    // ── 9. format_recommendations ────────────────────────────────────────────

    #[test]
    fn test_format_recommendations() {
        let recs = vec![
            Recommendation {
                pattern_id: "oracle_workers".to_string(),
                pattern_name: "Oracle + Workers".to_string(),
                score: 6.0,
                matched_criteria: vec!["Large parallelisable tasks".to_string()],
                anti_matched: vec![],
                role_assignments: vec![RoleAssignment {
                    slot: "oracle".to_string(),
                    role_id: "security_architect".to_string(),
                    role_name: "Security Architect".to_string(),
                    icon: "🔒".to_string(),
                }],
            },
            Recommendation {
                pattern_id: "plan_then_execute".to_string(),
                pattern_name: "Plan Then Execute".to_string(),
                score: 4.0,
                matched_criteria: vec![],
                anti_matched: vec![],
                role_assignments: vec![],
            },
        ];

        let output = format_recommendations(&recs);

        assert!(output.contains("Oracle + Workers"), "should contain first pattern name");
        assert!(output.contains("Plan Then Execute"), "should contain second pattern name");
        assert!(output.contains("[RECOMMENDED]"), "first result should be labeled RECOMMENDED");
        assert!(output.contains("Score: 6.0"), "should show score");
        assert!(!output.contains("No matching patterns"), "should not show empty message");

        // Empty case
        let empty_output = format_recommendations(&[]);
        assert!(
            empty_output.contains("No matching patterns"),
            "empty recs should say no matching patterns"
        );
    }
}
