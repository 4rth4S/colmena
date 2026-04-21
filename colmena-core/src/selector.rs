use crate::calibrate::{determine_tier, TrustThresholds};
use crate::config::Action;
use crate::delegate::{DelegationConditions, RuntimeDelegation};
use crate::elo::AgentRating;
use crate::findings::{load_findings, FindingsFilter};
use crate::library::{Pattern, Role};
pub use crate::pattern_scaffold::{
    map_topology_roles, scaffold_pattern, suggest_pattern_for_mission, PatternSuggestion,
    PatternTopology, SlotDesc, SlotRoleType,
};
use crate::templates::{detect_category, generate_role_prompt, generate_role_yaml, RoleCategory};
use anyhow::{Context, Result};
use chrono::Utc;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

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

/// Inter-agent token efficiency directive injected into multi-agent missions.
pub const INTER_AGENT_DIRECTIVE: &str = "\
## Colmena Inter-Agent Protocol
When communicating with other agents in this mission:
- Facts only. No explanations unless requested.
- Format: [finding] [evidence] [severity/status]. Next.
- Reference artifacts as path:line — no prose descriptions.
- Skip articles, filler, hedging, pleasantries.
- NEVER compress: code, commands, file contents, configurations, error messages.
- Human-facing output: normal verbosity (this protocol is agent-to-agent only).";

/// Mission marker prefix embedded in agent prompts for Mission Gate validation.
pub const MISSION_MARKER_PREFIX: &str = "<!-- colmena:mission_id=";

/// Result of `spawn_mission()` — everything needed to launch a Colmena mission.
#[derive(Debug)]
pub struct SpawnResult {
    pub mission_name: String,
    pub pattern_id: String,
    pub pattern_auto_created: bool,
    pub agent_prompts: Vec<AgentPrompt>,
    /// Delegations that were newly persisted to `runtime-delegations.json`.
    pub delegations_created: Vec<RuntimeDelegation>,
    /// Delegations skipped because an existing one covers them with TTL ≥ mission end.
    /// Tuple is (candidate, existing_expires_at) for human-readable reporting.
    pub delegations_skipped: Vec<(RuntimeDelegation, chrono::DateTime<chrono::Utc>)>,
    /// Delegations that would have conflicted with shorter-lived existing entries.
    /// Empty when `spawn_mission` returns Ok (the function `bail!`s on aborted merges
    /// unless `--extend-existing` was passed).
    pub delegations_aborted: Vec<RuntimeDelegation>,
    pub role_gaps: Vec<String>,
    pub mission_config: MissionConfig,
    /// Subagent `.md` files (under `~/.claude/agents/`) that were written or
    /// regenerated during this spawn. Empty in `dry_run`.
    pub subagent_files_written: Vec<PathBuf>,
    /// Existing subagent `.md` files that already satisfy the minimums check
    /// and were respected (not overwritten).
    pub subagent_files_respected: Vec<PathBuf>,
}

/// A ready-to-paste agent prompt with mission marker.
#[derive(Debug)]
pub struct AgentPrompt {
    pub role_id: String,
    pub role_name: String,
    pub prompt: String,
    pub claude_md_path: PathBuf,
}

/// Generated mission configuration
#[derive(Debug)]
pub struct MissionConfig {
    pub mission_dir: PathBuf,
    pub agent_configs: Vec<AgentConfig>,
    /// Auto-generated delegations from role permissions
    pub delegations: Vec<RuntimeDelegation>,
    /// Reviewer lead assigned by ELO (highest-rated agent in the squad)
    pub reviewer_lead: Option<ReviewerLead>,
}

#[derive(Debug)]
pub struct AgentConfig {
    pub role_id: String,
    pub role_name: String,
    pub claude_md_path: PathBuf,
    /// The CLAUDE.md content. Always populated so callers can use it
    /// without a disk read (important under `dry_run`, where
    /// `claude_md_path` points at a file that was NOT persisted).
    pub claude_md_content: String,
}

/// Reviewer lead assignment based on ELO
#[derive(Debug, Clone)]
pub struct ReviewerLead {
    pub role_id: String,
    pub role_name: String,
    pub elo: i32,
    pub review_count: u32,
}

// ── Tokenizer ─────────────────────────────────────────────────────────────────

/// Stop words to filter from mission text
const STOP_WORDS: &[&str] = &[
    "the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for", "of", "with", "by",
    "from", "is", "are", "was", "were", "be", "been", "being", "have", "has", "had", "do", "does",
    "did", "will", "would", "could", "should", "may", "might", "can", "this", "that", "these",
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
pub fn select_patterns(mission: &str, patterns: &[Pattern], roles: &[Role]) -> Vec<Recommendation> {
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
                    let spec_tokens: Vec<String> = role
                        .specializations
                        .iter()
                        .flat_map(|s| tokenize(s))
                        .collect();
                    spec_hits += keyword_overlap(&mission_tokens, &spec_tokens);
                }
            }

            let score = (when_hits.len() as f64) * 2.0 + (spec_hits as f64) * 1.5
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

    recommendations.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
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
    let all_specs: Vec<String> = roles
        .iter()
        .flat_map(|r| r.specializations.iter())
        .flat_map(|s| tokenize(s))
        .collect();

    // Common security keywords that might indicate a missing role
    let domain_keywords = [
        "cloud",
        "aws",
        "gcp",
        "azure",
        "kubernetes",
        "k8s",
        "docker",
        "mobile",
        "ios",
        "android",
        "flutter",
        "react",
        "frontend",
        "blockchain",
        "smart_contract",
        "defi",
        "infrastructure",
        "network",
        "wireless",
        "iot",
        "firmware",
        "hardware",
        "social_engineering",
        "phishing",
        "red_team",
    ];

    mission_tokens
        .iter()
        .filter(|t| domain_keywords.contains(&t.as_str()) && !all_specs.contains(t))
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
/// If `elo_ratings` is provided, the highest-ELO agent is assigned as reviewer lead.
/// If `config_dir` is provided and mission text matches prompt review keywords,
/// the prompt review context is injected into all agents' CLAUDE.md files.
/// If `manifest` is provided, per-role scope, task, and review protocol sections
/// are appended to every generated CLAUDE.md using `emitters::claude_code` helpers.
#[allow(clippy::too_many_arguments)]
pub fn generate_mission(
    mission: &str,
    recommendation: &Recommendation,
    roles: &[Role],
    library_dir: &Path,
    missions_dir: &Path,
    session_id: Option<&str>,
    elo_ratings: &[AgentRating],
    config_dir: Option<&Path>,
    manifest: Option<&crate::mission_manifest::MissionManifest>,
    dry_run: bool,
) -> Result<MissionConfig> {
    let role_map: HashMap<&str, &Role> = roles.iter().map(|r| (r.id.as_str(), r)).collect();

    // Assign reviewer lead: highest ELO among mission roles, or fallback to high trust level
    let reviewer_lead = assign_reviewer_lead(recommendation, &role_map, elo_ratings);

    // Detect if this is a prompt review mission
    let prompt_review_context = config_dir.and_then(|cd| {
        detect_prompt_review_target(mission, roles).and_then(|target_role_id| {
            generate_prompt_review_context(&target_role_id, roles, library_dir, cd, elo_ratings)
                .ok()
        })
    });

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

    if !dry_run {
        std::fs::create_dir_all(&agents_dir)
            .with_context(|| format!("Failed to create mission dir: {}", mission_dir.display()))?;
    }

    // Write mission.yaml
    let mission_yaml = format!(
        "mission: \"{}\"\npattern: {}\npattern_name: \"{}\"\ncreated: {}\nagents:\n{}",
        mission.replace('"', "\\\""),
        recommendation.pattern_id,
        recommendation.pattern_name,
        Utc::now().to_rfc3339(),
        recommendation
            .role_assignments
            .iter()
            .map(|a| format!("  - role: {}\n    slot: {}", a.role_id, a.slot))
            .collect::<Vec<_>>()
            .join("\n")
    );
    if !dry_run {
        std::fs::write(mission_dir.join("mission.yaml"), &mission_yaml)?;
    }

    // Generate CLAUDE.md per agent + role-bound delegations
    let mut agent_configs = Vec::new();
    let mut delegations = Vec::new();
    let now = Utc::now();
    // M7.3 fix: honour manifest.mission_ttl_hours for delegation TTL so that
    // generated delegations expire with the mission, not at the hardcoded default.
    let ttl_hours = manifest
        .map(|m| m.mission_ttl_hours)
        .unwrap_or(DEFAULT_MISSION_TTL_HOURS);
    let ttl = chrono::Duration::hours(ttl_hours);

    for assignment in &recommendation.role_assignments {
        let agent_dir = agents_dir.join(&assignment.role_id);
        if !dry_run {
            std::fs::create_dir_all(&agent_dir)?;
        }

        let role = role_map.get(assignment.role_id.as_str())
            .ok_or_else(|| anyhow::anyhow!(
                "Pattern '{}' references undefined role '{}'. Add it with: colmena library create-role --id {} --description \"...\"",
                recommendation.pattern_id, assignment.role_id, assignment.role_id
            ))?;

        // Generate delegations from role's tools_allowed + permissions
        let role_delegations =
            generate_role_delegations(role, &mission_name, &mission_dir, session_id, now, ttl);
        delegations.extend(role_delegations);

        // Load the system prompt
        let system_prompt = crate::library::load_prompt(library_dir, &role.system_prompt_ref)
            .with_context(|| format!("Failed to load prompt for role '{}'", assignment.role_id))?;

        // Build pre-approved operations section
        let pre_approved = format_pre_approved_ops(role);

        // Build review instructions based on role
        let review_section = build_review_section(
            &assignment.role_id,
            &reviewer_lead,
            &mission_name,
            &recommendation.role_assignments,
            role.role_type.as_deref(),
        );

        // Append prompt review context if this is a prompt review mission
        let review_context_section = prompt_review_context.as_deref().unwrap_or("");

        // Inter-agent directive for multi-agent missions (2+ agents)
        let interagent_section = if recommendation.role_assignments.len() >= 2 {
            format!("\n\n{}", INTER_AGENT_DIRECTIVE)
        } else {
            String::new()
        };

        // Manifest-driven sections (M7.3): scope + task + review protocol.
        // Empty strings if no manifest — the existing prompt structure is preserved.
        let manifest_role = manifest.and_then(|m| m.role(&assignment.role_id));
        let scope_section = manifest_role
            .map(|r| crate::emitters::claude_code::scope_block(&r.scope.owns, &r.scope.forbidden))
            .unwrap_or_default();
        let task_section = manifest_role
            .map(|r| crate::emitters::claude_code::task_block(&r.task))
            .unwrap_or_default();
        // M7.3 fix: role_type=auditor is exempt from submitting artifact reviews
        // (it evaluates others via review_evaluate, it doesn't author work that
        // needs peer review). Emitting a MANDATORY review_submit block would
        // trap the auditor under SubagentStop with nothing valid to submit.
        let review_protocol_section =
            if manifest.is_some() && role.role_type.as_deref() != Some("auditor") {
                // Identify the auditor in the squad, if any.
                let auditor_role_id: Option<String> =
                    recommendation.role_assignments.iter().find_map(|a| {
                        role_map
                            .get(a.role_id.as_str())
                            .filter(|r| r.role_type.as_deref() == Some("auditor"))
                            .map(|_| a.role_id.clone())
                    });
                // Centralize reviews to the auditor when present (matches the ELO
                // success recipe — centralized-auditor pattern). Otherwise fall
                // back to the full pool of non-author roles.
                let available_roles: Vec<String> = match auditor_role_id {
                    Some(auditor_id) if auditor_id != assignment.role_id => vec![auditor_id],
                    _ => recommendation
                        .role_assignments
                        .iter()
                        .filter(|a| a.role_id != assignment.role_id)
                        .map(|a| a.role_id.clone())
                        .collect(),
                };
                // M7.3 fix: the mission_id passed to review_submit MUST match the
                // mission_id stamped onto delegations and the Mission Gate marker.
                // All three use `mission_name` (date-prefixed slug), so the prompt
                // follows suit — otherwise review_submit() lands under an id that
                // matches no delegation and the ELO cycle silently breaks.
                crate::emitters::claude_code::review_protocol_block(
                    &mission_name,
                    &assignment.role_id,
                    &available_roles,
                )
            } else {
                String::new()
            };

        // Compose base CLAUDE.md (existing structure, unchanged semantics)
        let base_md = if review_context_section.is_empty() {
            format!(
                "{}\n\n---\n\n## Mission\n\n{}\n\n## Your Role in This Mission\n\n\
                You are the **{}** ({}) in a **{}** pattern.\n\
                Your slot: **{}**\n\n\
                ## Team\n\n{}\n\n## Trust Level\n\n{}\n\n{}\n\n{}{}",
                system_prompt,
                mission,
                assignment.role_name,
                assignment.icon,
                recommendation.pattern_name,
                assignment.slot,
                recommendation
                    .role_assignments
                    .iter()
                    .map(|a| format!("- {} {} ({})", a.icon, a.role_name, a.slot))
                    .collect::<Vec<_>>()
                    .join("\n"),
                role.default_trust_level,
                pre_approved,
                review_section,
                interagent_section,
            )
        } else {
            format!(
                "{}\n\n---\n\n## Mission\n\n{}\n\n## Your Role in This Mission\n\n\
                You are the **{}** ({}) in a **{}** pattern.\n\
                Your slot: **{}**\n\n\
                ## Team\n\n{}\n\n## Trust Level\n\n{}\n\n{}\n\n{}{}\n\n---\n\n{}",
                system_prompt,
                mission,
                assignment.role_name,
                assignment.icon,
                recommendation.pattern_name,
                assignment.slot,
                recommendation
                    .role_assignments
                    .iter()
                    .map(|a| format!("- {} {} ({})", a.icon, a.role_name, a.slot))
                    .collect::<Vec<_>>()
                    .join("\n"),
                role.default_trust_level,
                pre_approved,
                review_section,
                interagent_section,
                review_context_section,
            )
        };

        // Append manifest sections after base (empty strings when no manifest).
        let claude_md = format!(
            "{}\n{}{}{}\n",
            base_md, scope_section, task_section, review_protocol_section
        );

        let claude_md_path = agent_dir.join("CLAUDE.md");
        if !dry_run {
            std::fs::write(&claude_md_path, &claude_md)?;
        }

        agent_configs.push(AgentConfig {
            role_id: assignment.role_id.clone(),
            role_name: assignment.role_name.clone(),
            claude_md_path,
            claude_md_content: claude_md,
        });
    }

    Ok(MissionConfig {
        mission_dir,
        agent_configs,
        delegations,
        reviewer_lead,
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

    // M7.3: bundle ELO-cycle tools (review_submit + review_evaluate + findings_query)
    // alongside whatever the role YAML declares, so any role in a mission can act
    // as author AND as reviewer without the operator having to update every YAML.
    let mission_tools = crate::emitters::claude_code::mission_tool_set(&role.tools_allowed);

    for tool in &mission_tools {
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
                            Some(
                                perms
                                    .path_within
                                    .iter()
                                    .map(|p| p.replace("${MISSION_DIR}", &mission_dir_str))
                                    .collect(),
                            )
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
    lines.push(
        "The following operations are pre-approved for your role in this mission:".to_string(),
    );

    // Stay consistent with generate_role_delegations: show ELO-cycle MCP tools
    // in the brief even if the role YAML doesn't list them explicitly.
    let mission_tools = crate::emitters::claude_code::mission_tool_set(&role.tools_allowed);

    for tool in &mission_tools {
        if tool == "Bash" {
            if let Some(ref perms) = role.permissions {
                if !perms.bash_patterns.is_empty() {
                    let patterns: Vec<String> = perms
                        .bash_patterns
                        .iter()
                        .map(|p| format!("`{}`", p))
                        .collect();
                    lines.push(format!(
                        "- **Bash**: commands matching {}",
                        patterns.join(", ")
                    ));
                    continue;
                }
            }
            lines.push("- **Bash**: all commands".to_string());
        } else {
            let scope = if let Some(ref perms) = role.permissions {
                if !perms.path_within.is_empty()
                    && ["Read", "Write", "Edit", "Glob", "Grep"].contains(&tool.as_str())
                {
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

// ── Reviewer Lead Assignment ─────────────────────────────────────────────────

/// Assign reviewer lead based on ELO ratings. Highest ELO wins.
/// Fallback: role with default_trust_level "high" (typically security_architect).
/// Single-agent missions return None.
fn assign_reviewer_lead(
    recommendation: &Recommendation,
    role_map: &HashMap<&str, &Role>,
    elo_ratings: &[AgentRating],
) -> Option<ReviewerLead> {
    if recommendation.role_assignments.len() <= 1 {
        return None; // Single-agent mission: no review needed
    }

    let rating_map: HashMap<&str, &AgentRating> =
        elo_ratings.iter().map(|r| (r.agent.as_str(), r)).collect();

    // Find highest ELO among mission roles
    let mut best: Option<(&RoleAssignment, i32, u32)> = None;
    for assignment in &recommendation.role_assignments {
        let (elo, reviews) = rating_map
            .get(assignment.role_id.as_str())
            .map(|r| (r.elo, r.review_count))
            .unwrap_or((1500, 0));

        match &best {
            None => best = Some((assignment, elo, reviews)),
            Some((_, best_elo, _)) => {
                if elo > *best_elo {
                    best = Some((assignment, elo, reviews));
                }
            }
        }
    }

    // If all agents have the same ELO (uncalibrated), pick the one with highest trust level
    let all_same_elo = recommendation.role_assignments.iter().all(|a| {
        let elo = rating_map
            .get(a.role_id.as_str())
            .map(|r| r.elo)
            .unwrap_or(1500);
        let best_elo = best.as_ref().map(|(_, e, _)| *e).unwrap_or(1500);
        elo == best_elo
    });

    if all_same_elo {
        // Fallback: pick role with default_trust_level "high"
        for assignment in &recommendation.role_assignments {
            if let Some(role) = role_map.get(assignment.role_id.as_str()) {
                if role.default_trust_level == "high" {
                    return Some(ReviewerLead {
                        role_id: assignment.role_id.clone(),
                        role_name: assignment.role_name.clone(),
                        elo: 1500,
                        review_count: 0,
                    });
                }
            }
        }
    }

    best.map(|(assignment, elo, reviews)| ReviewerLead {
        role_id: assignment.role_id.clone(),
        role_name: assignment.role_name.clone(),
        elo,
        review_count: reviews,
    })
}

/// Build review instructions section for a CLAUDE.md based on the agent's role.
fn build_review_section(
    role_id: &str,
    reviewer_lead: &Option<ReviewerLead>,
    mission_id: &str,
    all_assignments: &[RoleAssignment],
    role_type: Option<&str>,
) -> String {
    let reviewer_lead = match reviewer_lead {
        Some(rl) => rl,
        None => return String::new(), // Single-agent, no review section
    };

    let available_roles: Vec<String> = all_assignments
        .iter()
        .map(|a| format!("\"{}\"", a.role_id))
        .collect();
    let roles_list = available_roles.join(", ");

    if role_id == reviewer_lead.role_id {
        // This agent IS the reviewer lead
        let base = format!(
            "## Review Responsibility\n\n\
            You are the designated reviewer (highest ELO in this squad, ELO: {}).\n\
            When you receive review assignments via `mcp__colmena__review_list`:\n\
            1. Read the artifact (diff/commit) thoroughly\n\
            2. Call `mcp__colmena__review_evaluate` with scores and findings\n\
            3. If score < 7.0 or any critical finding: flag for human review, do NOT auto-complete\n\
            4. Use category `prompt_improvement` for suggestions about the agent's approach or prompt\n\
            5. Be constructive — findings feed into ELO and help calibrate trust over time",
            reviewer_lead.elo,
        );

        // Auditor role_type gets the evaluation protocol
        if role_type == Some("auditor") {
            format!(
                "{}\n\n\
                ## Evaluation Protocol\n\n\
                When evaluating a worker's submission via mcp__colmena__review_evaluate:\n\
                1. Read the artifact (diff/commit) thoroughly\n\
                2. Score each dimension: correctness, security, completeness, methodology (1-10 each)\n\
                3. Document your reasoning for each score in the evaluation_narrative field\n\
                4. Generate 3 alternative evaluation approaches you considered but rejected, explaining why\n\
                5. List all findings with severity and recommendations\n\
                6. Include the full narrative + alternatives in the evaluation_narrative parameter\n\n\
                Your evaluation narrative must include:\n\
                - WHY you assigned each score (not just the numbers)\n\
                - 3 alternative approaches with different scoring rationale\n\
                - Which approach you chose and why",
                base,
            )
        } else {
            base
        }
    } else {
        // This agent is a worker — should submit for review
        format!(
            "## Post-Work Protocol\n\n\
            When your work is complete:\n\
            1. Commit all changes to your worktree branch\n\
            2. Call `mcp__colmena__review_submit` with:\n\
            \x20\x20\x20- artifact_path: your worktree branch path or the diff of your changes\n\
            \x20\x20\x20- author_role: \"{role_id}\"\n\
            \x20\x20\x20- mission: \"{mission_id}\"\n\
            \x20\x20\x20- available_roles: [{roles_list}]\n\
            3. Your work will be reviewed by **{reviewer_name}** (ELO: {elo})",
            role_id = role_id,
            mission_id = mission_id,
            roles_list = roles_list,
            reviewer_name = reviewer_lead.role_name,
            elo = reviewer_lead.elo,
        )
    }
}

// ── Prompt Review Context ────────────────────────────────────────────────────

/// Detect if a mission text is a prompt review request and extract the target role ID.
///
/// Matches patterns like:
/// - "review pentester prompt"
/// - "improve auditor instructions"
/// - "why is pentester scoring low"
/// - "refine researcher approach"
///
/// Returns `Some(role_id)` if a known role is detected, `None` otherwise.
pub fn detect_prompt_review_target(mission: &str, roles: &[Role]) -> Option<String> {
    let lower = mission.to_lowercase();

    // Patterns: "{keyword} {role} {suffix}" or "{prefix} {role} {suffix}"
    let patterns: &[(&[&str], &[&str])] = &[
        // "review {role} prompt"
        (
            &["review"],
            &["prompt", "instructions", "approach", "system"],
        ),
        // "improve {role} instructions"
        (
            &["improve", "refine", "enhance", "fix", "update"],
            &["prompt", "instructions", "approach"],
        ),
        // "why is {role} scoring low"
        (&["why"], &["scoring", "low", "underperforming", "failing"]),
    ];

    for role in roles {
        let role_lower = role.id.to_lowercase();
        let name_lower = role.name.to_lowercase();

        // Check if the role is mentioned in the mission text
        if !lower.contains(&role_lower) && !lower.contains(&name_lower) {
            continue;
        }

        // Check if the mission matches any prompt review pattern
        for (prefixes, suffixes) in patterns {
            let has_prefix = prefixes.iter().any(|p| lower.contains(p));
            let has_suffix = suffixes.iter().any(|s| lower.contains(s));
            if has_prefix && has_suffix {
                return Some(role.id.clone());
            }
        }
    }

    None
}

/// Generate prompt review context for debate/mentor agents to analyze a target role's prompt.
///
/// Loads the target role's system prompt, ELO performance, and recent findings,
/// then formats them using the prompt-review-context template.
///
/// Returns the formatted context string to inject into agent CLAUDE.md files.
pub fn generate_prompt_review_context(
    target_role_id: &str,
    roles: &[Role],
    library_dir: &Path,
    config_dir: &Path,
    elo_ratings: &[AgentRating],
) -> Result<String> {
    // Find the target role
    let role = roles
        .iter()
        .find(|r| r.id == target_role_id)
        .ok_or_else(|| anyhow::anyhow!("Target role '{}' not found in library", target_role_id))?;

    // Load the target role's current system prompt
    let current_prompt = crate::library::load_prompt(library_dir, &role.system_prompt_ref)
        .unwrap_or_else(|_| format!("(prompt file not found: {})", role.system_prompt_ref));

    // Get ELO rating for the target role
    let rating = elo_ratings.iter().find(|r| r.agent == target_role_id);
    let (elo, trend, review_count) = match rating {
        Some(r) => (r.elo, r.trend_7d, r.review_count),
        None => (1500, 0, 0),
    };

    // Determine trust tier
    let thresholds = TrustThresholds::default();
    let tier = match rating {
        Some(r) => determine_tier(r, &thresholds).as_str().to_string(),
        None => "UNCALIBRATED".to_string(),
    };

    // Format trend with sign
    let trend_str = if trend > 0 {
        format!("+{}", trend)
    } else {
        format!("{}", trend)
    };

    // Load recent findings where the target role was the author (last 10)
    let findings_dir = config_dir.join("findings");
    let filter = FindingsFilter {
        author_role: Some(target_role_id.to_string()),
        limit: Some(10),
        ..Default::default()
    };
    let findings_section = match load_findings(&findings_dir, &filter) {
        Ok(records) if records.is_empty() => "No findings yet for this agent.".to_string(),
        Ok(records) => {
            let mut lines = Vec::new();
            for record in &records {
                for finding in &record.findings {
                    lines.push(format!(
                        "- [{}] **{}**: {} (mission: {}, reviewer: {})",
                        finding.severity,
                        finding.category,
                        finding.description,
                        record.mission,
                        record.reviewer_role,
                    ));
                }
            }
            if lines.is_empty() {
                "No findings yet for this agent.".to_string()
            } else {
                lines.join("\n")
            }
        }
        Err(_) => "No findings yet for this agent.".to_string(),
    };

    // Build the context section
    let context = format!(
        "## Prompt Review Context\n\n\
        You are reviewing the prompt for: **{}** ({})\n\n\
        ### Current Prompt\n{}\n\n\
        ### Recent ELO Performance\n\
        - Current ELO: {}\n\
        - Trend (7d): {}\n\
        - Review count: {}\n\
        - Trust tier: {}\n\n\
        ### Recent Findings Against This Agent\n{}\n\n\
        ### Your Task\n\
        Analyze this agent's prompt and recent performance. Submit findings with\n\
        category \"prompt_improvement\" for any weaknesses or gaps you identify.\n\
        Focus on actionable, specific suggestions — not vague advice.\n\n\
        Each finding should include:\n\
        - `category`: \"prompt_improvement\"\n\
        - `severity`: \"medium\" or \"low\" (these are suggestions, not bugs)\n\
        - `description`: what is weak or missing in the current prompt\n\
        - `recommendation`: specific text or structural change to the prompt",
        role.name,
        target_role_id,
        current_prompt,
        elo,
        trend_str,
        review_count,
        tier,
        findings_section,
    );

    Ok(context)
}

// ── Role Scaffold Generator ───────────────────────────────────────────────────

/// Create a new role scaffold in the library.
/// If `category` is None, it is auto-detected from the description.
pub fn scaffold_role(
    id: &str,
    description: &str,
    category: Option<RoleCategory>,
    library_dir: &Path,
) -> Result<(PathBuf, PathBuf)> {
    // Validate role ID
    if id.is_empty() || id.len() > 64 {
        anyhow::bail!("Role ID must be 1-64 characters, got {}", id.len());
    }
    if !id
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
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

    let resolved_category = category.unwrap_or_else(|| detect_category(description));

    let role_yaml = generate_role_yaml(id, description, resolved_category);
    let prompt_md = generate_role_prompt(id, description, resolved_category);

    std::fs::write(&role_path, role_yaml)?;
    std::fs::write(&prompt_path, prompt_md)?;

    Ok((role_path, prompt_path))
}

// ── Mission Sizing ──────────────────────────────────────────────────────────

/// Complexity level for a mission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Complexity {
    Trivial, // 1 agent — don't use Colmena
    Small,   // 2 agents — marginal benefit
    Medium,  // 3-4 agents — sweet spot for Colmena
    Large,   // 5-6 agents — full orchestration
}

impl Complexity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Complexity::Trivial => "trivial",
            Complexity::Small => "small",
            Complexity::Medium => "medium",
            Complexity::Large => "large",
        }
    }
}

/// Result of mission sizing analysis.
#[derive(Debug, Clone)]
pub struct MissionSuggestion {
    pub complexity: Complexity,
    pub recommended_agents: usize,
    pub needs_colmena: bool,
    pub suggested_pattern: Option<String>,
    pub suggested_roles: Vec<String>,
    pub confidence: f64,
    pub reason: String,
    pub domains_detected: Vec<String>,
}

/// Domain keywords for mission sizing.
const DOMAIN_KEYWORDS: &[(&str, &[&str])] = &[
    (
        "code",
        &[
            "implement",
            "develop",
            "build",
            "feature",
            "code",
            "refactor",
            "migrate",
            "write",
            "function",
            "module",
            "class",
            "method",
        ],
    ),
    (
        "testing",
        &[
            "test",
            "coverage",
            "validate",
            "edge",
            "regression",
            "spec",
            "assertion",
            "mock",
            "fixture",
        ],
    ),
    (
        "security",
        &[
            "vulnerability",
            "pentest",
            "audit",
            "owasp",
            "cve",
            "exploit",
            "injection",
            "xss",
            "csrf",
            "authentication",
        ],
    ),
    (
        "documentation",
        &[
            "docs",
            "document",
            "readme",
            "guide",
            "changelog",
            "api_docs",
            "tutorial",
            "comment",
        ],
    ),
    (
        "architecture",
        &[
            "design",
            "architecture",
            "tradeoff",
            "adr",
            "interface",
            "api_design",
            "schema",
            "diagram",
        ],
    ),
    (
        "review",
        &[
            "review",
            "quality",
            "standards",
            "best_practices",
            "lint",
            "style",
            "convention",
        ],
    ),
    (
        "operations",
        &[
            "deploy",
            "cicd",
            "pipeline",
            "monitor",
            "infrastructure",
            "docker",
            "kubernetes",
            "terraform",
        ],
    ),
];

/// Keywords that bump complexity (risk/scope indicators).
const COMPLEXITY_BUMPERS: &[&str] = &[
    "production",
    "migration",
    "security",
    "compliance",
    "critical",
    "sensitive",
    "full",
    "comprehensive",
    "end-to-end",
    "complete",
    "entire",
    "all",
];

/// Keywords that reduce complexity (simplicity indicators).
const COMPLEXITY_REDUCERS: &[&str] = &[
    "fix", "typo", "rename", "small", "quick", "simple", "minor", "trivial", "tweak",
];

/// Analyze a mission description and recommend whether to use Colmena.
pub fn suggest_mission_size(
    description: &str,
    roles: &[Role],
    patterns: &[Pattern],
) -> MissionSuggestion {
    if description.trim().is_empty() {
        return MissionSuggestion {
            complexity: Complexity::Trivial,
            recommended_agents: 1,
            needs_colmena: false,
            suggested_pattern: None,
            suggested_roles: vec![],
            confidence: 0.0,
            reason: "Empty description. Provide a mission description for analysis.".into(),
            domains_detected: vec![],
        };
    }

    let desc_lower = description.to_lowercase();
    let desc_words: Vec<&str> = desc_lower
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|w| w.len() > 2)
        .collect();

    // 1. Detect domains
    let mut domains_detected: Vec<String> = Vec::new();
    let mut keyword_hits = 0usize;
    let mut total_keywords = 0usize;

    for (domain, keywords) in DOMAIN_KEYWORDS {
        let hits: usize = keywords
            .iter()
            .filter(|kw| {
                let kw_lower = kw.to_lowercase();
                let variants = [
                    kw_lower.clone(),
                    kw_lower.replace('_', " "),
                    kw_lower.replace('_', "-"),
                ];
                variants.iter().any(|v| {
                    desc_words.iter().any(|w| w.contains(v.as_str()))
                        || desc_lower.contains(v.as_str())
                })
            })
            .count();
        total_keywords += keywords.len();
        if hits > 0 {
            domains_detected.push(domain.to_string());
            keyword_hits += hits;
        }
    }

    // 2. Calculate base complexity from domain count
    let mut complexity_score: i32 = domains_detected.len() as i32;

    // 3. Apply bumpers and reducers
    let bumps: usize = COMPLEXITY_BUMPERS
        .iter()
        .filter(|kw| desc_lower.contains(**kw))
        .count();
    let reduces: usize = COMPLEXITY_REDUCERS
        .iter()
        .filter(|kw| desc_lower.contains(**kw))
        .count();
    complexity_score += bumps as i32;
    complexity_score -= reduces as i32;

    // 4. Map to Complexity enum
    let (complexity, recommended_agents) = match complexity_score {
        ..=1 => (Complexity::Trivial, 1),
        2 => (Complexity::Small, 2),
        3 => (Complexity::Medium, 3),
        _ => (Complexity::Large, complexity_score.min(6) as usize),
    };

    let needs_colmena = recommended_agents >= 3;

    // 5. Confidence: keyword match density
    let confidence = if total_keywords > 0 {
        let raw = (keyword_hits as f64) / (desc_words.len().max(1) as f64);
        (raw * 2.0).min(1.0) // scale up, cap at 1.0
    } else {
        0.0
    };

    // 6. Pattern and role suggestions (only if needs_colmena)
    let (suggested_pattern, suggested_roles) = if needs_colmena {
        let recs = select_patterns(description, patterns, roles);
        if let Some(top) = recs.first() {
            let roles_list: Vec<String> = top
                .role_assignments
                .iter()
                .map(|a| a.role_id.clone())
                .collect();
            (Some(top.pattern_id.clone()), roles_list)
        } else {
            (None, vec![])
        }
    } else {
        (None, vec![])
    };

    // 7. Build reason
    let reason = match complexity {
        Complexity::Trivial => format!(
            "Single-domain task ({}). Use Claude Code directly — Colmena adds overhead without value for simple tasks.",
            if domains_detected.is_empty() { "none detected".to_string() } else { domains_detected.join(", ") }
        ),
        Complexity::Small => format!(
            "Two domains detected ({}). Marginal benefit from Colmena — consider if the task truly needs multi-agent coordination.",
            domains_detected.join(", ")
        ),
        Complexity::Medium => format!(
            "Three domains detected ({}). Good fit for Colmena — {} agents with structured review and ELO tracking.",
            domains_detected.join(", "), recommended_agents
        ),
        Complexity::Large => format!(
            "Multi-domain task ({}) with complexity indicators. Full Colmena orchestration recommended — {} agents.",
            domains_detected.join(", "), recommended_agents
        ),
    };

    MissionSuggestion {
        complexity,
        recommended_agents,
        needs_colmena,
        suggested_pattern,
        suggested_roles,
        confidence,
        reason,
        domains_detected,
    }
}

// ── Mission Spawn — One-Step Pipeline ────────────────────────────────────────

/// One-step mission creation: select pattern → auto-create if needed → map roles →
/// generate mission with markers → persist delegations.
///
/// Pipeline:
/// 1. `select_patterns()` to find best matching pattern
/// 2. If no match: `suggest_pattern_for_mission()` → `scaffold_pattern()` to auto-create
/// 3. `generate_mission()` to create CLAUDE.md files with mission markers + manifest sections
/// 4. Read generated CLAUDE.md files to build AgentPrompt with mission marker prefix
/// 5. Persist delegations directly to `runtime_delegations_path` with idempotent merge:
///    - `decide_merge` picks Insert / SkipRespected / TtlTooShort per candidate.
///    - TtlTooShort without `extend_existing` aborts the spawn with a descriptive error.
///    - `dry_run` plans without writing to disk.
#[allow(clippy::too_many_arguments)]
pub fn spawn_mission(
    mission: &str,
    manifest: Option<&crate::mission_manifest::MissionManifest>,
    roles: &[Role],
    patterns: &[Pattern],
    library_dir: &Path,
    missions_dir: &Path,
    runtime_delegations_path: &Path,
    agents_dir: &Path,
    session_id: Option<&str>,
    elo_ratings: &[AgentRating],
    config_dir: Option<&Path>,
    extend_existing: bool,
    dry_run: bool,
    overwrite_subagents: bool,
) -> Result<SpawnResult> {
    if roles.is_empty() {
        anyhow::bail!("No roles available in library. Run `colmena setup` to install defaults.");
    }

    let now = Utc::now();

    // 1. Select best pattern.
    // If a manifest provides an explicit pattern id, try to find it in the
    // library first (exact id match) before falling back to score-based selection.
    let manifest_pattern_id = manifest.map(|m| m.pattern.as_str());
    let mut recommendations = if let Some(pid) = manifest_pattern_id {
        let exact: Vec<Recommendation> = patterns
            .iter()
            .filter(|p| p.id == pid)
            .map(|p| {
                let role_map: HashMap<&str, &Role> =
                    roles.iter().map(|r| (r.id.as_str(), r)).collect();
                let role_assignments = build_role_assignments(&p.roles_suggested, &role_map);
                Recommendation {
                    pattern_id: p.id.clone(),
                    pattern_name: p.name.clone(),
                    score: 100.0,
                    matched_criteria: vec!["Manifest-specified pattern".to_string()],
                    anti_matched: vec![],
                    role_assignments,
                }
            })
            .collect();
        if exact.is_empty() {
            select_patterns(mission, patterns, roles)
        } else {
            exact
        }
    } else {
        select_patterns(mission, patterns, roles)
    };
    let mut pattern_auto_created = false;
    let mut auto_created_pattern: Option<crate::library::Pattern> = None;

    let mut recommendation = if recommendations.is_empty() {
        // 2. No match — auto-create a pattern
        let suggestion = suggest_pattern_for_mission(mission);
        let pattern_path = scaffold_pattern(
            &suggestion.suggested_id,
            mission,
            Some(suggestion.topology),
            library_dir,
        )?;
        pattern_auto_created = true;

        // Load the newly created pattern
        let content = std::fs::read_to_string(&pattern_path).with_context(|| {
            format!(
                "Failed to read auto-created pattern: {}",
                pattern_path.display()
            )
        })?;
        let pattern: crate::library::Pattern =
            serde_yml::from_str(&content).with_context(|| {
                format!(
                    "Failed to parse auto-created pattern: {}",
                    pattern_path.display()
                )
            })?;

        // Use map_topology_roles to assign real roles to auto-created pattern slots
        // (scaffold generates generic IDs like "agent_lead" — we need real library roles)
        let role_map: HashMap<&str, &Role> = roles.iter().map(|r| (r.id.as_str(), r)).collect();
        let role_ids: Vec<String> = roles.iter().map(|r| r.id.clone()).collect();
        let role_specs: HashMap<String, Vec<String>> = roles
            .iter()
            .map(|r| (r.id.clone(), r.specializations.clone()))
            .collect();

        let topology = pattern
            .topology
            .parse::<PatternTopology>()
            .unwrap_or(PatternTopology::Hierarchical);
        let slot_assignments = map_topology_roles(topology, mission, &role_ids, &role_specs);

        let role_assignments: Vec<RoleAssignment> = slot_assignments
            .iter()
            .map(|(slot, rid)| {
                let (name, icon) = role_map
                    .get(rid.as_str())
                    .map(|r| (r.name.clone(), r.icon.clone()))
                    .unwrap_or_else(|| (rid.clone(), "?".to_string()));
                RoleAssignment {
                    slot: slot.clone(),
                    role_id: rid.clone(),
                    role_name: name,
                    icon,
                }
            })
            .collect();

        auto_created_pattern = Some(pattern.clone());
        Recommendation {
            pattern_id: pattern.id.clone(),
            pattern_name: pattern.name.clone(),
            score: 0.0,
            matched_criteria: vec!["Auto-created pattern (no existing match)".to_string()],
            anti_matched: vec![],
            role_assignments,
        }
    } else {
        recommendations.remove(0)
    };

    // 2b. If a manifest provides explicit roles, override the pattern's role
    // assignments with the manifest's ordered list. This ensures manifest-driven
    // spawn honours the exact squad the caller specified, regardless of which
    // pattern was selected or auto-created.
    if let Some(m) = manifest {
        if !m.roles.is_empty() {
            let role_map: HashMap<&str, &Role> = roles.iter().map(|r| (r.id.as_str(), r)).collect();
            let manifest_assignments: Vec<RoleAssignment> = m
                .roles
                .iter()
                .enumerate()
                .map(|(i, mr)| {
                    let (name, icon) = role_map
                        .get(mr.name.as_str())
                        .map(|r| (r.name.clone(), r.icon.clone()))
                        .unwrap_or_else(|| (mr.name.clone(), "?".to_string()));
                    RoleAssignment {
                        slot: format!("slot_{}", i + 1),
                        role_id: mr.name.clone(),
                        role_name: name,
                        icon,
                    }
                })
                .collect();
            recommendation.role_assignments = manifest_assignments;
        }
    }

    // Detect role gaps
    let role_gaps = detect_role_gaps(mission, roles);

    // 3. Generate mission (creates CLAUDE.md + delegations).
    //    Honour `dry_run`: when true, generate_mission composes prompts in
    //    memory but does NOT create directories or write mission.yaml /
    //    per-agent CLAUDE.md files.
    let mission_config = generate_mission(
        mission,
        &recommendation,
        roles,
        library_dir,
        missions_dir,
        session_id,
        elo_ratings,
        config_dir,
        manifest,
        dry_run,
    )?;

    let mission_name = mission_config
        .mission_dir
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    // 4. Build AgentPrompts — read generated CLAUDE.md + prepend mission marker
    let mission_marker = format!("{}{} -->", MISSION_MARKER_PREFIX, mission_name);
    let mut agent_prompts = Vec::new();

    for agent_cfg in &mission_config.agent_configs {
        // Use the in-memory content so dry_run works — the CLAUDE.md file
        // may not exist on disk when generate_mission was called with dry_run.
        let prompt = format!("{}\n{}", mission_marker, agent_cfg.claude_md_content);

        agent_prompts.push(AgentPrompt {
            role_id: agent_cfg.role_id.clone(),
            role_name: agent_cfg.role_name.clone(),
            prompt,
            claude_md_path: agent_cfg.claude_md_path.clone(),
        });
    }

    // 4b. M7.3 live-surface: write ~/.claude/agents/<role>.md for each mission role.
    //     Respect operator-authored files that satisfy minimums; abort loud otherwise
    //     unless overwrite_subagents is true.
    let role_map_for_subagents: std::collections::HashMap<&str, &Role> =
        roles.iter().map(|r| (r.id.as_str(), r)).collect();

    let mut subagent_files_written: Vec<PathBuf> = Vec::new();
    let mut subagent_files_respected: Vec<PathBuf> = Vec::new();
    let mut subagent_fails: Vec<(String, Vec<String>)> = Vec::new();

    for assignment in &recommendation.role_assignments {
        let role = role_map_for_subagents
            .get(assignment.role_id.as_str())
            .ok_or_else(|| anyhow::anyhow!("role not in map: {}", assignment.role_id))?;

        let subagent_path = agents_dir.join(format!("{}.md", assignment.role_id));

        // Hybrid roles (auditor) need both worker and reviewer tools.
        let mut required: Vec<&str> = crate::emitters::claude_code::WORKER_REQUIRED_TOOLS.to_vec();
        if role.role_type.as_deref() == Some("auditor") {
            required.extend_from_slice(crate::emitters::claude_code::REVIEWER_REQUIRED_TOOLS);
        }

        let check = crate::emitters::claude_code::check_subagent_minimums(
            &subagent_path,
            &assignment.role_id,
            &required,
        )?;

        match check {
            crate::emitters::claude_code::MinimumsCheck::Pass => {
                subagent_files_respected.push(subagent_path.clone());
            }
            crate::emitters::claude_code::MinimumsCheck::Fail { reasons } => {
                if overwrite_subagents {
                    if !dry_run {
                        let body = format!(
                            "# {role_name} ({role_id})\n\n\
                             Auto-generated by Colmena `mission spawn`. See \
                             `{mission_dir}/agents/{role_id}/CLAUDE.md` for the full mission prompt.\n",
                            role_name = assignment.role_name,
                            role_id = assignment.role_id,
                            mission_dir = mission_config.mission_dir.display(),
                        );
                        crate::emitters::claude_code::write_subagent_file(
                            &subagent_path,
                            &assignment.role_id,
                            &crate::emitters::claude_code::mission_tool_set(&role.tools_allowed),
                            &body,
                            true, // overwrite
                        )?;
                    }
                    subagent_files_written.push(subagent_path.clone());
                } else {
                    subagent_fails.push((assignment.role_id.clone(), reasons));
                }
            }
            crate::emitters::claude_code::MinimumsCheck::Absent => {
                if !dry_run {
                    let body = format!(
                        "# {role_name} ({role_id})\n\n\
                         Auto-generated by Colmena `mission spawn`. See \
                         `{mission_dir}/agents/{role_id}/CLAUDE.md` for the full mission prompt.\n",
                        role_name = assignment.role_name,
                        role_id = assignment.role_id,
                        mission_dir = mission_config.mission_dir.display(),
                    );
                    crate::emitters::claude_code::write_subagent_file(
                        &subagent_path,
                        &assignment.role_id,
                        &crate::emitters::claude_code::mission_tool_set(&role.tools_allowed),
                        &body,
                        false,
                    )?;
                }
                subagent_files_written.push(subagent_path.clone());
            }
        }
    }

    if !subagent_fails.is_empty() {
        let detail = subagent_fails
            .iter()
            .map(|(id, reasons)| format!("  {}:\n    - {}", id, reasons.join("\n    - ")))
            .collect::<Vec<_>>()
            .join("\n");
        anyhow::bail!(
            "Subagent file(s) exist but do not satisfy minimums. Re-run with \
             --overwrite to regenerate (a .colmena-backup will be kept).\n{}",
            detail
        );
    }

    // 5. Persist delegations directly to runtime-delegations.json with idempotency.
    //    Replaces the old `delegation_commands: Vec<String>` which emitted a
    //    non-existent `--bash-pattern` CLI flag.
    let ttl_hours = manifest
        .map(|m| m.mission_ttl_hours)
        .unwrap_or(DEFAULT_MISSION_TTL_HOURS);
    let mission_end_at = now + chrono::Duration::hours(ttl_hours);

    let existing_delegations = crate::delegate::load_delegations(runtime_delegations_path);

    let mut delegations_to_insert: Vec<RuntimeDelegation> = Vec::new();
    let mut delegations_skipped: Vec<(RuntimeDelegation, chrono::DateTime<Utc>)> = Vec::new();
    let mut delegations_aborted: Vec<RuntimeDelegation> = Vec::new();

    for candidate in &mission_config.delegations {
        use crate::delegate::{decide_merge, MergeDecision};
        match decide_merge(candidate, &existing_delegations, mission_end_at) {
            MergeDecision::Insert => {
                delegations_to_insert.push(candidate.clone());
            }
            MergeDecision::SkipRespected {
                existing_expires_at,
            } => {
                delegations_skipped.push((candidate.clone(), existing_expires_at));
            }
            MergeDecision::TtlTooShort { .. } => {
                if extend_existing {
                    delegations_to_insert.push(candidate.clone());
                } else {
                    delegations_aborted.push(candidate.clone());
                }
            }
        }
    }

    if !delegations_aborted.is_empty() {
        anyhow::bail!(
            "{} delegation(s) have TTL shorter than mission end. Re-run with --extend-existing to replace them, or revoke them manually first. Affected: {}",
            delegations_aborted.len(),
            delegations_aborted
                .iter()
                .map(|d| format!("{}/{}", d.tool, d.agent_id.clone().unwrap_or_default()))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    if !dry_run && !delegations_to_insert.is_empty() {
        // Merge: drop existing entries whose (tool, agent_id) is being replaced
        // (only meaningful when --extend-existing upgraded a TtlTooShort), then append.
        let mut merged: Vec<RuntimeDelegation> = existing_delegations
            .into_iter()
            .filter(|e| {
                !delegations_to_insert
                    .iter()
                    .any(|c| c.tool == e.tool && c.agent_id == e.agent_id)
            })
            .collect();
        merged.extend(delegations_to_insert.iter().cloned());
        crate::delegate::save_delegations(runtime_delegations_path, &merged)?;
    }

    // Clean up auto-created pattern from patterns list if needed (it was persisted by scaffold_pattern)
    let _ = &auto_created_pattern; // suppress unused warning

    Ok(SpawnResult {
        mission_name,
        pattern_id: recommendation.pattern_id,
        pattern_auto_created,
        agent_prompts,
        delegations_created: delegations_to_insert,
        delegations_skipped,
        delegations_aborted: Vec::new(), // empty when we reach here (bail'd otherwise)
        role_gaps,
        mission_config,
        subagent_files_written,
        subagent_files_respected,
    })
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
            role_type: None,
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
        use crate::library::{RoleSlot, RolesSuggested};
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
            make_role(
                "security_architect",
                "Security Architect",
                vec!["audit", "compliance", "pci"],
            ),
            make_role(
                "auditor",
                "Auditor",
                vec!["audit", "compliance", "pci_dss", "payments"],
            ),
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
                vec![("oracle", "security_architect"), ("worker1", "auditor")],
            ),
            make_pattern(
                "plan_then_execute",
                "Plan Then Execute",
                vec![
                    "Tasks requiring upfront planning",
                    "Compliance and audit workflows",
                ],
                vec![],
                vec![("planner", "security_architect"), ("executor", "auditor")],
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
            make_role(
                "security_architect",
                "Security Architect",
                vec!["threat_modeling", "code_review"],
            ),
            make_role("auditor", "Auditor", vec!["compliance", "pci_dss"]),
        ];

        let mission = "audit cloud AWS infrastructure security";
        let mut gaps = detect_role_gaps(mission, &roles);
        gaps.sort();

        // "cloud" and "aws" should be detected as gaps
        assert!(
            gaps.contains(&"cloud".to_string()),
            "expected 'cloud' in gaps, got: {:?}",
            gaps
        );
        assert!(
            gaps.contains(&"aws".to_string()),
            "expected 'aws' in gaps, got: {:?}",
            gaps
        );
    }

    // ── 4. scaffold_role ─────────────────────────────────────────────────────

    #[test]
    fn test_scaffold_role() {
        let tmp = tempfile::tempdir().unwrap();
        let library_dir = tmp.path();

        let (role_path, prompt_path) = scaffold_role(
            "cloud_engineer",
            "Manages cloud infrastructure and deployments",
            None,
            library_dir,
        )
        .expect("scaffold_role should succeed");

        // Files should exist
        assert!(
            role_path.exists(),
            "role yaml should exist at {:?}",
            role_path
        );
        assert!(
            prompt_path.exists(),
            "prompt md should exist at {:?}",
            prompt_path
        );

        // role yaml should be valid YAML that deserializes as a Role
        let yaml_contents = std::fs::read_to_string(&role_path).unwrap();
        assert!(yaml_contents.contains("cloud_engineer"));
        assert!(yaml_contents.contains("Manages cloud infrastructure"));

        // prompt md should contain the id
        let md_contents = std::fs::read_to_string(&prompt_path).unwrap();
        assert!(md_contents.to_lowercase().contains("cloud engineer"));
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
            &[],   // no ELO ratings — uncalibrated
            None,  // no config_dir — no prompt review detection
            None,  // no manifest
            false, // dry_run: test writes to disk
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
        assert_eq!(
            mission_config.agent_configs.len(),
            2,
            "should have 2 agent configs"
        );
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
        let result = scaffold_role("evil\nid: hacked", "desc", None, tmp.path());
        assert!(result.is_err(), "newline in ID should be rejected");

        // Path traversal
        let result = scaffold_role("../../../etc/passwd", "desc", None, tmp.path());
        assert!(result.is_err(), "path traversal in ID should be rejected");

        // Empty
        let result = scaffold_role("", "desc", None, tmp.path());
        assert!(result.is_err(), "empty ID should be rejected");

        // Valid ID works
        let result = scaffold_role("cloud-security", "Cloud specialist", None, tmp.path());
        assert!(result.is_ok(), "valid ID should succeed: {:?}", result);
    }

    // ── 8. Security: scaffold overwrite protection (Fix 5) ───────────────────

    #[test]
    fn test_scaffold_role_rejects_existing() {
        let tmp = tempfile::tempdir().unwrap();

        // First create succeeds
        let result = scaffold_role("test-role", "Test", None, tmp.path());
        assert!(
            result.is_ok(),
            "first scaffold should succeed: {:?}",
            result
        );

        // Second create fails (already exists)
        let result = scaffold_role("test-role", "Test", None, tmp.path());
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

        assert!(
            output.contains("Oracle + Workers"),
            "should contain first pattern name"
        );
        assert!(
            output.contains("Plan Then Execute"),
            "should contain second pattern name"
        );
        assert!(
            output.contains("[RECOMMENDED]"),
            "first result should be labeled RECOMMENDED"
        );
        assert!(output.contains("Score: 6.0"), "should show score");
        assert!(
            !output.contains("No matching patterns"),
            "should not show empty message"
        );

        // Empty case
        let empty_output = format_recommendations(&[]);
        assert!(
            empty_output.contains("No matching patterns"),
            "empty recs should say no matching patterns"
        );
    }

    // ── 10. detect_prompt_review_target ──────────────────────────────────────

    #[test]
    fn test_detect_prompt_review_positive() {
        let roles = vec![
            make_role("pentester", "Pentester", vec!["pentesting"]),
            make_role("auditor", "Auditor", vec!["compliance"]),
        ];

        // "review {role} prompt"
        assert_eq!(
            detect_prompt_review_target("review pentester prompt", &roles),
            Some("pentester".to_string()),
        );

        // "improve {role} instructions"
        assert_eq!(
            detect_prompt_review_target("improve auditor instructions", &roles),
            Some("auditor".to_string()),
        );

        // "why is {role} scoring low"
        assert_eq!(
            detect_prompt_review_target("why is pentester scoring low", &roles),
            Some("pentester".to_string()),
        );

        // "refine {role} approach"
        assert_eq!(
            detect_prompt_review_target("refine pentester approach", &roles),
            Some("pentester".to_string()),
        );

        // Case insensitive
        assert_eq!(
            detect_prompt_review_target("Review Pentester Prompt", &roles),
            Some("pentester".to_string()),
        );
    }

    #[test]
    fn test_detect_prompt_review_negative() {
        let roles = vec![
            make_role("pentester", "Pentester", vec!["pentesting"]),
            make_role("auditor", "Auditor", vec!["compliance"]),
        ];

        // Normal mission text — no prompt review keywords
        assert_eq!(
            detect_prompt_review_target("audit PCI-DSS compliance of payments API", &roles),
            None,
        );

        // Mentions a role but no review keyword
        assert_eq!(
            detect_prompt_review_target("pentester should check the API", &roles),
            None,
        );

        // Has keywords but no valid role
        assert_eq!(
            detect_prompt_review_target("review ghost_agent prompt", &roles),
            None,
        );

        // Empty mission
        assert_eq!(detect_prompt_review_target("", &roles), None,);
    }

    // ── 11. generate_prompt_review_context ───────────────────────────────────

    #[test]
    fn test_generate_prompt_review_context_valid_role() {
        let tmp = tempfile::tempdir().unwrap();
        let library_dir = tmp.path().join("library");
        let config_dir = tmp.path();
        std::fs::create_dir_all(library_dir.join("prompts")).unwrap();

        // Write a prompt file for the target role
        std::fs::write(
            library_dir.join("prompts/pentester.md"),
            "# Pentester\n\nYou find vulnerabilities.",
        )
        .unwrap();

        let roles = vec![make_role("pentester", "Pentester", vec!["pentesting"])];

        let context = generate_prompt_review_context(
            "pentester",
            &roles,
            &library_dir,
            config_dir,
            &[], // no ELO ratings
        )
        .expect("should succeed");

        assert!(
            context.contains("Prompt Review Context"),
            "should contain header"
        );
        assert!(
            context.contains("**Pentester** (pentester)"),
            "should contain role name and id"
        );
        assert!(
            context.contains("You find vulnerabilities"),
            "should contain prompt text"
        );
        assert!(
            context.contains("Current ELO: 1500"),
            "should show default ELO"
        );
        assert!(
            context.contains("UNCALIBRATED"),
            "should show uncalibrated tier"
        );
        assert!(
            context.contains("No findings yet"),
            "should show no findings"
        );
        assert!(
            context.contains("prompt_improvement"),
            "should mention finding category"
        );
    }

    #[test]
    fn test_generate_prompt_review_context_no_findings() {
        let tmp = tempfile::tempdir().unwrap();
        let library_dir = tmp.path().join("library");
        let config_dir = tmp.path();
        std::fs::create_dir_all(library_dir.join("prompts")).unwrap();

        std::fs::write(
            library_dir.join("prompts/auditor.md"),
            "# Auditor\n\nYou audit code.",
        )
        .unwrap();

        let roles = vec![make_role("auditor", "Auditor", vec!["compliance"])];

        // Create empty findings dir
        std::fs::create_dir_all(config_dir.join("findings")).unwrap();

        let context =
            generate_prompt_review_context("auditor", &roles, &library_dir, config_dir, &[])
                .expect("should succeed");

        assert!(
            context.contains("No findings yet"),
            "should show no findings for empty store"
        );
    }

    #[test]
    fn test_generate_prompt_review_context_uncalibrated_role() {
        let tmp = tempfile::tempdir().unwrap();
        let library_dir = tmp.path().join("library");
        let config_dir = tmp.path();
        std::fs::create_dir_all(library_dir.join("prompts")).unwrap();

        std::fs::write(
            library_dir.join("prompts/pentester.md"),
            "# Pentester\n\nPrompt content.",
        )
        .unwrap();

        let roles = vec![make_role("pentester", "Pentester", vec!["pentesting"])];

        // No ELO ratings = uncalibrated
        let context =
            generate_prompt_review_context("pentester", &roles, &library_dir, config_dir, &[])
                .expect("should succeed");

        assert!(
            context.contains("ELO: 1500"),
            "uncalibrated should show 1500"
        );
        assert!(
            context.contains("UNCALIBRATED"),
            "should show UNCALIBRATED tier"
        );
        assert!(context.contains("Review count: 0"), "should show 0 reviews");
    }

    #[test]
    fn test_generate_prompt_review_context_with_elo() {
        let tmp = tempfile::tempdir().unwrap();
        let library_dir = tmp.path().join("library");
        let config_dir = tmp.path();
        std::fs::create_dir_all(library_dir.join("prompts")).unwrap();

        std::fs::write(
            library_dir.join("prompts/pentester.md"),
            "# Pentester\n\nPrompt content.",
        )
        .unwrap();

        let roles = vec![make_role("pentester", "Pentester", vec!["pentesting"])];

        let elo_ratings = vec![AgentRating {
            agent: "pentester".to_string(),
            elo: 1650,
            trend_7d: 15,
            review_count: 5,
            last_active: Some(Utc::now()),
        }];

        let context = generate_prompt_review_context(
            "pentester",
            &roles,
            &library_dir,
            config_dir,
            &elo_ratings,
        )
        .expect("should succeed");

        assert!(context.contains("ELO: 1650"), "should show actual ELO");
        assert!(context.contains("+15"), "should show positive trend");
        assert!(
            context.contains("Review count: 5"),
            "should show review count"
        );
        assert!(context.contains("elevated"), "1650 should be elevated tier");
    }

    #[test]
    fn test_generate_prompt_review_context_unknown_role() {
        let tmp = tempfile::tempdir().unwrap();
        let library_dir = tmp.path().join("library");
        let config_dir = tmp.path();
        std::fs::create_dir_all(library_dir.join("prompts")).unwrap();

        let roles = vec![make_role("pentester", "Pentester", vec!["pentesting"])];

        let result =
            generate_prompt_review_context("ghost_agent", &roles, &library_dir, config_dir, &[]);

        assert!(result.is_err(), "unknown role should return error");
        assert!(
            result.unwrap_err().to_string().contains("not found"),
            "error should mention not found"
        );
    }

    // ── 12. generate_mission with prompt review context ─────────────────────

    #[test]
    fn test_generate_mission_with_prompt_review() {
        let tmp = tempfile::tempdir().unwrap();
        let library_dir = tmp.path().join("library");
        let missions_dir = tmp.path().join("missions");
        let config_dir = tmp.path();
        std::fs::create_dir_all(library_dir.join("prompts")).unwrap();
        std::fs::create_dir_all(&missions_dir).unwrap();

        // Write prompt files
        std::fs::write(
            library_dir.join("prompts/security_architect.md"),
            "# Security Architect\n\nSystem prompt.",
        )
        .unwrap();
        std::fs::write(
            library_dir.join("prompts/pentester.md"),
            "# Pentester\n\nYou find vulnerabilities.",
        )
        .unwrap();

        let roles = vec![
            make_role("security_architect", "Security Architect", vec!["audit"]),
            make_role("pentester", "Pentester", vec!["pentesting"]),
        ];

        let rec = Recommendation {
            pattern_id: "debate".to_string(),
            pattern_name: "Debate".to_string(),
            score: 4.0,
            matched_criteria: vec![],
            anti_matched: vec![],
            role_assignments: vec![
                RoleAssignment {
                    slot: "debater_offense".to_string(),
                    role_id: "pentester".to_string(),
                    role_name: "Pentester".to_string(),
                    icon: "🗡️".to_string(),
                },
                RoleAssignment {
                    slot: "judge".to_string(),
                    role_id: "security_architect".to_string(),
                    role_name: "Security Architect".to_string(),
                    icon: "🔒".to_string(),
                },
            ],
        };

        // Prompt review mission — "review pentester prompt"
        let mission_config = generate_mission(
            "review pentester prompt — scoring low on thoroughness",
            &rec,
            &roles,
            &library_dir,
            &missions_dir,
            None,
            &[],
            Some(config_dir),
            None,
            false,
        )
        .expect("generate_mission should succeed");

        // All agents should have prompt review context
        for agent in &mission_config.agent_configs {
            let contents = std::fs::read_to_string(&agent.claude_md_path).unwrap();
            assert!(
                contents.contains("Prompt Review Context"),
                "CLAUDE.md for {} should contain prompt review context",
                agent.role_id
            );
            assert!(
                contents.contains("You find vulnerabilities"),
                "should contain pentester's prompt text for {}",
                agent.role_id
            );
        }
    }

    #[test]
    fn test_generate_mission_normal_no_prompt_review() {
        let tmp = tempfile::tempdir().unwrap();
        let library_dir = tmp.path().join("library");
        let missions_dir = tmp.path().join("missions");
        let config_dir = tmp.path();
        std::fs::create_dir_all(library_dir.join("prompts")).unwrap();
        std::fs::create_dir_all(&missions_dir).unwrap();

        std::fs::write(
            library_dir.join("prompts/security_architect.md"),
            "# Security Architect\n\nSystem prompt.",
        )
        .unwrap();
        std::fs::write(
            library_dir.join("prompts/auditor.md"),
            "# Auditor\n\nAudit prompt.",
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
            matched_criteria: vec![],
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

        // Normal mission — should NOT have prompt review context
        let mission_config = generate_mission(
            "audit PCI-DSS compliance of payments API",
            &rec,
            &roles,
            &library_dir,
            &missions_dir,
            None,
            &[],
            Some(config_dir),
            None,
            false,
        )
        .expect("generate_mission should succeed");

        for agent in &mission_config.agent_configs {
            let contents = std::fs::read_to_string(&agent.claude_md_path).unwrap();
            assert!(
                !contents.contains("Prompt Review Context"),
                "CLAUDE.md for {} should NOT contain prompt review context in normal mission",
                agent.role_id
            );
        }
    }

    // ── 14. New dev roles load from YAML ────────────────────────────────────

    #[test]
    fn test_new_roles_load_valid() {
        let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap();
        let library_dir = workspace_root.join("config/library");

        for role_file in &[
            "developer.yaml",
            "code-reviewer.yaml",
            "tester.yaml",
            "architect.yaml",
        ] {
            let role_path = library_dir.join("roles").join(role_file);
            assert!(role_path.exists(), "Role file should exist: {}", role_file);

            let content = std::fs::read_to_string(&role_path).unwrap();
            let role: crate::library::Role = serde_yml::from_str(&content)
                .unwrap_or_else(|e| panic!("Failed to parse {}: {}", role_file, e));

            assert!(!role.id.is_empty(), "{}: id should not be empty", role_file);
            assert!(
                !role.tools_allowed.is_empty(),
                "{}: tools_allowed should not be empty",
                role_file
            );
            assert!(
                !role.specializations.is_empty(),
                "{}: specializations should not be empty",
                role_file
            );
            assert_eq!(
                role.default_trust_level, "ask",
                "{}: new roles should start at ask",
                role_file
            );
            assert!(
                role.permissions.is_some(),
                "{}: should have permissions block",
                role_file
            );
        }
    }

    // ── 15. New dev patterns load from YAML ─────────────────────────────────

    #[test]
    fn test_new_patterns_load_valid() {
        let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap();
        let library_dir = workspace_root.join("config/library");

        for pattern_file in &[
            "code-review-cycle.yaml",
            "docs-from-code.yaml",
            "refactor-safe.yaml",
        ] {
            let pattern_path = library_dir.join("patterns").join(pattern_file);
            assert!(
                pattern_path.exists(),
                "Pattern file should exist: {}",
                pattern_file
            );

            let content = std::fs::read_to_string(&pattern_path).unwrap();
            let pattern: crate::library::Pattern = serde_yml::from_str(&content)
                .unwrap_or_else(|e| panic!("Failed to parse {}: {}", pattern_file, e));

            assert!(
                !pattern.id.is_empty(),
                "{}: id should not be empty",
                pattern_file
            );
            assert!(
                !pattern.when_to_use.is_empty(),
                "{}: when_to_use should not be empty",
                pattern_file
            );
            assert_eq!(
                pattern.source.as_deref(),
                Some("builtin"),
                "{}: dev patterns should be builtin",
                pattern_file
            );
        }
    }

    // ── 16. select_patterns matches dev mission ─────────────────────────────

    #[test]
    fn test_select_patterns_matches_dev_mission() {
        let roles = vec![
            make_role(
                "developer",
                "Developer",
                vec!["feature_implementation", "refactoring", "code_writing"],
            ),
            make_role(
                "tester",
                "Tester",
                vec!["test_writing", "coverage_analysis", "regression_detection"],
            ),
            make_role("auditor", "Auditor", vec!["compliance", "audit"]),
        ];

        let patterns = vec![
            make_pattern(
                "code-review-cycle",
                "Code Review Cycle",
                vec![
                    "Feature implementation with quality review",
                    "Code writing followed by structured review",
                    "Feedback loop between implementer and reviewer",
                ],
                vec!["Tasks requiring multiple parallel specialists"],
                vec![("agent", "developer"), ("critic", "auditor")],
            ),
            make_pattern(
                "refactor-safe",
                "Refactor Safe",
                vec![
                    "Refactoring that must not break existing behavior",
                    "Code restructuring with regression risk",
                    "Technical debt cleanup requiring test validation",
                ],
                vec!["Simple rename or cosmetic changes"],
                vec![
                    ("stage_1", "developer"),
                    ("stage_2", "tester"),
                    ("stage_3", "auditor"),
                ],
            ),
        ];

        let mission = "implement JWT authentication feature with code review";
        let recs = select_patterns(mission, &patterns, &roles);
        assert!(!recs.is_empty(), "should match at least one dev pattern");
        assert!(
            recs[0].pattern_id == "code-review-cycle" || recs[0].pattern_id == "refactor-safe",
            "top pattern should be a dev pattern, got: {}",
            recs[0].pattern_id
        );
    }

    // ── 17. generate_mission includes inter-agent directive ─────────────────

    #[test]
    fn test_generate_mission_includes_interagent_directive() {
        let tmp = tempfile::tempdir().unwrap();
        let library_dir = tmp.path().join("library");
        let missions_dir = tmp.path().join("missions");
        std::fs::create_dir_all(library_dir.join("prompts")).unwrap();
        std::fs::create_dir_all(&missions_dir).unwrap();

        std::fs::write(
            library_dir.join("prompts/developer.md"),
            "# Developer\n\nYou write code.",
        )
        .unwrap();
        std::fs::write(
            library_dir.join("prompts/auditor.md"),
            "# Auditor\n\nYou review.",
        )
        .unwrap();

        let roles = vec![
            make_role("developer", "Developer", vec!["code_writing"]),
            make_role("auditor", "Auditor", vec!["audit"]),
        ];

        let rec = Recommendation {
            pattern_id: "code-review-cycle".to_string(),
            pattern_name: "Code Review Cycle".to_string(),
            score: 3.0,
            matched_criteria: vec![],
            anti_matched: vec![],
            role_assignments: vec![
                RoleAssignment {
                    slot: "agent".to_string(),
                    role_id: "developer".to_string(),
                    role_name: "Developer".to_string(),
                    icon: "💻".to_string(),
                },
                RoleAssignment {
                    slot: "critic".to_string(),
                    role_id: "auditor".to_string(),
                    role_name: "Auditor".to_string(),
                    icon: "📋".to_string(),
                },
            ],
        };

        let mission_config = generate_mission(
            "implement JWT auth",
            &rec,
            &roles,
            &library_dir,
            &missions_dir,
            None,
            &[],
            None,
            None,
            false,
        )
        .expect("generate_mission should succeed");

        // Both agents should have the inter-agent directive (2 agents = multi-agent)
        for agent in &mission_config.agent_configs {
            let contents = std::fs::read_to_string(&agent.claude_md_path).unwrap();
            assert!(
                contents.contains("Colmena Inter-Agent Protocol"),
                "CLAUDE.md for {} should contain inter-agent directive",
                agent.role_id
            );
            assert!(
                contents.contains("Facts only"),
                "directive should include communication rules for {}",
                agent.role_id
            );
        }
    }

    // ── 18. inter-agent directive not in solo missions ───────────────────────

    #[test]
    fn test_interagent_directive_not_in_solo_mode() {
        let tmp = tempfile::tempdir().unwrap();
        let library_dir = tmp.path().join("library");
        let missions_dir = tmp.path().join("missions");
        std::fs::create_dir_all(library_dir.join("prompts")).unwrap();
        std::fs::create_dir_all(&missions_dir).unwrap();

        std::fs::write(
            library_dir.join("prompts/researcher.md"),
            "# Researcher\n\nYou research.",
        )
        .unwrap();

        let roles = vec![make_role("researcher", "Researcher", vec!["research"])];

        let rec = Recommendation {
            pattern_id: "single-agent".to_string(),
            pattern_name: "Single Agent".to_string(),
            score: 2.0,
            matched_criteria: vec![],
            anti_matched: vec![],
            role_assignments: vec![RoleAssignment {
                slot: "agent".to_string(),
                role_id: "researcher".to_string(),
                role_name: "Researcher".to_string(),
                icon: "🔬".to_string(),
            }],
        };

        let mission_config = generate_mission(
            "research API security best practices",
            &rec,
            &roles,
            &library_dir,
            &missions_dir,
            None,
            &[],
            None,
            None,
            false,
        )
        .expect("generate_mission should succeed");

        // Single agent should NOT have inter-agent directive
        for agent in &mission_config.agent_configs {
            let contents = std::fs::read_to_string(&agent.claude_md_path).unwrap();
            assert!(
                !contents.contains("Colmena Inter-Agent Protocol"),
                "CLAUDE.md for solo agent should NOT contain inter-agent directive",
            );
        }
    }

    // ── 19. spawn_mission — matching pattern ────────────────────────────────

    #[test]
    fn test_spawn_mission_with_matching_pattern() {
        let tmp = tempfile::tempdir().unwrap();
        let library_dir = tmp.path().join("library");
        let missions_dir = tmp.path().join("missions");
        std::fs::create_dir_all(library_dir.join("prompts")).unwrap();
        std::fs::create_dir_all(library_dir.join("patterns")).unwrap();
        std::fs::create_dir_all(&missions_dir).unwrap();

        // Write prompt files
        std::fs::write(
            library_dir.join("prompts/developer.md"),
            "# Developer\nYou write code.",
        )
        .unwrap();
        std::fs::write(
            library_dir.join("prompts/auditor.md"),
            "# Auditor\nYou review.",
        )
        .unwrap();

        let roles = vec![
            make_role(
                "developer",
                "Developer",
                vec!["feature_implementation", "code_writing"],
            ),
            make_role("auditor", "Auditor", vec!["audit", "compliance"]),
        ];

        let patterns = vec![make_pattern(
            "code-review-cycle",
            "Code Review Cycle",
            vec![
                "Feature implementation with quality review",
                "Code writing followed by structured review",
            ],
            vec![],
            vec![("agent", "developer"), ("critic", "auditor")],
        )];

        let runtime_delegations_path = tmp.path().join("runtime-delegations.json");
        let agents_dir = tmp.path().join("agents");
        let result = spawn_mission(
            "implement feature with code review",
            None, // manifest
            &roles,
            &patterns,
            &library_dir,
            &missions_dir,
            &runtime_delegations_path,
            &agents_dir,
            None,  // session_id
            &[],   // elo_ratings
            None,  // config_dir
            false, // extend_existing
            false, // dry_run
            false, // overwrite_subagents
        );
        assert!(result.is_ok(), "spawn_mission failed: {:?}", result.err());

        let spawn = result.unwrap();
        assert_eq!(spawn.pattern_id, "code-review-cycle");
        assert!(!spawn.pattern_auto_created);
        assert!(!spawn.agent_prompts.is_empty());
        // All prompts should contain mission marker
        for ap in &spawn.agent_prompts {
            assert!(
                ap.prompt.contains(MISSION_MARKER_PREFIX),
                "Prompt for {} should contain mission marker",
                ap.role_id
            );
        }
        // Delegations should have been persisted (either created or skipped — non-empty for this role set).
        assert!(
            !spawn.delegations_created.is_empty() || !spawn.delegations_skipped.is_empty(),
            "should have created or skipped delegations"
        );
    }

    // ── 20. spawn_mission — auto-creates pattern ────────────────────────────

    #[test]
    fn test_spawn_mission_auto_creates_pattern() {
        let tmp = tempfile::tempdir().unwrap();
        let library_dir = tmp.path().join("library");
        let missions_dir = tmp.path().join("missions");
        std::fs::create_dir_all(library_dir.join("prompts")).unwrap();
        std::fs::create_dir_all(library_dir.join("patterns")).unwrap();
        std::fs::create_dir_all(&missions_dir).unwrap();

        std::fs::write(library_dir.join("prompts/developer.md"), "# Dev\nCode.").unwrap();

        let roles = vec![make_role("developer", "Developer", vec!["code_writing"])];

        // Empty patterns — will auto-create
        let patterns: Vec<Pattern> = vec![];

        let runtime_delegations_path = tmp.path().join("runtime-delegations.json");
        let agents_dir = tmp.path().join("agents");
        let result = spawn_mission(
            "do something completely unique",
            None, // manifest
            &roles,
            &patterns,
            &library_dir,
            &missions_dir,
            &runtime_delegations_path,
            &agents_dir,
            None,  // session_id
            &[],   // elo_ratings
            None,  // config_dir
            false, // extend_existing
            false, // dry_run
            false, // overwrite_subagents
        );
        assert!(
            result.is_ok(),
            "spawn_mission should auto-create: {:?}",
            result.err()
        );

        let spawn = result.unwrap();
        assert!(spawn.pattern_auto_created, "pattern should be auto-created");
        assert!(!spawn.agent_prompts.is_empty());
    }

    // ── 21. spawn_mission — empty library fails ─────────────────────────────

    #[test]
    fn test_spawn_mission_empty_library_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let library_dir = tmp.path().join("library");
        let missions_dir = tmp.path().join("missions");
        std::fs::create_dir_all(&library_dir).unwrap();
        std::fs::create_dir_all(&missions_dir).unwrap();

        let runtime_delegations_path = tmp.path().join("runtime-delegations.json");
        let agents_dir = tmp.path().join("agents");
        let result = spawn_mission(
            "some mission",
            None, // manifest
            &[],
            &[],
            &library_dir,
            &missions_dir,
            &runtime_delegations_path,
            &agents_dir,
            None,  // session_id
            &[],   // elo_ratings
            None,  // config_dir
            false, // extend_existing
            false, // dry_run
            false, // overwrite_subagents
        );
        assert!(
            result.is_err(),
            "spawn_mission with empty library should fail"
        );
        assert!(result.unwrap_err().to_string().contains("No roles"));
    }

    // ── 22. spawn_mission — marker format ───────────────────────────────────

    #[test]
    fn test_spawn_mission_marker_format() {
        assert!(MISSION_MARKER_PREFIX.starts_with("<!--"));
        assert!(MISSION_MARKER_PREFIX.contains("colmena:mission_id="));
    }

    // ── 23. spawn_mission — delegations persisted to runtime-delegations.json ──

    #[test]
    fn test_spawn_mission_persists_delegations() {
        let tmp = tempfile::tempdir().unwrap();
        let library_dir = tmp.path().join("library");
        let missions_dir = tmp.path().join("missions");
        std::fs::create_dir_all(library_dir.join("prompts")).unwrap();
        std::fs::create_dir_all(library_dir.join("patterns")).unwrap();
        std::fs::create_dir_all(&missions_dir).unwrap();

        std::fs::write(library_dir.join("prompts/developer.md"), "# Dev\nCode.").unwrap();
        std::fs::write(library_dir.join("prompts/auditor.md"), "# Auditor\nReview.").unwrap();

        let mut dev = make_role("developer", "Developer", vec!["code_writing"]);
        dev.tools_allowed = vec!["Read".to_string(), "Write".to_string(), "Bash".to_string()];
        // Bash delegations require a scope condition — give the dev a bash_pattern
        // so `save_delegations` accepts the generated entry.
        dev.permissions = Some(crate::library::RolePermissions {
            bash_patterns: vec!["^cargo (test|build|check)".to_string()],
            path_within: vec![],
            path_not_match: vec![],
        });
        let roles = vec![dev, make_role("auditor", "Auditor", vec!["audit"])];

        let patterns = vec![make_pattern(
            "code-review-cycle",
            "Code Review Cycle",
            vec!["Feature implementation with quality review"],
            vec![],
            vec![("agent", "developer"), ("critic", "auditor")],
        )];

        let runtime_delegations_path = tmp.path().join("runtime-delegations.json");
        let agents_dir = tmp.path().join("agents");
        let result = spawn_mission(
            "implement feature with code review",
            None, // manifest
            &roles,
            &patterns,
            &library_dir,
            &missions_dir,
            &runtime_delegations_path,
            &agents_dir,
            None,  // session_id
            &[],   // elo_ratings
            None,  // config_dir
            false, // extend_existing
            false, // dry_run
            false, // overwrite_subagents
        )
        .unwrap();

        // Delegations should have been created (fresh store — no existing delegations).
        assert!(
            !result.delegations_created.is_empty(),
            "should have created delegations"
        );
        assert!(
            result.delegations_skipped.is_empty(),
            "nothing to skip on a fresh store"
        );
        assert!(result.delegations_aborted.is_empty(), "no aborts when Ok");

        // Verify the runtime-delegations.json file was actually written.
        assert!(
            runtime_delegations_path.exists(),
            "runtime-delegations.json should have been persisted"
        );
        let persisted = crate::delegate::load_delegations(&runtime_delegations_path);
        assert!(
            !persisted.is_empty(),
            "persisted delegations should be non-empty"
        );
        // Sanity: created delegations match what we persisted.
        assert_eq!(
            persisted.len(),
            result.delegations_created.len(),
            "persisted count should equal delegations_created count on a fresh store"
        );
    }

    // ── 23a+. M7.3 post-dogfood: ELO-cycle tool bundling + centralized auditor ─

    #[test]
    fn test_generate_role_delegations_bundles_elo_cycle_tools() {
        // Mirror of the bug found in 2026-04-21 dogfood: role YAML only declares
        // review_submit, but mission_spawn must still delegate review_evaluate
        // so the role can act as reviewer without the operator gluing it.
        let mut dev = make_role("developer", "Developer", vec!["code_writing"]);
        dev.tools_allowed = vec![
            "Read".to_string(),
            "mcp__colmena__review_submit".to_string(),
            "mcp__colmena__findings_query".to_string(),
        ];

        let tmp = tempfile::tempdir().unwrap();
        let delegations = generate_role_delegations(
            &dev,
            "2026-04-21-test-mission",
            tmp.path(),
            None,
            Utc::now(),
            chrono::Duration::hours(8),
        );

        let tools: Vec<&str> = delegations.iter().map(|d| d.tool.as_str()).collect();
        assert!(
            tools.contains(&"mcp__colmena__review_submit"),
            "review_submit must be delegated (was in YAML): {:?}",
            tools
        );
        assert!(
            tools.contains(&"mcp__colmena__review_evaluate"),
            "review_evaluate MUST be auto-bundled even though YAML omits it: {:?}",
            tools
        );
        assert!(
            tools.contains(&"mcp__colmena__findings_query"),
            "findings_query must remain delegated: {:?}",
            tools
        );
    }

    #[test]
    fn test_spawn_mission_centralizes_review_to_auditor_when_present() {
        use crate::mission_manifest::MissionManifest;

        let tmp = tempfile::tempdir().unwrap();
        let library_dir = tmp.path().join("library");
        let missions_dir = tmp.path().join("missions");
        std::fs::create_dir_all(library_dir.join("prompts")).unwrap();
        std::fs::create_dir_all(library_dir.join("patterns")).unwrap();
        std::fs::create_dir_all(&missions_dir).unwrap();

        std::fs::write(library_dir.join("prompts/developer.md"), "# Dev\nCode.").unwrap();
        std::fs::write(library_dir.join("prompts/auditor.md"), "# Auditor\nReview.").unwrap();

        let dev = make_role("developer", "Developer", vec!["code_writing"]);
        let mut auditor = make_role("auditor", "Auditor", vec!["audit"]);
        auditor.role_type = Some("auditor".to_string());
        let roles = vec![dev, auditor];

        let patterns = vec![make_pattern(
            "code-review-cycle",
            "Code Review Cycle",
            vec!["Feature implementation with quality review"],
            vec![],
            vec![("agent", "developer"), ("critic", "auditor")],
        )];

        let manifest = MissionManifest::from_yaml(
            "id: m73-centralize-test\n\
             pattern: code-review-cycle\n\
             mission_ttl_hours: 1\n\
             roles:\n  \
               - name: developer\n    \
                 task: Implement feature\n  \
               - name: auditor\n    \
                 task: Evaluate developer work\n",
        )
        .unwrap();

        let runtime_delegations_path = tmp.path().join("runtime-delegations.json");
        let agents_dir = tmp.path().join("agents");
        let result = spawn_mission(
            "implement feature with code review",
            Some(&manifest),
            &roles,
            &patterns,
            &library_dir,
            &missions_dir,
            &runtime_delegations_path,
            &agents_dir,
            None,
            &[],
            None,
            false,
            false,
            true, // overwrite_subagents
        )
        .unwrap();

        let dev_md_path = result
            .agent_prompts
            .iter()
            .find(|p| p.role_id == "developer")
            .expect("developer prompt should exist")
            .claude_md_path
            .clone();
        let dev_md = std::fs::read_to_string(&dev_md_path).unwrap();
        assert!(
            dev_md.contains("available_roles: [\"auditor\"]"),
            "developer review_submit must centralize on auditor; got:\n{}",
            dev_md
        );

        let auditor_md_path = result
            .agent_prompts
            .iter()
            .find(|p| p.role_id == "auditor")
            .expect("auditor prompt should exist")
            .claude_md_path
            .clone();
        let auditor_md = std::fs::read_to_string(&auditor_md_path).unwrap();
        assert!(
            !auditor_md.contains("## Review Protocol — MANDATORY"),
            "auditor (role_type=auditor) must be exempt from review_submit block; got:\n{}",
            auditor_md
        );
    }

    // ── 23b. spawn_mission — dry_run does not write to disk ─────────────────

    #[test]
    fn test_spawn_mission_dry_run_skips_persistence() {
        let tmp = tempfile::tempdir().unwrap();
        let library_dir = tmp.path().join("library");
        let missions_dir = tmp.path().join("missions");
        std::fs::create_dir_all(library_dir.join("prompts")).unwrap();
        std::fs::create_dir_all(library_dir.join("patterns")).unwrap();
        std::fs::create_dir_all(&missions_dir).unwrap();

        std::fs::write(library_dir.join("prompts/developer.md"), "# Dev\nCode.").unwrap();
        std::fs::write(library_dir.join("prompts/auditor.md"), "# Auditor\nReview.").unwrap();

        let roles = vec![
            make_role("developer", "Developer", vec!["code_writing"]),
            make_role("auditor", "Auditor", vec!["audit"]),
        ];
        let patterns = vec![make_pattern(
            "code-review-cycle",
            "Code Review Cycle",
            vec!["Feature implementation with quality review"],
            vec![],
            vec![("agent", "developer"), ("critic", "auditor")],
        )];

        let runtime_delegations_path = tmp.path().join("runtime-delegations.json");
        let agents_dir = tmp.path().join("agents");
        let result = spawn_mission(
            "implement feature with code review",
            None,
            &roles,
            &patterns,
            &library_dir,
            &missions_dir,
            &runtime_delegations_path,
            &agents_dir,
            None,
            &[],
            None,
            false, // extend_existing
            true,  // dry_run
            false, // overwrite_subagents
        )
        .unwrap();

        // Plan still computed (we know which delegations would be inserted)…
        assert!(!result.delegations_created.is_empty());
        // …but no file was written.
        assert!(
            !runtime_delegations_path.exists(),
            "dry_run must NOT write to disk"
        );
    }

    // ── 24. suggest_mission_size — trivial ──────────────────────────────────

    #[test]
    fn test_suggest_trivial_single_domain() {
        let roles = vec![make_role("developer", "Developer", vec!["code_writing"])];
        let patterns: Vec<Pattern> = vec![];
        let s = suggest_mission_size("fix typo in README", &roles, &patterns);
        assert_eq!(s.complexity, Complexity::Trivial);
        assert!(!s.needs_colmena);
        assert_eq!(s.recommended_agents, 1);
    }

    // ── 25. suggest_mission_size — small ────────────────────────────────────

    #[test]
    fn test_suggest_small_two_domains() {
        let roles = vec![make_role("developer", "Developer", vec!["code_writing"])];
        let patterns: Vec<Pattern> = vec![];
        let s = suggest_mission_size(
            "implement feature and write tests for it",
            &roles,
            &patterns,
        );
        assert_eq!(s.complexity, Complexity::Small);
        assert!(!s.needs_colmena);
        assert_eq!(s.recommended_agents, 2);
    }

    // ── 26. suggest_mission_size — medium ───────────────────────────────────

    #[test]
    fn test_suggest_medium_three_domains() {
        let roles = vec![
            make_role("developer", "Developer", vec!["feature_implementation"]),
            make_role("tester", "Tester", vec!["test_writing"]),
            make_role("auditor", "Auditor", vec!["audit"]),
        ];
        let patterns: Vec<Pattern> = vec![];
        let s = suggest_mission_size(
            "implement authentication feature with test coverage and security review",
            &roles,
            &patterns,
        );
        assert!(s.complexity == Complexity::Medium || s.complexity == Complexity::Large);
        assert!(s.needs_colmena);
        assert!(s.recommended_agents >= 3);
    }

    // ── 27. suggest_mission_size — large ────────────────────────────────────

    #[test]
    fn test_suggest_large_many_domains() {
        let roles = vec![make_role("developer", "Developer", vec!["code_writing"])];
        let patterns: Vec<Pattern> = vec![];
        let s = suggest_mission_size(
            "full platform migration with security audit, comprehensive testing, documentation, and CI/CD pipeline deployment",
            &roles, &patterns,
        );
        assert_eq!(s.complexity, Complexity::Large);
        assert!(s.needs_colmena);
        assert!(s.recommended_agents >= 4);
    }

    // ── 28. risk keywords bump complexity ───────────────────────────────────

    #[test]
    fn test_suggest_risk_keywords_bump_complexity() {
        let roles = vec![make_role("developer", "Developer", vec!["code_writing"])];
        let patterns: Vec<Pattern> = vec![];
        // "production" and "security" are bumpers
        let s = suggest_mission_size(
            "deploy to production with security constraints",
            &roles,
            &patterns,
        );
        // Should be higher than base domain count alone
        assert!(
            s.recommended_agents >= 2,
            "risk keywords should bump complexity"
        );
    }

    // ── 29. simplicity keywords reduce complexity ───────────────────────────

    #[test]
    fn test_suggest_simplicity_keywords_reduce() {
        let roles = vec![make_role("developer", "Developer", vec!["code_writing"])];
        let patterns: Vec<Pattern> = vec![];
        let s = suggest_mission_size("quick simple fix for a small typo", &roles, &patterns);
        assert_eq!(s.complexity, Complexity::Trivial);
        assert!(!s.needs_colmena);
    }

    // ── 30. needs_colmena threshold ─────────────────────────────────────────

    #[test]
    fn test_suggest_needs_colmena_threshold() {
        let roles = vec![make_role("developer", "Developer", vec!["code_writing"])];
        let patterns: Vec<Pattern> = vec![];
        // Exactly at threshold
        let s = suggest_mission_size(
            "implement code, write tests, and review security",
            &roles,
            &patterns,
        );
        assert!(
            s.needs_colmena == (s.recommended_agents >= 3),
            "needs_colmena should be true iff agents >= 3, got agents={} needs={}",
            s.recommended_agents,
            s.needs_colmena
        );
    }

    // ── 31. empty description ───────────────────────────────────────────────

    #[test]
    fn test_suggest_empty_description() {
        let roles = vec![make_role("developer", "Developer", vec!["code_writing"])];
        let patterns: Vec<Pattern> = vec![];
        let s = suggest_mission_size("", &roles, &patterns);
        assert_eq!(s.complexity, Complexity::Trivial);
        assert_eq!(s.confidence, 0.0);
        assert!(!s.needs_colmena);
    }
}
