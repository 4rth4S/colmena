// ── Pattern Scaffold Generator ───────────────────────────────────────────────
//
// Creates new pattern scaffolds with topology-aware structure.
// Part of M6: intelligent role creation.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::Result;

// ── PatternTopology ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PatternTopology {
    Hierarchical, // Oracle-Workers, Plan-Then-Execute — hub-and-spoke
    Sequential,   // Pipeline — chain communication
    Adversarial,  // Multi-Agent Debate — structured-exchange
    Peer,         // Swarm Consensus — broadcast
    FanOutMerge,  // Map-Reduce — parallel fan-out then merge
    Recursive,    // Sub-Agent Spawning, Tree-of-Thought — delegation-tree
    Iterative,    // Reflection Loop, Progressive Escalation — loop
}

impl fmt::Display for PatternTopology {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for PatternTopology {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "hierarchical" => Ok(PatternTopology::Hierarchical),
            "sequential" => Ok(PatternTopology::Sequential),
            "adversarial" => Ok(PatternTopology::Adversarial),
            "peer" => Ok(PatternTopology::Peer),
            "fan-out-merge" | "fanoutmerge" | "fan_out_merge" => Ok(PatternTopology::FanOutMerge),
            "recursive" => Ok(PatternTopology::Recursive),
            "iterative" => Ok(PatternTopology::Iterative),
            _ => anyhow::bail!(
                "Unknown topology '{}'. Valid values: hierarchical, sequential, adversarial, \
                 peer, fan-out-merge, recursive, iterative",
                s
            ),
        }
    }
}

// ── All 7 variants for iteration ─────────────────────────────────────────────

const ALL_TOPOLOGIES: [PatternTopology; 7] = [
    PatternTopology::Hierarchical,
    PatternTopology::Sequential,
    PatternTopology::Adversarial,
    PatternTopology::Peer,
    PatternTopology::FanOutMerge,
    PatternTopology::Recursive,
    PatternTopology::Iterative,
];

// ── PatternTopology methods ──────────────────────────────────────────────────

impl PatternTopology {
    /// Communication style label for this topology.
    pub fn communication(&self) -> &'static str {
        match self {
            PatternTopology::Hierarchical => "hub-and-spoke",
            PatternTopology::Sequential => "chain",
            PatternTopology::Adversarial => "structured-exchange",
            PatternTopology::Peer => "broadcast",
            PatternTopology::FanOutMerge => "map-reduce",
            PatternTopology::Recursive => "delegation-tree",
            PatternTopology::Iterative => "loop",
        }
    }

    /// Lowercase kebab-case identifier.
    pub fn as_str(&self) -> &'static str {
        match self {
            PatternTopology::Hierarchical => "hierarchical",
            PatternTopology::Sequential => "sequential",
            PatternTopology::Adversarial => "adversarial",
            PatternTopology::Peer => "peer",
            PatternTopology::FanOutMerge => "fan-out-merge",
            PatternTopology::Recursive => "recursive",
            PatternTopology::Iterative => "iterative",
        }
    }

    /// Estimated number of agents for this topology.
    /// Minimum 3 agents per topology — Colmena requires auditor + 2 workers minimum.
    pub fn estimated_agents(&self) -> &'static str {
        match self {
            PatternTopology::Hierarchical => "3-5",
            PatternTopology::Sequential => "3-4",
            PatternTopology::Adversarial => "3",
            PatternTopology::Peer => "4-6",
            PatternTopology::FanOutMerge => "4-6",
            PatternTopology::Recursive => "3-4",
            PatternTopology::Iterative => "3",
        }
    }

    /// Estimated token cost level.
    pub fn estimated_token_cost(&self) -> &'static str {
        match self {
            PatternTopology::Hierarchical => "medium",
            PatternTopology::Sequential => "low",
            PatternTopology::Adversarial => "medium",
            PatternTopology::Peer => "high",
            PatternTopology::FanOutMerge => "high",
            PatternTopology::Recursive => "medium",
            PatternTopology::Iterative => "low",
        }
    }

    /// Whether ELO lead selection is used for this topology.
    pub fn elo_lead_selection(&self) -> bool {
        matches!(
            self,
            PatternTopology::Hierarchical | PatternTopology::FanOutMerge
        )
    }

    /// When to use this topology (positive criteria).
    pub fn when_to_use(&self) -> &'static [&'static str] {
        match self {
            PatternTopology::Hierarchical => &[
                "Clearly decomposable tasks with independent workers",
                "Need unified output from multiple specialists",
                "Strategic coordination required",
                "Security audit with multiple focus areas",
                "Architecture review requiring diverse expertise",
            ],
            PatternTopology::Sequential => &[
                "Each phase depends on previous output",
                "Need human checkpoints between stages",
                "Budget-conscious missions",
                "Reconnaissance followed by testing followed by review",
                "Methodical step-by-step analysis required",
            ],
            PatternTopology::Adversarial => &[
                "Need to surface disagreements or competing priorities",
                "Offense vs defense perspective needed",
                "Risk assessment where severity is debatable",
                "Trade-off analysis between competing concerns",
                "Threat modeling with conflicting assumptions",
            ],
            PatternTopology::Peer => &[
                "Broad exploration where coverage matters most",
                "Unknown attack surface that needs mapping",
                "Complex system where different perspectives find different issues",
                "Validation of findings through independent discovery",
                "Comprehensive assessment of new system",
            ],
            PatternTopology::FanOutMerge => &[
                "Large input that can be split into independent chunks",
                "Need to process many items in parallel then aggregate",
                "Search or analysis across multiple sources simultaneously",
                "Batch processing where each item is independent",
                "Wide coverage needed with a single synthesized result",
            ],
            PatternTopology::Recursive => &[
                "Problem naturally decomposes into sub-problems",
                "Depth of analysis matters more than breadth",
                "Tree-structured exploration needed",
                "Each sub-task may spawn further sub-tasks",
            ],
            PatternTopology::Iterative => &[
                "Quality improves through repeated refinement",
                "Self-critique and correction are valuable",
                "Output converges toward a target standard",
                "Feedback loop between creator and reviewer",
            ],
        }
    }

    /// When NOT to use this topology (anti-criteria).
    pub fn when_not_to_use(&self) -> &'static [&'static str] {
        match self {
            PatternTopology::Hierarchical => &[
                "Tasks require real-time negotiation between agents",
                "The decomposition itself is the hard problem",
                "Very small scope that one agent can handle",
            ],
            PatternTopology::Sequential => &[
                "Tasks that are naturally parallel and independent",
                "Time-sensitive missions requiring fast results",
                "Broad coverage needed simultaneously",
            ],
            PatternTopology::Adversarial => &[
                "Clear-cut technical tasks with one right answer",
                "Time-sensitive issues requiring immediate action",
                "Tasks where collaboration is more valuable than debate",
            ],
            PatternTopology::Peer => &[
                "Well-defined scope with clear task decomposition",
                "Budget-constrained missions",
                "Simple tasks that don't benefit from multiple perspectives",
            ],
            PatternTopology::FanOutMerge => &[
                "Items have strong dependencies on each other",
                "Sequential ordering matters for correctness",
                "Small input that doesn't benefit from splitting",
            ],
            PatternTopology::Recursive => &[
                "Flat problem structure with no natural decomposition",
                "Strict budget constraints on agent spawning",
                "Breadth matters more than depth",
            ],
            PatternTopology::Iterative => &[
                "First draft quality is sufficient",
                "No clear convergence criteria exist",
                "Time-sensitive tasks where iteration adds too much latency",
            ],
        }
    }

    /// Advantages of this topology.
    pub fn pros(&self) -> &'static [&'static str] {
        match self {
            PatternTopology::Hierarchical => &[
                "Clear accountability — lead owns the outcome",
                "Parallelizable — workers run independently",
                "Lower token cost — workers don't share full context",
            ],
            PatternTopology::Sequential => &[
                "Lower cost — each agent runs sequentially",
                "Each stage builds on validated previous output",
                "Clear checkpoints for human review",
            ],
            PatternTopology::Adversarial => &[
                "Surfaces hidden assumptions and blind spots",
                "Thorough coverage of opposing viewpoints",
                "Forces explicit reasoning and evidence",
            ],
            PatternTopology::Peer => &[
                "Maximum coverage — independent exploration",
                "Findings validated when multiple agents converge",
                "No single point of failure",
            ],
            PatternTopology::FanOutMerge => &[
                "Highly parallelizable — all mappers run concurrently",
                "Scales linearly with input size",
                "Reducer produces unified output from diverse sources",
            ],
            PatternTopology::Recursive => &[
                "Handles arbitrary depth of analysis",
                "Each level can specialize for its sub-problem",
                "Natural fit for divide-and-conquer problems",
            ],
            PatternTopology::Iterative => &[
                "Output quality improves with each cycle",
                "Low agent count keeps costs manageable",
                "Catches errors through self-critique",
            ],
        }
    }

    /// Disadvantages of this topology.
    pub fn cons(&self) -> &'static [&'static str] {
        match self {
            PatternTopology::Hierarchical => &[
                "Lead is single point of failure",
                "Workers can't course-correct each other",
                "Lead context grows with number of workers",
            ],
            PatternTopology::Sequential => &[
                "Slower — fully sequential execution",
                "No cross-pollination between agents",
                "Late-stage agents can't inform early-stage decisions",
            ],
            PatternTopology::Adversarial => &[
                "Higher token cost than sequential approaches",
                "May over-focus on contentious areas",
                "Requires good judge to synthesize",
            ],
            PatternTopology::Peer => &[
                "Highest token cost — all agents run fully",
                "Duplicate work likely",
                "Consensus phase can be complex",
            ],
            PatternTopology::FanOutMerge => &[
                "High total token cost from parallel mappers",
                "Reducer must handle heterogeneous outputs",
                "Chunk boundaries may miss cross-cutting concerns",
            ],
            PatternTopology::Recursive => &[
                "Depth can spiral without proper termination",
                "Hard to predict total token cost",
                "Debugging deep call trees is complex",
            ],
            PatternTopology::Iterative => &[
                "Convergence not guaranteed",
                "Diminishing returns after initial cycles",
                "Only two agents active — limited perspectives",
            ],
        }
    }
}

// ── Detection keywords ───────────────────────────────────────────────────────

fn detection_keywords() -> HashMap<PatternTopology, Vec<&'static str>> {
    let mut map = HashMap::new();

    map.insert(
        PatternTopology::Hierarchical,
        vec![
            "coordinate",
            "lead",
            "delegate",
            "oracle",
            "workers",
            "manage",
            "oversee",
            "hub",
            "central",
            "supervise",
            "orchestrate",
            "dispatch",
        ],
    );
    map.insert(
        PatternTopology::Sequential,
        vec![
            "pipeline",
            "sequential",
            "stage",
            "phase",
            "step",
            "chain",
            "build_on",
            "progressive",
            "waterfall",
            "handoff",
            "one_by_one",
            "serial",
        ],
    );
    map.insert(
        PatternTopology::Adversarial,
        vec![
            "debate",
            "adversarial",
            "opposing",
            "challenge",
            "red_blue",
            "devil_advocate",
            "critique",
            "defend",
            "argue",
            "counter",
            "offense",
            "versus",
        ],
    );
    map.insert(
        PatternTopology::Peer,
        vec![
            "swarm",
            "consensus",
            "vote",
            "quorum",
            "crowd",
            "collective",
            "independent",
            "distributed",
            "ensemble",
            "converge",
            "agree",
            "majority",
        ],
    );
    map.insert(
        PatternTopology::FanOutMerge,
        vec![
            "map_reduce",
            "fan_out",
            "aggregate",
            "merge",
            "split",
            "parallel_process",
            "batch",
            "combine",
            "collect",
            "scatter",
            "chunk",
            "gather",
        ],
    );
    map.insert(
        PatternTopology::Recursive,
        vec![
            "recursive",
            "tree",
            "branch",
            "decompose",
            "sub_task",
            "nested",
            "divide_conquer",
            "spawn",
            "drill_down",
            "depth",
            "sub_problem",
            "hierarchy_deep",
        ],
    );
    map.insert(
        PatternTopology::Iterative,
        vec![
            "reflection",
            "iterate",
            "loop",
            "refine",
            "improve",
            "cycle",
            "feedback",
            "self_critique",
            "converge",
            "evolve",
            "polish",
            "revision",
        ],
    );

    map
}

// ── Topology detection ───────────────────────────────────────────────────────

/// Detect topology from description using keyword scoring.
/// Default fallback: Hierarchical.
pub fn detect_topology(description: &str) -> PatternTopology {
    let keywords = detection_keywords();
    let desc_lower = description.to_lowercase();

    // Tokenize: split on whitespace, punctuation, underscores, hyphens
    let tokens: Vec<&str> = desc_lower
        .split(|c: char| c.is_whitespace() || c == ',' || c == '.' || c == ';' || c == ':')
        .filter(|t| !t.is_empty())
        .collect();

    let mut best_topology = PatternTopology::Hierarchical;
    let mut best_score = 0usize;

    for topology in &ALL_TOPOLOGIES {
        if let Some(kws) = keywords.get(topology) {
            let score: usize = kws
                .iter()
                .filter(|kw| {
                    // Match keyword against tokens, handling both underscore and
                    // hyphen variants. Also check substring match in the full
                    // description for multi-word keywords.
                    let kw_lower = kw.to_lowercase();
                    let kw_variants: Vec<String> = vec![
                        kw_lower.clone(),
                        kw_lower.replace('_', " "),
                        kw_lower.replace('_', "-"),
                    ];
                    kw_variants.iter().any(|variant| {
                        tokens.iter().any(|t| t.contains(variant.as_str()))
                            || desc_lower.contains(variant.as_str())
                    })
                })
                .count();

            if score > best_score {
                best_score = score;
                best_topology = *topology;
            }
        }
    }

    best_topology
}

// ── Role slots per topology ──────────────────────────────────────────────────

fn roles_suggested_yaml(topology: PatternTopology) -> String {
    match topology {
        PatternTopology::Hierarchical => {
            "roles_suggested:\n  lead: agent_lead\n  workers: [agent_worker_1, agent_worker_2]"
                .to_string()
        }
        PatternTopology::Sequential => {
            "roles_suggested:\n  stage_1: agent_stage_1\n  stage_2: agent_stage_2\n  stage_3: agent_stage_3"
                .to_string()
        }
        PatternTopology::Adversarial => {
            "roles_suggested:\n  debater_a: agent_debater_a\n  debater_b: agent_debater_b\n  judge: agent_judge"
                .to_string()
        }
        PatternTopology::Peer => {
            "roles_suggested:\n  participants: [agent_participant_1, agent_participant_2, agent_participant_3]\n  synthesizer: agent_synthesizer"
                .to_string()
        }
        PatternTopology::FanOutMerge => {
            "roles_suggested:\n  coordinator: agent_coordinator\n  mappers: [agent_mapper_1, agent_mapper_2]\n  reducer: agent_reducer"
                .to_string()
        }
        PatternTopology::Recursive => {
            "roles_suggested:\n  root: agent_root\n  sub_agents: [agent_sub_1, agent_sub_2]\n  evaluator: agent_evaluator"
                .to_string()
        }
        PatternTopology::Iterative => {
            "roles_suggested:\n  worker: agent_worker\n  reviewer: agent_reviewer\n  evaluator: agent_evaluator".to_string()
        }
    }
}

// ── YAML generation ──────────────────────────────────────────────────────────

/// Generate complete pattern YAML string.
pub fn generate_pattern_yaml(
    id: &str,
    name: &str,
    description: &str,
    topology: PatternTopology,
) -> String {
    let when_to_use_lines: String = topology
        .when_to_use()
        .iter()
        .map(|s| format!("  - \"{}\"", s))
        .collect::<Vec<_>>()
        .join("\n");

    let when_not_to_use_lines: String = topology
        .when_not_to_use()
        .iter()
        .map(|s| format!("  - \"{}\"", s))
        .collect::<Vec<_>>()
        .join("\n");

    let pros_lines: String = topology
        .pros()
        .iter()
        .map(|s| format!("  - \"{}\"", s))
        .collect::<Vec<_>>()
        .join("\n");

    let cons_lines: String = topology
        .cons()
        .iter()
        .map(|s| format!("  - \"{}\"", s))
        .collect::<Vec<_>>()
        .join("\n");

    let roles = roles_suggested_yaml(topology);

    format!(
        r#"name: {name}
id: {id}
source: custom
description: "{description}"
topology: {topology}
communication: {communication}
when_to_use:
{when_to_use}
when_not_to_use:
{when_not_to_use}
pros:
{pros}
cons:
{cons}
estimated_token_cost: {token_cost}
estimated_agents: "{agents}"
{roles}
elo_lead_selection: {elo_lead}
"#,
        name = name,
        id = id,
        description = description.replace('"', "\\\""),
        topology = topology.as_str(),
        communication = topology.communication(),
        when_to_use = when_to_use_lines,
        when_not_to_use = when_not_to_use_lines,
        pros = pros_lines,
        cons = cons_lines,
        token_cost = topology.estimated_token_cost(),
        agents = topology.estimated_agents(),
        roles = roles,
        elo_lead = topology.elo_lead_selection(),
    )
}

// ── Pattern scaffold ─────────────────────────────────────────────────────────

/// Create a new pattern scaffold in the library.
/// Validates ID (same rules as role: 1-64 chars, alphanumeric/-/_).
/// Checks pattern doesn't already exist.
/// Creates patterns/ directory if needed.
/// Returns path to created YAML file.
pub fn scaffold_pattern(
    id: &str,
    description: &str,
    topology: Option<PatternTopology>,
    library_dir: &Path,
) -> Result<PathBuf> {
    // Validate pattern ID
    if id.is_empty() || id.len() > 64 {
        anyhow::bail!("Pattern ID must be 1-64 characters, got {}", id.len());
    }
    if !id
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        anyhow::bail!(
            "Pattern ID '{}' contains invalid characters — only alphanumeric, dash, underscore allowed",
            id
        );
    }

    // Reject path traversal attempts
    if id.contains("..") || id.contains('/') || id.contains('\\') {
        anyhow::bail!("Pattern ID '{}' contains path traversal characters", id);
    }

    let pattern_path = library_dir.join("patterns").join(format!("{}.yaml", id));

    if pattern_path.exists() {
        anyhow::bail!(
            "Pattern '{}' already exists at {}. Remove it first to recreate.",
            id,
            pattern_path.display()
        );
    }

    // Create patterns directory if it doesn't exist
    std::fs::create_dir_all(library_dir.join("patterns"))?;

    // Auto-detect topology if not provided
    let topo = topology.unwrap_or_else(|| detect_topology(description));

    // Generate human-readable name from ID
    let name = id.replace(['_', '-'], " ");

    let yaml = generate_pattern_yaml(id, &name, description, topo);
    std::fs::write(&pattern_path, yaml)?;

    Ok(pattern_path)
}

// ── Topology-Aware Role Mapping ──────────────────────────────────────────────

/// Semantic slot types for topology positions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SlotRoleType {
    Lead,      // Orchestrator, coordinator
    Offensive, // Active testing, implementation
    Defensive, // Review, validation, protection
    Research,  // Discovery, analysis
    Worker,    // General execution
    Judge,     // Final evaluation
}

impl SlotRoleType {
    /// Preferred role IDs for this slot type, in priority order.
    fn preferred_roles(&self) -> &'static [&'static str] {
        match self {
            SlotRoleType::Lead => &["security_architect", "architect"],
            SlotRoleType::Offensive => {
                &["pentester", "web_pentester", "api_pentester", "developer"]
            }
            SlotRoleType::Defensive => &["code_reviewer", "auditor", "security_architect"],
            SlotRoleType::Research => &["researcher", "architect"],
            SlotRoleType::Worker => &["developer", "tester"],
            SlotRoleType::Judge => &["auditor"],
        }
    }
}

/// A named slot in a topology with its semantic type.
#[derive(Debug, Clone)]
pub struct SlotDesc {
    pub name: String,
    pub slot_type: SlotRoleType,
}

/// Return the slot layout for a given topology.
fn topology_slots(topology: PatternTopology) -> Vec<SlotDesc> {
    match topology {
        PatternTopology::Hierarchical => vec![
            SlotDesc {
                name: "lead".into(),
                slot_type: SlotRoleType::Lead,
            },
            SlotDesc {
                name: "offensive".into(),
                slot_type: SlotRoleType::Offensive,
            },
            SlotDesc {
                name: "research".into(),
                slot_type: SlotRoleType::Research,
            },
        ],
        PatternTopology::Sequential => vec![
            SlotDesc {
                name: "stage_1".into(),
                slot_type: SlotRoleType::Research,
            },
            SlotDesc {
                name: "stage_2".into(),
                slot_type: SlotRoleType::Defensive,
            },
            SlotDesc {
                name: "stage_3".into(),
                slot_type: SlotRoleType::Offensive,
            },
        ],
        PatternTopology::Adversarial => vec![
            SlotDesc {
                name: "attacker".into(),
                slot_type: SlotRoleType::Offensive,
            },
            SlotDesc {
                name: "defender".into(),
                slot_type: SlotRoleType::Defensive,
            },
            SlotDesc {
                name: "judge".into(),
                slot_type: SlotRoleType::Judge,
            },
        ],
        PatternTopology::Peer => vec![
            SlotDesc {
                name: "participant_1".into(),
                slot_type: SlotRoleType::Offensive,
            },
            SlotDesc {
                name: "participant_2".into(),
                slot_type: SlotRoleType::Defensive,
            },
            SlotDesc {
                name: "participant_3".into(),
                slot_type: SlotRoleType::Research,
            },
            SlotDesc {
                name: "synthesizer".into(),
                slot_type: SlotRoleType::Lead,
            },
        ],
        PatternTopology::FanOutMerge => vec![
            SlotDesc {
                name: "coordinator".into(),
                slot_type: SlotRoleType::Lead,
            },
            SlotDesc {
                name: "mapper_1".into(),
                slot_type: SlotRoleType::Offensive,
            },
            SlotDesc {
                name: "mapper_2".into(),
                slot_type: SlotRoleType::Research,
            },
            SlotDesc {
                name: "reducer".into(),
                slot_type: SlotRoleType::Defensive,
            },
        ],
        PatternTopology::Recursive => vec![
            SlotDesc {
                name: "root".into(),
                slot_type: SlotRoleType::Lead,
            },
            SlotDesc {
                name: "sub_agent_1".into(),
                slot_type: SlotRoleType::Offensive,
            },
            SlotDesc {
                name: "sub_agent_2".into(),
                slot_type: SlotRoleType::Research,
            },
            SlotDesc {
                name: "evaluator".into(),
                slot_type: SlotRoleType::Judge,
            },
        ],
        PatternTopology::Iterative => vec![
            SlotDesc {
                name: "worker".into(),
                slot_type: SlotRoleType::Worker,
            },
            SlotDesc {
                name: "reviewer".into(),
                slot_type: SlotRoleType::Defensive,
            },
            SlotDesc {
                name: "evaluator".into(),
                slot_type: SlotRoleType::Judge,
            },
        ],
    }
}

/// Score a role against mission keywords based on specialization overlap.
fn mission_role_score(mission: &str, specializations: &[String]) -> usize {
    let mission_lower = mission.to_lowercase();
    let mission_words: Vec<&str> = mission_lower
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .filter(|w| w.len() > 2)
        .collect();

    specializations
        .iter()
        .filter(|spec| {
            let spec_lower = spec.to_lowercase();
            let spec_variants = [
                spec_lower.clone(),
                spec_lower.replace('_', " "),
                spec_lower.replace('_', "-"),
            ];
            spec_variants.iter().any(|variant| {
                mission_words.iter().any(|w| w.contains(variant.as_str()))
                    || mission_lower.contains(variant.as_str())
            })
        })
        .count()
}

/// Map real roles to topology slots based on slot type preferences and mission keywords.
///
/// Each role is assigned to at most one slot (no duplicates).
/// Tie-breaking: when multiple roles match a slot type, the one with higher
/// mission keyword overlap wins.
///
/// Returns `(slot_name, role_id)` pairs.
pub fn map_topology_roles(
    topology: PatternTopology,
    mission: &str,
    role_ids: &[String],
    role_specializations: &HashMap<String, Vec<String>>,
) -> Vec<(String, String)> {
    let slots = topology_slots(topology);
    let mut assigned: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut result = Vec::new();

    for slot in &slots {
        let preferred = slot.slot_type.preferred_roles();

        // Collect candidate roles: those in preferred list AND available (not yet assigned)
        let mut candidates: Vec<(&str, usize)> = preferred
            .iter()
            .filter(|&&pref| role_ids.contains(&pref.to_string()) && !assigned.contains(pref))
            .map(|&pref| {
                let score = role_specializations
                    .get(pref)
                    .map(|specs| mission_role_score(mission, specs))
                    .unwrap_or(0);
                (pref, score)
            })
            .collect();

        // Sort by mission keyword score (descending), then by preference order (implicit from iter order)
        candidates.sort_by(|a, b| b.1.cmp(&a.1));

        if let Some((role_id, _)) = candidates.first() {
            assigned.insert(role_id.to_string());
            result.push((slot.name.clone(), role_id.to_string()));
        } else {
            // Fallback: pick any unassigned role
            if let Some(fallback) = role_ids.iter().find(|r| !assigned.contains(r.as_str())) {
                assigned.insert(fallback.clone());
                result.push((slot.name.clone(), fallback.clone()));
            }
        }
    }

    result
}

// ── Pattern suggestion ───────────────────────────────────────────────────────

/// Suggestion for a new pattern based on mission analysis.
#[derive(Debug, Clone)]
pub struct PatternSuggestion {
    pub topology: PatternTopology,
    pub reasoning: String,
    pub suggested_id: String,
    pub create_command: String,
}

/// Suggest a pattern for a mission when no existing pattern matches.
/// Returns topology suggestion with reasoning and CLI command.
pub fn suggest_pattern_for_mission(mission: &str) -> PatternSuggestion {
    let topology = detect_topology(mission);

    // Generate suggested_id from first 3-4 mission words in kebab-case
    let suggested_id: String = mission
        .split_whitespace()
        .take(4)
        .map(|w| {
            w.chars()
                .filter(|c| c.is_alphanumeric() || *c == '-')
                .collect::<String>()
                .to_lowercase()
        })
        .filter(|w| !w.is_empty())
        .collect::<Vec<_>>()
        .join("-");

    // Cap to 64 chars
    let suggested_id = if suggested_id.len() > 64 {
        suggested_id[..64].to_string()
    } else if suggested_id.is_empty() {
        "custom-pattern".to_string()
    } else {
        suggested_id
    };

    let reasoning = format!(
        "Detected '{}' topology for this mission. Communication style: {}. \
         Estimated agents: {}. Token cost: {}. {}",
        topology.as_str(),
        topology.communication(),
        topology.estimated_agents(),
        topology.estimated_token_cost(),
        if topology.elo_lead_selection() {
            "ELO-based lead selection enabled."
        } else {
            "No ELO-based lead selection."
        }
    );

    let create_command = format!(
        "colmena library create-pattern --id {} --description \"{}\" --topology {}",
        suggested_id,
        mission.replace('"', "\\\""),
        topology.as_str()
    );

    PatternSuggestion {
        topology,
        reasoning,
        suggested_id,
        create_command,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_detect_topology_parallel() {
        let desc = "Split the input into chunks, fan out to mappers, then aggregate results";
        assert_eq!(detect_topology(desc), PatternTopology::FanOutMerge);
    }

    #[test]
    fn test_detect_topology_sequential() {
        let desc =
            "Run a pipeline with stage 1 recon, stage 2 testing, each phase builds on previous";
        assert_eq!(detect_topology(desc), PatternTopology::Sequential);
    }

    #[test]
    fn test_detect_topology_debate() {
        let desc = "Have two agents debate the issue from opposing sides with a judge to decide";
        assert_eq!(detect_topology(desc), PatternTopology::Adversarial);
    }

    #[test]
    fn test_detect_topology_default() {
        let desc = "Do something generic with no specific keywords";
        assert_eq!(detect_topology(desc), PatternTopology::Hierarchical);
    }

    #[test]
    fn test_scaffold_pattern_creates_valid_yaml() {
        let dir = tempfile::tempdir().expect("Failed to create temp dir");
        let library_dir = dir.path();

        let result = scaffold_pattern(
            "test-pattern",
            "A test pattern for validation",
            Some(PatternTopology::Sequential),
            library_dir,
        );

        assert!(
            result.is_ok(),
            "scaffold_pattern failed: {:?}",
            result.err()
        );
        let path = result.unwrap();
        assert!(path.exists(), "Pattern file was not created");

        // Verify the YAML is parseable
        let content = std::fs::read_to_string(&path).expect("Failed to read pattern file");
        let parsed: serde_yml::Value =
            serde_yml::from_str(&content).expect("Generated YAML is not valid");

        // Verify key fields
        assert_eq!(parsed["id"].as_str(), Some("test-pattern"));
        assert_eq!(parsed["topology"].as_str(), Some("sequential"));
        assert_eq!(parsed["communication"].as_str(), Some("chain"));
        assert_eq!(parsed["source"].as_str(), Some("custom"));
    }

    #[test]
    fn test_scaffold_pattern_rejects_existing() {
        let dir = tempfile::tempdir().expect("Failed to create temp dir");
        let library_dir = dir.path();

        // Create the first time — should succeed
        let result = scaffold_pattern(
            "my-pattern",
            "First creation",
            Some(PatternTopology::Hierarchical),
            library_dir,
        );
        assert!(result.is_ok());

        // Create the same ID again — should fail
        let result = scaffold_pattern(
            "my-pattern",
            "Second creation",
            Some(PatternTopology::Hierarchical),
            library_dir,
        );
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("already exists"),
            "Expected 'already exists' error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_scaffold_pattern_rejects_invalid_id() {
        let dir = tempfile::tempdir().expect("Failed to create temp dir");
        let library_dir = dir.path();

        // Empty ID
        let result = scaffold_pattern("", "desc", Some(PatternTopology::Hierarchical), library_dir);
        assert!(result.is_err());

        // Special characters
        let result = scaffold_pattern(
            "bad@id!",
            "desc",
            Some(PatternTopology::Hierarchical),
            library_dir,
        );
        assert!(result.is_err());

        // Path traversal
        let result = scaffold_pattern(
            "../escape",
            "desc",
            Some(PatternTopology::Hierarchical),
            library_dir,
        );
        assert!(result.is_err());

        // Too long (65 chars)
        let long_id: String = "a".repeat(65);
        let result = scaffold_pattern(
            &long_id,
            "desc",
            Some(PatternTopology::Hierarchical),
            library_dir,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_suggest_pattern_for_mission() {
        let suggestion = suggest_pattern_for_mission(
            "Run a pipeline to analyze API endpoints sequentially in phases",
        );

        assert_eq!(suggestion.topology, PatternTopology::Sequential);
        assert!(!suggestion.reasoning.is_empty());
        assert!(!suggestion.suggested_id.is_empty());
        assert!(suggestion.create_command.contains("create-pattern"));
        assert!(suggestion.create_command.contains("--id"));
        assert!(suggestion.create_command.contains("--topology"));
    }

    #[test]
    fn test_topology_display_and_from_str() {
        for topology in &ALL_TOPOLOGIES {
            let s = topology.to_string();
            let parsed: PatternTopology = s.parse().unwrap_or_else(|e| {
                panic!("Failed to parse '{}' back to PatternTopology: {}", s, e)
            });
            assert_eq!(
                *topology, parsed,
                "Roundtrip failed for {:?}: '{}' parsed as {:?}",
                topology, s, parsed
            );
        }
    }

    #[test]
    fn test_generate_pattern_yaml_has_required_fields() {
        let yaml_str = generate_pattern_yaml(
            "test-gen",
            "Test Generation",
            "A pattern for testing generation",
            PatternTopology::FanOutMerge,
        );

        let parsed: serde_yml::Value =
            serde_yml::from_str(&yaml_str).expect("Generated YAML is not valid");

        assert_eq!(parsed["topology"].as_str(), Some("fan-out-merge"));
        assert_eq!(parsed["communication"].as_str(), Some("map-reduce"));
        assert!(
            parsed["roles_suggested"].is_mapping(),
            "roles_suggested should be a mapping"
        );
        assert!(
            parsed["when_to_use"].is_sequence(),
            "when_to_use should be a sequence"
        );
        assert!(
            parsed["when_not_to_use"].is_sequence(),
            "when_not_to_use should be a sequence"
        );
        assert!(parsed["pros"].is_sequence(), "pros should be a sequence");
        assert!(parsed["cons"].is_sequence(), "cons should be a sequence");
        assert_eq!(
            parsed["elo_lead_selection"].as_bool(),
            Some(true),
            "FanOutMerge should have elo_lead_selection true"
        );
    }

    // ── map_topology_roles tests ────────────────────────────────────────────

    fn make_specs() -> HashMap<String, Vec<String>> {
        let mut m = HashMap::new();
        m.insert(
            "security_architect".into(),
            vec!["threat_modeling".into(), "architecture_review".into()],
        );
        m.insert(
            "pentester".into(),
            vec!["web_vulnerabilities".into(), "injection_attacks".into()],
        );
        m.insert("auditor".into(), vec!["compliance".into(), "audit".into()]);
        m.insert(
            "developer".into(),
            vec!["feature_implementation".into(), "refactoring".into()],
        );
        m.insert(
            "tester".into(),
            vec!["test_writing".into(), "coverage_analysis".into()],
        );
        m.insert(
            "architect".into(),
            vec!["system_design".into(), "tradeoff_analysis".into()],
        );
        m.insert(
            "code_reviewer".into(),
            vec!["code_review".into(), "bug_detection".into()],
        );
        m.insert(
            "researcher".into(),
            vec!["research".into(), "analysis".into()],
        );
        m
    }

    #[test]
    fn test_map_topology_roles_hierarchical() {
        let roles = vec![
            "security_architect".into(),
            "pentester".into(),
            "researcher".into(),
        ];
        let specs = make_specs();
        let result = map_topology_roles(
            PatternTopology::Hierarchical,
            "coordinate security audit with researchers",
            &roles,
            &specs,
        );
        assert_eq!(result.len(), 3);
        // Lead slot should get security_architect (preferred for Lead)
        assert_eq!(result[0].0, "lead");
        assert_eq!(result[0].1, "security_architect");
    }

    #[test]
    fn test_map_topology_roles_adversarial() {
        let roles = vec!["pentester".into(), "code_reviewer".into(), "auditor".into()];
        let specs = make_specs();
        let result = map_topology_roles(
            PatternTopology::Adversarial,
            "debate security findings with opposing perspectives",
            &roles,
            &specs,
        );
        assert_eq!(result.len(), 3);
        // Attacker = Offensive → pentester, Defender = Defensive → code_reviewer, Judge → auditor
        assert_eq!(result[0].0, "attacker");
        assert_eq!(result[0].1, "pentester");
        assert_eq!(result[2].0, "judge");
        assert_eq!(result[2].1, "auditor");
    }

    #[test]
    fn test_map_topology_roles_iterative() {
        let roles = vec!["developer".into(), "code_reviewer".into(), "auditor".into()];
        let specs = make_specs();
        let result = map_topology_roles(
            PatternTopology::Iterative,
            "implement feature with review cycle",
            &roles,
            &specs,
        );
        assert_eq!(result.len(), 3);
        // Worker → developer, Reviewer (Defensive) → code_reviewer, Evaluator (Judge) → auditor
        assert_eq!(result[0].0, "worker");
        assert_eq!(result[0].1, "developer");
        assert_eq!(result[1].0, "reviewer");
        assert_eq!(result[1].1, "code_reviewer");
        assert_eq!(result[2].0, "evaluator");
        assert_eq!(result[2].1, "auditor");
    }

    #[test]
    fn test_map_topology_roles_no_duplicates() {
        let roles = vec![
            "security_architect".into(),
            "architect".into(),
            "auditor".into(),
        ];
        let specs = make_specs();
        let result = map_topology_roles(
            PatternTopology::Hierarchical,
            "review system architecture",
            &roles,
            &specs,
        );
        // Ensure no role appears twice
        let assigned: Vec<&str> = result.iter().map(|(_, r)| r.as_str()).collect();
        let unique: std::collections::HashSet<&str> = assigned.iter().copied().collect();
        assert_eq!(
            assigned.len(),
            unique.len(),
            "Duplicate role assignments found: {:?}",
            assigned
        );
    }

    #[test]
    fn test_map_topology_roles_empty_library() {
        let roles: Vec<String> = vec![];
        let specs = HashMap::new();
        let result = map_topology_roles(PatternTopology::Iterative, "some mission", &roles, &specs);
        // No roles available — all slots empty
        assert!(
            result.is_empty(),
            "Should produce no assignments with empty library"
        );
    }

    #[test]
    fn test_map_topology_roles_mission_keyword_scoring() {
        // Both architect and security_architect match Lead, but "system design tradeoff"
        // should score architect higher due to specialization overlap
        let roles = vec![
            "architect".into(),
            "security_architect".into(),
            "developer".into(),
        ];
        let specs = make_specs();
        let result = map_topology_roles(
            PatternTopology::Hierarchical,
            "system design tradeoff analysis for new module",
            &roles,
            &specs,
        );
        // Lead slot: architect should win due to "system_design" + "tradeoff_analysis" overlap
        assert_eq!(result[0].0, "lead");
        assert_eq!(result[0].1, "architect");
    }
}
