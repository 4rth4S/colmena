use rmcp::{
    ServerHandler, ServiceExt,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{Implementation, ServerCapabilities, ServerInfo},
    schemars, tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Input types — each tool gets its own params struct
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, JsonSchema)]
struct ConfigCheckInput {
    /// Optional path to the trust-firewall.yaml config file (uses default if omitted)
    config_path: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct QueueListInput {}

#[derive(Debug, Deserialize, JsonSchema)]
struct DelegateInput {
    /// Tool name to auto-approve (e.g. "Bash", "WebFetch")
    tool: String,
    /// Optional agent ID — limits the delegation to one agent
    agent: Option<String>,
    /// TTL in hours (default: 4, max: 24)
    #[serde(default = "default_ttl")]
    ttl: i64,
}

fn default_ttl() -> i64 {
    4
}

#[derive(Debug, Deserialize, JsonSchema)]
struct DelegateListInput {}

#[derive(Debug, Deserialize, JsonSchema)]
struct DelegateRevokeInput {
    /// Tool name to revoke
    tool: String,
    /// Optional agent ID — only revoke delegation for this agent
    agent: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct EvaluateInput {
    /// Tool name being evaluated (e.g. "Bash")
    tool_name: String,
    /// Tool input payload as a JSON value
    tool_input: serde_json::Value,
    /// Working directory for ${PROJECT_DIR} resolution
    cwd: String,
    /// Optional agent ID for per-agent rule lookup
    agent_id: Option<String>,
}

// ── Peer Review + ELO + Findings input types ─────────────────────────────────

#[derive(Debug, Deserialize, JsonSchema)]
struct ReviewSubmitInput {
    /// Path to the artifact file to submit for review
    artifact_path: String,
    /// Author's role ID (e.g., "pentester")
    author_role: String,
    /// Mission ID this review belongs to
    mission: String,
    /// Available reviewer roles in this mission
    available_roles: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ReviewListInput {
    /// Optional state filter: "pending", "completed", "needs_human_review"
    state: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct ReviewEvaluateInput {
    /// Review ID to evaluate
    review_id: String,
    /// Reviewer's role ID
    reviewer_role: String,
    /// Scores per dimension (e.g., {"accuracy": 8, "completeness": 7})
    scores: std::collections::HashMap<String, u32>,
    /// Findings from the review
    findings: Vec<FindingInput>,
    /// Path to the artifact being reviewed (for hash verification)
    artifact_path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct FindingInput {
    /// Finding category (e.g., "completeness", "accuracy", "security_gap")
    category: String,
    /// Severity: "critical", "high", "medium", "low"
    severity: String,
    /// Description of what was found
    description: String,
    /// Recommendation for improvement
    recommendation: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct EloRatingsInput {}

#[derive(Debug, Deserialize, JsonSchema)]
struct FindingsQueryInput {
    /// Filter by author role
    author_role: Option<String>,
    /// Filter by reviewer role
    reviewer_role: Option<String>,
    /// Filter by finding severity
    severity: Option<String>,
    /// Filter by finding category
    category: Option<String>,
    /// Filter by mission ID
    mission: Option<String>,
    /// Only findings after this date (ISO 8601)
    after: Option<String>,
    /// Only findings before this date (ISO 8601)
    before: Option<String>,
    /// Maximum number of results (default: 20)
    limit: Option<usize>,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct FindingsListInput {
    /// Maximum number of results (default: 20)
    limit: Option<usize>,
}

// ── Wisdom Library input types ────────────────────────────────────────────────

#[derive(Debug, Deserialize, JsonSchema)]
struct LibraryListInput {}

#[derive(Debug, Deserialize, JsonSchema)]
struct LibraryShowInput {
    /// Role or pattern ID (e.g., "pentester", "oracle-workers")
    id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct LibrarySelectInput {
    /// Mission description (e.g., "audit PCI-DSS compliance of payments API")
    mission: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct LibraryGenerateInput {
    /// Mission description
    mission: String,
    /// Pattern ID to use (from library_select results)
    pattern_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct LibraryCreateRoleInput {
    /// Role ID (e.g., "cloud-security")
    id: String,
    /// Role description
    description: String,
}

// ── Mission + Calibration input types ────────────────────────────────────────

#[derive(Debug, Deserialize, JsonSchema)]
struct MissionDeactivateInput {
    /// Mission ID (slug from mission directory name, e.g. "2026-04-01-audit-payments")
    mission_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
struct CalibrateInput {}

#[derive(Debug, Deserialize, JsonSchema)]
struct SessionStatsInput {
    /// Session ID to show stats for (uses current session if available)
    session_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Server struct
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct ColmenaServer {
    config_dir: std::path::PathBuf,
    tool_router: ToolRouter<Self>,
}

impl ColmenaServer {
    fn new(config_dir: std::path::PathBuf) -> Self {
        Self {
            config_dir,
            tool_router: Self::tool_router(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

#[tool_router]
impl ColmenaServer {
    #[rmcp::tool(description = "Validate the Colmena trust firewall configuration")]
    fn config_check(
        &self,
        Parameters(input): Parameters<ConfigCheckInput>,
    ) -> Result<String, String> {
        let config_path = input
            .config_path
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| self.config_dir.join("trust-firewall.yaml"));

        let cfg = colmena_core::config::load_config(&config_path, "/tmp")
            .map_err(|e| format!("Config load failed: {e}"))?;

        match colmena_core::config::compile_config(&cfg) {
            Ok(_) => {
                let warnings = colmena_core::config::validate_tool_names(&cfg);
                let mut result = format!(
                    "Config valid.\nVersion: {}\nTrust circle: {} rules\nRestricted: {} rules\nBlocked: {} rules",
                    cfg.version,
                    cfg.trust_circle.len(),
                    cfg.restricted.len(),
                    cfg.blocked.len()
                );
                for w in &warnings {
                    result.push_str(&format!("\nWARNING: {w}"));
                }
                Ok(result)
            }
            Err(e) => Err(format!("Config invalid: {e}")),
        }
    }

    #[rmcp::tool(description = "List pending approval items in the Colmena queue")]
    fn queue_list(&self, Parameters(_input): Parameters<QueueListInput>) -> Result<String, String> {
        let entries = colmena_core::queue::list_pending(&self.config_dir)
            .map_err(|e| format!("Queue read failed: {e}"))?;

        if entries.is_empty() {
            return Ok("No pending approvals.".to_string());
        }

        serde_json::to_string_pretty(&entries).map_err(|e| format!("Serialize failed: {e}"))
    }

    #[rmcp::tool(
        description = "Request a runtime trust delegation — returns CLI command for human confirmation (MCP cannot create delegations directly)"
    )]
    fn delegate(&self, Parameters(input): Parameters<DelegateInput>) -> Result<String, String> {
        // Fix 1 (DREAD 9.4): MCP delegate is read-only — returns instructions, never executes.
        // Human must run the CLI command to actually create the delegation.
        let ttl = input.ttl.clamp(1, colmena_core::delegate::MAX_TTL_HOURS);
        let scope = input.agent.as_deref().unwrap_or("all agents");

        let mut cmd = format!("colmena delegate add --tool {} --ttl {}", input.tool, ttl);
        if let Some(ref agent) = input.agent {
            cmd.push_str(&format!(" --agent {}", agent));
        }

        Ok(format!(
            "Delegation requested: auto-approve '{}' for {} ({}h TTL).\n\n\
             To confirm, run this command in the terminal:\n\n  {}\n\n\
             MCP tools cannot create delegations directly — human confirmation required.",
            input.tool, scope, ttl, cmd
        ))
    }

    #[rmcp::tool(description = "List active runtime trust delegations")]
    fn delegate_list(
        &self,
        Parameters(_input): Parameters<DelegateListInput>,
    ) -> Result<String, String> {
        let delegations_path = self.config_dir.join("runtime-delegations.json");
        let delegations = colmena_core::delegate::list_delegations(&delegations_path);

        if delegations.is_empty() {
            return Ok("No active delegations.".to_string());
        }

        let mut output = format!("{} active delegation(s):\n", delegations.len());
        for d in &delegations {
            let agent = d.agent_id.as_deref().unwrap_or("*");
            let ttl = match d.expires_at {
                Some(exp) => {
                    let remaining = exp - chrono::Utc::now();
                    if remaining.num_minutes() > 60 {
                        format!("{}h remaining", remaining.num_hours())
                    } else {
                        format!("{}m remaining", remaining.num_minutes())
                    }
                }
                None => "no expiry".to_string(),
            };
            output.push_str(&format!("  {} → agent={} ({})\n", d.tool, agent, ttl));
        }

        Ok(output)
    }

    #[rmcp::tool(
        description = "Request revocation of a delegation — returns CLI command for human confirmation"
    )]
    fn delegate_revoke(
        &self,
        Parameters(input): Parameters<DelegateRevokeInput>,
    ) -> Result<String, String> {
        // Read-only: returns CLI command for human to execute
        let mut cmd = format!("colmena delegate revoke --tool {}", input.tool);
        if let Some(ref agent) = input.agent {
            cmd.push_str(&format!(" --agent {}", agent));
        }

        Ok(format!(
            "Revocation requested for '{}'.\n\n\
             To confirm, run this command in the terminal:\n\n  {}\n\n\
             MCP tools cannot revoke delegations directly — human confirmation required.",
            input.tool, cmd
        ))
    }

    #[rmcp::tool(description = "Evaluate a tool call against the Colmena trust firewall rules")]
    fn evaluate(&self, Parameters(input): Parameters<EvaluateInput>) -> Result<String, String> {
        let config_path = self.config_dir.join("trust-firewall.yaml");
        let cfg = colmena_core::config::load_config(&config_path, &input.cwd)
            .map_err(|e| format!("Config load failed: {e}"))?;
        let patterns = colmena_core::config::compile_config(&cfg)
            .map_err(|e| format!("Config compile failed: {e}"))?;

        let delegations_path = self.config_dir.join("runtime-delegations.json");
        let delegations = colmena_core::delegate::load_delegations(&delegations_path);

        // Fix 13 (DREAD 7.0): unique IDs per MCP evaluate call
        let ts = chrono::Utc::now().timestamp_millis();
        let eval_input = colmena_core::models::EvaluationInput {
            session_id: format!("mcp-{}", ts),
            tool_name: input.tool_name.clone(),
            tool_input: input.tool_input.clone(),
            tool_use_id: format!("mcp-eval-{}", ts),
            agent_id: input.agent_id.clone(),
            cwd: input.cwd.clone(),
        };

        let decision =
            colmena_core::firewall::evaluate(&cfg, &patterns, &delegations, &eval_input);

        let result = serde_json::json!({
            "action": format!("{:?}", decision.action),
            "reason": decision.reason,
            "matched_rule": decision.matched_rule,
        });

        serde_json::to_string_pretty(&result).map_err(|e| format!("Serialize failed: {e}"))
    }

    #[rmcp::tool(description = "List all roles and patterns in the Colmena Wisdom Library")]
    fn library_list(
        &self,
        Parameters(_input): Parameters<LibraryListInput>,
    ) -> Result<String, String> {
        let library_dir = self.config_dir.join("library");

        let roles = colmena_core::library::load_roles(&library_dir)
            .map_err(|e| format!("Failed to load roles: {e}"))?;
        let patterns = colmena_core::library::load_patterns(&library_dir)
            .map_err(|e| format!("Failed to load patterns: {e}"))?;

        let mut output = String::new();

        output.push_str(&format!("Roles ({}):\n", roles.len()));
        for role in &roles {
            output.push_str(&format!(
                "  {} {} — {}\n",
                role.icon, role.id, role.name
            ));
        }

        output.push('\n');
        output.push_str(&format!("Patterns ({}):\n", patterns.len()));
        for pattern in &patterns {
            output.push_str(&format!(
                "  {} — {} [{}]\n",
                pattern.id, pattern.name, pattern.topology
            ));
        }

        Ok(output)
    }

    #[rmcp::tool(description = "Show details for a role or pattern in the Colmena Wisdom Library")]
    fn library_show(
        &self,
        Parameters(input): Parameters<LibraryShowInput>,
    ) -> Result<String, String> {
        let library_dir = self.config_dir.join("library");

        let roles = colmena_core::library::load_roles(&library_dir)
            .map_err(|e| format!("Failed to load roles: {e}"))?;
        let patterns = colmena_core::library::load_patterns(&library_dir)
            .map_err(|e| format!("Failed to load patterns: {e}"))?;

        // Search roles first
        if let Some(role) = roles.iter().find(|r| r.id == input.id) {
            let output = format!(
                "Role: {} {}\nID: {}\nDescription: {}\nTrust level: {}\nTools: {}\nSpecializations: {}\nELO initial: {}\nCan mentor: {}\nMentored by: {}\n",
                role.icon,
                role.name,
                role.id,
                role.description,
                role.default_trust_level,
                role.tools_allowed.join(", "),
                role.specializations.join(", "),
                role.elo.initial,
                role.mentoring.can_mentor.join(", "),
                role.mentoring.mentored_by.join(", "),
            );
            return Ok(output);
        }

        // Search patterns
        if let Some(pattern) = patterns.iter().find(|p| p.id == input.id) {
            let roles_str: Vec<String> = pattern
                .roles_suggested
                .0
                .iter()
                .map(|(slot, role_slot)| format!("{}: {}", slot, role_slot.as_vec().join(", ")))
                .collect();

            let output = format!(
                "Pattern: {}\nID: {}\nTopology: {}\nCommunication: {}\nDescription: {}\nEstimated agents: {}\nToken cost: {}\nWhen to use:\n{}\nRoles suggested:\n{}\n",
                pattern.name,
                pattern.id,
                pattern.topology,
                pattern.communication,
                pattern.description,
                pattern.estimated_agents,
                pattern.estimated_token_cost,
                pattern.when_to_use.iter().map(|w| format!("  - {w}")).collect::<Vec<_>>().join("\n"),
                roles_str.iter().map(|r| format!("  {r}")).collect::<Vec<_>>().join("\n"),
            );
            return Ok(output);
        }

        Err(format!("No role or pattern found with id '{}'", input.id))
    }

    #[rmcp::tool(description = "Select patterns from the Wisdom Library for a given mission")]
    fn library_select(
        &self,
        Parameters(input): Parameters<LibrarySelectInput>,
    ) -> Result<String, String> {
        let library_dir = self.config_dir.join("library");

        let roles = colmena_core::library::load_roles(&library_dir)
            .map_err(|e| format!("Failed to load roles: {e}"))?;
        let patterns = colmena_core::library::load_patterns(&library_dir)
            .map_err(|e| format!("Failed to load patterns: {e}"))?;

        let recommendations =
            colmena_core::selector::select_patterns(&input.mission, &patterns, &roles);

        let mut output = colmena_core::selector::format_recommendations(&recommendations);

        // Append role gap warnings
        let gaps = colmena_core::selector::detect_role_gaps(&input.mission, &roles);
        if !gaps.is_empty() {
            output.push_str("\nRole gap warnings:\n");
            for gap in &gaps {
                output.push_str(&format!("  WARNING: No role covers domain keyword '{}'\n", gap));
            }
        }

        Ok(output)
    }

    #[rmcp::tool(
        description = "Generate a mission directory from a pattern — creates CLAUDE.md per agent"
    )]
    fn library_generate(
        &self,
        Parameters(input): Parameters<LibraryGenerateInput>,
    ) -> Result<String, String> {
        let library_dir = self.config_dir.join("library");
        let missions_dir = self.config_dir.join("missions");

        let roles = colmena_core::library::load_roles(&library_dir)
            .map_err(|e| format!("Failed to load roles: {e}"))?;
        let patterns = colmena_core::library::load_patterns(&library_dir)
            .map_err(|e| format!("Failed to load patterns: {e}"))?;

        // Find the requested pattern
        let pattern = patterns
            .iter()
            .find(|p| p.id == input.pattern_id)
            .ok_or_else(|| format!("Pattern '{}' not found in library", input.pattern_id))?;

        // Build a Recommendation from the pattern directly (no scoring needed — user specified it)
        let role_map: std::collections::HashMap<&str, &colmena_core::library::Role> =
            roles.iter().map(|r| (r.id.as_str(), r)).collect();

        let role_assignments: Vec<colmena_core::selector::RoleAssignment> = pattern
            .roles_suggested
            .0
            .iter()
            .flat_map(|(slot, role_slot)| {
                role_slot.as_vec().into_iter().map(|role_id| {
                    let (name, icon) = role_map
                        .get(role_id.as_str())
                        .map(|r| (r.name.clone(), r.icon.clone()))
                        .unwrap_or_else(|| (role_id.clone(), "?".to_string()));
                    colmena_core::selector::RoleAssignment {
                        slot: slot.clone(),
                        role_id,
                        role_name: name,
                        icon,
                    }
                })
            })
            .collect();

        let recommendation = colmena_core::selector::Recommendation {
            pattern_id: pattern.id.clone(),
            pattern_name: pattern.name.clone(),
            score: 0.0,
            matched_criteria: vec![],
            anti_matched: vec![],
            role_assignments,
        };

        let mission_config = colmena_core::selector::generate_mission(
            &input.mission,
            &recommendation,
            &roles,
            &library_dir,
            &missions_dir,
            None, // session_id: MCP context doesn't have session binding
        )
        .map_err(|e| format!("Mission generation failed: {e}"))?;

        let mut output = format!(
            "Mission generated: {}\n\nFiles created:\n  {}\n",
            mission_config.mission_dir.display(),
            mission_config.mission_dir.join("mission.yaml").display(),
        );
        for agent in &mission_config.agent_configs {
            output.push_str(&format!(
                "  {} — {}\n",
                agent.role_id,
                agent.claude_md_path.display()
            ));
        }

        // Generate CLI commands for delegations (read-only: never persist from MCP)
        if !mission_config.delegations.is_empty() {
            output.push_str("\n\n## Delegations (require human confirmation)\n\nRun the following commands to activate mission delegations:\n\n```\n");
            for d in &mission_config.delegations {
                let hours = d
                    .expires_at
                    .map(|exp| {
                        let dur = exp - d.created_at;
                        let h = dur.num_hours();
                        if h < 1 { 1 } else { h }
                    })
                    .unwrap_or(colmena_core::selector::DEFAULT_MISSION_TTL_HOURS);

                let mut cmd = format!("colmena delegate add --tool {}", d.tool);
                if let Some(ref agent) = d.agent_id {
                    cmd.push_str(&format!(" --agent {}", agent));
                }
                cmd.push_str(&format!(" --ttl {}", hours));
                if let Some(ref conds) = d.conditions {
                    if let Some(ref bp) = conds.bash_pattern {
                        cmd.push_str(&format!(" --bash-pattern \"{}\"", bp));
                    }
                }
                output.push_str(&format!("{}\n", cmd));
            }
            output.push_str("```");
        }

        Ok(output)
    }

    #[rmcp::tool(description = "Create a new role scaffold in the Colmena Wisdom Library")]
    fn library_create_role(
        &self,
        Parameters(input): Parameters<LibraryCreateRoleInput>,
    ) -> Result<String, String> {
        let library_dir = self.config_dir.join("library");

        let (role_path, prompt_path) =
            colmena_core::selector::scaffold_role(&input.id, &input.description, &library_dir)
                .map_err(|e| format!("Scaffold failed: {e}"))?;

        Ok(format!(
            "Role '{}' scaffolded.\n\nFiles created:\n  {}\n  {}\n",
            input.id,
            role_path.display(),
            prompt_path.display(),
        ))
    }

    // ── Peer Review tools ────────────────────────────────────────────────────

    #[rmcp::tool(
        description = "Submit an artifact for peer review — assigns a reviewer and creates a pending review"
    )]
    fn review_submit(
        &self,
        Parameters(input): Parameters<ReviewSubmitInput>,
    ) -> Result<String, String> {
        let review_dir = self.config_dir.join("reviews");
        let artifact_path = std::path::PathBuf::from(&input.artifact_path);

        // Load existing reviews to enforce anti-reciprocal invariant
        let existing = colmena_core::review::list_reviews(&review_dir, None)
            .map_err(|e| format!("Error: {e}"))?;
        let existing_pairs: Vec<(String, String)> = existing
            .iter()
            .map(|r| (r.reviewer_role.clone(), r.author_role.clone()))
            .collect();

        let entry = colmena_core::review::submit_review(
            &review_dir,
            &artifact_path,
            &input.author_role,
            &input.mission,
            &input.available_roles,
            &existing_pairs,
        )
        .map_err(|e| format!("Error: {e}"))?;

        // Audit log (best-effort)
        let audit_log = self.config_dir.join("audit.log");
        let _ = colmena_core::audit::log_event(
            &audit_log,
            &colmena_core::audit::AuditEvent::ReviewSubmit {
                review_id: &entry.review_id,
                author_role: &entry.author_role,
                artifact_path: &input.artifact_path,
                mission: &entry.mission,
            },
        );

        Ok(format!(
            "Review created:\n  review_id: {}\n  author: {}\n  reviewer: {}\n  hash: {}\n  state: pending",
            entry.review_id, entry.author_role, entry.reviewer_role, entry.artifact_hash
        ))
    }

    #[rmcp::tool(description = "List peer reviews — pending, completed, or all")]
    fn review_list(
        &self,
        Parameters(input): Parameters<ReviewListInput>,
    ) -> Result<String, String> {
        let review_dir = self.config_dir.join("reviews");

        let state_filter = match input.state.as_deref() {
            Some("pending") => Some(colmena_core::review::ReviewState::Pending),
            Some("completed") => Some(colmena_core::review::ReviewState::Completed),
            Some("evaluated") => Some(colmena_core::review::ReviewState::Evaluated),
            Some("needs_human_review") => {
                Some(colmena_core::review::ReviewState::NeedsHumanReview)
            }
            Some("rejected") => Some(colmena_core::review::ReviewState::Rejected),
            Some(other) => return Err(format!("Unknown state filter: '{other}'")),
            None => None,
        };

        let entries = colmena_core::review::list_reviews(&review_dir, state_filter)
            .map_err(|e| format!("Error: {e}"))?;

        if entries.is_empty() {
            return Ok("No reviews found.".to_string());
        }

        serde_json::to_string_pretty(&entries).map_err(|e| format!("Error: {e}"))
    }

    #[rmcp::tool(
        description = "Evaluate a peer review — submit scores and findings as a reviewer"
    )]
    fn review_evaluate(
        &self,
        Parameters(input): Parameters<ReviewEvaluateInput>,
    ) -> Result<String, String> {
        let review_dir = self.config_dir.join("reviews");
        let artifact_path = std::path::PathBuf::from(&input.artifact_path);

        // Validate severity values before processing
        for f in &input.findings {
            colmena_core::findings::validate_severity(&f.severity)
                .map_err(|e| e.to_string())?;
        }

        // Convert FindingInput → colmena_core::findings::Finding
        let findings: Vec<colmena_core::findings::Finding> = input
            .findings
            .iter()
            .map(|f| colmena_core::findings::Finding {
                category: f.category.clone(),
                severity: f.severity.clone(),
                description: f.description.clone(),
                recommendation: f.recommendation.clone(),
            })
            .collect();

        let entry = colmena_core::review::evaluate_review(
            &review_dir,
            &input.review_id,
            &input.reviewer_role,
            input.scores.clone(),
            findings.clone(),
            &artifact_path,
        )
        .map_err(|e| format!("Error: {e}"))?;

        let score_avg = entry.score_average.unwrap_or(0.0);

        // Trust gate decision
        let gate = colmena_core::review::trust_gate(score_avg, &findings);
        let outcome = match gate {
            colmena_core::review::TrustGateResult::AutoComplete => "auto_complete",
            colmena_core::review::TrustGateResult::NeedsHumanReview => "needs_human_review",
        };

        // ELO updates
        let elo_log = self.config_dir.join("elo/elo-log.jsonl");
        let mut elo_updates = 0u32;

        // Author delta from score average
        let author_d = colmena_core::elo::author_delta(score_avg);
        if author_d != 0 {
            let _ = colmena_core::elo::log_elo_event(
                &elo_log,
                &colmena_core::elo::EloEvent {
                    agent: entry.author_role.clone(),
                    event_type: colmena_core::elo::EloEventType::Reviewed,
                    delta: author_d,
                    reason: format!("review score avg {score_avg:.1}"),
                    mission: entry.mission.clone(),
                    review_id: entry.review_id.clone(),
                },
            );
            elo_updates += 1;
        }

        // Per-finding ELO events
        for finding in &findings {
            let finding_d = colmena_core::elo::finding_delta_author(&finding.severity);
            if finding_d != 0 {
                let _ = colmena_core::elo::log_elo_event(
                    &elo_log,
                    &colmena_core::elo::EloEvent {
                        agent: entry.author_role.clone(),
                        event_type: colmena_core::elo::EloEventType::FindingAgainst,
                        delta: finding_d,
                        reason: format!(
                            "{} {} finding",
                            finding.severity, finding.category
                        ),
                        mission: entry.mission.clone(),
                        review_id: entry.review_id.clone(),
                    },
                );
                elo_updates += 1;
            }

            // Reviewer gets positive delta for each finding
            let _ = colmena_core::elo::log_elo_event(
                &elo_log,
                &colmena_core::elo::EloEvent {
                    agent: entry.reviewer_role.clone(),
                    event_type: colmena_core::elo::EloEventType::ReviewQuality,
                    delta: colmena_core::elo::REVIEWER_FINDING_DELTA,
                    reason: format!(
                        "found {} {} issue",
                        finding.severity, finding.category
                    ),
                    mission: entry.mission.clone(),
                    review_id: entry.review_id.clone(),
                },
            );
            elo_updates += 1;
        }

        // Save finding record
        let findings_dir = self.config_dir.join("findings");
        let finding_record = colmena_core::findings::FindingRecord {
            review_id: entry.review_id.clone(),
            mission: entry.mission.clone(),
            author_role: entry.author_role.clone(),
            reviewer_role: entry.reviewer_role.clone(),
            artifact_path: input.artifact_path.clone(),
            artifact_hash: entry.artifact_hash.clone(),
            timestamp: chrono::Utc::now(),
            scores: input.scores,
            score_average: score_avg,
            findings,
        };
        let _ = colmena_core::findings::save_finding_record(&findings_dir, &finding_record);

        // Audit log (best-effort)
        let audit_log = self.config_dir.join("audit.log");
        let finding_count = entry.finding_count.unwrap_or(0);
        let _ = colmena_core::audit::log_event(
            &audit_log,
            &colmena_core::audit::AuditEvent::ReviewEvaluate {
                review_id: &entry.review_id,
                reviewer_role: &entry.reviewer_role,
                score_avg,
                finding_count,
            },
        );
        let _ = colmena_core::audit::log_event(
            &audit_log,
            &colmena_core::audit::AuditEvent::ReviewCompleted {
                review_id: &entry.review_id,
                outcome,
            },
        );

        Ok(format!(
            "Review evaluated:\n  review_id: {}\n  score: {:.1}\n  findings: {}\n  outcome: {}\n  ELO events logged: {}",
            entry.review_id, score_avg, finding_count, outcome, elo_updates
        ))
    }

    // ── ELO tools ────────────────────────────────────────────────────────────

    #[rmcp::tool(description = "View ELO ratings leaderboard with temporal decay applied")]
    fn elo_ratings(
        &self,
        Parameters(_input): Parameters<EloRatingsInput>,
    ) -> Result<String, String> {
        let elo_log = self.config_dir.join("elo/elo-log.jsonl");
        let events =
            colmena_core::elo::read_elo_log(&elo_log).map_err(|e| format!("Error: {e}"))?;

        // Load roles for baseline ELO values
        let library_dir = self.config_dir.join("library");
        let baselines: Vec<(String, u32)> =
            if let Ok(roles) = colmena_core::library::load_roles(&library_dir) {
                roles.iter().map(|r| (r.id.clone(), r.elo.initial)).collect()
            } else {
                Vec::new()
            };

        let board = colmena_core::elo::leaderboard(&events, &baselines);

        if board.is_empty() {
            return Ok("No ELO ratings yet.".to_string());
        }

        // Build a JSON-serializable representation
        let entries: Vec<serde_json::Value> = board
            .iter()
            .map(|r| {
                serde_json::json!({
                    "agent": r.agent,
                    "elo": r.elo,
                    "trend_7d": r.trend_7d,
                    "review_count": r.review_count,
                    "last_active": r.last_active.map(|t| t.to_rfc3339()),
                })
            })
            .collect();

        serde_json::to_string_pretty(&entries).map_err(|e| format!("Error: {e}"))
    }

    // ── Findings tools ───────────────────────────────────────────────────────

    #[rmcp::tool(
        description = "Query findings store — search by role, category, severity, date, mission"
    )]
    fn findings_query(
        &self,
        Parameters(input): Parameters<FindingsQueryInput>,
    ) -> Result<String, String> {
        let findings_dir = self.config_dir.join("findings");

        let after = input
            .after
            .as_deref()
            .map(|s| {
                chrono::DateTime::parse_from_rfc3339(s)
                    .map(|dt| dt.with_timezone(&chrono::Utc))
                    .map_err(|e| format!("Invalid 'after' date: {e}"))
            })
            .transpose()?;

        let before = input
            .before
            .as_deref()
            .map(|s| {
                chrono::DateTime::parse_from_rfc3339(s)
                    .map(|dt| dt.with_timezone(&chrono::Utc))
                    .map_err(|e| format!("Invalid 'before' date: {e}"))
            })
            .transpose()?;

        let filter = colmena_core::findings::FindingsFilter {
            author_role: input.author_role,
            reviewer_role: input.reviewer_role,
            severity: input.severity,
            category: input.category,
            mission: input.mission,
            after,
            before,
            limit: Some(input.limit.unwrap_or(20)),
        };

        let records = colmena_core::findings::load_findings(&findings_dir, &filter)
            .map_err(|e| format!("Error: {e}"))?;

        if records.is_empty() {
            return Ok("No findings match the query.".to_string());
        }

        serde_json::to_string_pretty(&records).map_err(|e| format!("Error: {e}"))
    }

    #[rmcp::tool(description = "List recent findings from the findings store")]
    fn findings_list(
        &self,
        Parameters(input): Parameters<FindingsListInput>,
    ) -> Result<String, String> {
        let findings_dir = self.config_dir.join("findings");

        let filter = colmena_core::findings::FindingsFilter {
            limit: Some(input.limit.unwrap_or(20)),
            ..Default::default()
        };

        let records = colmena_core::findings::load_findings(&findings_dir, &filter)
            .map_err(|e| format!("Error: {e}"))?;

        if records.is_empty() {
            return Ok("No findings yet.".to_string());
        }

        serde_json::to_string_pretty(&records).map_err(|e| format!("Error: {e}"))
    }

    // ── Mission management ───────────────────────────────────────────────────

    #[rmcp::tool(description = "Deactivate a mission — returns CLI command to revoke all its delegations (read-only, requires human confirmation)")]
    fn mission_deactivate(
        &self,
        Parameters(input): Parameters<MissionDeactivateInput>,
    ) -> Result<String, String> {
        let cmd = format!("colmena mission deactivate --id {}", input.mission_id);
        Ok(format!(
            "Mission deactivation requested for '{}'.\n\n\
             To confirm, run this command in the terminal:\n\n  {}\n\n\
             MCP tools cannot deactivate missions directly — human confirmation required.",
            input.mission_id, cmd
        ))
    }

    // ── Calibration ──────────────────────────────────────────────────────────

    #[rmcp::tool(description = "Show current ELO-based trust calibration state — which agents are elevated, restricted, or on probation")]
    fn calibrate(
        &self,
        Parameters(_input): Parameters<CalibrateInput>,
    ) -> Result<String, String> {
        let library_dir = colmena_core::library::default_library_dir();
        let elo_log_path = self.config_dir.join("elo-events.jsonl");

        let roles = colmena_core::library::load_roles(&library_dir)
            .map_err(|e| format!("Error loading roles: {e}"))?;
        let events = colmena_core::elo::read_elo_log(&elo_log_path)
            .map_err(|e| format!("Error reading ELO log: {e}"))?;

        let baselines: Vec<(String, u32)> = roles.iter()
            .map(|r| (r.id.clone(), r.elo.initial))
            .collect();
        let ratings = colmena_core::elo::leaderboard(&events, &baselines);
        let thresholds = colmena_core::calibrate::TrustThresholds::default();

        let mut output = format!(
            "Trust calibration (thresholds: elevated>={}, restrict<{}, floor<{}, min_reviews={}):\n\n",
            thresholds.elevate_elo, thresholds.restrict_elo, thresholds.floor_elo,
            thresholds.min_reviews_to_calibrate,
        );

        if ratings.is_empty() {
            output.push_str("No agents with ELO history.\n");
        } else {
            for rating in &ratings {
                let tier = colmena_core::calibrate::determine_tier(rating, &thresholds);
                output.push_str(&format!(
                    "  {:<25} ELO:{:<6} reviews:{:<3} tier:{}\n",
                    rating.agent, rating.elo, rating.review_count,
                    tier.as_str().to_uppercase(),
                ));
            }
        }

        output.push_str(
            "\nTo apply calibration, run: colmena calibrate run\n\
             To reset all overrides:     colmena calibrate reset"
        );

        Ok(output)
    }

    // ── Session Stats ────────────────────────────────────────────────────────

    #[rmcp::tool(description = "Show Colmena session stats — prompts saved by auto-approve + tokens saved by output filtering. Call this before ending a session to show the value summary.")]
    fn session_stats(
        &self,
        Parameters(input): Parameters<SessionStatsInput>,
    ) -> Result<String, String> {
        let audit_path = self.config_dir.join("audit.log");
        let stats_path = self.config_dir.join("filter-stats.jsonl");

        let audit = colmena_core::audit::session_stats(
            &audit_path,
            input.session_id.as_deref(),
        );

        let all_events = colmena_filter::stats::read_filter_stats(&stats_path)
            .unwrap_or_default();

        let session_events: Vec<_> = if let Some(ref sid) = input.session_id {
            all_events.into_iter().filter(|e| e.session_id == *sid).collect()
        } else {
            all_events
        };
        let filter = colmena_filter::stats::summarize(&session_events);

        let scope = if input.session_id.is_some() { "This Session" } else { "All Sessions" };

        let auto_pct = if audit.total_decisions > 0 {
            (audit.allow_count as f64 / audit.total_decisions as f64) * 100.0
        } else {
            0.0
        };

        let mut output = format!("Colmena Stats — {scope}\n{}\n\n",
            "=".repeat(40));

        output.push_str("  Firewall Decisions\n");
        output.push_str(&format!("  Auto-approved:      {} ({:.0}%)\n", audit.allow_count, auto_pct));
        output.push_str(&format!("  Asked human:        {}\n", audit.ask_count));
        output.push_str(&format!("  Blocked:            {}\n", audit.deny_count));
        output.push_str(&format!("  Total:              {}\n", audit.total_decisions));
        output.push_str(&format!("  Unique agents:      {}\n", audit.unique_agents));
        output.push_str(&format!("\n  → {} prompts saved (auto-approved without asking)\n\n", audit.allow_count));

        output.push_str("  Output Filtering\n");
        if filter.total_events > 0 {
            let tokens_saved = filter.total_chars_saved / 4;
            output.push_str(&format!("  Outputs filtered:   {}\n", filter.total_events));
            output.push_str(&format!("  Chars saved:        {}\n", filter.total_chars_saved));
            output.push_str(&format!("  Est. tokens saved:  ~{}\n", tokens_saved));
            output.push_str(&format!("  Avg reduction:      {:.1}%\n", filter.avg_reduction_pct));
        } else {
            output.push_str("  No outputs filtered yet.\n");
        }

        output.push_str(&format!(
            "\n  ════════════════════════════════════\n  Total value: {} prompts saved + ~{} tokens saved\n",
            audit.allow_count,
            filter.total_chars_saved / 4,
        ));

        Ok(output)
    }
}

// ---------------------------------------------------------------------------
// ServerHandler — wires the tool router into the MCP server lifecycle
// ---------------------------------------------------------------------------

#[tool_handler(router = self.tool_router)]
impl ServerHandler for ColmenaServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("colmena", env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "Colmena — Trust Firewall + Approval Hub for multi-agent orchestration. \
                 Use these tools to manage trust rules, delegations, and approval queues.",
            )
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config_dir = colmena_core::paths::default_config_dir();
    let server = ColmenaServer::new(config_dir);

    let transport = rmcp::transport::io::stdio();
    let service = server.serve(transport).await?;
    service.waiting().await?;

    Ok(())
}
