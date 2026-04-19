mod defaults;
mod doctor;
mod hook;
mod install;
mod notify;
mod setup;

use std::io::{BufReader, Read as _};
use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::Utc;
use clap::{Parser, Subcommand};

use colmena_core::config::Action;
use colmena_core::delegate::RuntimeDelegation;
use colmena_core::elo;
use colmena_core::library::{default_library_dir, load_patterns, load_roles, validate_library};
use colmena_core::paths::default_config_dir;
use colmena_core::review::{self, ReviewState};
use colmena_core::sanitize::sanitize_error;
use colmena_core::selector::{
    detect_role_gaps, format_recommendations, generate_mission, scaffold_role, select_patterns,
};

/// Colmena — Trust Firewall + Approval Hub for Claude Code multi-agent orchestration
#[derive(Parser)]
#[command(name = "colmena", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Hot path: stdin JSON → evaluate → stdout JSON (used by CC hook)
    Hook {
        /// Path to trust-firewall.yaml
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Queue management
    Queue {
        #[command(subcommand)]
        action: QueueAction,
    },
    /// Manage runtime trust delegations
    Delegate {
        #[command(subcommand)]
        action: DelegateAction,
    },
    /// Validate trust-firewall.yaml
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Register colmena hook in ~/.claude/settings.json
    Install,
    /// Wisdom library: roles, patterns, and orchestration selection
    Library {
        #[command(subcommand)]
        action: LibraryAction,
    },
    /// Peer review management
    Review {
        #[command(subcommand)]
        action: ReviewAction,
    },
    /// ELO ratings
    Elo {
        #[command(subcommand)]
        action: EloAction,
    },
    /// Mission management (delegations lifecycle)
    Mission {
        #[command(subcommand)]
        action: MissionAction,
    },
    /// ELO-based trust calibration
    Calibrate {
        #[command(subcommand)]
        action: CalibrateAction,
    },
    /// Colmena statistics (firewall decisions + token savings)
    Stats {
        /// Show stats for a specific session ID only
        #[arg(long)]
        session: Option<String>,
    },
    /// One-command setup: config, hooks, MCP — everything to get started
    Setup {
        /// Preview what would happen without making changes
        #[arg(long)]
        dry_run: bool,
        /// Overwrite all files with defaults (ignores custom modifications)
        #[arg(long)]
        force: bool,
    },
    /// Diagnose the health of a Colmena installation
    Doctor,
    /// Analyze a mission and recommend whether to use Colmena
    Suggest {
        /// Mission description to analyze
        mission: String,
    },
}

#[derive(Subcommand)]
enum DelegateAction {
    /// Add a new delegation
    Add {
        /// Tool to delegate
        #[arg(long)]
        tool: String,
        /// Restrict to a specific agent
        #[arg(long)]
        agent: Option<String>,
        /// TTL in hours (default: 4, max: 24)
        #[arg(long, default_value = "4")]
        ttl: i64,
        /// Optional session ID — limits delegation to this CC session only
        #[arg(long)]
        session: Option<String>,
    },
    /// List active delegations
    List,
    /// Revoke a delegation
    Revoke {
        /// Tool to revoke
        #[arg(long)]
        tool: String,
        /// Only revoke for a specific agent
        #[arg(long)]
        agent: Option<String>,
    },
}

#[derive(Subcommand)]
enum QueueAction {
    /// List pending approval items
    List,
    /// Prune old queue entries
    Prune {
        /// Maximum age in days (default: 7)
        #[arg(long, default_value = "7")]
        older_than: i64,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Check configuration file for errors
    Check {
        /// Path to trust-firewall.yaml
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum LibraryAction {
    /// List all roles and patterns
    List,
    /// Show details of a specific role or pattern
    Show {
        /// Role or pattern ID (e.g., "pentester", "oracle-workers")
        id: String,
    },
    /// Select an orchestration pattern for a mission
    Select {
        /// Mission description
        #[arg(long)]
        mission: String,
    },
    /// Create a new role with intelligent defaults
    CreateRole {
        /// Role ID (e.g., "cloud-security")
        #[arg(long)]
        id: String,
        /// Role description
        #[arg(long)]
        description: String,
        /// Category: offensive, defensive, compliance, architecture, research, development, operations, creative
        #[arg(long)]
        category: Option<String>,
    },
    /// Create a new pattern scaffold
    CreatePattern {
        /// Pattern ID (e.g., "parallel-audit")
        #[arg(long)]
        id: String,
        /// Pattern description
        #[arg(long)]
        description: String,
        /// Topology: hierarchical, sequential, adversarial, peer, fan-out-merge, recursive, iterative
        #[arg(long)]
        topology: Option<String>,
    },
}

#[derive(Subcommand)]
enum ReviewAction {
    /// List reviews (pending, completed)
    List {
        /// Filter by state: pending, completed, needs_human_review
        #[arg(long)]
        state: Option<String>,
    },
    /// Show details of a specific review
    Show {
        /// Review ID
        id: String,
    },
}

#[derive(Subcommand)]
enum EloAction {
    /// Show ELO leaderboard
    Show,
}

#[derive(Subcommand)]
enum MissionAction {
    /// List active missions with delegation counts
    List,
    /// Deactivate a mission (revoke all its delegations)
    Deactivate {
        /// Mission ID (slug from mission directory name)
        #[arg(long)]
        id: String,
    },
    /// Spawn a mission with auto-generated delegations + enriched prompts.
    Spawn {
        /// Path to a mission manifest YAML.
        #[arg(long)]
        from: Option<PathBuf>,
        /// Shortcut: mission description when no manifest.
        #[arg(long)]
        mission: Option<String>,
        /// Shortcut: pattern id.
        #[arg(long)]
        pattern: Option<String>,
        /// Shortcut: role name. Repeatable.
        #[arg(long = "role", value_name = "ROLE")]
        roles: Vec<String>,
        /// Shortcut: scope "owns" (comma-separated) — applies to the last --role.
        #[arg(long = "scope", value_name = "FILES", requires = "roles")]
        scopes: Vec<String>,
        /// Shortcut: role task — applies to the last --role.
        #[arg(long = "task", value_name = "TASK", requires = "roles")]
        tasks: Vec<String>,
        /// TTL for generated delegations in hours. Default 8, max 24.
        #[arg(long, default_value_t = 8)]
        mission_ttl: i64,
        /// Simulate: print what would be done, do not write.
        #[arg(long)]
        dry_run: bool,
        /// Overwrite existing delegations whose TTL is shorter than mission end.
        #[arg(long)]
        extend_existing: bool,
    },
}

#[derive(Subcommand)]
enum CalibrateAction {
    /// Run calibration from current ELO scores
    Run,
    /// Show current trust tiers per agent
    Show,
    /// Clear all ELO-based overrides
    Reset,
}

fn main() {
    let cli = Cli::parse();
    let result = match cli.command {
        Commands::Hook { config } => run_hook(config),
        Commands::Queue { action } => match action {
            QueueAction::List => run_queue_list(),
            QueueAction::Prune { older_than } => run_queue_prune(older_than),
        },
        Commands::Delegate { action } => match action {
            DelegateAction::Add {
                tool,
                agent,
                ttl,
                session,
            } => run_delegate(tool, agent, ttl, session),
            DelegateAction::List => run_delegate_list(),
            DelegateAction::Revoke { tool, agent } => run_delegate_revoke(tool, agent),
        },
        Commands::Config { action } => match action {
            ConfigAction::Check { config } => run_config_check(config),
        },
        Commands::Install => install::run_install(),
        Commands::Library { action } => match action {
            LibraryAction::List => run_library_list(),
            LibraryAction::Show { id } => run_library_show(id),
            LibraryAction::Select { mission } => run_library_select(mission),
            LibraryAction::CreateRole {
                id,
                description,
                category,
            } => run_library_create_role(id, description, category),
            LibraryAction::CreatePattern {
                id,
                description,
                topology,
            } => run_library_create_pattern(id, description, topology),
        },
        Commands::Review { action } => match action {
            ReviewAction::List { state } => run_review_list(state),
            ReviewAction::Show { id } => run_review_show(id),
        },
        Commands::Elo { action } => match action {
            EloAction::Show => run_elo_show(),
        },
        Commands::Mission { action } => match action {
            MissionAction::List => run_mission_list(),
            MissionAction::Deactivate { id } => run_mission_deactivate(id),
            MissionAction::Spawn {
                from,
                mission,
                pattern,
                roles,
                scopes,
                tasks,
                mission_ttl,
                dry_run,
                extend_existing,
            } => run_mission_spawn(
                from,
                mission,
                pattern,
                roles,
                scopes,
                tasks,
                mission_ttl,
                dry_run,
                extend_existing,
            ),
        },
        Commands::Calibrate { action } => match action {
            CalibrateAction::Run => run_calibrate(),
            CalibrateAction::Show => run_calibrate_show(),
            CalibrateAction::Reset => run_calibrate_reset(),
        },
        Commands::Stats { session } => match session {
            Some(sid) => run_session_stats(&sid),
            None => run_stats(),
        },
        Commands::Setup { dry_run, force } => setup::run_setup(dry_run, force),
        Commands::Doctor => doctor::run_doctor(),
        Commands::Suggest { mission } => run_suggest(&mission),
    };

    if let Err(e) = result {
        log_error(&format!("Hook error: {e:#}"));
        // Fix 15 (DREAD 6.2): sanitize error messages — generic for stdout, details in log only
        let sanitized = sanitize_error(&format!("{e}"));
        let fallback = hook::HookResponse::ask(sanitized);
        let _ = serde_json::to_writer(std::io::stdout(), &fallback);
        std::process::exit(0);
    }
}

/// Hook hot path: stdin → deserialize → dispatch by event → stdout
fn run_hook(config_path: Option<PathBuf>) -> Result<()> {
    // M6: Watchdog thread — if stdin doesn't close within 5s, output an 'ask' response
    // and exit. Prevents the hook from blocking the entire CC session indefinitely
    // if Claude Code hangs or does not close stdin properly.
    let watchdog_active = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    {
        let flag = std::sync::Arc::clone(&watchdog_active);
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(5));
            if flag.load(std::sync::atomic::Ordering::Relaxed) {
                let _ = std::io::Write::write_all(
                    &mut std::io::stdout(),
                    b"{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"ask\",\"permissionDecisionReason\":\"Hook stdin timeout (5s)\"}}",
                );
                // Best-effort audit log for timeout event
                let config_dir = colmena_core::paths::default_config_dir();
                let audit_path = config_dir.join("audit.log");
                let _ = colmena_core::audit::log_event(
                    &audit_path,
                    &colmena_core::audit::AuditEvent::Timeout {
                        reason: "Hook stdin timeout (5s)",
                    },
                );
                std::process::exit(0);
            }
        });
    }

    // 1. Read stdin with 10MB limit (Fix 7, DREAD 7.6)
    const MAX_STDIN_BYTES: u64 = 10 * 1024 * 1024;
    let mut input = String::new();
    let bytes_read = BufReader::new(std::io::stdin())
        .take(MAX_STDIN_BYTES + 1)
        .read_to_string(&mut input)
        .context("Failed to read stdin")?;

    // Disarm watchdog — stdin read completed successfully
    watchdog_active.store(false, std::sync::atomic::Ordering::Relaxed);

    if bytes_read as u64 > MAX_STDIN_BYTES {
        let response = hook::HookResponse::ask("Stdin payload exceeds 10MB limit");
        serde_json::to_writer(std::io::stdout(), &response)
            .context("Failed to write hook response")?;
        return Ok(());
    }

    // Parse raw JSON first — SubagentStop has a different payload shape than tool events
    let raw: serde_json::Value =
        serde_json::from_str(&input).context("Failed to parse hook JSON")?;
    let event_name = raw
        .get("hook_event_name")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    // 1b. Settings.json integrity check (Fix 12, DREAD 7.8)
    check_hook_integrity();

    // Dispatch by hook event
    match event_name {
        "PreToolUse" => {
            let payload: hook::HookPayload =
                serde_json::from_value(raw).context("Failed to parse PreToolUse payload")?;
            run_pre_tool_use_hook(payload, config_path)
        }
        "PostToolUse" => {
            let payload: hook::HookPayload =
                serde_json::from_value(raw).context("Failed to parse PostToolUse payload")?;
            run_post_tool_use_hook(payload)
        }
        "PermissionRequest" => {
            let payload: hook::HookPayload =
                serde_json::from_value(raw).context("Failed to parse PermissionRequest payload")?;
            run_permission_request_hook(payload)
        }
        "SubagentStop" => {
            let payload: hook::SubagentStopPayload =
                serde_json::from_value(raw).context("Failed to parse SubagentStop payload")?;
            run_subagent_stop_hook(payload)
        }
        other => {
            log_error(&format!("Unknown hook event: {other}"));
            let response = hook::PostToolUseResponse::passthrough();
            serde_json::to_writer(std::io::stdout(), &response)
                .context("Failed to write passthrough response")?;
            Ok(())
        }
    }
}

/// PreToolUse: evaluate tool call against trust firewall rules.
fn run_suggest(mission: &str) -> Result<()> {
    let library_dir = colmena_core::library::default_library_dir();
    let roles = colmena_core::library::load_roles(&library_dir).context("Failed to load roles")?;
    let patterns =
        colmena_core::library::load_patterns(&library_dir).context("Failed to load patterns")?;

    let suggestion = colmena_core::selector::suggest_mission_size(mission, &roles, &patterns);

    println!("Mission Analysis");
    println!("================");
    println!();
    println!("Description: \"{}\"", mission);
    println!();
    println!("Complexity:    {}", suggestion.complexity.as_str());
    println!("Agents:        {}", suggestion.recommended_agents);

    if !suggestion.domains_detected.is_empty() {
        println!("Domains:       {}", suggestion.domains_detected.join(", "));
    }

    println!("Confidence:    {:.2}", suggestion.confidence);
    println!();

    if suggestion.needs_colmena {
        if let Some(ref pattern) = suggestion.suggested_pattern {
            println!("Pattern:       {}", pattern);
        }
        if !suggestion.suggested_roles.is_empty() {
            println!("Roles:         {}", suggestion.suggested_roles.join(" → "));
        }
        println!();
        println!("→ Ready to go:");
        println!("  colmena library select --mission \"{}\"", mission);
        println!("  # or use mcp__colmena__mission_spawn via MCP");
    } else {
        println!("⚡ You don't need Colmena for this. Use Claude Code directly.");
        println!();
        println!("Why: {}", suggestion.reason);
    }

    Ok(())
}

fn run_pre_tool_use_hook(payload: hook::HookPayload, config_path: Option<PathBuf>) -> Result<()> {
    // 2. Resolve config path
    let config_file = config_path
        .or_else(|| std::env::var("COLMENA_CONFIG").ok().map(PathBuf::from))
        .unwrap_or_else(|| colmena_core::paths::default_config_dir().join("trust-firewall.yaml"));

    let cfg = colmena_core::config::load_config(&config_file, &payload.cwd)?;
    let patterns = colmena_core::config::compile_config(&cfg)?;

    for w in colmena_core::config::validate_tool_names(&cfg) {
        log_error(&format!("Config warning: {w}"));
    }

    // 3. Load runtime delegations (with expired for audit logging)
    let config_dir = config_file
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let audit_path = config_dir.join("audit.log");
    let delegations_path = config_dir.join("runtime-delegations.json");
    let (delegations, expired) =
        colmena_core::delegate::load_delegations_with_expired(&delegations_path);
    // Log expired delegations for audit trail
    for exp in &expired {
        let _ = colmena_core::audit::log_event(
            &audit_path,
            &colmena_core::audit::AuditEvent::DelegateExpire {
                tool: &exp.tool,
                agent: exp.agent_id.as_deref(),
                source: exp.source.as_deref().unwrap_or("unknown"),
            },
        );
    }

    // 3b. Load ELO-calibrated overrides (safe fallback: empty if missing)
    let elo_overrides_path = config_dir.join("elo-overrides.json");
    let elo_overrides = colmena_core::calibrate::load_overrides(&elo_overrides_path);

    // 3c. Load revoked agents for mission kill switch
    let revoked_agents = colmena_core::delegate::load_revoked_missions(config_dir);

    // 4. Map HookPayload to EvaluationInput and evaluate
    let eval_input = payload.to_evaluation_input();
    let decision = colmena_core::firewall::evaluate_with_elo(
        &cfg,
        &patterns,
        &delegations,
        &eval_input,
        &elo_overrides,
        &revoked_agents,
    );

    // 4b. Audit log — record EVERY decision (Fix 4, DREAD 8.8)
    let action_str = match decision.action {
        Action::AutoApprove => "ALLOW",
        Action::Ask => "ASK",
        Action::Block => "DENY",
    };
    let key_field =
        colmena_core::audit::extract_key_field(&eval_input.tool_name, &eval_input.tool_input);
    let _ = colmena_core::audit::log_event(
        &audit_path,
        &colmena_core::audit::AuditEvent::Decision {
            action: action_str,
            session_id: &eval_input.session_id,
            agent_id: eval_input.agent_id.as_deref(),
            tool: &eval_input.tool_name,
            key_field: &key_field,
            rule: decision.matched_rule.as_deref().unwrap_or("none"),
        },
    );

    // 4c. Mission Gate: if enforce_missions and tool is Agent, check for mission marker
    // M7.3 live-surface: gate active if explicit or if mission delegations are live.
    let gate_active = cfg.is_mission_gate_active(&delegations);

    let decision = if gate_active
        && eval_input.tool_name == "Agent"
        && decision.action != Action::Block
    {
        // Check if the Agent prompt contains a mission marker
        let prompt = eval_input
            .tool_input
            .get("prompt")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !prompt.contains(colmena_core::selector::MISSION_MARKER_PREFIX) {
            // Log Mission Gate event
            let _ = colmena_core::audit::log_event(
                &audit_path,
                &colmena_core::audit::AuditEvent::MissionGate {
                    session_id: &eval_input.session_id,
                    agent_id: eval_input.agent_id.as_deref(),
                },
            );
            colmena_core::firewall::Decision {
                action: Action::Ask,
                reason: "Mission gate: this Agent call has no Colmena mission binding. \
                         Use mcp__colmena__mission_suggest to check if you need a mission, \
                         or mcp__colmena__mission_spawn to create one directly. \
                         Approve manually to proceed without mission binding."
                    .to_string(),
                matched_rule: Some("mission_gate".to_string()),
                priority: colmena_core::firewall::Priority::Medium,
            }
        } else {
            decision
        }
    } else {
        decision
    };

    // 5. If Ask → enqueue pending
    if decision.action == Action::Ask {
        if let Err(e) = colmena_core::queue::enqueue_pending(config_dir, &eval_input, &decision) {
            log_error(&format!("Queue write failed: {e:#}"));
        }
    }

    // 6. Fire notification (non-blocking)
    notify::notify(
        &decision.action,
        &decision.priority,
        &payload.tool_name,
        payload.agent_id.as_deref(),
        cfg.notifications.as_ref(),
    );

    // 7. Build and write response
    let response = match decision.action {
        Action::AutoApprove => hook::HookResponse::allow(&decision.reason),
        Action::Block => hook::HookResponse::deny(&decision.reason),
        Action::Ask => hook::HookResponse::ask(&decision.reason),
    };

    serde_json::to_writer(std::io::stdout(), &response).context("Failed to write hook response")?;

    Ok(())
}

/// PostToolUse: filter tool output before CC processes it.
/// Safe fallback: any error → passthrough (never "ask" or "deny").
fn run_post_tool_use_hook(payload: hook::HookPayload) -> Result<()> {
    match run_post_tool_use_hook_inner(&payload) {
        Ok(()) => Ok(()),
        Err(e) => {
            log_error(&format!("PostToolUse filter error: {e:#}"));
            let response = hook::PostToolUseResponse::passthrough();
            serde_json::to_writer(std::io::stdout(), &response)
                .context("Failed to write passthrough response")?;
            Ok(())
        }
    }
}

fn run_post_tool_use_hook_inner(payload: &hook::HookPayload) -> Result<()> {
    // Only filter Bash tool outputs
    if payload.tool_name != "Bash" {
        let response = hook::PostToolUseResponse::passthrough();
        serde_json::to_writer(std::io::stdout(), &response)?;
        return Ok(());
    }

    // Extract tool response (CC sends "tool_response", not "tool_output")
    let tool_response = match &payload.tool_response {
        Some(v) => v,
        None => {
            let response = hook::PostToolUseResponse::passthrough();
            serde_json::to_writer(std::io::stdout(), &response)?;
            return Ok(());
        }
    };

    let stdout = tool_response
        .get("stdout")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let stderr = tool_response
        .get("stderr")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    // CC sends "interrupted" (bool), not "exitCode" (int). Treat interrupted=true as exit code 1.
    let exit_code = tool_response
        .get("exitCode")
        .and_then(|v| v.as_i64())
        .map(|v| v as i32)
        .or_else(|| {
            tool_response
                .get("interrupted")
                .and_then(|v| v.as_bool())
                .map(|interrupted| if interrupted { 1 } else { 0 })
        });
    let command = payload
        .tool_input
        .get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Load filter config (or use defaults)
    let filter_config_path = colmena_core::paths::default_config_dir().join("filter-config.yaml");
    let filter_config =
        colmena_filter::config::load_filter_config(&filter_config_path).unwrap_or_default();

    if !filter_config.enabled {
        let response = hook::PostToolUseResponse::passthrough();
        serde_json::to_writer(std::io::stdout(), &response)?;
        return Ok(());
    }

    // Build and run filter pipeline
    let pipeline = colmena_filter::pipeline::FilterPipeline::from_config(&filter_config);
    let result = pipeline.run(stdout, stderr, command, exit_code);

    // If nothing changed, passthrough
    if !result.modified {
        let response = hook::PostToolUseResponse::passthrough();
        serde_json::to_writer(std::io::stdout(), &response)?;
        return Ok(());
    }

    // Log stats (best-effort)
    let stats_path = colmena_core::paths::colmena_home().join("config/filter-stats.jsonl");
    let _ = colmena_filter::stats::log_filter_stats(
        &stats_path,
        &colmena_filter::stats::FilterStatsEvent {
            ts: chrono::Utc::now(),
            session_id: payload.session_id.clone(),
            tool_use_id: payload.tool_use_id.clone(),
            command_prefix: command.chars().take(80).collect(),
            original_chars: result.original_chars,
            filtered_chars: result.filtered_chars,
            chars_saved: result.original_chars.saturating_sub(result.filtered_chars),
            filters_applied: result.notes,
        },
    );

    // Write filtered response
    let response = hook::PostToolUseResponse::with_output(result.output);
    serde_json::to_writer(std::io::stdout(), &response)?;

    Ok(())
}

/// PermissionRequest: evaluate tool call against role tools_allowed and teach CC session rules.
/// Fires when CC is about to prompt the user for permission.
/// If agent has an active mission and the tool is in the role's tools_allowed,
/// returns allow + updatedPermissions so CC auto-approves future calls.
fn run_permission_request_hook(payload: hook::HookPayload) -> Result<()> {
    // Safe fallback: any error → no output (CC continues to prompt user)
    match run_permission_request_hook_inner(&payload) {
        Ok(()) => Ok(()),
        Err(e) => {
            log_error(&format!("PermissionRequest error: {e:#}"));
            Ok(()) // No output = CC prompts user (safe fallback)
        }
    }
}

fn run_permission_request_hook_inner(payload: &hook::HookPayload) -> Result<()> {
    let config_dir = colmena_core::paths::default_config_dir();

    // 1. Check if agent has active role delegation (mission was approved by human)
    let agent_id = match &payload.agent_id {
        Some(id) => id,
        None => return Ok(()), // No agent_id → not a mission agent, pass through
    };

    // Fix Finding #8 (DREAD 5.6): Check revoked-missions BEFORE checking role delegation.
    // Without this, a revoked agent's PermissionRequest fires before PreToolUse processes
    // the revocation, teaching CC session rules that persist beyond the revocation.
    let revoked_agents = colmena_core::delegate::load_revoked_missions(&config_dir);
    if revoked_agents.contains(agent_id.as_str()) {
        // Agent is revoked — do NOT teach session rules. Return no output so CC prompts user.
        // The PreToolUse mission_revocation check will deny the actual tool call.
        let audit_path = config_dir.join("audit.log");
        let _ = colmena_core::audit::log_event(
            &audit_path,
            &colmena_core::audit::AuditEvent::Decision {
                action: "PERM_REQ_REVOKED",
                session_id: &payload.session_id,
                agent_id: Some(agent_id),
                tool: &payload.tool_name,
                key_field: "mission_revoked",
                rule: "revoked_missions_check",
            },
        );
        return Ok(()); // No output = CC prompts user (revoked agent gets no session rules)
    }

    let delegations_path = config_dir.join("runtime-delegations.json");
    let delegations = colmena_core::delegate::load_delegations(&delegations_path);

    let has_role_delegation = delegations.iter().any(|d| {
        d.agent_id.as_deref() == Some(agent_id.as_str()) && d.source.as_deref() == Some("role")
    });

    if !has_role_delegation {
        return Ok(()); // No active mission, let CC prompt user
    }

    // 2. Load role tools map
    let library_dir = colmena_core::library::default_library_dir();
    let roles = colmena_core::library::load_roles(&library_dir)?;
    let role_tools_map = colmena_core::library::build_role_tools_map(&roles);

    let role_data = match role_tools_map.get(agent_id.as_str()) {
        Some(r) => r,
        None => return Ok(()), // agent_id doesn't match a known role
    };

    // 3. Check if tool is in role's tools_allowed
    if !role_data.allows_tool(&payload.tool_name) {
        return Ok(()); // Tool not allowed for this role, let CC prompt user
    }

    // 4. Tool is allowed → teach CC session rules for ALL tools this role can use
    let permission_updates = build_permission_updates(role_data);
    let response = hook::PermissionRequestResponse::allow_with_updates(permission_updates);
    serde_json::to_writer(std::io::stdout(), &response)
        .context("Failed to write PermissionRequest response")?;

    // 5. Audit log
    let audit_path = config_dir.join("audit.log");
    let _ = colmena_core::audit::log_event(
        &audit_path,
        &colmena_core::audit::AuditEvent::RoleToolsAllow {
            agent: agent_id,
            tool: &payload.tool_name,
            role_id: agent_id,
        },
    );

    Ok(())
}

/// Build PermissionUpdate rules from role's tools_allowed.
/// Teaches CC to auto-approve ALL tools this role is allowed to use.
/// STRIDE TM Finding #1 (DREAD 7.0): Bash and Agent MUST always go through
/// PreToolUse firewall — never teach CC to auto-approve them via session rules.
/// Once CC learns a session rule, it applies BEFORE the hook, bypassing chain guard,
/// blocked rules, ELO restrictions, and mission revocation entirely.
const NEVER_SESSION_RULE_TOOLS: &[&str] = &["Bash", "Agent"];

fn build_permission_updates(
    role_data: &colmena_core::library::RoleToolsAllowed,
) -> Vec<hook::PermissionUpdate> {
    let rules: Vec<hook::PermissionRule> = role_data
        .tools
        .iter()
        .chain(role_data.tool_patterns.iter())
        .filter(|t| {
            !NEVER_SESSION_RULE_TOOLS
                .iter()
                .any(|blocked| t.eq_ignore_ascii_case(blocked))
        })
        .map(|t| hook::PermissionRule {
            tool_name: t.clone(),
        })
        .collect();

    vec![hook::PermissionUpdate {
        update_type: "addRules".to_string(),
        rules,
        behavior: "allow".to_string(),
        destination: "session".to_string(),
    }]
}

/// SubagentStop: enforce peer review before mission workers can stop.
/// Safe fallback: any error → approve (never trap an agent).
///
/// Fix Finding #19 (DREAD 5.4): When safe fallback triggers, create a warning-level
/// alert so the human has visibility that the review gate was bypassed.
fn run_subagent_stop_hook(payload: hook::SubagentStopPayload) -> Result<()> {
    let result = subagent_stop_inner(&payload);

    let response = match result {
        Ok(resp) => resp,
        Err(e) => {
            log_error(&format!("SubagentStop error (safe fallback approve): {e}"));

            // Create a warning alert for the safe fallback (best-effort)
            let config_dir = colmena_core::paths::default_config_dir();
            let alerts_path = config_dir.join("alerts.json");
            let agent_id_str = payload.agent_id.as_deref().unwrap_or("unknown");
            let alert = colmena_core::alerts::Alert {
                alert_id: colmena_core::alerts::generate_alert_id(),
                timestamp: chrono::Utc::now(),
                severity: "warning".to_string(),
                mission_id: "unknown".to_string(),
                agent_id: agent_id_str.to_string(),
                review_id: "n/a".to_string(),
                score_average: 0.0,
                critical_findings: 0,
                message: format!(
                    "SubagentStop safe fallback activated for agent '{}': review gate bypassed due to error: {}",
                    agent_id_str, e
                ),
                acknowledged: false,
            };
            let _ = colmena_core::alerts::create_alert(&alerts_path, alert);

            hook::SubagentStopResponse::approve()
        }
    };

    serde_json::to_writer(std::io::stdout(), &response)
        .context("Failed to write SubagentStop response")?;
    Ok(())
}

fn subagent_stop_inner(payload: &hook::SubagentStopPayload) -> Result<hook::SubagentStopResponse> {
    // 1. No agent_id → approve (main agent, not a subagent)
    let agent_id = match &payload.agent_id {
        Some(id) => id,
        None => return Ok(hook::SubagentStopResponse::approve()),
    };

    // 2. Load delegations, find one with this agent_id + source: "role"
    let config_dir = colmena_core::paths::default_config_dir();
    let delegations_path = config_dir.join("runtime-delegations.json");
    let delegations = colmena_core::delegate::load_delegations(&delegations_path);

    let mission_delegation = delegations.iter().find(|d| {
        d.agent_id.as_deref() == Some(agent_id.as_str()) && d.source.as_deref() == Some("role")
    });

    // 3. No mission delegation → approve (not a mission worker)
    let delegation = match mission_delegation {
        Some(d) => d,
        None => return Ok(hook::SubagentStopResponse::approve()),
    };

    // 4. Load role from library, check role_type == "auditor"
    let library_dir = colmena_core::library::default_library_dir();
    if let Ok(roles) = colmena_core::library::load_roles(&library_dir) {
        if let Some(role) = roles.iter().find(|r| r.id == *agent_id) {
            if role.role_type.as_deref() == Some("auditor") {
                // Auditor is exempt from review requirement
                return Ok(hook::SubagentStopResponse::approve());
            }
        }
    }

    // 5. Check review obligations for this mission
    let mission_id = delegation.mission_id.as_deref().unwrap_or("unknown");
    let review_dir = config_dir.join("reviews");

    // 5a. Reviewer gate: block if agent has pending evaluations to complete.
    // Must come BEFORE the review_submit check — an agent that is both author
    // AND reviewer could pass has_submitted_review but still owe evaluations.
    if colmena_core::review::has_pending_evaluations(&review_dir, agent_id, mission_id) {
        return Ok(hook::SubagentStopResponse::block(format!(
            "You have pending reviews to evaluate for mission '{}'. \
             Call mcp__colmena__review_evaluate for each pending review before stopping.",
            mission_id
        )));
    }

    // 5b. Worker gate: check if agent has submitted their work for review
    if colmena_core::review::has_submitted_review(&review_dir, agent_id, mission_id) {
        // 6. Review exists → approve
        // Audit log
        let audit_path = config_dir.join("audit.log");
        let _ = colmena_core::audit::log_event(
            &audit_path,
            &colmena_core::audit::AuditEvent::Decision {
                action: "AGENT_STOP",
                session_id: &payload.session_id,
                agent_id: Some(agent_id),
                tool: "SubagentStop",
                key_field: "review_submitted",
                rule: "peer_review_gate",
            },
        );
        Ok(hook::SubagentStopResponse::approve())
    } else {
        // 7. No review → block
        Ok(hook::SubagentStopResponse::block(format!(
            "You must call mcp__colmena__review_submit before stopping. \
             Your work needs peer review as part of mission '{}' protocol. \
             Submit your work for review, then you can stop.",
            mission_id
        )))
    }
}

fn run_queue_list() -> Result<()> {
    let config_dir = colmena_core::paths::default_config_dir();
    let entries = colmena_core::queue::list_pending(&config_dir)?;

    if entries.is_empty() {
        println!("No pending approvals.");
        return Ok(());
    }

    println!("{} pending approval(s):\n", entries.len());
    for entry in &entries {
        let agent = entry.agent_id.as_deref().unwrap_or("unknown");
        println!(
            "  [{priority}] {tool} — {agent}",
            priority = entry.priority,
            tool = entry.tool,
            agent = agent,
        );
        println!("    Reason: {}", entry.reason);
        println!("    Time:   {}", entry.timestamp);
        println!("    ID:     {}", entry.id);
        println!();
    }

    Ok(())
}

fn run_queue_prune(older_than_days: i64) -> Result<()> {
    let config_dir = colmena_core::paths::default_config_dir();
    let duration = chrono::Duration::days(older_than_days);
    let pruned = colmena_core::queue::prune_old_entries(&config_dir, duration)?;
    if pruned == 0 {
        println!("No entries older than {older_than_days} days.");
    } else {
        println!("Pruned {pruned} entries older than {older_than_days} days → queue/decided/");
    }
    Ok(())
}

fn run_delegate(
    tool: String,
    agent: Option<String>,
    ttl_hours: i64,
    session: Option<String>,
) -> Result<()> {
    for w in colmena_core::config::validate_tool_name_single(&tool) {
        eprintln!("WARNING: {w}");
    }

    // Bash delegations blocked at CLI level: unscoped Bash auto-approve is a security risk.
    // The CLI does not support --bash-pattern or --path-within flags.
    if tool == "Bash" {
        anyhow::bail!(
            "Bash delegations blocked: unscoped Bash auto-approve means ALL commands \
             run without human review.\n\n\
             To grant scoped Bash access:\n  \
             1. Edit trust-firewall.yaml → agent_overrides, add rules with \
             bash_pattern (regex) or path_within conditions.\n  \
             2. Or use 'colmena library select --mission <desc>' to generate a \
             mission with scoped Bash patterns automatically.\n\n\
             Note: --bash-pattern and --path-within are NOT CLI flags. \
             Scoped Bash is configured via YAML or mission generation only."
        );
    }

    let ttl = colmena_core::delegate::validate_ttl(ttl_hours)?;

    let config_dir = colmena_core::paths::default_config_dir();
    let delegations_path = config_dir.join("runtime-delegations.json");

    let mut delegations = colmena_core::delegate::load_delegations(&delegations_path);

    let now = Utc::now();
    let expires_at = Some(now + ttl);

    let new_delegation = RuntimeDelegation {
        tool: tool.clone(),
        agent_id: agent.clone(),
        action: Action::AutoApprove,
        created_at: now,
        expires_at,
        session_id: session.clone(),
        source: Some("human".to_string()),
        mission_id: None,
        conditions: None,
    };

    delegations.push(new_delegation);

    // Warn about global scope only when no --session specified
    if session.is_none() {
        eprintln!(
            "WARNING: This delegation applies to ALL active CC sessions (no --session specified)."
        );
        eprintln!(
            "         Use 'colmena delegate add --tool {} --session <id>' to limit scope.",
            tool
        );
    }

    colmena_core::delegate::save_delegations(&delegations_path, &delegations)?;

    // Audit log
    let audit_path = config_dir.join("audit.log");
    let _ = colmena_core::audit::log_event(
        &audit_path,
        &colmena_core::audit::AuditEvent::DelegateCreate {
            tool: &tool,
            agent: agent.as_deref(),
            ttl: &format!("{ttl_hours}h"),
            source: "cli",
        },
    );

    let scope = match &agent {
        Some(a) => format!("agent '{a}'"),
        None => "all agents".to_string(),
    };

    println!("Delegated auto-approve for '{tool}' to {scope} ({ttl_hours}h)");
    Ok(())
}

fn run_delegate_list() -> Result<()> {
    let config_dir = colmena_core::paths::default_config_dir();
    let delegations_path = config_dir.join("runtime-delegations.json");
    let delegations = colmena_core::delegate::list_delegations(&delegations_path);

    if delegations.is_empty() {
        println!("No active delegations.");
        return Ok(());
    }

    println!("{} active delegation(s):\n", delegations.len());
    for d in &delegations {
        let agent = d.agent_id.as_deref().unwrap_or("*");
        let ttl = match d.expires_at {
            Some(exp) => {
                let remaining = exp - Utc::now();
                if remaining.num_minutes() > 60 {
                    format!("{}h remaining", remaining.num_hours())
                } else {
                    format!("{}m remaining", remaining.num_minutes())
                }
            }
            None => "no expiry".to_string(),
        };
        println!("  {} → agent={} ({})", d.tool, agent, ttl);
    }

    Ok(())
}

fn run_delegate_revoke(tool: String, agent: Option<String>) -> Result<()> {
    let config_dir = colmena_core::paths::default_config_dir();
    let delegations_path = config_dir.join("runtime-delegations.json");

    let revoked =
        colmena_core::delegate::revoke_delegations(&delegations_path, &tool, agent.as_deref())?;

    if revoked == 0 {
        println!("No matching delegations found for '{tool}'.");
    } else {
        println!("Revoked {revoked} delegation(s) for '{tool}'.");

        // Audit log
        let audit_path = config_dir.join("audit.log");
        let _ = colmena_core::audit::log_event(
            &audit_path,
            &colmena_core::audit::AuditEvent::DelegateRevoke {
                tool: &tool,
                agent: agent.as_deref(),
            },
        );
    }

    Ok(())
}

fn run_config_check(config_path: Option<PathBuf>) -> Result<()> {
    let config_file = config_path
        .or_else(|| std::env::var("COLMENA_CONFIG").ok().map(PathBuf::from))
        .unwrap_or_else(|| colmena_core::paths::default_config_dir().join("trust-firewall.yaml"));

    println!("Checking {}...", config_file.display());

    let cfg = colmena_core::config::load_config(&config_file, "/tmp/placeholder")?;

    println!("  Version:      {}", cfg.version);
    println!("  Default:      {:?}", cfg.defaults.action);
    println!("  Trust circle: {} rule(s)", cfg.trust_circle.len());
    println!("  Restricted:   {} rule(s)", cfg.restricted.len());
    println!("  Blocked:      {} rule(s)", cfg.blocked.len());
    println!("  Agent overrides: {} agent(s)", cfg.agent_overrides.len());

    let warnings = colmena_core::config::validate_tool_names(&cfg);
    for w in &warnings {
        eprintln!("  WARNING: {w}");
    }

    match colmena_core::config::compile_config(&cfg) {
        Ok(_) => println!("\nConfig is valid."),
        Err(e) => {
            eprintln!("  ERROR: {e}");
            std::process::exit(1);
        }
    }

    Ok(())
}

fn run_library_list() -> Result<()> {
    let library_dir = default_library_dir();
    if !library_dir.exists() {
        eprintln!(
            "Library directory not found: {}\nRun `colmena install` or create the directory manually.",
            library_dir.display()
        );
        std::process::exit(1);
    }

    let roles = load_roles(&library_dir)?;
    let patterns = load_patterns(&library_dir)?;

    // Print roles table
    println!("Roles ({}):", roles.len());
    println!("  {:<20} {:<6} SPECIALIZATIONS", "ID", "ICON");
    println!("  {:-<20} {:-<6} {:-<40}", "", "", "");
    for role in &roles {
        println!(
            "  {:<20} {:<6} {}",
            role.id,
            role.icon,
            role.specializations.len()
        );
    }

    println!();

    // Print patterns table
    println!("Patterns ({}):", patterns.len());
    println!("  {:<30} {:<12} ESTIMATED AGENTS", "ID", "TOPOLOGY");
    println!("  {:-<30} {:-<12} {:-<16}", "", "", "");
    for pattern in &patterns {
        println!(
            "  {:<30} {:<12} {}",
            pattern.id, pattern.topology, pattern.estimated_agents
        );
    }

    // Validate and print warnings
    let warnings = validate_library(&roles, &patterns, &library_dir);
    if !warnings.is_empty() {
        println!();
        println!("Warnings ({}):", warnings.len());
        for w in &warnings {
            println!("  WARNING: {w}");
        }
    }

    Ok(())
}

fn run_library_show(id: String) -> Result<()> {
    let library_dir = default_library_dir();
    if !library_dir.exists() {
        eprintln!("Library directory not found: {}", library_dir.display());
        std::process::exit(1);
    }

    let roles = load_roles(&library_dir)?;
    let patterns = load_patterns(&library_dir)?;

    // Search roles first
    if let Some(role) = roles.iter().find(|r| r.id == id) {
        println!("Role: {} {}", role.icon, role.name);
        println!("  ID:                {}", role.id);
        println!("  Description:       {}", role.description);
        println!("  Default trust:     {}", role.default_trust_level);
        println!("  System prompt ref: {}", role.system_prompt_ref);
        println!("  Tools allowed:     {}", role.tools_allowed.join(", "));
        println!("  Specializations:   {}", role.specializations.join(", "));
        println!("  ELO initial:       {}", role.elo.initial);
        if !role.elo.categories.is_empty() {
            let cats: Vec<String> = role
                .elo
                .categories
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect();
            println!("  ELO categories:    {}", cats.join(", "));
        }
        if !role.mentoring.can_mentor.is_empty() {
            println!(
                "  Can mentor:        {}",
                role.mentoring.can_mentor.join(", ")
            );
        }
        if !role.mentoring.mentored_by.is_empty() {
            println!(
                "  Mentored by:       {}",
                role.mentoring.mentored_by.join(", ")
            );
        }
        return Ok(());
    }

    // Search patterns
    if let Some(pattern) = patterns.iter().find(|p| p.id == id) {
        println!("Pattern: {}", pattern.name);
        println!("  ID:               {}", pattern.id);
        if let Some(source) = &pattern.source {
            println!("  Source:           {}", source);
        }
        println!("  Description:      {}", pattern.description);
        println!("  Topology:         {}", pattern.topology);
        println!("  Communication:    {}", pattern.communication);
        println!("  Estimated agents: {}", pattern.estimated_agents);
        println!("  Token cost:       {}", pattern.estimated_token_cost);
        println!("  ELO lead select:  {}", pattern.elo_lead_selection);
        println!("  When to use:");
        for w in &pattern.when_to_use {
            println!("    - {w}");
        }
        if !pattern.when_not_to_use.is_empty() {
            println!("  When NOT to use:");
            for w in &pattern.when_not_to_use {
                println!("    - {w}");
            }
        }
        println!("  Pros:");
        for p in &pattern.pros {
            println!("    + {p}");
        }
        println!("  Cons:");
        for c in &pattern.cons {
            println!("    - {c}");
        }
        println!("  Roles suggested:");
        for (slot, role_slot) in &pattern.roles_suggested.0 {
            println!("    {slot}: {}", role_slot.as_vec().join(", "));
        }
        return Ok(());
    }

    eprintln!("Not found: no role or pattern with id '{id}'");
    std::process::exit(1);
}

fn run_library_select(mission: String) -> Result<()> {
    let library_dir = default_library_dir();
    if !library_dir.exists() {
        eprintln!("Library directory not found: {}", library_dir.display());
        std::process::exit(1);
    }

    let roles = load_roles(&library_dir)?;
    let patterns = load_patterns(&library_dir)?;

    let recommendations = select_patterns(&mission, &patterns, &roles);
    let formatted = format_recommendations(&recommendations);
    println!("{formatted}");

    // Check for role gaps and warn
    let gaps = detect_role_gaps(&mission, &roles);
    if !gaps.is_empty() {
        println!("Role gap warnings — no role covers these mission keywords:");
        for gap in &gaps {
            println!("  - {gap}");
        }
        println!("  Consider running: colmena library create-role --id <id> --description <desc>");
        println!();
    }

    if recommendations.is_empty() {
        println!("No patterns matched. Try a more descriptive mission.");
        return Ok(());
    }

    // Prompt user to choose
    print!("Choose a pattern [1");
    for i in 2..=recommendations.len() {
        print!("/{i}");
    }
    println!("] (default: 1): ");

    let mut choice_line = String::new();
    std::io::stdin()
        .read_line(&mut choice_line)
        .context("Failed to read pattern choice")?;

    let choice: usize = choice_line.trim().parse().unwrap_or(1);
    let idx = if choice == 0 || choice > recommendations.len() {
        0
    } else {
        choice - 1
    };

    let selected = &recommendations[idx];
    println!("Selected: {}", selected.pattern_name);

    let missions_dir = default_config_dir().join("missions");

    // Query ELO ratings for reviewer lead assignment
    let elo_log_path = default_config_dir().join("elo/elo-log.jsonl");
    let elo_events = colmena_core::elo::read_elo_log(&elo_log_path).unwrap_or_default();
    let baselines: Vec<(String, u32)> = roles
        .iter()
        .map(|r| (r.id.clone(), r.elo.initial))
        .collect();
    let elo_ratings = colmena_core::elo::leaderboard(&elo_events, &baselines);

    let mission_config = generate_mission(
        &mission,
        selected,
        &roles,
        &library_dir,
        &missions_dir,
        None, // session_id: CLI doesn't have session context
        &elo_ratings,
        Some(&default_config_dir()),
        None,  // manifest: legacy CLI path does not take a manifest
        false, // dry_run: this CLI path always persists
    )?;

    // Save role-generated delegations
    if !mission_config.delegations.is_empty() {
        let delegations_path = default_config_dir().join("runtime-delegations.json");
        let mut existing = colmena_core::delegate::load_delegations(&delegations_path);
        existing.extend(mission_config.delegations.clone());
        colmena_core::delegate::save_delegations(&delegations_path, &existing)?;
        println!(
            "Created {} role-bound delegations ({}h TTL)",
            mission_config.delegations.len(),
            colmena_core::selector::DEFAULT_MISSION_TTL_HOURS
        );
    }

    println!();
    println!("Mission created: {}", mission_config.mission_dir.display());
    println!("Agent configs:");
    for agent in &mission_config.agent_configs {
        println!("  {} — {}", agent.role_id, agent.claude_md_path.display());
    }
    println!();
    println!(
        "Next: open each agent's CLAUDE.md and launch Claude Code with --project pointing to its directory."
    );

    Ok(())
}

fn run_library_create_role(
    id: String,
    description: String,
    category: Option<String>,
) -> Result<()> {
    let library_dir = default_library_dir();

    let category = category
        .as_deref()
        .map(|c| c.parse::<colmena_core::templates::RoleCategory>())
        .transpose()?;

    let (role_path, prompt_path) = scaffold_role(&id, &description, category, &library_dir)?;

    let resolved =
        category.unwrap_or_else(|| colmena_core::templates::detect_category(&description));
    println!("Created role '{id}' (category: {resolved}):");
    println!("  Role YAML:   {}", role_path.display());
    println!("  Prompt file: {}", prompt_path.display());

    Ok(())
}

fn run_library_create_pattern(
    id: String,
    description: String,
    topology: Option<String>,
) -> Result<()> {
    let library_dir = default_library_dir();

    let topology = topology
        .as_deref()
        .map(|t| t.parse::<colmena_core::pattern_scaffold::PatternTopology>())
        .transpose()?;

    let pattern_path = colmena_core::pattern_scaffold::scaffold_pattern(
        &id,
        &description,
        topology,
        &library_dir,
    )?;

    let resolved =
        topology.unwrap_or_else(|| colmena_core::pattern_scaffold::detect_topology(&description));
    println!("Created pattern '{id}' (topology: {resolved}):");
    println!("  Pattern YAML: {}", pattern_path.display());

    Ok(())
}

fn run_review_list(state: Option<String>) -> Result<()> {
    let review_dir = default_config_dir().join("reviews");
    if !review_dir.exists() {
        println!("No reviews found.");
        return Ok(());
    }

    // Map state string to ReviewState enum
    let state_filter = match state.as_deref() {
        Some("pending") => Some(ReviewState::Pending),
        Some("in_review") => Some(ReviewState::InReview),
        Some("evaluated") => Some(ReviewState::Evaluated),
        Some("completed") => Some(ReviewState::Completed),
        Some("needs_human_review") => Some(ReviewState::NeedsHumanReview),
        Some("rejected") => Some(ReviewState::Rejected),
        Some(other) => {
            eprintln!(
                "Unknown state '{other}'. Valid: pending, in_review, evaluated, completed, needs_human_review, rejected"
            );
            std::process::exit(1);
        }
        None => None,
    };

    let entries = review::list_reviews(&review_dir, state_filter)?;

    if entries.is_empty() {
        println!("No reviews found.");
        return Ok(());
    }

    println!("{} review(s):\n", entries.len());
    println!(
        "  {:<14} {:<16} {:<25} {:<8} {:<25} CREATED",
        "STATE", "REVIEW ID", "AUTHOR -> REVIEWER", "SCORE", "MISSION"
    );
    println!(
        "  {:-<14} {:-<16} {:-<25} {:-<8} {:-<25} {:-<20}",
        "", "", "", "", "", ""
    );

    for entry in &entries {
        let state_str = format_review_state(&entry.state);
        let pairing = format!("{} -> {}", entry.author_role, entry.reviewer_role);
        let score = match entry.score_average {
            Some(avg) => format!("{avg:.1}"),
            None => "-".to_string(),
        };
        let created = entry.created_at.format("%Y-%m-%d %H:%M").to_string();

        println!(
            "  {:<14} {:<16} {:<25} {:<8} {:<25} {}",
            state_str, entry.review_id, pairing, score, entry.mission, created
        );
    }

    Ok(())
}

fn run_review_show(id: String) -> Result<()> {
    let review_dir = default_config_dir().join("reviews");
    if !review_dir.exists() {
        eprintln!("No reviews directory found.");
        std::process::exit(1);
    }

    let entries = review::list_reviews(&review_dir, None)?;
    let entry = entries.iter().find(|e| e.review_id == id);

    let entry = match entry {
        Some(e) => e,
        None => {
            eprintln!("Review '{id}' not found.");
            std::process::exit(1);
        }
    };

    println!("Review: {}", entry.review_id);
    println!("  State:         {}", format_review_state(&entry.state));
    println!("  Mission:       {}", entry.mission);
    println!("  Author:        {}", entry.author_role);
    println!("  Reviewer:      {}", entry.reviewer_role);
    println!("  Artifact:      {}", entry.artifact_path);
    println!("  Hash:          {}", entry.artifact_hash);
    println!(
        "  Created:       {}",
        entry.created_at.format("%Y-%m-%d %H:%M:%S UTC")
    );

    if let Some(evaluated_at) = entry.evaluated_at {
        println!(
            "  Evaluated:     {}",
            evaluated_at.format("%Y-%m-%d %H:%M:%S UTC")
        );
    }

    if let Some(ref scores) = entry.scores {
        println!("  Scores:");
        for (dim, val) in scores {
            println!("    {dim}: {val}");
        }
    }

    if let Some(avg) = entry.score_average {
        println!("  Average:       {avg:.1}");
    }

    if let Some(count) = entry.finding_count {
        println!("  Findings:      {count}");
    }

    Ok(())
}

fn run_elo_show() -> Result<()> {
    let config_dir = default_config_dir();
    let elo_log_path = config_dir.join("elo/elo-log.jsonl");

    let events = elo::read_elo_log(&elo_log_path)?;

    // Load roles from library to get baseline ELO values
    let library_dir = default_library_dir();
    let baselines: Vec<(String, u32)> = if library_dir.exists() {
        match load_roles(&library_dir) {
            Ok(roles) => roles
                .iter()
                .map(|r| (r.id.clone(), r.elo.initial))
                .collect(),
            Err(_) => Vec::new(),
        }
    } else {
        Vec::new()
    };

    let ratings = elo::leaderboard(&events, &baselines);

    if ratings.is_empty() {
        println!("No ELO data available.");
        return Ok(());
    }

    println!(
        "  {:<20} {:<8} {:<12} {:<10} LAST ACTIVE",
        "AGENT", "ELO", "TREND(7d)", "REVIEWS"
    );
    println!(
        "  {:-<20} {:-<8} {:-<12} {:-<10} {:-<20}",
        "", "", "", "", ""
    );

    for rating in &ratings {
        let trend = if rating.trend_7d > 0 {
            format!("+{}", rating.trend_7d)
        } else {
            format!("{}", rating.trend_7d)
        };

        let last_active = match rating.last_active {
            Some(ts) => ts.format("%Y-%m-%d %H:%M").to_string(),
            None => "-".to_string(),
        };

        println!(
            "  {:<20} {:<8} {:<12} {:<10} {}",
            rating.agent, rating.elo, trend, rating.review_count, last_active
        );
    }

    Ok(())
}

fn run_stats() -> Result<()> {
    let config_dir = colmena_core::paths::default_config_dir();
    let audit_path = config_dir.join("audit.log");
    let stats_path = config_dir.join("filter-stats.jsonl");

    // Audit stats (all sessions)
    let audit = colmena_core::audit::session_stats(&audit_path, None);
    let filter_events = colmena_filter::stats::read_filter_stats(&stats_path)?;
    let filter = colmena_filter::stats::summarize(&filter_events);

    print_combined_stats(&audit, &filter, "All Sessions");

    Ok(())
}

fn run_session_stats(session_id: &str) -> Result<()> {
    let config_dir = colmena_core::paths::default_config_dir();
    let audit_path = config_dir.join("audit.log");
    let stats_path = config_dir.join("filter-stats.jsonl");

    // Audit stats for this session
    let audit = colmena_core::audit::session_stats(&audit_path, Some(session_id));

    // Filter stats for this session
    let all_events = colmena_filter::stats::read_filter_stats(&stats_path)?;
    let session_events: Vec<_> = all_events
        .into_iter()
        .filter(|e| e.session_id == session_id)
        .collect();
    let filter = colmena_filter::stats::summarize(&session_events);

    print_combined_stats(&audit, &filter, "This Session");

    Ok(())
}

fn print_combined_stats(
    audit: &colmena_core::audit::SessionStats,
    filter: &colmena_filter::stats::FilterStatsSummary,
    scope: &str,
) {
    println!("Colmena Stats — {scope}");
    println!("{}", "=".repeat(40));
    println!();

    // Firewall stats
    if audit.total_decisions > 0 {
        let auto_pct = if audit.total_decisions > 0 {
            (audit.allow_count as f64 / audit.total_decisions as f64) * 100.0
        } else {
            0.0
        };

        println!("  Firewall Decisions");
        println!("  ──────────────────");
        println!(
            "  Auto-approved:      {} ({:.0}%)",
            audit.allow_count, auto_pct
        );
        println!("  Asked human:        {}", audit.ask_count);
        println!("  Blocked:            {}", audit.deny_count);
        println!("  Total:              {}", audit.total_decisions);
        println!("  Delegation matches: {}", audit.delegation_matches);
        println!("  Unique agents:      {}", audit.unique_agents);
        println!("  Unique tools:       {}", audit.unique_tools);
        println!();
        println!(
            "  → {} prompts saved (auto-approved without asking)",
            audit.allow_count
        );
    } else {
        println!("  No firewall decisions recorded.");
    }

    println!();

    // Filter stats
    if filter.total_events > 0 {
        println!("  Output Filtering");
        println!("  ────────────────");
        println!("  Outputs filtered:   {}", filter.total_events);
        println!(
            "  Chars saved:        {}",
            format_chars(filter.total_chars_saved)
        );
        println!("  Est. tokens saved:  ~{}", filter.total_chars_saved / 4);
        println!("  Avg reduction:      {:.1}%", filter.avg_reduction_pct);
    } else {
        println!("  No output filtering recorded yet.");
    }

    println!();
    println!("  ════════════════════════════════════");
    println!(
        "  Total value: {} prompts saved + ~{} tokens saved",
        audit.allow_count,
        filter.total_chars_saved / 4,
    );
}

fn format_chars(chars: usize) -> String {
    if chars >= 1_000_000 {
        format!("{:.1}M", chars as f64 / 1_000_000.0)
    } else if chars >= 1_000 {
        format!("{:.1}K", chars as f64 / 1_000.0)
    } else {
        format!("{chars}")
    }
}

/// Format a ReviewState for display.
fn format_review_state(state: &ReviewState) -> &'static str {
    match state {
        ReviewState::Pending => "pending",
        ReviewState::InReview => "in_review",
        ReviewState::Evaluated => "evaluated",
        ReviewState::Completed => "completed",
        ReviewState::NeedsHumanReview => "needs_human",
        ReviewState::Rejected => "rejected",
        ReviewState::Invalidated => "invalidated",
    }
}

/// Check that the hook registered in settings.json matches the running binary (Fix 12, DREAD 7.8).
/// Best-effort: logs warning if mismatch, never fails the hook.
fn check_hook_integrity() {
    let our_binary = match std::env::current_exe() {
        Ok(p) => p.to_string_lossy().to_string(),
        Err(_) => return,
    };

    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => return,
    };

    let settings_path = PathBuf::from(&home).join(".claude/settings.json");
    let contents = match std::fs::read_to_string(&settings_path) {
        Ok(c) => c,
        Err(_) => return,
    };
    let settings: serde_json::Value = match serde_json::from_str(&contents) {
        Ok(v) => v,
        Err(_) => return,
    };

    // Walk PreToolUse and PostToolUse hooks to find our command
    for event_name in &["PreToolUse", "PostToolUse"] {
        if let Some(hooks) = settings
            .get("hooks")
            .and_then(|h| h.get(*event_name))
            .and_then(|p| p.as_array())
        {
            for entry in hooks {
                if let Some(inner_hooks) = entry.get("hooks").and_then(|h| h.as_array()) {
                    for h in inner_hooks {
                        if let Some(cmd) = h.get("command").and_then(|c| c.as_str()) {
                            if cmd.contains("colmena hook") && !cmd.contains(&our_binary) {
                                log_error(&format!(
                                    "Hook integrity warning: settings.json {event_name} hook command '{}' does not match running binary '{}'",
                                    cmd, our_binary
                                ));
                            }
                        }
                    }
                }
            }
        }
    }
}

// ── Mission subcommands ──────────────────────────────────────────────────────

fn run_mission_list() -> Result<()> {
    let config_dir = default_config_dir();
    let delegations_path = config_dir.join("runtime-delegations.json");
    let delegations = colmena_core::delegate::load_delegations(&delegations_path);

    // Group delegations by mission_id
    let mut missions: std::collections::HashMap<String, Vec<&RuntimeDelegation>> =
        std::collections::HashMap::new();
    for d in &delegations {
        if let Some(ref mid) = d.mission_id {
            missions.entry(mid.clone()).or_default().push(d);
        }
    }

    if missions.is_empty() {
        println!("No active missions with delegations.");
        return Ok(());
    }

    println!("Active missions:\n");
    for (mission_id, mission_delegations) in &missions {
        let agents: std::collections::HashSet<&str> = mission_delegations
            .iter()
            .filter_map(|d| d.agent_id.as_deref())
            .collect();
        let earliest_expiry = mission_delegations
            .iter()
            .filter_map(|d| d.expires_at)
            .min();
        let expiry_str = earliest_expiry
            .map(|e| e.format("%Y-%m-%d %H:%M UTC").to_string())
            .unwrap_or_else(|| "no expiry".to_string());

        println!(
            "  {} — {} delegations, {} agents, expires ~{}",
            mission_id,
            mission_delegations.len(),
            agents.len(),
            expiry_str,
        );
    }
    Ok(())
}

fn run_mission_deactivate(mission_id: String) -> Result<()> {
    let config_dir = default_config_dir();
    let delegations_path = config_dir.join("runtime-delegations.json");

    let revoked = colmena_core::delegate::revoke_by_mission(&delegations_path, &mission_id)?;

    if revoked == 0 {
        println!("No delegations found for mission '{}'.", mission_id);
    } else {
        println!(
            "Revoked {} delegations for mission '{}'.",
            revoked, mission_id
        );

        // Audit log
        let audit_path = config_dir.join("audit.log");
        let _ = colmena_core::audit::log_event(
            &audit_path,
            &colmena_core::audit::AuditEvent::MissionDeactivate {
                mission_id: &mission_id,
                revoked,
            },
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_mission_spawn(
    from: Option<PathBuf>,
    mission: Option<String>,
    pattern: Option<String>,
    roles_arg: Vec<String>,
    scopes_arg: Vec<String>,
    tasks_arg: Vec<String>,
    mission_ttl: i64,
    dry_run: bool,
    extend_existing: bool,
) -> Result<()> {
    use colmena_core::mission_manifest::{ManifestRole, ManifestScope, MissionManifest};

    let manifest: MissionManifest = if let Some(path) = from {
        match MissionManifest::from_path(&path) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("ERROR: {e}");
                std::process::exit(1);
            }
        }
    } else {
        // Shortcut path: build a manifest from flags
        let mission_text = mission.ok_or_else(|| {
            anyhow::anyhow!("--mission <string> required when --from not provided")
        })?;
        let pattern_id = pattern
            .ok_or_else(|| anyhow::anyhow!("--pattern <id> required when --from not provided"))?;
        if roles_arg.is_empty() {
            anyhow::bail!("at least one --role required when --from not provided");
        }
        let roles: Vec<ManifestRole> = roles_arg
            .iter()
            .enumerate()
            .map(|(i, name)| ManifestRole {
                name: name.clone(),
                scope: ManifestScope {
                    owns: scopes_arg
                        .get(i)
                        .map(|csv| {
                            csv.split(',')
                                .map(|s| s.trim().to_string())
                                .filter(|s| !s.is_empty())
                                .collect()
                        })
                        .unwrap_or_default(),
                    forbidden: Vec::new(),
                },
                task: tasks_arg.get(i).cloned().unwrap_or_default(),
            })
            .collect();
        let m = MissionManifest {
            id: mission_text.clone(),
            pattern: pattern_id,
            mission_ttl_hours: mission_ttl,
            roles,
        };
        if let Err(e) = m.validate() {
            eprintln!("ERROR: {e}");
            std::process::exit(1);
        }
        m
    };

    let library_dir = colmena_core::library::default_library_dir();
    let all_roles =
        colmena_core::library::load_roles(&library_dir).context("failed to load roles")?;
    let all_patterns =
        colmena_core::library::load_patterns(&library_dir).context("failed to load patterns")?;

    // Validate all roles referenced by the manifest exist in the library.
    for r in &manifest.roles {
        if !all_roles.iter().any(|lr| lr.id == r.name) {
            eprintln!(
                "ERROR: Role '{}' referenced in manifest but not found in library. \
                 Create it first with: colmena library create-role --id {} --description \"...\"",
                r.name, r.name
            );
            std::process::exit(1);
        }
    }

    let config_dir = colmena_core::paths::default_config_dir();
    let runtime_delegations_path = config_dir.join("runtime-delegations.json");
    let missions_dir = config_dir.join("missions");

    let result = colmena_core::selector::spawn_mission(
        &manifest.id,
        Some(&manifest),
        &all_roles,
        &all_patterns,
        &library_dir,
        &missions_dir,
        &runtime_delegations_path,
        None, // session_id
        &[],  // elo_ratings — calibrate lookup deferred for CLI simplicity
        Some(&config_dir),
        extend_existing,
        dry_run,
    )?;

    // Emit summary
    println!();
    println!("Mission spawned: {}", result.mission_name);
    println!(
        "  OK {} subagent prompts composed",
        result.agent_prompts.len()
    );
    if dry_run {
        println!(
            "  (dry-run) {} delegations WOULD be created",
            result.delegations_created.len()
        );
    } else {
        println!(
            "  OK {} delegations created",
            result.delegations_created.len()
        );
    }
    if !result.delegations_skipped.is_empty() {
        println!(
            "  WARN {} delegations preserved (already exist with sufficient TTL)",
            result.delegations_skipped.len()
        );
        for (d, exp) in &result.delegations_skipped {
            println!(
                "       - {}/{} (expires {})",
                d.tool,
                d.agent_id.clone().unwrap_or_default(),
                exp.to_rfc3339()
            );
        }
    }
    if !result.role_gaps.is_empty() {
        println!("  INFO role gaps detected: {}", result.role_gaps.join(", "));
    }
    println!();
    println!("Next steps:");
    for ap in &result.agent_prompts {
        println!(
            "  spawn agent '{}' with prompt at: {}",
            ap.role_id,
            ap.claude_md_path.display()
        );
    }

    Ok(())
}

// ── Calibrate subcommands ────────────────────────────────────────────────────

fn run_calibrate() -> Result<()> {
    let config_dir = default_config_dir();
    let library_dir = default_library_dir();
    let elo_log_path = config_dir.join("elo-events.jsonl");
    let overrides_path = config_dir.join("elo-overrides.json");

    let roles = load_roles(&library_dir)?;
    let events = elo::read_elo_log(&elo_log_path)?;
    let baselines: Vec<(String, u32)> = roles
        .iter()
        .map(|r| (r.id.clone(), r.elo.initial))
        .collect();
    let ratings = elo::leaderboard(&events, &baselines);

    let previous = colmena_core::calibrate::load_overrides(&overrides_path);
    let thresholds = colmena_core::calibrate::TrustThresholds::default();
    let result = colmena_core::calibrate::calibrate(&ratings, &roles, &thresholds, &previous);

    colmena_core::calibrate::save_overrides(&overrides_path, &result)?;

    if result.changes.is_empty() {
        println!("No trust tier changes.");
    } else {
        println!("Trust tier changes:\n");
        let audit_path = config_dir.join("audit.log");
        for change in &result.changes {
            println!(
                "  {} — {} → {} (ELO: {})",
                change.agent,
                change.old_tier.as_str(),
                change.new_tier.as_str(),
                change.elo,
            );
            let _ = colmena_core::audit::log_event(
                &audit_path,
                &colmena_core::audit::AuditEvent::Calibration {
                    agent: &change.agent,
                    old_tier: change.old_tier.as_str(),
                    new_tier: change.new_tier.as_str(),
                    elo: change.elo,
                },
            );
        }
    }

    println!("\nOverrides saved to {}", overrides_path.display());
    Ok(())
}

fn run_calibrate_show() -> Result<()> {
    let config_dir = default_config_dir();
    let library_dir = default_library_dir();
    let elo_log_path = config_dir.join("elo-events.jsonl");

    let roles = load_roles(&library_dir)?;
    let events = elo::read_elo_log(&elo_log_path)?;
    let baselines: Vec<(String, u32)> = roles
        .iter()
        .map(|r| (r.id.clone(), r.elo.initial))
        .collect();
    let ratings = elo::leaderboard(&events, &baselines);

    let thresholds = colmena_core::calibrate::TrustThresholds::default();

    println!("Agent trust tiers (calibration thresholds: elevated≥{}, restrict<{}, floor<{}, min_reviews={}):\n",
        thresholds.elevate_elo, thresholds.restrict_elo, thresholds.floor_elo, thresholds.min_reviews_to_calibrate);

    for rating in &ratings {
        let tier = colmena_core::calibrate::determine_tier(rating, &thresholds);
        println!(
            "  {:<25} ELO:{:<6} reviews:{:<3} tier:{}",
            rating.agent,
            rating.elo,
            rating.review_count,
            tier.as_str().to_uppercase(),
        );
    }

    if ratings.is_empty() {
        println!("  No agents with ELO history.");
    }
    Ok(())
}

fn run_calibrate_reset() -> Result<()> {
    let config_dir = default_config_dir();
    let overrides_path = config_dir.join("elo-overrides.json");

    if overrides_path.exists() {
        std::fs::remove_file(&overrides_path).context("Failed to remove ELO overrides file")?;
        println!("ELO overrides cleared. All agents return to default trust rules.");
    } else {
        println!("No ELO overrides file found — already at defaults.");
    }
    Ok(())
}

/// Best-effort append to colmena error log. Never panics.
/// STRIDE TM Finding #3 (DREAD 6.8): Error log with rotation.
/// Max 5 MiB before rotating (colmena-errors.log.1). Single rotation is sufficient
/// for error logs (much lower volume than audit.log).
fn log_error(msg: &str) {
    let log_path = colmena_core::paths::colmena_home().join("colmena-errors.log");
    let timestamp = chrono::Utc::now().to_rfc3339();
    let line = format!("[{timestamp}] {msg}\n");

    // Rotate if over 5 MiB
    const MAX_ERROR_LOG_BYTES: u64 = 5 * 1024 * 1024;
    if let Ok(meta) = std::fs::metadata(&log_path) {
        if meta.len() >= MAX_ERROR_LOG_BYTES {
            let rotated = log_path.with_extension("log.1");
            let _ = std::fs::rename(&log_path, rotated);
        }
    }

    let _ = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .and_then(|mut f| {
            use std::io::Write;
            f.write_all(line.as_bytes())
        });
}
