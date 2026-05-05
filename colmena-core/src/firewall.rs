use std::collections::HashMap;
use std::path::Path;

use regex::Regex;

use crate::config::{Action, Conditions, FirewallConfig, Rule};
use crate::delegate::RuntimeDelegation;
use crate::models::EvaluationInput;

/// Priority level for a decision (affects notification sound).
#[derive(Debug, Clone, PartialEq)]
pub enum Priority {
    Low,
    Medium,
    High,
}

/// The result of evaluating a hook payload against the firewall rules.
#[derive(Debug)]
pub struct Decision {
    pub action: Action,
    pub reason: String,
    pub matched_rule: Option<String>,
    pub priority: Priority,
}

/// Pre-compile regex patterns from delegation conditions.
/// Returns a map keyed by delegation index → compiled Regex.
pub fn compile_delegation_patterns(delegations: &[RuntimeDelegation]) -> HashMap<usize, Regex> {
    let mut patterns = HashMap::new();
    for (i, d) in delegations.iter().enumerate() {
        if let Some(ref cond) = d.conditions {
            if let Some(ref pat) = cond.bash_pattern {
                if let Ok(re) = Regex::new(pat) {
                    patterns.insert(i, re);
                }
                // Invalid regex silently skipped — delegation won't match Bash conditions
            }
        }
    }
    patterns
}

/// Evaluate a hook payload against the firewall config, runtime delegations,
/// and ELO-calibrated overrides.
///
/// Precedence order:
/// 1. Blocked rules (non-overridable)
/// 2. Runtime delegations (human trust expansion + role-generated)
/// 3. Agent overrides: YAML (human) first, then ELO-calibrated
/// 4. Restricted rules
/// 5. Trust circle rules
/// 6. Defaults (fallback)
pub fn evaluate(
    config: &FirewallConfig,
    patterns: &crate::config::CompiledPatterns,
    delegations: &[RuntimeDelegation],
    payload: &EvaluationInput,
) -> Decision {
    evaluate_with_elo(
        config,
        patterns,
        delegations,
        payload,
        &HashMap::new(),
        &std::collections::HashSet::new(),
        None, // no auto-elevate in tests
    )
}

/// Full evaluation including ELO-calibrated overrides and mission revocation checks.
pub fn evaluate_with_elo(
    config: &FirewallConfig,
    patterns: &crate::config::CompiledPatterns,
    delegations: &[RuntimeDelegation],
    payload: &EvaluationInput,
    elo_overrides: &HashMap<String, Vec<Rule>>,
    revoked_agents: &std::collections::HashSet<String>,
    config_dir: Option<&Path>,
) -> Decision {
    // Compile ELO override regex patterns and merge with existing patterns.
    // ELO overrides loaded from JSON don't go through compile_config, so their
    // bash_pattern regex must be compiled here before check_rules can match them.
    let mut all_patterns = patterns.clone();
    for (agent_id, rules) in elo_overrides {
        let tier = format!("elo_override:{agent_id}");
        // Silently skip invalid regex — same safety contract as delegation patterns.
        // An invalid pattern means the rule won't match (safe fallback to ask).
        let _ = crate::config::compile_rules(rules, &tier, &mut all_patterns);
    }

    // 1. Blocked — first, non-overridable
    if let Some(decision) = check_rules(&config.blocked, payload, "blocked", &all_patterns) {
        return decision;
    }

    // 2. Runtime delegations (with conditions support)
    let delegation_patterns = compile_delegation_patterns(delegations);
    if let Some(decision) = check_delegations(delegations, payload, &delegation_patterns) {
        return decision;
    }

    // 3. Agent overrides — YAML (human) takes precedence over ELO
    //
    // We consult both `agent_id` (per-invocation identity — the stable role id
    // when mission_spawn created the delegation, or an ephemeral hash for custom
    // single-agents) and `agent_type` (the stable class name — the `name:` from
    // the subagent `.md` frontmatter). The first field that finds a match wins.
    //
    // This lets users author `agent_overrides` keyed by the stable agent name
    // (e.g. `cron-worker`) and have it match regardless of whether CC passes
    // that name as `agent_id` or only as `agent_type`.
    for key in [payload.agent_id.as_deref(), payload.agent_type.as_deref()]
        .into_iter()
        .flatten()
    {
        // 3a. YAML-defined overrides (human always wins)
        if let Some(rules) = config.agent_overrides.get(key) {
            let tier = format!("agent_override:{key}");
            if let Some(decision) = check_rules(rules, payload, &tier, &all_patterns) {
                return decision;
            }
        }
        // 3b. ELO-calibrated overrides
        if let Some(rules) = elo_overrides.get(key) {
            let tier = format!("elo_override:{key}");
            if let Some(decision) = check_rules(rules, payload, &tier, &all_patterns) {
                return decision;
            }
        }
    }

    // 4. Restricted
    if let Some(decision) = check_rules(&config.restricted, payload, "restricted", &all_patterns) {
        return decision;
    }

    // 4.5. M7.10: Chain-aware Bash evaluator. Splits top-level chains (&&/||/;/|)
    // and re-evaluates each piece against blocked/restricted/trust_circle.
    // Returns Some(decision) when the chain decision is final; returns None
    // when the caller should fall through to the legacy chain_guard
    // (subshell/backtick rejection, single-piece input, flag off, non-Bash).
    if let Some(decision) = evaluate_chain_aware(config, &all_patterns, payload, config_dir) {
        return decision;
    }

    // 4.6. H1: Shell chain guard — fallback for everything chain_aware refused
    // to decide (subshells, backticks, unmatched quotes). Preserves the
    // safe-prefix-plus-payload protection: e.g. `echo foo && rm -rf /` would
    // still ask here if chain_aware is disabled. With chain_aware enabled,
    // step 4.5 already handled it.
    if payload.tool_name == "Bash" {
        if let Some(cmd) = payload.tool_input.get("command").and_then(|v| v.as_str()) {
            if contains_shell_chain(cmd) {
                return Decision {
                    action: config.defaults.action.clone(),
                    reason: "Bash command contains shell chain operators (&&, ||, ;, $(...)) — requires human review".to_string(),
                    matched_rule: Some("chain_guard".to_string()),
                    priority: Priority::Medium,
                };
            }
        }
    }

    // 4.8. Mission revocation kill switch
    // If agent's mission was deactivated, deny all tools. This overrides CC session rules
    // that were taught via PermissionRequest hooks before the mission was revoked.
    // Check both agent_id and agent_type so revocations against the stable agent
    // name (the only stable key single-agent owners can target) kill switch
    // reliably regardless of which field CC populates.
    for candidate in [payload.agent_id.as_deref(), payload.agent_type.as_deref()]
        .into_iter()
        .flatten()
    {
        if revoked_agents.contains(candidate) {
            return Decision {
                action: Action::Block,
                reason: format!(
                    "Mission revoked for agent '{}' — permissions expired",
                    candidate
                ),
                matched_rule: Some(format!("mission_revoked:{}", candidate)),
                priority: Priority::High,
            };
        }
    }

    // 5. Trust circle
    if let Some(decision) =
        check_rules(&config.trust_circle, payload, "trust_circle", &all_patterns)
    {
        return decision;
    }

    // 6. Defaults
    Decision {
        action: config.defaults.action.clone(),
        reason: "No matching rule — falling back to default".to_string(),
        matched_rule: Some("defaults".to_string()),
        priority: Priority::Medium,
    }
}

fn check_delegations(
    delegations: &[RuntimeDelegation],
    payload: &EvaluationInput,
    delegation_patterns: &HashMap<usize, Regex>,
) -> Option<Decision> {
    for (i, d) in delegations.iter().enumerate() {
        if d.tool != payload.tool_name {
            continue;
        }
        // If delegation specifies an agent_id, either `payload.agent_id` or
        // `payload.agent_type` must match it. Matching on either field lets
        // delegations created against a stable agent name (e.g. via
        // `colmena delegate add --tool X --agent cron-worker`) continue to
        // apply when CC passes that name as agent_type while emitting an
        // ephemeral agent_id for the spawn.
        if let Some(ref delegation_agent) = d.agent_id {
            let id_matches = payload.agent_id.as_ref() == Some(delegation_agent);
            let type_matches = payload.agent_type.as_ref() == Some(delegation_agent);
            if !id_matches && !type_matches {
                continue;
            }
        }
        // If delegation specifies a session_id, it must match
        if let Some(ref delegation_session) = d.session_id {
            if &payload.session_id != delegation_session {
                continue;
            }
        }
        // If delegation has conditions, evaluate them
        if let Some(ref cond) = d.conditions {
            if !delegation_conditions_match(cond, payload, i, delegation_patterns) {
                continue;
            }
        }
        let source = d.source.as_deref().unwrap_or("human");
        return Some(Decision {
            action: d.action.clone(),
            reason: format!(
                "Runtime delegation for tool '{}' (source: {})",
                d.tool, source
            ),
            matched_rule: Some("runtime_delegation".to_string()),
            priority: Priority::Low,
        });
    }
    None
}

/// Evaluate delegation conditions against the payload.
fn delegation_conditions_match(
    cond: &crate::delegate::DelegationConditions,
    payload: &EvaluationInput,
    delegation_idx: usize,
    delegation_patterns: &HashMap<usize, Regex>,
) -> bool {
    // Check bash_pattern (only for Bash tool)
    if cond.bash_pattern.is_some() && payload.tool_name == "Bash" {
        let command = payload
            .tool_input
            .get("command")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if let Some(re) = delegation_patterns.get(&delegation_idx) {
            if !re.is_match(command) {
                return false;
            }
        } else {
            return false; // pattern couldn't be compiled
        }
    }

    // Check path_within — use Path::starts_with for component-based comparison (H2).
    let path = extract_path(payload).map(|p| normalize_path(&p));
    if let Some(ref allowed_dirs) = cond.path_within {
        if let Some(ref p) = path {
            if !allowed_dirs
                .iter()
                .any(|dir| std::path::Path::new(p).starts_with(dir))
            {
                return false;
            }
        }
        if path.is_none() {
            return false;
        }
    }

    // Check path_not_match
    if let Some(ref blocked_patterns) = cond.path_not_match {
        if let Some(ref p) = path {
            for pattern in blocked_patterns {
                if glob_match(pattern, p) {
                    return false;
                }
            }
        }
    }

    true
}

fn check_rules(
    rules: &[Rule],
    payload: &EvaluationInput,
    tier: &str,
    patterns: &crate::config::CompiledPatterns,
) -> Option<Decision> {
    for (i, rule) in rules.iter().enumerate() {
        if !rule.tools.contains(&payload.tool_name) {
            continue;
        }
        let rule_key = format!("{tier}[{i}]");
        if let Some(ref conditions) = rule.conditions {
            if !conditions_match(conditions, payload, &rule_key, patterns) {
                continue;
            }
        }
        let priority = match rule.action {
            Action::Block => Priority::High,
            Action::Ask => Priority::Medium,
            Action::AutoApprove => Priority::Low,
        };
        return Some(Decision {
            action: rule.action.clone(),
            reason: rule
                .reason
                .clone()
                .unwrap_or_else(|| format!("Matched {tier} rule #{i}")),
            matched_rule: Some(format!("{tier}[{i}]")),
            priority,
        });
    }
    None
}

fn conditions_match(
    conditions: &Conditions,
    payload: &EvaluationInput,
    rule_key: &str,
    patterns: &crate::config::CompiledPatterns,
) -> bool {
    // Check bash_pattern against tool_input["command"] — only applies to Bash tool
    if let Some(ref _pattern) = conditions.bash_pattern {
        if payload.tool_name == "Bash" {
            let command = payload
                .tool_input
                .get("command")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if let Some(re) = patterns.get(rule_key) {
                if !re.is_match(command) {
                    return false;
                }
            } else {
                return false; // pattern was supposed to be compiled but wasn't found
            }
        }
        // For non-Bash tools, bash_pattern is not applicable — skip it
    }

    // Resolve the relevant path from tool_input, normalizing to prevent traversal
    let path = extract_path(payload).map(|p| normalize_path(&p));

    // Check path_within — use Path::starts_with for component-based comparison.
    // H2: String::starts_with("/project") would incorrectly match "/project-evil/file.rs".
    // Path::starts_with is component-aware and prevents this sibling-directory bypass.
    if let Some(ref allowed_dirs) = conditions.path_within {
        if let Some(ref p) = path {
            if !allowed_dirs
                .iter()
                .any(|dir| std::path::Path::new(p).starts_with(dir))
            {
                return false;
            }
        }
        // If no path found in input but path_within is required, no match
        if path.is_none() {
            return false;
        }
    }

    // Check path_not_match (glob-like exclusions)
    if let Some(ref blocked_patterns) = conditions.path_not_match {
        if let Some(ref p) = path {
            for pattern in blocked_patterns {
                if glob_match(pattern, p) {
                    return false;
                }
            }
        }
    }

    true
}

/// Normalize a path by resolving `.` and `..` segments without touching the filesystem.
/// This prevents path traversal bypasses like `/project/src/../../etc/passwd`.
fn normalize_path(path: &str) -> String {
    use std::path::{Component, PathBuf};
    let mut normalized = PathBuf::new();
    for component in std::path::Path::new(path).components() {
        match component {
            Component::ParentDir => {
                normalized.pop();
            }
            Component::CurDir => {}
            other => normalized.push(other),
        }
    }
    normalized.to_string_lossy().to_string()
}

/// Extract the relevant file path from tool_input based on tool type.
fn extract_path(payload: &EvaluationInput) -> Option<String> {
    match payload.tool_name.as_str() {
        "Read" | "Write" | "Edit" => payload
            .tool_input
            .get("file_path")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        "Glob" | "Grep" => payload
            .tool_input
            .get("path")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        "WebFetch" => payload
            .tool_input
            .get("url")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        _ => None,
    }
}

/// Strip content inside matched single and double quotes from a command string.
/// Replaces quoted regions with spaces so that operators inside quotes are not detected.
/// Unmatched trailing quotes preserve all consumed content (conservative: better false
/// positive than bypass). (Finding #15, DREAD 5.6)
fn strip_quoted_regions(cmd: &str) -> String {
    let mut result = String::with_capacity(cmd.len());
    let chars: Vec<(usize, char)> = cmd.char_indices().collect();
    let mut i = 0;
    while i < chars.len() {
        let (byte_idx, c) = chars[i];
        if c == '\'' || c == '"' {
            let quote = c;
            // Scan ahead for matching close quote
            let mut found_close = None;
            for (j, &(_, ch)) in chars.iter().enumerate().skip(i + 1) {
                if ch == quote {
                    found_close = Some(j);
                    break;
                }
            }
            if let Some(close_idx) = found_close {
                // Replace entire quoted region (open + content + close) with a space
                result.push(' ');
                i = close_idx + 1;
            } else {
                // Unmatched quote — preserve everything from here (conservative)
                result.push_str(&cmd[byte_idx..]);
                break;
            }
        } else {
            result.push(c);
            i += 1;
        }
    }
    result
}

/// Normalize Unicode homoglyphs to their ASCII equivalents before chain guard check.
/// Replaces known shell-operator lookalikes with their ASCII counterparts.
/// (Finding #3, DREAD 5.2)
fn normalize_unicode_operators(cmd: &str) -> String {
    cmd.chars()
        .map(|c| match c {
            // Greek question mark (U+037E) looks like semicolon
            '\u{037E}' => ';',
            // Fullwidth semicolon (U+FF1B)
            '\u{FF1B}' => ';',
            // Fullwidth ampersand (U+FF06)
            '\u{FF06}' => '&',
            // Fullwidth vertical line (U+FF5C)
            '\u{FF5C}' => '|',
            // Fullwidth dollar sign (U+FF04)
            '\u{FF04}' => '$',
            // Fullwidth grave accent (U+FF40)
            '\u{FF40}' => '`',
            // Fullwidth left parenthesis (U+FF08)
            '\u{FF08}' => '(',
            // Armenian semicolon (U+0589) — looks like colon but can confuse
            // Small semicolon (U+FE54)
            '\u{FE54}' => ';',
            // Keep all other characters as-is
            _ => c,
        })
        .collect()
}

/// Recognize a bare shell variable assignment piece: `KEY=value` or `KEY="..."`
/// or `KEY='...'`, with no following command.
///
/// Used by the chain-aware evaluator (M7.10) to auto-approve assignment-only
/// pieces produced by splitting `KEY=v; cmd` chains. Safety relies on the
/// caller already having rejected `$(...)` and backticks at the whole-input
/// scan, so the assignment value cannot embed command substitution.
///
/// Conservative grammar: key is `^[A-Z_][A-Z0-9_]*` (uppercase only). Anything
/// after the value (a space + extra tokens) disqualifies the piece.
pub fn is_bare_assignment(piece: &str) -> bool {
    let trimmed = piece.trim();
    if trimmed.is_empty() {
        return false;
    }
    // Find '=' and validate the key.
    let eq_pos = match trimmed.find('=') {
        Some(p) => p,
        None => return false,
    };
    let key = &trimmed[..eq_pos];
    if key.is_empty() {
        return false;
    }
    if !key
        .chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
    {
        return false;
    }
    if !key
        .chars()
        .next()
        .map(|c| c.is_ascii_uppercase() || c == '_')
        .unwrap_or(false)
    {
        return false;
    }
    // Validate the value: must be a single token (no unescaped spaces unless
    // they sit inside matched quotes).
    let value = &trimmed[eq_pos + 1..];
    let stripped_value = strip_quoted_regions(value);
    // After quote stripping, quoted regions have been replaced with spaces.
    // Trim surrounding spaces (artifact of quote replacement), then check
    // that no interior whitespace remains — interior whitespace would mean
    // a follow-up command token outside any quoted region.
    !stripped_value.trim().contains(char::is_whitespace)
}

/// Split a Bash command into top-level pieces along `&&`, `||`, `;`, or `|`,
/// respecting matched single/double quotes. Returns `None` for inputs the
/// caller must NOT chain-evaluate: presence of `$(`, backticks, or unmatched
/// quotes — those should fall through to the legacy `chain_guard` ask.
///
/// The returned strings are allocated (owned) from the normalized input,
/// including any surrounding whitespace. Callers should `trim` each piece
/// before evaluating.
///
/// A non-chained input still returns `Some(vec![cmd])` (single element); the
/// caller decides whether to short-circuit. Unicode homoglyphs are normalized
/// before scanning so fullwidth `&&` etc. are caught.
pub fn split_top_level_chain(cmd: &str) -> Option<Vec<String>> {
    let normalized = normalize_unicode_operators(cmd);
    // Reject inputs containing command substitution outside quotes.
    let stripped = strip_quoted_regions(&normalized);
    if stripped.contains("$(") || stripped.contains('`') {
        return None;
    }
    // Detect unmatched quote.
    let mut quote_state: Option<char> = None;
    for c in normalized.chars() {
        match (quote_state, c) {
            (None, '\'') | (None, '"') => quote_state = Some(c),
            (Some(q), c) if c == q => quote_state = None,
            _ => {}
        }
    }
    if quote_state.is_some() {
        return None;
    }

    // Byte-level scan with quote tracking + top-level operator splitting.
    let bytes = normalized.as_bytes();
    let mut pieces: Vec<String> = Vec::new();
    let mut current_start = 0usize;
    let mut i = 0usize;
    let mut in_quote: Option<u8> = None;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = in_quote {
            if b == q {
                in_quote = None;
            }
            i += 1;
            continue;
        }
        if b == b'\'' || b == b'"' {
            in_quote = Some(b);
            i += 1;
            continue;
        }
        // Two-char operators first.
        if i + 1 < bytes.len() {
            let pair = &bytes[i..i + 2];
            if pair == b"&&" || pair == b"||" {
                pieces.push(normalized[current_start..i].to_string());
                i += 2;
                current_start = i;
                continue;
            }
        }
        if b == b';' || b == b'|' {
            pieces.push(normalized[current_start..i].to_string());
            i += 1;
            current_start = i;
            continue;
        }
        i += 1;
    }
    pieces.push(normalized[current_start..].to_string());
    Some(pieces)
}

/// Compositional Bash chain evaluator (M7.10).
///
/// Returns:
/// - `None` when the caller should fall through (non-Bash, single-piece input,
///   `chain_aware` flag off, subshell/backtick rejection, unmatched quotes).
/// - `Some(decision)` when the chain has been evaluated end-to-end. Fold rule:
///   any piece blocks → block, any piece asks → ask, all auto-approve →
///   auto-approve.
///
/// Per-piece evaluation reuses `check_rules` against `blocked`, `restricted`,
/// and `trust_circle`. Bare shell assignments (`KEY=value`) are short-circuited
/// to auto-approve since the whole-input scan has already excluded command
/// substitution.
///
/// Agent overrides and ELO overrides are NOT re-applied here — the caller's
/// step 3 already exercised them against the parent payload, and re-applying
/// would risk a per-piece ELO ask blocking a chain that the global trust
/// circle approves.
fn evaluate_chain_aware(
    config: &FirewallConfig,
    patterns: &crate::config::CompiledPatterns,
    payload: &EvaluationInput,
    config_dir: Option<&Path>,
) -> Option<Decision> {
    if !config.chain_aware {
        return None;
    }
    if payload.tool_name != "Bash" {
        return None;
    }
    let cmd = payload.tool_input.get("command").and_then(|v| v.as_str())?;
    let pieces = split_top_level_chain(cmd)?;
    if pieces.len() < 2 {
        return None;
    }

    let mut any_block = false;
    let mut any_ask = false;
    let mut matched_rules: Vec<String> = Vec::with_capacity(pieces.len());

    for piece in pieces {
        let trimmed = piece.trim();
        if trimmed.is_empty() {
            continue;
        }
        if is_bare_assignment(trimmed) {
            matched_rules.push("assignment".to_string());
            continue;
        }
        // Build a synthetic payload for this piece.
        let mut sub_input = payload.tool_input.clone();
        if let Some(obj) = sub_input.as_object_mut() {
            obj.insert(
                "command".to_string(),
                serde_json::Value::String(trimmed.to_string()),
            );
        }
        let sub_payload = EvaluationInput {
            session_id: payload.session_id.clone(),
            tool_name: payload.tool_name.clone(),
            tool_input: sub_input,
            tool_use_id: payload.tool_use_id.clone(),
            agent_id: payload.agent_id.clone(),
            agent_type: payload.agent_type.clone(),
            cwd: payload.cwd.clone(),
        };
        // 1. Blocked
        if let Some(d) = check_rules(&config.blocked, &sub_payload, "blocked", patterns) {
            any_block = true;
            matched_rules.push(d.matched_rule.unwrap_or_else(|| "blocked".to_string()));
            continue;
        }
        // 2. Restricted
        if let Some(d) = check_rules(&config.restricted, &sub_payload, "restricted", patterns) {
            match d.action {
                Action::Block => {
                    any_block = true;
                }
                Action::Ask => {
                    // M7.15: auto-elevate — if the operator has confirmed this
                    // binary skeleton >=2× within the window, skip the ask.
                    let elevated = config_dir.is_some_and(|cd| {
                        let skeleton = crate::auto_elevate::extract_skeleton(trimmed);
                        crate::auto_elevate::is_elevated(
                            cd,
                            &payload.session_id,
                            payload.agent_type.as_deref(),
                            &skeleton,
                            &config.auto_elevate,
                        )
                    });
                    if elevated {
                        matched_rules.push("auto_elevate".to_string());
                    } else {
                        any_ask = true;
                        matched_rules
                            .push(d.matched_rule.unwrap_or_else(|| "restricted".to_string()));
                    }
                }
                Action::AutoApprove => {
                    matched_rules.push(d.matched_rule.unwrap_or_else(|| "restricted".to_string()));
                }
            }
            continue;
        }
        // 3. Trust circle
        if let Some(d) = check_rules(&config.trust_circle, &sub_payload, "trust_circle", patterns) {
            match d.action {
                Action::AutoApprove => {
                    matched_rules
                        .push(d.matched_rule.unwrap_or_else(|| "trust_circle".to_string()));
                }
                Action::Ask => {
                    any_ask = true;
                    matched_rules
                        .push(d.matched_rule.unwrap_or_else(|| "trust_circle".to_string()));
                }
                Action::Block => {
                    any_block = true;
                    matched_rules
                        .push(d.matched_rule.unwrap_or_else(|| "trust_circle".to_string()));
                }
            }
            continue;
        }
        // 4. No match → defaults (ask). One ask poisons the chain.
        any_ask = true;
        matched_rules.push("defaults".to_string());
    }

    let summary = format!("chain_aware:[{}]", matched_rules.join(","));
    let action = if any_block {
        Action::Block
    } else if any_ask {
        Action::Ask
    } else {
        Action::AutoApprove
    };
    let priority = match action {
        Action::Block => Priority::High,
        Action::Ask => Priority::Medium,
        Action::AutoApprove => Priority::Low,
    };
    let reason = match action {
        Action::AutoApprove => format!(
            "Chain-aware: {} pieces all auto-approved",
            matched_rules.len()
        ),
        Action::Ask => "Chain-aware: at least one piece needs human review".to_string(),
        Action::Block => "Chain-aware: at least one piece is blocked".to_string(),
    };
    Some(Decision {
        action,
        reason,
        matched_rule: Some(summary),
        priority,
    })
}

/// Detect shell chain operators in a Bash command.
///
/// Returns true if the command contains `&&`, `||`, `;`, `$(`, or a backtick
/// **outside of quoted strings**.
/// Plain pipes (`|`) are intentionally excluded — single pipes are safe for
/// the piped-commands trust_circle rules (`cat file | grep foo`).
///
/// Quote-aware: operators inside matched single/double quotes are ignored
/// (Finding #15, DREAD 5.6). Unmatched quotes are treated conservatively.
///
/// Unicode-normalized: homoglyph characters are replaced with ASCII equivalents
/// before detection (Finding #3, DREAD 5.2).
fn contains_shell_chain(cmd: &str) -> bool {
    let normalized = normalize_unicode_operators(cmd);
    let stripped = strip_quoted_regions(&normalized);
    stripped.contains("&&")
        || stripped.contains("||")
        || stripped.contains(';')
        || stripped.contains("$(")
        || stripped.contains('`')
}

/// Glob matching for path_not_match rules.
///
/// STRIDE TM Finding #2 (DREAD 6.4): `*contains*` patterns match against the
/// FULL PATH (not just filename) so that `*reviews*` blocks writes to any path
/// containing "reviews" (e.g. `config/reviews/pending/fake.json`).
///
/// Extension patterns (`*.ext`) and exact matches still operate on filename only.
fn glob_match(pattern: &str, value: &str) -> bool {
    let filename = std::path::Path::new(value)
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or(value);

    if pattern.starts_with('*') && pattern.ends_with('*') && pattern.len() > 2 {
        // Substring pattern: match against FULL PATH for directory protection
        let needle = &pattern[1..pattern.len() - 1];
        value.contains(needle)
    } else if let Some(suffix) = pattern.strip_prefix('*') {
        // Extension pattern: match against filename
        filename.ends_with(suffix)
    } else if let Some(prefix) = pattern.strip_suffix('*') {
        filename.starts_with(prefix)
    } else {
        filename == pattern
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{load_config, Action};
    use crate::delegate::RuntimeDelegation;
    use chrono::{Duration, Utc};
    use serde_json::json;
    use std::path::Path;

    fn load_test_config_and_patterns() -> (FirewallConfig, crate::config::CompiledPatterns) {
        let config_path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../config/trust-firewall.yaml");
        let config = load_config(&config_path, "/Users/test/project").unwrap();
        let patterns = crate::config::compile_config(&config).unwrap();
        (config, patterns)
    }

    fn make_payload(tool: &str, input: serde_json::Value) -> EvaluationInput {
        EvaluationInput {
            session_id: "test-session".to_string(),
            tool_name: tool.to_string(),
            tool_input: input,
            tool_use_id: "tu_test".to_string(),
            agent_id: None,
            agent_type: None,
            cwd: "/Users/test/project".to_string(),
        }
    }

    fn make_payload_for_agent(
        tool: &str,
        input: serde_json::Value,
        agent_id: Option<&str>,
        agent_type: Option<&str>,
    ) -> EvaluationInput {
        EvaluationInput {
            session_id: "test-session".to_string(),
            tool_name: tool.to_string(),
            tool_input: input,
            tool_use_id: "tu_test".to_string(),
            agent_id: agent_id.map(String::from),
            agent_type: agent_type.map(String::from),
            cwd: "/Users/test/project".to_string(),
        }
    }

    #[test]
    fn test_auto_approve_read() {
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload(
            "Read",
            json!({"file_path": "/Users/test/project/src/main.rs"}),
        );
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(decision.action, Action::AutoApprove);
    }

    #[test]
    fn test_auto_approve_safe_bash() {
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload("Bash", json!({"command": "cat foo.txt"}));
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(decision.action, Action::AutoApprove);
    }

    #[test]
    fn test_block_force_push() {
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload("Bash", json!({"command": "git push --force origin main"}));
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(decision.action, Action::Block);
    }

    #[test]
    fn test_block_force_push_short_flag() {
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload("Bash", json!({"command": "git push -f origin main"}));
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(decision.action, Action::Block);
    }

    #[test]
    fn test_block_reset_hard() {
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload("Bash", json!({"command": "git reset --hard HEAD~1"}));
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(decision.action, Action::Block);
    }

    #[test]
    fn test_commit_message_with_force_not_blocked() {
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload(
            "Bash",
            json!({"command": "git commit -m 'removed --force flag'"}),
        );
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_ne!(decision.action, Action::Block);
    }

    #[test]
    fn test_block_rm_rf() {
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload("Bash", json!({"command": "rm -rf /"}));
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(decision.action, Action::Block);
    }

    #[test]
    fn test_restricted_destructive_bash() {
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload("Bash", json!({"command": "rm -r /tmp/somedir"}));
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(decision.action, Action::Ask);
    }

    #[test]
    fn test_path_within_project() {
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload(
            "Write",
            json!({"file_path": "/Users/test/project/src/lib.rs"}),
        );
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(decision.action, Action::AutoApprove);
    }

    #[test]
    fn test_path_not_match_env() {
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload("Write", json!({"file_path": "/Users/test/project/.env"}));
        let decision = evaluate(&config, &patterns, &[], &payload);
        // .env matches path_not_match, so the trust_circle rule won't match -> falls to default (ask)
        assert_eq!(decision.action, Action::Ask);
    }

    #[test]
    fn test_delegation_overrides_restricted() {
        let (config, patterns) = load_test_config_and_patterns();
        let delegation = RuntimeDelegation {
            tool: "Bash".to_string(),
            agent_id: None,
            action: Action::AutoApprove,
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + Duration::hours(4)),
            session_id: None,
            source: None,
            mission_id: None,
            conditions: None,
        };
        // A destructive bash command that would normally be "ask"
        let payload = make_payload("Bash", json!({"command": "rm -r /tmp/foo"}));
        let decision = evaluate(&config, &patterns, &[delegation], &payload);
        // Delegation can't override blocked, but "rm -r" (without "rm -rf /") is restricted, not blocked
        // Blocked check runs first and doesn't match "rm -r /tmp/foo"
        // Then delegation matches -> auto-approve
        assert_eq!(decision.action, Action::AutoApprove);
    }

    #[test]
    fn test_delegation_cannot_override_blocked() {
        let (config, patterns) = load_test_config_and_patterns();
        let delegation = RuntimeDelegation {
            tool: "Bash".to_string(),
            agent_id: None,
            action: Action::AutoApprove,
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + Duration::hours(4)),
            session_id: None,
            source: None,
            mission_id: None,
            conditions: None,
        };
        let payload = make_payload("Bash", json!({"command": "git push --force origin main"}));
        let decision = evaluate(&config, &patterns, &[delegation], &payload);
        // Blocked fires first, delegation can't override
        assert_eq!(decision.action, Action::Block);
    }

    // ── agent_type matching for agent_overrides and runtime delegations ──────
    //
    // Regression for: single-agent scoped permissions failing because CC emits
    // ephemeral `agent_id` hashes for custom subagents, while `agent_overrides`
    // are authored against the stable agent class name. The firewall now treats
    // either `agent_id` or `agent_type` as a valid lookup key.

    fn agent_override_rule_for(tool: &str) -> crate::config::Rule {
        crate::config::Rule {
            tools: vec![tool.to_string()],
            conditions: None,
            action: Action::AutoApprove,
            reason: Some("test agent_override".to_string()),
        }
    }

    #[test]
    fn test_agent_override_matches_by_agent_id() {
        let (mut config, patterns) = load_test_config_and_patterns();
        config.agent_overrides.insert(
            "pentester".to_string(),
            vec![agent_override_rule_for("mcp__external__tool")],
        );
        let payload = make_payload_for_agent(
            "mcp__external__tool",
            json!({"arg": "value"}),
            Some("pentester"),
            None,
        );
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(decision.action, Action::AutoApprove);
        assert_eq!(
            decision.matched_rule,
            Some("agent_override:pentester[0]".to_string())
        );
    }

    #[test]
    fn test_agent_override_matches_by_agent_type_when_agent_id_absent() {
        // Core case for single-agent scoped permissions (e.g. launchd-triggered
        // autonomous subagents where CC does not populate a meaningful agent_id).
        let (mut config, patterns) = load_test_config_and_patterns();
        config.agent_overrides.insert(
            "cron-worker".to_string(),
            vec![agent_override_rule_for("mcp__external__tool")],
        );
        let payload = make_payload_for_agent(
            "mcp__external__tool",
            json!({"arg": "value"}),
            None,
            Some("cron-worker"),
        );
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(decision.action, Action::AutoApprove);
        assert_eq!(
            decision.matched_rule,
            Some("agent_override:cron-worker[0]".to_string())
        );
    }

    #[test]
    fn test_agent_override_matches_by_agent_type_when_agent_id_is_ephemeral() {
        // CC emits an opaque agent_id hash for the spawn while keeping
        // agent_type stable. The override authored against agent_type must
        // still apply.
        let (mut config, patterns) = load_test_config_and_patterns();
        config.agent_overrides.insert(
            "cron-worker".to_string(),
            vec![agent_override_rule_for("mcp__external__tool")],
        );
        let payload = make_payload_for_agent(
            "mcp__external__tool",
            json!({"arg": "value"}),
            Some("aa0aae6b1f3568365"),
            Some("cron-worker"),
        );
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(decision.action, Action::AutoApprove);
        assert_eq!(
            decision.matched_rule,
            Some("agent_override:cron-worker[0]".to_string())
        );
    }

    #[test]
    fn test_agent_override_prefers_agent_id_over_agent_type() {
        // If both fields are present and both have overrides, the agent_id
        // lookup must run first (preserves existing mission_spawn semantics).
        let (mut config, patterns) = load_test_config_and_patterns();
        config.agent_overrides.insert(
            "pentester".to_string(),
            vec![agent_override_rule_for("mcp__external__tool")],
        );
        config.agent_overrides.insert(
            "cron-worker".to_string(),
            vec![crate::config::Rule {
                tools: vec!["mcp__external__tool".to_string()],
                conditions: None,
                action: Action::Block,
                reason: Some("agent_type side — should lose".to_string()),
            }],
        );
        let payload = make_payload_for_agent(
            "mcp__external__tool",
            json!({"arg": "value"}),
            Some("pentester"),
            Some("cron-worker"),
        );
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(decision.action, Action::AutoApprove);
        assert_eq!(
            decision.matched_rule,
            Some("agent_override:pentester[0]".to_string())
        );
    }

    #[test]
    fn test_delegation_matches_on_agent_type() {
        let (config, patterns) = load_test_config_and_patterns();
        let delegation = RuntimeDelegation {
            tool: "mcp__external__tool".to_string(),
            agent_id: Some("cron-worker".to_string()),
            action: Action::AutoApprove,
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + Duration::hours(1)),
            session_id: None,
            source: Some("human".to_string()),
            mission_id: None,
            conditions: None,
        };
        let payload = make_payload_for_agent(
            "mcp__external__tool",
            json!({}),
            Some("aa0aae6b1f3568365"),
            Some("cron-worker"),
        );
        let decision = evaluate(&config, &patterns, &[delegation], &payload);
        assert_eq!(decision.action, Action::AutoApprove);
        assert_eq!(
            decision.matched_rule,
            Some("runtime_delegation".to_string())
        );
    }

    #[test]
    fn test_delegation_agent_id_mismatch_still_blocks() {
        // Sanity: delegation keyed on "pentester" must NOT fire for a payload
        // whose agent_id/agent_type are both different values.
        let (config, patterns) = load_test_config_and_patterns();
        let delegation = RuntimeDelegation {
            tool: "mcp__external__tool".to_string(),
            agent_id: Some("pentester".to_string()),
            action: Action::AutoApprove,
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + Duration::hours(1)),
            session_id: None,
            source: Some("human".to_string()),
            mission_id: None,
            conditions: None,
        };
        let payload = make_payload_for_agent(
            "mcp__external__tool",
            json!({}),
            Some("some-hash"),
            Some("cron-worker"),
        );
        let decision = evaluate(&config, &patterns, &[delegation], &payload);
        // Falls through to defaults (Ask)
        assert_eq!(decision.action, Action::Ask);
    }

    #[test]
    fn test_precedence_order() {
        let (config, patterns) = load_test_config_and_patterns();
        // A command that matches both blocked (--force) and restricted (rm)
        let payload = make_payload("Bash", json!({"command": "rm -rf /"}));
        let decision = evaluate(&config, &patterns, &[], &payload);
        // Blocked should win
        assert_eq!(decision.action, Action::Block);
    }

    #[test]
    fn test_default_fallback() {
        let (config, patterns) = load_test_config_and_patterns();
        // Unknown MCP tool
        let payload = make_payload("mcp__unknown__tool", json!({"arg": "value"}));
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(decision.action, Action::Ask);
        assert_eq!(decision.matched_rule, Some("defaults".to_string()));
    }

    #[test]
    fn test_glob_match_exact_extension() {
        assert!(glob_match("*.env", "/project/.env"));
        assert!(glob_match("*.env", "/project/local.env"));
        assert!(!glob_match("*.env", "/project/.env.production"));
        assert!(!glob_match("*.env", "/project/.env.backup"));
    }

    #[test]
    fn test_glob_match_contains() {
        assert!(glob_match("*credentials*", "/project/credentials.json"));
        assert!(glob_match("*credentials*", "/project/aws_credentials"));
        assert!(glob_match(
            "*credentials*",
            "/project/my-credentials-file.txt"
        ));
    }

    #[test]
    fn test_glob_match_exact_filename() {
        assert!(glob_match("*.key", "/project/server.key"));
        assert!(!glob_match("*.key", "/project/server.keystore"));
    }

    #[test]
    fn test_path_not_match_env_production() {
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload(
            "Write",
            json!({"file_path": "/Users/test/project/.env.production"}),
        );
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(decision.action, Action::AutoApprove);
    }

    #[test]
    fn test_path_traversal_blocked() {
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload(
            "Write",
            json!({"file_path": "/Users/test/project/src/../../etc/passwd"}),
        );
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(decision.action, Action::Ask);
    }

    #[test]
    fn test_malformed_input() {
        let (config, patterns) = load_test_config_and_patterns();
        // Bash tool with no "command" field
        let payload = make_payload("Bash", json!({"wrong_field": "value"}));
        let decision = evaluate(&config, &patterns, &[], &payload);
        // bash_pattern won't match empty command -> falls through trust_circle
        // restricted bash_pattern also won't match -> falls to default
        assert_eq!(decision.action, Action::Ask);
    }

    #[test]
    fn test_delegation_session_id_filtering() {
        let (config, patterns) = load_test_config_and_patterns();

        // Delegation scoped to session "sess_A"
        let delegation = RuntimeDelegation {
            tool: "Bash".to_string(),
            agent_id: None,
            action: Action::AutoApprove,
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + Duration::hours(4)),
            session_id: Some("sess_A".to_string()),
            source: None,
            mission_id: None,
            conditions: None,
        };

        // Payload from same session → should match
        let mut payload_a = make_payload("Bash", json!({"command": "rm -r /tmp/foo"}));
        payload_a.session_id = "sess_A".to_string();
        let decision = evaluate(
            &config,
            &patterns,
            std::slice::from_ref(&delegation),
            &payload_a,
        );
        assert_eq!(
            decision.action,
            Action::AutoApprove,
            "same session should match delegation"
        );

        // Payload from different session → should NOT match
        let mut payload_b = make_payload("Bash", json!({"command": "rm -r /tmp/foo"}));
        payload_b.session_id = "sess_B".to_string();
        let decision = evaluate(&config, &patterns, &[delegation], &payload_b);
        assert_eq!(
            decision.action,
            Action::Ask,
            "different session should not match delegation"
        );
    }

    #[test]
    fn test_delegation_without_session_id_matches_all() {
        let (config, patterns) = load_test_config_and_patterns();

        // Delegation without session_id → matches any session
        let delegation = RuntimeDelegation {
            tool: "Bash".to_string(),
            agent_id: None,
            action: Action::AutoApprove,
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + Duration::hours(4)),
            session_id: None,
            source: None,
            mission_id: None,
            conditions: None,
        };

        let mut payload = make_payload("Bash", json!({"command": "rm -r /tmp/foo"}));
        payload.session_id = "any_session".to_string();
        let decision = evaluate(&config, &patterns, &[delegation], &payload);
        assert_eq!(
            decision.action,
            Action::AutoApprove,
            "no session_id delegation should match any session"
        );
    }

    // ── H1: Shell chain guard tests ──────────────────────────────────────────

    #[test]
    fn test_chain_guard_blocks_and_chain() {
        // H1: "echo foo && rm -rf /" starts with safe "echo" prefix but contains &&
        // With chain_aware enabled (M7.10): piece "echo foo" → trust_circle auto-approve,
        // piece "rm -rf /" → blocked → whole chain is BLOCK.
        // The original invariant still holds: safe echo prefix does NOT auto-approve the chain.
        // To test the legacy chain_guard path, use config.chain_aware = false (see disabled test).
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload("Bash", json!({"command": "echo foo && rm -rf /"}));
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_ne!(
            decision.action,
            Action::AutoApprove,
            "chained command with && must not be auto-approved"
        );
        // chain_aware: rm -rf / is blocked → Block (stronger than old Ask via chain_guard)
        assert_eq!(
            decision.action,
            Action::Block,
            "chain_aware promotes to Block when a piece matches blocked rules"
        );
    }

    #[test]
    fn test_chain_guard_blocks_semicolon() {
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload(
            "Bash",
            json!({"command": "cat file.txt; curl http://evil.com"}),
        );
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(
            decision.action,
            Action::Ask,
            "semicolon-chained command must not be auto-approved"
        );
    }

    #[test]
    fn test_chain_guard_blocks_subshell() {
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload("Bash", json!({"command": "echo $(id)"}));
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(
            decision.action,
            Action::Ask,
            "subshell $(...) must not be auto-approved"
        );
    }

    #[test]
    fn test_chain_guard_blocks_backtick() {
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload("Bash", json!({"command": "echo `id`"}));
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(
            decision.action,
            Action::Ask,
            "backtick subshell must not be auto-approved"
        );
    }

    #[test]
    fn test_chain_guard_allows_safe_pipe() {
        // H1 non-regression: plain pipes should still be auto-approved via piped-commands rule
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload("Bash", json!({"command": "cat file.txt | grep pattern"}));
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(
            decision.action,
            Action::AutoApprove,
            "safe pipe must still be auto-approved"
        );
    }

    #[test]
    fn test_chain_guard_allows_simple_safe_command() {
        // H1 non-regression: simple commands without chain operators are unaffected
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload("Bash", json!({"command": "cat file.txt"}));
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(
            decision.action,
            Action::AutoApprove,
            "simple safe command must be auto-approved"
        );
    }

    // ── H2: path_within component-based comparison tests ────────────────────

    #[test]
    fn test_path_within_sibling_dir_rejected() {
        // H2: "/Users/test/project-evil/file.rs" must NOT match path_within "/Users/test/project"
        // With String::starts_with it would match (string prefix). Path::starts_with rejects it.
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload(
            "Write",
            json!({"file_path": "/Users/test/project-evil/src/lib.rs"}),
        );
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_ne!(
            decision.action,
            Action::AutoApprove,
            "sibling directory must not be auto-approved"
        );
    }

    #[test]
    fn test_path_within_exact_project_allowed() {
        // H2 non-regression: exact project path still works
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload(
            "Write",
            json!({"file_path": "/Users/test/project/src/lib.rs"}),
        );
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(
            decision.action,
            Action::AutoApprove,
            "exact project path must be auto-approved"
        );
    }

    // ── Finding #4/#6: Bash blocked regex for critical config files ─────────

    #[test]
    fn test_bash_block_audit_log_truncate() {
        // Finding #4 (DREAD 7.6): Bash commands targeting audit.log must be blocked
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload("Bash", json!({"command": "truncate -s 0 config/audit.log"}));
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(
            decision.action,
            Action::Block,
            "truncate audit.log must be blocked"
        );
    }

    #[test]
    fn test_bash_block_audit_log_sed() {
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload(
            "Bash",
            json!({"command": "sed -i '/DENY/d' config/audit.log"}),
        );
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(
            decision.action,
            Action::Block,
            "sed on audit.log must be blocked"
        );
    }

    #[test]
    fn test_bash_block_elo_overrides_redirect() {
        // Finding #6: destructive redirect targeting elo-overrides must be blocked
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload(
            "Bash",
            json!({"command": "jq '.' /tmp/x > config/elo-overrides.json"}),
        );
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(
            decision.action,
            Action::Block,
            "redirect to elo-overrides.json must be blocked"
        );
    }

    #[test]
    fn test_bash_allow_jq_readonly_elo_overrides() {
        // jq without redirect is read-only — should NOT be blocked
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload(
            "Bash",
            json!({"command": "jq '.pentester' config/elo-overrides.json"}),
        );
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_ne!(
            decision.action,
            Action::Block,
            "read-only jq should not be blocked"
        );
    }

    #[test]
    fn test_bash_block_revoked_missions() {
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload(
            "Bash",
            json!({"command": "echo '[]' > config/revoked-missions.json"}),
        );
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(
            decision.action,
            Action::Block,
            "writing to revoked-missions.json via Bash must be blocked"
        );
    }

    #[test]
    fn test_bash_block_trust_firewall_yaml() {
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload(
            "Bash",
            json!({"command": "python3 -c 'open(\"trust-firewall.yaml\",\"w\").write(\"\")'"}),
        );
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(
            decision.action,
            Action::Block,
            "python writing trust-firewall.yaml must be blocked"
        );
    }

    #[test]
    fn test_bash_block_runtime_delegations() {
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload(
            "Bash",
            json!({"command": "cat malicious.json > config/runtime-delegations.json"}),
        );
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(
            decision.action,
            Action::Block,
            "overwriting runtime-delegations.json via Bash must be blocked"
        );
    }

    #[test]
    fn test_bash_block_alerts_json() {
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload("Bash", json!({"command": "rm config/alerts.json"}));
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(
            decision.action,
            Action::Block,
            "removing alerts.json via Bash must be blocked"
        );
    }

    #[test]
    fn test_bash_block_reviews_dir() {
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload("Bash", json!({"command": "rm -r config/reviews/pending/"}));
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(
            decision.action,
            Action::Block,
            "removing reviews/ dir via Bash must be blocked"
        );
    }

    #[test]
    fn test_bash_block_findings_dir() {
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload("Bash", json!({"command": "find config/findings/ -delete"}));
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(
            decision.action,
            Action::Block,
            "deleting findings/ via Bash must be blocked"
        );
    }

    #[test]
    fn test_bash_safe_commands_still_work() {
        // Non-regression: normal safe commands must not be blocked by config protection regex
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload("Bash", json!({"command": "cat src/main.rs"}));
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(
            decision.action,
            Action::AutoApprove,
            "cat on normal file must still be auto-approved"
        );
    }

    // ── Finding #15: Quote-aware chain guard ────────────────────────────────

    #[test]
    fn test_chain_guard_ignores_semicolon_in_double_quotes() {
        // Finding #15 (DREAD 5.6): operators inside quotes should not trigger chain guard
        assert!(
            !contains_shell_chain("echo \"a;b\""),
            "semicolon inside double quotes should not trigger"
        );
    }

    #[test]
    fn test_chain_guard_ignores_ampersand_in_single_quotes() {
        assert!(
            !contains_shell_chain("echo 'a && b'"),
            "&& inside single quotes should not trigger"
        );
    }

    #[test]
    fn test_chain_guard_ignores_subshell_in_quotes() {
        assert!(
            !contains_shell_chain("echo \"$(date)\""),
            "$() inside double quotes should not trigger"
        );
    }

    #[test]
    fn test_chain_guard_detects_semicolon_outside_quotes() {
        // Non-regression: real operators outside quotes must still be detected
        assert!(
            contains_shell_chain("echo \"safe\"; rm -rf /"),
            "semicolon outside quotes must trigger"
        );
    }

    #[test]
    fn test_chain_guard_detects_ampersand_outside_quotes() {
        assert!(
            contains_shell_chain("echo 'safe' && rm -rf /"),
            "&& outside quotes must trigger"
        );
    }

    #[test]
    fn test_chain_guard_unmatched_quote_conservative() {
        // Unmatched quote: conservative — the trailing content remains and is checked
        assert!(
            contains_shell_chain("echo \"unterminated; rm -rf /"),
            "unmatched quote should be conservative"
        );
    }

    #[test]
    fn test_chain_guard_grep_semicolon_pattern() {
        // Real use case: grep for semicolon in code
        assert!(
            !contains_shell_chain("grep \";\" file.txt"),
            "grep for semicolon in quotes should not trigger"
        );
    }

    #[test]
    fn test_chain_guard_echo_ampersand_string() {
        // Real use case: echo a string containing &&
        assert!(
            !contains_shell_chain("echo \"test && done\""),
            "echo with && in quotes should not trigger"
        );
    }

    // ── Finding #3: Unicode homoglyph normalization ─────────────────────────

    #[test]
    fn test_chain_guard_unicode_greek_semicolon() {
        // Finding #3 (DREAD 5.2): Greek question mark (U+037E) looks like ';'
        let cmd = "echo foo\u{037E} rm -rf /";
        assert!(
            contains_shell_chain(cmd),
            "Greek question mark U+037E must be normalized to semicolon"
        );
    }

    #[test]
    fn test_chain_guard_unicode_fullwidth_ampersand() {
        // Fullwidth ampersand (U+FF06) pair as &&
        let cmd = "echo foo \u{FF06}\u{FF06} rm -rf /";
        assert!(
            contains_shell_chain(cmd),
            "Fullwidth ampersands must be normalized to &&"
        );
    }

    #[test]
    fn test_chain_guard_unicode_fullwidth_dollar() {
        // Fullwidth dollar sign (U+FF04) + (
        let cmd = "echo \u{FF04}(id)";
        assert!(
            contains_shell_chain(cmd),
            "Fullwidth dollar sign must be normalized to $"
        );
    }

    #[test]
    fn test_chain_guard_unicode_fullwidth_backtick() {
        // Fullwidth grave accent (U+FF40)
        let cmd = "echo \u{FF40}id\u{FF40}";
        assert!(
            contains_shell_chain(cmd),
            "Fullwidth backtick must be normalized"
        );
    }

    #[test]
    fn test_chain_guard_normal_ascii_unaffected_by_normalize() {
        // Non-regression: normal ASCII commands must work the same
        assert!(
            !contains_shell_chain("ls -la"),
            "normal command should not trigger after normalization"
        );
        assert!(
            contains_shell_chain("echo foo && bar"),
            "normal && should still trigger after normalization"
        );
    }

    #[test]
    fn test_strip_quoted_regions_basic() {
        assert_eq!(strip_quoted_regions("echo \"a;b\" foo"), "echo   foo");
        assert_eq!(strip_quoted_regions("echo 'a&&b' foo"), "echo   foo");
    }

    #[test]
    fn test_normalize_unicode_operators_basic() {
        assert_eq!(normalize_unicode_operators("foo\u{037E}bar"), "foo;bar");
        assert_eq!(
            normalize_unicode_operators("foo\u{FF06}\u{FF06}bar"),
            "foo&&bar"
        );
    }

    // ── is_bare_assignment tests (M7.10) ────────────────────────────────────

    #[test]
    fn test_bare_assignment_simple() {
        assert!(is_bare_assignment("TOKEN=abc"));
        assert!(is_bare_assignment("SDK=/path/to/sdk"));
        assert!(is_bare_assignment("FOO_BAR=value123"));
    }

    #[test]
    fn test_bare_assignment_quoted() {
        assert!(is_bare_assignment("TOKEN=\"some value\""));
        assert!(is_bare_assignment("PATH='abc:def'"));
    }

    #[test]
    fn test_bare_assignment_rejects_command() {
        assert!(!is_bare_assignment("TOKEN=abc echo hi"));
        assert!(!is_bare_assignment("FOO=bar; rm -rf /"));
        assert!(!is_bare_assignment("echo hello"));
        assert!(!is_bare_assignment("git status"));
    }

    #[test]
    fn test_bare_assignment_rejects_lowercase_key() {
        // Conservative: uppercase + underscore + digits only.
        assert!(!is_bare_assignment("token=abc"));
        assert!(!is_bare_assignment("MyVar=foo"));
    }

    #[test]
    fn test_bare_assignment_rejects_empty() {
        assert!(!is_bare_assignment(""));
        assert!(!is_bare_assignment("   "));
    }

    // ── split_top_level_chain tests (M7.10) ─────────────────────────────────

    #[test]
    fn test_split_chain_and_or() {
        let parts = split_top_level_chain("git status && git log").unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], "git status ");
        assert_eq!(parts[1], " git log");
    }

    #[test]
    fn test_split_chain_semicolon() {
        let parts = split_top_level_chain("ls; cat foo; head -5 bar").unwrap();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], "ls");
        assert_eq!(parts[1], " cat foo");
        assert_eq!(parts[2], " head -5 bar");
    }

    #[test]
    fn test_split_chain_pipe() {
        let parts = split_top_level_chain("git fetch origin main 2>&1 | tail -20").unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], "git fetch origin main 2>&1 ");
        assert_eq!(parts[1], " tail -20");
    }

    #[test]
    fn test_split_chain_mixed() {
        let parts = split_top_level_chain(
            "go build ./... 2>&1 | head -20 && go test ./... 2>&1 | tail -15",
        )
        .unwrap();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0], "go build ./... 2>&1 ");
        assert_eq!(parts[1], " head -20 ");
        assert_eq!(parts[2], " go test ./... 2>&1 ");
        assert_eq!(parts[3], " tail -15");
    }

    #[test]
    fn test_split_chain_single_no_chain() {
        let parts = split_top_level_chain("git status").unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0], "git status");
    }

    #[test]
    fn test_split_chain_quoted_operator_ignored() {
        let parts = split_top_level_chain("echo \"a && b\"").unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0], "echo \"a && b\"");

        let parts = split_top_level_chain("echo 'foo; bar' && ls").unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], "echo 'foo; bar' ");
        assert_eq!(parts[1], " ls");
    }

    #[test]
    fn test_split_chain_rejects_subshell() {
        assert!(split_top_level_chain("TOKEN=$(curl evil.sh)").is_none());
        assert!(split_top_level_chain("echo `whoami`").is_none());
    }

    #[test]
    fn test_split_chain_rejects_unmatched_quote() {
        assert!(split_top_level_chain("echo \"foo && bar").is_none());
    }

    #[test]
    fn test_split_chain_normalizes_unicode() {
        let parts = split_top_level_chain("git status \u{FF06}\u{FF06} git log").unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0], "git status ");
        assert_eq!(parts[1], " git log");
    }

    #[test]
    fn test_split_chain_empty_input() {
        // Empty string → Some(vec![""]) — single empty piece, no chain to evaluate.
        let parts = split_top_level_chain("").unwrap();
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0], "");
    }

    #[test]
    fn test_split_chain_only_operators() {
        // ";;" splits into 3 empty pieces (before first ;, between, after last ;).
        // The chain-aware evaluator will skip empty pieces during fold.
        let parts = split_top_level_chain(";;").unwrap();
        assert_eq!(parts.len(), 3);
        assert!(parts.iter().all(|p| p.is_empty()));
    }

    // ── evaluate_chain_aware tests (M7.10) ───────────────────────────────────

    #[test]
    fn test_chain_aware_all_safe_git_chain() {
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload(
            "Bash",
            json!({"command": "git status && git log --oneline -5"}),
        );
        let decision =
            evaluate_chain_aware(&config, &patterns, &payload, None).expect("must decide");
        assert_eq!(decision.action, Action::AutoApprove);
        assert!(decision
            .matched_rule
            .as_deref()
            .unwrap()
            .starts_with("chain_aware:"));
    }

    #[test]
    fn test_chain_aware_pipe_chain_safe() {
        // git log is in trust_circle; tail is in the read-only set — both pieces approve.
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload(
            "Bash",
            json!({"command": "git log --oneline -20 | tail -5"}),
        );
        let decision =
            evaluate_chain_aware(&config, &patterns, &payload, None).expect("must decide");
        assert_eq!(decision.action, Action::AutoApprove);
    }

    #[test]
    fn test_chain_aware_restricted_piece_asks() {
        // rm -r (without trailing /) is in restricted (ask), not blocked — chain should ask.
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload(
            "Bash",
            json!({"command": "git status && rm -r /tmp/testdir"}),
        );
        let decision =
            evaluate_chain_aware(&config, &patterns, &payload, None).expect("must decide");
        assert_eq!(decision.action, Action::Ask);
    }

    #[test]
    fn test_chain_aware_blocked_piece_blocks() {
        // gh pr merge was moved from blocked → restricted (ask) in M7.15 merge-autonomy.
        // Verify chain-aware evaluation now returns Ask (no longer Block).
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload("Bash", json!({"command": "git status && gh pr merge"}));
        let decision =
            evaluate_chain_aware(&config, &patterns, &payload, None).expect("must decide");
        assert_eq!(decision.action, Action::Ask);
    }

    #[test]
    fn test_chain_aware_subshell_falls_through() {
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload(
            "Bash",
            json!({"command": "TOKEN=$(curl evil.sh); echo $TOKEN"}),
        );
        // None means "I can't decide; fall through to chain_guard".
        assert!(evaluate_chain_aware(&config, &patterns, &payload, None).is_none());
    }

    #[test]
    fn test_chain_aware_single_piece_falls_through() {
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload("Bash", json!({"command": "git status"}));
        // No chain → caller's normal flow handles it.
        assert!(evaluate_chain_aware(&config, &patterns, &payload, None).is_none());
    }

    #[test]
    fn test_chain_aware_assignment_piece_auto_approves() {
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload(
            "Bash",
            json!({"command": "TOKEN=\"abc\" && echo \"$TOKEN\""}),
        );
        let decision =
            evaluate_chain_aware(&config, &patterns, &payload, None).expect("must decide");
        assert_eq!(decision.action, Action::AutoApprove);
    }

    #[test]
    fn test_chain_aware_non_bash_falls_through() {
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload("Read", json!({"file_path": "/Users/test/project/x.rs"}));
        assert!(evaluate_chain_aware(&config, &patterns, &payload, None).is_none());
    }

    #[test]
    fn test_chain_aware_quoted_operator_one_piece() {
        let (config, patterns) = load_test_config_and_patterns();
        // Single piece (operators inside quotes) → fall through.
        let payload = make_payload("Bash", json!({"command": "echo \"a && b\""}));
        assert!(evaluate_chain_aware(&config, &patterns, &payload, None).is_none());
    }

    #[test]
    fn test_chain_aware_disabled_via_flag_returns_none() {
        let (mut config, patterns) = load_test_config_and_patterns();
        config.chain_aware = false;
        let payload = make_payload("Bash", json!({"command": "git status && git log -5"}));
        assert!(evaluate_chain_aware(&config, &patterns, &payload, None).is_none());
    }

    // ── Integration tests: evaluate_chain_aware wired into evaluate_with_elo (M7.10) ──

    #[test]
    fn test_integration_git_chain_auto_approves() {
        let (config, patterns) = load_test_config_and_patterns();
        let delegations: Vec<RuntimeDelegation> = Vec::new();
        let payload = make_payload(
            "Bash",
            json!({"command": "git status && git log --oneline -5"}),
        );
        let decision = evaluate(&config, &patterns, &delegations, &payload);
        assert_eq!(
            decision.action,
            Action::AutoApprove,
            "got {:?} reason={}",
            decision.action,
            decision.reason
        );
        assert!(decision
            .matched_rule
            .as_deref()
            .unwrap_or("")
            .starts_with("chain_aware:"));
    }

    #[test]
    fn test_integration_dangerous_chain_falls_to_ask() {
        let (config, patterns) = load_test_config_and_patterns();
        let delegations: Vec<RuntimeDelegation> = Vec::new();
        let payload = make_payload(
            "Bash",
            json!({"command": "git status && rm -r /tmp/testdir"}),
        );
        let decision = evaluate(&config, &patterns, &delegations, &payload);
        assert_eq!(decision.action, Action::Ask);
    }

    #[test]
    fn test_integration_subshell_still_asks_via_chain_guard() {
        let (config, patterns) = load_test_config_and_patterns();
        let delegations: Vec<RuntimeDelegation> = Vec::new();
        let payload = make_payload(
            "Bash",
            json!({"command": "TOKEN=$(curl evil.sh); echo $TOKEN"}),
        );
        let decision = evaluate(&config, &patterns, &delegations, &payload);
        assert_eq!(decision.action, Action::Ask);
        assert_eq!(decision.matched_rule.as_deref(), Some("chain_guard"));
    }

    #[test]
    fn test_integration_chain_aware_disabled_falls_back_to_chain_guard() {
        let (mut config, patterns) = load_test_config_and_patterns();
        config.chain_aware = false;
        let delegations: Vec<RuntimeDelegation> = Vec::new();
        let payload = make_payload(
            "Bash",
            json!({"command": "git status && git log --oneline -5"}),
        );
        let decision = evaluate(&config, &patterns, &delegations, &payload);
        // Pre-M7.10 behaviour: chain_guard catches the && and asks.
        assert_eq!(decision.action, Action::Ask);
        assert_eq!(decision.matched_rule.as_deref(), Some("chain_guard"));
    }

    #[test]
    fn test_integration_pipe_chain_auto_approves() {
        let (config, patterns) = load_test_config_and_patterns();
        let delegations: Vec<RuntimeDelegation> = Vec::new();
        let payload = make_payload(
            "Bash",
            json!({"command": "find . -name \"*.rs\" | xargs grep -l fn"}),
        );
        let decision = evaluate(&config, &patterns, &delegations, &payload);
        assert_eq!(decision.action, Action::AutoApprove, "got {:?}", decision);
    }

    #[test]
    fn test_integration_blocked_piece_blocks_chain() {
        let (config, patterns) = load_test_config_and_patterns();
        let delegations: Vec<RuntimeDelegation> = Vec::new();
        let payload = make_payload("Bash", json!({"command": "git status && gh pr merge"}));
        let decision = evaluate(&config, &patterns, &delegations, &payload);
        // gh pr merge moved from blocked → restricted (ask) in M7.15 merge-autonomy
        assert_eq!(decision.action, Action::Ask);
    }

    #[test]
    fn test_integration_cd_in_chain_auto_approves() {
        let (config, patterns) = load_test_config_and_patterns();
        let delegations: Vec<RuntimeDelegation> = Vec::new();
        let payload = make_payload(
            "Bash",
            json!({"command": "cd /Users/test/project && ls -la"}),
        );
        let decision = evaluate(&config, &patterns, &delegations, &payload);
        assert_eq!(decision.action, Action::AutoApprove);
    }

    #[test]
    fn test_integration_go_build_test_chain_auto_approves() {
        let (config, patterns) = load_test_config_and_patterns();
        let delegations: Vec<RuntimeDelegation> = Vec::new();
        let payload = make_payload(
            "Bash",
            json!({"command": "go build ./... 2>&1 | head -20 && go test ./... 2>&1 | tail -15"}),
        );
        let decision = evaluate(&config, &patterns, &delegations, &payload);
        assert_eq!(
            decision.action,
            Action::AutoApprove,
            "got {:?} reason={}",
            decision.action,
            decision.reason
        );
    }
}
