use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Action to take when a rule matches.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    AutoApprove,
    Ask,
    Block,
}

/// Conditions that must all be satisfied for a rule to match.
#[derive(Debug, Clone, Deserialize)]
pub struct Conditions {
    /// Regex pattern matched against Bash tool_input["command"].
    pub bash_pattern: Option<String>,
    /// File path must start with one of these directories.
    pub path_within: Option<Vec<String>>,
    /// File path must NOT match any of these glob patterns.
    pub path_not_match: Option<Vec<String>>,
}

/// A single firewall rule.
#[derive(Debug, Clone, Deserialize)]
pub struct Rule {
    pub tools: Vec<String>,
    pub conditions: Option<Conditions>,
    pub action: Action,
    pub reason: Option<String>,
}

/// Default action configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct Defaults {
    pub action: Action,
}

/// Notification settings.
#[derive(Debug, Clone, Deserialize)]
pub struct NotificationsConfig {
    pub enabled: bool,
}

/// Top-level firewall configuration loaded from trust-firewall.yaml.
#[derive(Debug, Clone, Deserialize)]
pub struct FirewallConfig {
    pub version: u32,
    pub defaults: Defaults,
    #[serde(default)]
    pub trust_circle: Vec<Rule>,
    #[serde(default)]
    pub restricted: Vec<Rule>,
    #[serde(default)]
    pub blocked: Vec<Rule>,
    #[serde(default)]
    pub agent_overrides: HashMap<String, Vec<Rule>>,
    pub notifications: Option<NotificationsConfig>,
}

/// Load and parse the firewall config from a YAML file.
/// Resolves `${PROJECT_DIR}` placeholders in path_within values against the given `cwd`.
pub fn load_config(path: &Path, cwd: &str) -> Result<FirewallConfig> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config file: {}", path.display()))?;

    let mut config: FirewallConfig = serde_yml::from_str(&contents)
        .with_context(|| format!("Failed to parse config file: {}", path.display()))?;

    resolve_project_dir(&mut config, cwd);
    Ok(config)
}

/// Pre-compiled regex patterns for all rules. Keyed by "{tier}[{index}]".
pub type CompiledPatterns = HashMap<String, Regex>;

/// Compile regex patterns (bash_pattern) for a slice of rules into the patterns map.
/// Keys are formatted as `"{tier_prefix}[{index}]"` matching the format used by `check_rules`.
/// Returns an error if any pattern is invalid, naming the exact rule.
pub fn compile_rules(rules: &[Rule], tier_prefix: &str, patterns: &mut CompiledPatterns) -> Result<()> {
    for (i, rule) in rules.iter().enumerate() {
        if let Some(ref cond) = rule.conditions {
            if let Some(ref pat) = cond.bash_pattern {
                let compiled = Regex::new(pat)
                    .with_context(|| format!("Invalid regex in {tier_prefix}[{i}]: {pat}"))?;
                patterns.insert(format!("{tier_prefix}[{i}]"), compiled);
            }
        }
    }
    Ok(())
}

/// Compile and validate all regex patterns in the config.
/// Returns an error if any pattern is invalid, naming the exact rule.
pub fn compile_config(config: &FirewallConfig) -> Result<CompiledPatterns> {
    let mut patterns = CompiledPatterns::new();

    compile_rules(&config.blocked, "blocked", &mut patterns)?;
    compile_rules(&config.restricted, "restricted", &mut patterns)?;
    compile_rules(&config.trust_circle, "trust_circle", &mut patterns)?;

    for (agent_id, rules) in &config.agent_overrides {
        compile_rules(rules, &format!("agent_override:{agent_id}"), &mut patterns)?;
    }

    Ok(patterns)
}

/// Known Claude Code tool names. MCP tools (mcp__*) are always valid.
const KNOWN_TOOLS: &[&str] = &[
    "Agent", "Bash", "Edit", "Glob", "Grep", "Read", "Write",
    "WebFetch", "WebSearch", "NotebookEdit",
    "AskUserQuestion", "EnterPlanMode", "ExitPlanMode",
    "EnterWorktree", "ExitWorktree",
    "TaskCreate", "TaskUpdate", "TaskGet", "TaskList", "TaskOutput", "TaskStop",
    "SendMessage", "Skill", "ToolSearch",
];

/// Check all tool names in the config against known tools.
/// Returns a list of warnings for unrecognized tool names.
/// MCP tools (prefixed with `mcp__`) are always accepted.
pub fn validate_tool_names(config: &FirewallConfig) -> Vec<String> {
    let mut warnings = Vec::new();

    let check_rules = |rules: &[Rule], tier: &str, warnings: &mut Vec<String>| {
        for (i, rule) in rules.iter().enumerate() {
            for tool in &rule.tools {
                if !tool.starts_with("mcp__") && !KNOWN_TOOLS.contains(&tool.as_str()) {
                    warnings.push(format!(
                        "Unknown tool '{}' in {tier}[{i}] — known tools: {:?}",
                        tool, KNOWN_TOOLS
                    ));
                }
            }
        }
    };

    check_rules(&config.trust_circle, "trust_circle", &mut warnings);
    check_rules(&config.restricted, "restricted", &mut warnings);
    check_rules(&config.blocked, "blocked", &mut warnings);
    for (agent_id, rules) in &config.agent_overrides {
        check_rules(rules, &format!("agent_override:{agent_id}"), &mut warnings);
    }

    warnings
}

/// Validate a single tool name. Returns warnings if unknown.
pub fn validate_tool_name_single(tool: &str) -> Vec<String> {
    if !tool.starts_with("mcp__") && !KNOWN_TOOLS.contains(&tool) {
        vec![format!("Unknown tool '{}' — known tools: {:?}", tool, KNOWN_TOOLS)]
    } else {
        vec![]
    }
}

/// Replace `${PROJECT_DIR}` with the actual cwd in all path_within values.
fn resolve_project_dir(config: &mut FirewallConfig, cwd: &str) {
    let resolve_rules = |rules: &mut [Rule]| {
        for rule in rules.iter_mut() {
            if let Some(ref mut conditions) = rule.conditions {
                if let Some(ref mut paths) = conditions.path_within {
                    for p in paths.iter_mut() {
                        *p = p.replace("${PROJECT_DIR}", cwd);
                    }
                }
            }
        }
    };

    resolve_rules(&mut config.trust_circle);
    resolve_rules(&mut config.restricted);
    resolve_rules(&mut config.blocked);

    for rules in config.agent_overrides.values_mut() {
        resolve_rules(rules);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_deserialize_kebab_case() {
        let yaml = "auto-approve";
        let action: Action = serde_yml::from_str(yaml).unwrap();
        assert_eq!(action, Action::AutoApprove);

        let yaml = "ask";
        let action: Action = serde_yml::from_str(yaml).unwrap();
        assert_eq!(action, Action::Ask);

        let yaml = "block";
        let action: Action = serde_yml::from_str(yaml).unwrap();
        assert_eq!(action, Action::Block);
    }

    #[test]
    fn test_rule_deserialize() {
        let yaml = r#"
tools: [Read, Glob, Grep]
action: auto-approve
reason: "Read-only operations"
"#;
        let rule: Rule = serde_yml::from_str(yaml).unwrap();
        assert_eq!(rule.tools, vec!["Read", "Glob", "Grep"]);
        assert_eq!(rule.action, Action::AutoApprove);
        assert!(rule.conditions.is_none());
        assert_eq!(rule.reason, Some("Read-only operations".to_string()));
    }

    #[test]
    fn test_rule_with_conditions() {
        let yaml = r#"
tools: [Write, Edit]
conditions:
  path_within: ["${PROJECT_DIR}"]
  path_not_match: ["*.env", "*credentials*"]
action: auto-approve
"#;
        let rule: Rule = serde_yml::from_str(yaml).unwrap();
        let cond = rule.conditions.unwrap();
        assert_eq!(cond.path_within, Some(vec!["${PROJECT_DIR}".to_string()]));
        assert_eq!(
            cond.path_not_match,
            Some(vec!["*.env".to_string(), "*credentials*".to_string()])
        );
    }

    #[test]
    fn test_load_config_from_file() {
        let config_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../config/trust-firewall.yaml");
        let config = load_config(&config_path, "/Users/test/project").unwrap();

        assert_eq!(config.version, 1);
        assert_eq!(config.defaults.action, Action::Ask);
        assert!(!config.trust_circle.is_empty());
        assert!(!config.restricted.is_empty());
        assert!(!config.blocked.is_empty());
    }

    #[test]
    fn test_compile_config_rejects_bad_regex() {
        let config = FirewallConfig {
            version: 1,
            defaults: Defaults { action: Action::Ask },
            trust_circle: vec![],
            restricted: vec![],
            blocked: vec![Rule {
                tools: vec!["Bash".to_string()],
                conditions: Some(Conditions {
                    bash_pattern: Some("(?P<broken>".to_string()),
                    path_within: None,
                    path_not_match: None,
                }),
                action: Action::Block,
                reason: Some("test".to_string()),
            }],
            agent_overrides: HashMap::new(),
            notifications: None,
        };
        let result = compile_config(&config);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("blocked[0]"));
    }

    #[test]
    fn test_validate_tool_names_catches_typos() {
        let config = FirewallConfig {
            version: 1,
            defaults: Defaults { action: Action::Ask },
            trust_circle: vec![Rule {
                tools: vec!["Raed".to_string()],
                conditions: None,
                action: Action::AutoApprove,
                reason: None,
            }],
            restricted: vec![],
            blocked: vec![],
            agent_overrides: HashMap::new(),
            notifications: None,
        };
        let warnings = validate_tool_names(&config);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("Raed"));
    }

    #[test]
    fn test_validate_tool_names_accepts_known() {
        let config = FirewallConfig {
            version: 1,
            defaults: Defaults { action: Action::Ask },
            trust_circle: vec![Rule {
                tools: vec!["Read".to_string(), "Write".to_string(), "Bash".to_string()],
                conditions: None,
                action: Action::AutoApprove,
                reason: None,
            }],
            restricted: vec![],
            blocked: vec![],
            agent_overrides: HashMap::new(),
            notifications: None,
        };
        let warnings = validate_tool_names(&config);
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_validate_tool_names_allows_mcp_prefix() {
        let config = FirewallConfig {
            version: 1,
            defaults: Defaults { action: Action::Ask },
            trust_circle: vec![],
            restricted: vec![Rule {
                tools: vec!["mcp__claude_ai_Slack__slack_send_message".to_string()],
                conditions: None,
                action: Action::Ask,
                reason: None,
            }],
            blocked: vec![],
            agent_overrides: HashMap::new(),
            notifications: None,
        };
        let warnings = validate_tool_names(&config);
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_project_dir_resolution() {
        let config_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../config/trust-firewall.yaml");
        let config = load_config(&config_path, "/Users/test/myproject").unwrap();

        // Find the Write/Edit rule with path_within
        let write_rule = config
            .trust_circle
            .iter()
            .find(|r| r.tools.contains(&"Write".to_string()))
            .expect("Should have a Write rule in trust_circle");

        let cond = write_rule.conditions.as_ref().unwrap();
        let paths = cond.path_within.as_ref().unwrap();
        assert!(paths.contains(&"/Users/test/myproject".to_string()));
        assert!(!paths.iter().any(|p| p.contains("${PROJECT_DIR}")));
    }
}
