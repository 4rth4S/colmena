use std::path::Path;

use anyhow::Result;

// ── Types ───────────────────────────────────────────────────────────────────

struct Check {
    category: &'static str,
    name: &'static str,
    status: Status,
}

enum Status {
    Ok(String),
    Warn(String),
    Err(String),
}

impl Check {
    fn ok(category: &'static str, name: &'static str, detail: impl Into<String>) -> Self {
        Self { category, name, status: Status::Ok(detail.into()) }
    }
    fn warn(category: &'static str, name: &'static str, detail: impl Into<String>) -> Self {
        Self { category, name, status: Status::Warn(detail.into()) }
    }
    fn err(category: &'static str, name: &'static str, detail: impl Into<String>) -> Self {
        Self { category, name, status: Status::Err(detail.into()) }
    }
}

// ── Entry point ─────────────────────────────────────────────────────────────

pub fn run_doctor() -> Result<()> {
    let version = env!("CARGO_PKG_VERSION");
    println!("Colmena Doctor (v{version})");
    println!("{}", "=".repeat(24 + version.len()));
    println!();

    let config_dir = colmena_core::paths::default_config_dir();

    let mut all: Vec<Check> = Vec::new();
    all.extend(check_environment(&config_dir));
    all.extend(check_config(&config_dir));
    all.extend(check_library(&config_dir));
    all.extend(check_hooks(&config_dir));
    all.extend(check_mcp());
    all.extend(check_runtime(&config_dir));
    all.extend(check_permissions(&config_dir));

    // Print grouped by category
    let mut current = "";
    for c in &all {
        if c.category != current {
            if !current.is_empty() {
                println!();
            }
            println!("{}:", c.category);
            current = c.category;
        }
        let (marker, detail) = match &c.status {
            Status::Ok(d) => ("OK", d.as_str()),
            Status::Warn(d) => ("WARN", d.as_str()),
            Status::Err(d) => ("ERR", d.as_str()),
        };
        println!("  [{marker:<4}] {} ({detail})", c.name);
    }

    // Summary
    let ok_n = all.iter().filter(|c| matches!(c.status, Status::Ok(_))).count();
    let warn_n = all.iter().filter(|c| matches!(c.status, Status::Warn(_))).count();
    let err_n = all.iter().filter(|c| matches!(c.status, Status::Err(_))).count();

    println!("\nSummary: {ok_n} ok, {warn_n} warnings, {err_n} errors");

    if err_n > 0 {
        println!("\nRun 'colmena setup' to fix common issues.");
        std::process::exit(1);
    }

    Ok(())
}

// ── 1. Environment ──────────────────────────────────────────────────────────

fn check_environment(config_dir: &Path) -> Vec<Check> {
    const CAT: &str = "Environment";
    let mut checks = Vec::new();

    // Version (always OK, informational)
    checks.push(Check::ok(CAT, "Version", env!("CARGO_PKG_VERSION")));

    // Colmena binary
    match std::env::current_exe() {
        Ok(exe) => checks.push(Check::ok(CAT, "Colmena binary", exe.display().to_string())),
        Err(e) => checks.push(Check::warn(CAT, "Colmena binary", format!("could not resolve: {e}"))),
    }

    // Mode detection
    let mode = detect_mode_label();
    checks.push(Check::ok(CAT, "Mode", mode));

    // Config directory
    if config_dir.is_dir() {
        checks.push(Check::ok(CAT, "Config directory", config_dir.display().to_string()));
    } else {
        checks.push(Check::err(CAT, "Config directory", format!("not found: {}", config_dir.display())));
    }

    // COLMENA_HOME env
    match std::env::var("COLMENA_HOME") {
        Ok(val) => {
            if Path::new(&val).is_dir() {
                checks.push(Check::ok(CAT, "COLMENA_HOME", val));
            } else {
                checks.push(Check::warn(CAT, "COLMENA_HOME", format!("set to '{val}' but directory does not exist")));
            }
        }
        Err(_) => checks.push(Check::ok(CAT, "COLMENA_HOME", "not set (using auto-detection)")),
    }

    // MCP binary
    match find_mcp_binary() {
        Some(p) => checks.push(Check::ok(CAT, "MCP binary", p.display().to_string())),
        None => checks.push(Check::warn(CAT, "MCP binary", "not found next to colmena binary")),
    }

    checks
}

/// Walk up from current_exe() looking for a workspace Cargo.toml containing colmena-core.
fn detect_mode_label() -> String {
    if let Ok(exe) = std::env::current_exe() {
        let mut dir = exe.as_path().parent();
        while let Some(d) = dir {
            let cargo_toml = d.join("Cargo.toml");
            if cargo_toml.exists() {
                if let Ok(contents) = std::fs::read_to_string(&cargo_toml) {
                    if contents.contains("[workspace]") && contents.contains("colmena-core") {
                        return format!("repo: {}", d.display());
                    }
                }
            }
            dir = d.parent();
        }
    }
    "standalone".to_string()
}

fn find_mcp_binary() -> Option<std::path::PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let mcp = dir.join("colmena-mcp");
            if mcp.exists() {
                return Some(mcp);
            }
        }
    }
    None
}

// ── 2. Config ───────────────────────────────────────────────────────────────

fn check_config(config_dir: &Path) -> Vec<Check> {
    const CAT: &str = "Config";
    let mut checks = Vec::new();

    // trust-firewall.yaml
    let firewall_path = config_dir.join("trust-firewall.yaml");
    match colmena_core::config::load_config(&firewall_path, "/tmp/doctor") {
        Ok(cfg) => {
            match colmena_core::config::compile_config(&cfg) {
                Ok(_) => {
                    checks.push(Check::ok(
                        CAT,
                        "trust-firewall.yaml",
                        format!(
                            "{} trust_circle, {} restricted, {} blocked",
                            cfg.trust_circle.len(),
                            cfg.restricted.len(),
                            cfg.blocked.len()
                        ),
                    ));

                    // Tool name validation
                    let warnings = colmena_core::config::validate_tool_names(&cfg);
                    if warnings.is_empty() {
                        checks.push(Check::ok(CAT, "Tool names", "all recognized"));
                    } else {
                        checks.push(Check::warn(
                            CAT,
                            "Tool names",
                            format!("{} unknown: {}", warnings.len(), warnings.join(", ")),
                        ));
                    }
                }
                Err(e) => {
                    checks.push(Check::err(CAT, "trust-firewall.yaml", format!("regex compile failed: {e}")));
                }
            }
        }
        Err(e) => {
            checks.push(Check::err(CAT, "trust-firewall.yaml", format!("{e}")));
        }
    }

    // filter-config.yaml
    let filter_path = config_dir.join("filter-config.yaml");
    if filter_path.exists() {
        match colmena_filter::config::load_filter_config(&filter_path) {
            Ok(fc) => {
                checks.push(Check::ok(
                    CAT,
                    "filter-config.yaml",
                    format!("enabled={}, max_lines={}", fc.enabled, fc.max_output_lines),
                ));
            }
            Err(e) => checks.push(Check::err(CAT, "filter-config.yaml", format!("{e}"))),
        }
    } else {
        checks.push(Check::warn(CAT, "filter-config.yaml", "not found, using defaults"));
    }

    // review-config.yaml (existence check — YAML validation done by core at runtime)
    let review_path = config_dir.join("review-config.yaml");
    if review_path.exists() {
        checks.push(Check::ok(CAT, "review-config.yaml", "present"));
    } else {
        checks.push(Check::warn(CAT, "review-config.yaml", "not found, using defaults"));
    }

    checks
}

// ── 3. Library ──────────────────────────────────────────────────────────────

fn check_library(config_dir: &Path) -> Vec<Check> {
    const CAT: &str = "Library";
    let mut checks = Vec::new();

    let library_dir = config_dir.join("library");
    if !library_dir.is_dir() {
        checks.push(Check::err(CAT, "Library directory", format!("not found: {}", library_dir.display())));
        return checks;
    }

    match (
        colmena_core::library::load_roles(&library_dir),
        colmena_core::library::load_patterns(&library_dir),
    ) {
        (Ok(roles), Ok(patterns)) => {
            let warnings = colmena_core::library::validate_library(&roles, &patterns, &library_dir);
            if warnings.is_empty() {
                checks.push(Check::ok(
                    CAT,
                    "Roles & patterns",
                    format!("{} roles, {} patterns", roles.len(), patterns.len()),
                ));
            } else {
                checks.push(Check::warn(
                    CAT,
                    "Roles & patterns",
                    format!(
                        "{} roles, {} patterns ({} warnings: {})",
                        roles.len(),
                        patterns.len(),
                        warnings.len(),
                        warnings.first().unwrap_or(&String::new())
                    ),
                ));
            }
        }
        (Err(e), _) | (_, Err(e)) => {
            checks.push(Check::err(CAT, "Roles & patterns", format!("{e}")));
        }
    }

    checks
}

// ── 4. Hooks ────────────────────────────────────────────────────────────────

fn check_hooks(config_dir: &Path) -> Vec<Check> {
    const CAT: &str = "Hooks";
    let mut checks = Vec::new();

    let settings_path = crate::install::settings_json_path();

    if !settings_path.exists() {
        checks.push(Check::err(CAT, "settings.json", format!("not found: {}", settings_path.display())));
        return checks;
    }

    let settings: serde_json::Value = match std::fs::read_to_string(&settings_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
    {
        Some(v) => {
            checks.push(Check::ok(CAT, "settings.json", "valid JSON"));
            v
        }
        None => {
            checks.push(Check::err(CAT, "settings.json", "invalid JSON or unreadable"));
            return checks;
        }
    };

    // Check PreToolUse
    let pre_registered = has_colmena_hook(&settings, "PreToolUse");
    if pre_registered {
        checks.push(Check::ok(CAT, "PreToolUse hook", "registered"));
    } else {
        checks.push(Check::err(CAT, "PreToolUse hook", "not registered"));
    }

    // Check PostToolUse
    let post_registered = has_colmena_hook(&settings, "PostToolUse");
    if post_registered {
        checks.push(Check::ok(CAT, "PostToolUse hook", "registered"));
    } else {
        checks.push(Check::err(CAT, "PostToolUse hook", "not registered"));
    }

    // Hook dry-run
    let binary_path = crate::install::colmena_binary_path();
    let binary = Path::new(&binary_path);
    if binary.exists() {
        let test_payload = r#"{"session_id":"doctor","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"/tmp/test"},"tool_use_id":"doctor","cwd":"/tmp"}"#;
        let config_flag = config_dir
            .join("trust-firewall.yaml")
            .to_string_lossy()
            .to_string();
        match std::process::Command::new(binary)
            .args(["hook", "--config", &config_flag])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write as _;
                child
                    .stdin
                    .take()
                    .unwrap()
                    .write_all(test_payload.as_bytes())
                    .unwrap();
                child.wait_with_output()
            }) {
            Ok(output) if output.status.success() => {
                checks.push(Check::ok(CAT, "Hook dry-run", "passed"));
            }
            Ok(output) => {
                checks.push(Check::warn(
                    CAT,
                    "Hook dry-run",
                    format!("exit {}", output.status.code().unwrap_or(-1)),
                ));
            }
            Err(e) => {
                checks.push(Check::warn(CAT, "Hook dry-run", format!("could not run: {e}")));
            }
        }
    } else {
        checks.push(Check::warn(CAT, "Hook dry-run", "binary not found, skipped"));
    }

    checks
}

/// Check if a "colmena hook" entry exists in a hook event array (PreToolUse or PostToolUse).
fn has_colmena_hook(settings: &serde_json::Value, event: &str) -> bool {
    let arr = match settings
        .get("hooks")
        .and_then(|h| h.get(event))
        .and_then(|a| a.as_array())
    {
        Some(a) => a,
        None => return false,
    };

    arr.iter().any(|entry| {
        // New format: { "matcher": "", "hooks": [{ "command": "..." }] }
        if let Some(inner_hooks) = entry.get("hooks").and_then(|h| h.as_array()) {
            inner_hooks.iter().any(|h| {
                h.get("command")
                    .and_then(|c| c.as_str())
                    .is_some_and(|c| c.contains("colmena hook"))
            })
        } else {
            // Legacy format: { "matcher": "", "command": "..." }
            entry
                .get("command")
                .and_then(|c| c.as_str())
                .is_some_and(|c| c.contains("colmena hook"))
        }
    })
}

// ── 5. MCP ──────────────────────────────────────────────────────────────────

fn check_mcp() -> Vec<Check> {
    const CAT: &str = "MCP";
    let mut checks = Vec::new();

    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => {
            checks.push(Check::err(CAT, "~/.mcp.json", "HOME not set"));
            return checks;
        }
    };
    let mcp_path = std::path::PathBuf::from(&home).join(".mcp.json");

    if !mcp_path.exists() {
        checks.push(Check::err(CAT, "~/.mcp.json", "not found"));
        return checks;
    }

    let mcp_config: serde_json::Value = match std::fs::read_to_string(&mcp_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
    {
        Some(v) => {
            checks.push(Check::ok(CAT, "~/.mcp.json", "valid JSON"));
            v
        }
        None => {
            checks.push(Check::err(CAT, "~/.mcp.json", "invalid JSON or unreadable"));
            return checks;
        }
    };

    // Check colmena server registration
    match mcp_config
        .get("mcpServers")
        .and_then(|s| s.get("colmena"))
    {
        Some(entry) => {
            match entry.get("command").and_then(|c| c.as_str()) {
                Some(cmd) => {
                    if Path::new(cmd).exists() {
                        checks.push(Check::ok(CAT, "colmena server", format!("registered, binary exists ({cmd})")));
                    } else {
                        checks.push(Check::err(
                            CAT,
                            "colmena server",
                            format!("registered but binary not found: {cmd}"),
                        ));
                    }
                }
                None => checks.push(Check::err(CAT, "colmena server", "registered but missing 'command' field")),
            }
        }
        None => checks.push(Check::err(CAT, "colmena server", "not registered in mcpServers")),
    }

    checks
}

// ── 6. Runtime State ────────────────────────────────────────────────────────

fn check_runtime(config_dir: &Path) -> Vec<Check> {
    const CAT: &str = "Runtime";
    let mut checks = Vec::new();

    // Delegations
    let deleg_path = config_dir.join("runtime-delegations.json");
    if deleg_path.exists() {
        let (active, expired) = colmena_core::delegate::load_delegations_with_expired(&deleg_path);
        checks.push(Check::ok(
            CAT,
            "Delegations",
            format!("{} active, {} expired", active.len(), expired.len()),
        ));
    } else {
        checks.push(Check::ok(CAT, "Delegations", "no file (0 active)"));
    }

    // Audit log
    let audit_path = config_dir.join("audit.log");
    if audit_path.exists() {
        match std::fs::metadata(&audit_path) {
            Ok(meta) => {
                let size_kb = meta.len() / 1024;
                if size_kb > 5120 {
                    checks.push(Check::warn(
                        CAT,
                        "Audit log",
                        format!("{} KB (>5 MB, consider rotation)", size_kb),
                    ));
                } else {
                    checks.push(Check::ok(CAT, "Audit log", format!("{} KB", size_kb)));
                }
            }
            Err(e) => checks.push(Check::warn(CAT, "Audit log", format!("cannot stat: {e}"))),
        }
    } else {
        checks.push(Check::ok(CAT, "Audit log", "not yet created"));
    }

    // ELO events
    let elo_path = config_dir.join("elo-events.jsonl");
    if elo_path.exists() {
        match colmena_core::elo::read_elo_log(&elo_path) {
            Ok(events) => checks.push(Check::ok(CAT, "ELO events", format!("{} events", events.len()))),
            Err(e) => checks.push(Check::warn(CAT, "ELO events", format!("parse error: {e}"))),
        }
    } else {
        checks.push(Check::ok(CAT, "ELO events", "not yet created"));
    }

    // ELO overrides
    let overrides_path = config_dir.join("elo-overrides.json");
    if overrides_path.exists() {
        let overrides = colmena_core::calibrate::load_overrides(&overrides_path);
        checks.push(Check::ok(CAT, "ELO overrides", format!("{} agents", overrides.len())));
    } else {
        checks.push(Check::ok(CAT, "ELO overrides", "no file (0 overrides)"));
    }

    // Queue pending
    match colmena_core::queue::list_pending(config_dir) {
        Ok(pending) => checks.push(Check::ok(CAT, "Queue", format!("{} pending", pending.len()))),
        Err(_) => checks.push(Check::ok(CAT, "Queue", "0 pending")),
    }

    // Filter stats
    let stats_path = config_dir.join("filter-stats.jsonl");
    if stats_path.exists() {
        match std::fs::metadata(&stats_path) {
            Ok(meta) => {
                let size_kb = meta.len() / 1024;
                checks.push(Check::ok(CAT, "Filter stats", format!("{} KB", size_kb)));
            }
            Err(e) => checks.push(Check::warn(CAT, "Filter stats", format!("cannot stat: {e}"))),
        }
    } else {
        checks.push(Check::ok(CAT, "Filter stats", "not yet created"));
    }

    checks
}

// ── 7. Permissions ──────────────────────────────────────────────────────────

fn check_permissions(config_dir: &Path) -> Vec<Check> {
    const CAT: &str = "Permissions";
    let mut checks = Vec::new();

    let warnings = colmena_core::config::check_config_permissions(config_dir);
    if warnings.is_empty() {
        checks.push(Check::ok(CAT, "Config file permissions", "no issues"));
    } else {
        for w in &warnings {
            checks.push(Check::warn(CAT, "File permission", w.clone()));
        }
    }

    checks
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_check_config_valid() {
        let tmp = TempDir::new().unwrap();
        let config_dir = tmp.path();

        // Copy the real firewall config for a valid test
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("config/trust-firewall.yaml");
        std::fs::copy(&src, config_dir.join("trust-firewall.yaml")).unwrap();

        let checks = check_config(config_dir);
        let firewall_check = checks.iter().find(|c| c.name == "trust-firewall.yaml").unwrap();
        assert!(
            matches!(firewall_check.status, Status::Ok(_)),
            "expected OK for valid firewall config"
        );
    }

    #[test]
    fn test_check_config_missing() {
        let tmp = TempDir::new().unwrap();
        let checks = check_config(tmp.path());
        let firewall_check = checks.iter().find(|c| c.name == "trust-firewall.yaml").unwrap();
        assert!(
            matches!(firewall_check.status, Status::Err(_)),
            "expected ERR for missing firewall config"
        );
    }

    #[test]
    fn test_check_config_invalid_yaml() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("trust-firewall.yaml"), "{{{{not yaml").unwrap();
        let checks = check_config(tmp.path());
        let firewall_check = checks.iter().find(|c| c.name == "trust-firewall.yaml").unwrap();
        assert!(
            matches!(firewall_check.status, Status::Err(_)),
            "expected ERR for invalid YAML"
        );
    }

    #[test]
    fn test_check_library_valid() {
        let tmp = TempDir::new().unwrap();
        let lib_dir = tmp.path().join("library");
        std::fs::create_dir_all(lib_dir.join("roles")).unwrap();
        std::fs::create_dir_all(lib_dir.join("patterns")).unwrap();

        let checks = check_library(tmp.path());
        let lib_check = checks.iter().find(|c| c.name == "Roles & patterns").unwrap();
        assert!(
            matches!(lib_check.status, Status::Ok(_)),
            "expected OK for empty but valid library"
        );
    }

    #[test]
    fn test_check_library_missing() {
        let tmp = TempDir::new().unwrap();
        let checks = check_library(tmp.path());
        let lib_check = checks.iter().find(|c| c.name == "Library directory").unwrap();
        assert!(
            matches!(lib_check.status, Status::Err(_)),
            "expected ERR for missing library dir"
        );
    }

    #[test]
    fn test_check_runtime_empty() {
        let tmp = TempDir::new().unwrap();
        let checks = check_runtime(tmp.path());
        // All should be OK (not ERR) when files don't exist yet
        for c in &checks {
            assert!(
                !matches!(c.status, Status::Err(_)),
                "check '{}' should not be ERR on fresh install",
                c.name
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_check_permissions_world_writable() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let file = tmp.path().join("trust-firewall.yaml");
        std::fs::write(&file, "defaults: { action: ask }").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).unwrap();

        let checks = check_permissions(tmp.path());
        let has_warn = checks.iter().any(|c| matches!(c.status, Status::Warn(_)));
        assert!(has_warn, "expected WARN for world-writable file");
    }

    #[test]
    fn test_has_colmena_hook_new_format() {
        let settings: serde_json::Value = serde_json::json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": "",
                    "hooks": [{
                        "type": "command",
                        "command": "/usr/bin/colmena hook --config /etc/colmena.yaml"
                    }]
                }]
            }
        });
        assert!(has_colmena_hook(&settings, "PreToolUse"));
        assert!(!has_colmena_hook(&settings, "PostToolUse"));
    }

    #[test]
    fn test_has_colmena_hook_legacy_format() {
        let settings: serde_json::Value = serde_json::json!({
            "hooks": {
                "PostToolUse": [{
                    "matcher": "",
                    "command": "/usr/bin/colmena hook --config /etc/colmena.yaml"
                }]
            }
        });
        assert!(has_colmena_hook(&settings, "PostToolUse"));
    }

    #[test]
    fn test_has_colmena_hook_missing() {
        let settings: serde_json::Value = serde_json::json!({});
        assert!(!has_colmena_hook(&settings, "PreToolUse"));
    }
}
