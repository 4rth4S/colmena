use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::defaults;

// ── Runtime files that setup must NEVER touch ────────────────────────────────
const RUNTIME_FILES: &[&str] = &[
    "audit.log",
    "runtime-delegations.json",
    "elo-overrides.json",
    "filter-stats.jsonl",
    "elo-events.jsonl",
    "revoked-missions.json",
    "queue",
    "missions",
];

// ── Directories to create under config_dir ───────────────────────────────────
const ENSURE_DIRS: &[&str] = &[
    "library/roles",
    "library/patterns",
    "library/prompts",
    "queue/pending",
    "queue/decided",
];

// ── Mode detection ───────────────────────────────────────────────────────────

enum SetupMode {
    Repo { project_root: PathBuf },
    Standalone,
}

/// Walk up from current_exe() looking for a workspace Cargo.toml containing colmena-core.
fn detect_mode() -> SetupMode {
    if let Ok(exe) = std::env::current_exe() {
        let mut dir = exe.as_path().parent();
        while let Some(d) = dir {
            let cargo_toml = d.join("Cargo.toml");
            if cargo_toml.exists() {
                if let Ok(contents) = std::fs::read_to_string(&cargo_toml) {
                    if contents.contains("[workspace]") && contents.contains("colmena-core") {
                        return SetupMode::Repo {
                            project_root: d.to_path_buf(),
                        };
                    }
                }
            }
            dir = d.parent();
        }
    }
    SetupMode::Standalone
}

// ── Config directory resolution ──────────────────────────────────────────────

fn resolve_config_dir(mode: &SetupMode) -> PathBuf {
    if let Ok(home) = std::env::var("COLMENA_HOME") {
        return PathBuf::from(home).join("config");
    }
    match mode {
        SetupMode::Repo { project_root } => project_root.join("config"),
        SetupMode::Standalone => {
            let home = std::env::var("HOME").unwrap_or_else(|_| {
                eprintln!("ERROR: HOME environment variable is not set. Set HOME or COLMENA_HOME.");
                std::process::exit(1);
            });
            PathBuf::from(home).join(".colmena/config")
        }
    }
}

// ── File merge logic ─────────────────────────────────────────────────────────

#[derive(Debug, PartialEq)]
enum CopyResult {
    Created,
    UpToDate,
    PreservedCustom,
    Overwritten,
}

impl std::fmt::Display for CopyResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CopyResult::Created => write!(f, "created"),
            CopyResult::UpToDate => write!(f, "up-to-date"),
            CopyResult::PreservedCustom => write!(f, "preserved"),
            CopyResult::Overwritten => write!(f, "overwritten"),
        }
    }
}

fn ensure_file(
    target_path: &Path,
    default_content: &str,
    defaults_backup_dir: &Path,
    rel_path: &str,
    dry_run: bool,
    force: bool,
) -> Result<CopyResult> {
    if target_path.exists() {
        let existing = std::fs::read_to_string(target_path)
            .with_context(|| format!("Failed to read {}", target_path.display()))?;

        if existing == default_content {
            return Ok(CopyResult::UpToDate);
        }

        if force {
            if !dry_run {
                atomic_write(target_path, default_content)?;
            }
            return Ok(CopyResult::Overwritten);
        }

        // Preserve custom file, save default to .defaults/ for reference
        if !dry_run {
            let backup_path = defaults_backup_dir.join(rel_path);
            if let Some(parent) = backup_path.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("Failed to create dir {}", parent.display()))?;
            }
            atomic_write(&backup_path, default_content)?;
        }
        return Ok(CopyResult::PreservedCustom);
    }

    // File does not exist — create it
    if !dry_run {
        if let Some(parent) = target_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create dir {}", parent.display()))?;
        }
        atomic_write(target_path, default_content)?;
    }
    Ok(CopyResult::Created)
}

/// Atomic write: temp file in same directory + rename.
fn atomic_write(path: &Path, content: &str) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)
        .with_context(|| format!("Failed to create dir {}", parent.display()))?;

    let temp_path = parent.join(format!(
        ".colmena-setup-{}.tmp",
        std::process::id()
    ));
    std::fs::write(&temp_path, content)
        .with_context(|| format!("Failed to write temp file {}", temp_path.display()))?;
    std::fs::rename(&temp_path, path).with_context(|| {
        format!(
            "Failed to rename {} -> {}",
            temp_path.display(),
            path.display()
        )
    })?;
    Ok(())
}

fn ensure_config_dir(config_dir: &Path, dry_run: bool) -> Result<()> {
    for sub in ENSURE_DIRS {
        let dir = config_dir.join(sub);
        if !dir.exists() {
            if dry_run {
                println!("  [would create] directory: {}", dir.display());
            } else {
                std::fs::create_dir_all(&dir)
                    .with_context(|| format!("Failed to create dir {}", dir.display()))?;
            }
        }
    }
    Ok(())
}

// ── MCP registration ─────────────────────────────────────────────────────────

fn mcp_json_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| {
        eprintln!("ERROR: HOME environment variable is not set.");
        std::process::exit(1);
    });
    PathBuf::from(home).join(".mcp.json")
}

fn find_mcp_binary() -> Option<PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let mcp_path = dir.join("colmena-mcp");
            if mcp_path.exists() {
                return Some(mcp_path);
            }
        }
    }
    None
}

fn register_mcp(dry_run: bool) -> Result<McpResult> {
    let mcp_binary = match find_mcp_binary() {
        Some(path) => path,
        None => {
            eprintln!("WARNING: colmena-mcp binary not found next to colmena binary.");
            eprintln!("  MCP registration skipped. Build with: cargo build --workspace --release");
            return Ok(McpResult::BinaryNotFound);
        }
    };

    let mcp_path = mcp_json_path();
    let mcp_binary_str = mcp_binary.to_string_lossy().to_string();

    if dry_run {
        println!("  [would register] MCP server in {}", mcp_path.display());
        println!("    binary: {mcp_binary_str}");
        return Ok(McpResult::Registered);
    }

    let mut mcp_config: serde_json::Value = if mcp_path.exists() {
        let contents = std::fs::read_to_string(&mcp_path)
            .with_context(|| format!("Failed to read {}", mcp_path.display()))?;
        serde_json::from_str(&contents)
            .with_context(|| format!("Failed to parse {}", mcp_path.display()))?
    } else {
        serde_json::json!({"mcpServers": {}})
    };

    let servers = mcp_config
        .as_object_mut()
        .context("~/.mcp.json root must be an object")?
        .entry("mcpServers")
        .or_insert_with(|| serde_json::json!({}));

    let servers_obj = servers
        .as_object_mut()
        .context("mcpServers must be an object")?;

    // Check if already registered with same path
    if let Some(existing) = servers_obj.get("colmena") {
        if let Some(cmd) = existing.get("command").and_then(|c| c.as_str()) {
            if cmd == mcp_binary_str {
                return Ok(McpResult::AlreadyRegistered);
            }
        }
    }

    servers_obj.insert(
        "colmena".to_string(),
        serde_json::json!({
            "command": mcp_binary_str,
            "args": [],
            "type": "stdio"
        }),
    );

    let json = serde_json::to_string_pretty(&mcp_config)
        .context("Failed to serialize MCP config")?;

    atomic_write(&mcp_path, &json)?;

    Ok(McpResult::Registered)
}

#[derive(Debug, PartialEq)]
enum McpResult {
    Registered,
    AlreadyRegistered,
    BinaryNotFound,
}

// ── Verification ─────────────────────────────────────────────────────────────

struct VerifyResult {
    check: &'static str,
    status: VerifyStatus,
}

#[derive(Debug)]
enum VerifyStatus {
    Ok(String),
    Warning(String),
    Error(String),
}

fn verify_setup(config_dir: &Path) -> Vec<VerifyResult> {
    let mut results = Vec::new();

    // 1. Config validation
    let firewall_path = config_dir.join("trust-firewall.yaml");
    match colmena_core::config::load_config(&firewall_path, "/tmp/verify") {
        Ok(cfg) => {
            match colmena_core::config::compile_config(&cfg) {
                Ok(_) => {
                    results.push(VerifyResult {
                        check: "Config valid",
                        status: VerifyStatus::Ok(format!(
                            "{} trust_circle, {} restricted, {} blocked",
                            cfg.trust_circle.len(),
                            cfg.restricted.len(),
                            cfg.blocked.len()
                        )),
                    });
                }
                Err(e) => {
                    results.push(VerifyResult {
                        check: "Config valid",
                        status: VerifyStatus::Error(format!("regex compile failed: {e}")),
                    });
                }
            }
        }
        Err(e) => {
            results.push(VerifyResult {
                check: "Config valid",
                status: VerifyStatus::Error(format!("{e}")),
            });
        }
    }

    // 2. Library validation
    let library_dir = config_dir.join("library");
    match (
        colmena_core::library::load_roles(&library_dir),
        colmena_core::library::load_patterns(&library_dir),
    ) {
        (Ok(roles), Ok(patterns)) => {
            let warnings = colmena_core::library::validate_library(&roles, &patterns, &library_dir);
            if warnings.is_empty() {
                results.push(VerifyResult {
                    check: "Library valid",
                    status: VerifyStatus::Ok(format!(
                        "{} roles, {} patterns",
                        roles.len(),
                        patterns.len()
                    )),
                });
            } else {
                results.push(VerifyResult {
                    check: "Library valid",
                    status: VerifyStatus::Warning(format!(
                        "{} roles, {} patterns ({} warnings)",
                        roles.len(),
                        patterns.len(),
                        warnings.len()
                    )),
                });
            }
        }
        (Err(e), _) | (_, Err(e)) => {
            results.push(VerifyResult {
                check: "Library valid",
                status: VerifyStatus::Error(format!("{e}")),
            });
        }
    }

    // 3. Hook dry-run
    let binary_path = crate::install::colmena_binary_path();
    let binary = Path::new(&binary_path);
    if binary.exists() {
        let test_payload = r#"{"session_id":"verify","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"/tmp/test"},"tool_use_id":"verify","cwd":"/tmp"}"#;
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
                results.push(VerifyResult {
                    check: "Hook dry-run",
                    status: VerifyStatus::Ok("passed".to_string()),
                });
            }
            Ok(output) => {
                results.push(VerifyResult {
                    check: "Hook dry-run",
                    status: VerifyStatus::Warning(format!(
                        "exit {}",
                        output.status.code().unwrap_or(-1)
                    )),
                });
            }
            Err(e) => {
                results.push(VerifyResult {
                    check: "Hook dry-run",
                    status: VerifyStatus::Warning(format!("could not run: {e}")),
                });
            }
        }
    } else {
        results.push(VerifyResult {
            check: "Hook dry-run",
            status: VerifyStatus::Warning("binary not found, skipped".to_string()),
        });
    }

    // 4. MCP binary exists
    match find_mcp_binary() {
        Some(path) => {
            results.push(VerifyResult {
                check: "MCP binary",
                status: VerifyStatus::Ok(format!("found at {}", path.display())),
            });
        }
        None => {
            results.push(VerifyResult {
                check: "MCP binary",
                status: VerifyStatus::Warning("not found next to colmena binary".to_string()),
            });
        }
    }

    results
}

// ── Summary printing ─────────────────────────────────────────────────────────

fn print_summary(
    dry_run: bool,
    mode: &SetupMode,
    config_dir: &Path,
    file_results: &[(&str, CopyResult)],
    hooks_ok: bool,
    mcp_result: &McpResult,
    verify_results: &[VerifyResult],
) {
    println!();
    if dry_run {
        println!("[DRY RUN] Colmena Setup Preview");
    } else {
        println!("Colmena Setup Complete");
    }
    println!("======================");

    match mode {
        SetupMode::Repo { project_root } => {
            println!("Mode:       repo ({})", project_root.display());
        }
        SetupMode::Standalone => {
            println!("Mode:       standalone");
        }
    }
    println!("Config dir: {}", config_dir.display());

    println!("\nFiles:");
    for (rel_path, result) in file_results {
        let extra = if *result == CopyResult::PreservedCustom {
            " (custom -> .defaults/)"
        } else {
            ""
        };
        println!("  [{result:<12}] {rel_path}{extra}");
    }

    println!();
    if hooks_ok {
        let settings_path = crate::install::settings_json_path();
        println!(
            "Hooks:   {} Pre/PostToolUse/PermissionRequest in {}",
            if dry_run { "~" } else { "ok" },
            settings_path.display()
        );
    } else {
        println!("Hooks:   skipped (dry-run)");
    }

    match mcp_result {
        McpResult::Registered => {
            println!(
                "MCP:     {} colmena-mcp in {}",
                if dry_run { "~" } else { "ok" },
                mcp_json_path().display()
            );
        }
        McpResult::AlreadyRegistered => {
            println!("MCP:     ok (already registered)");
        }
        McpResult::BinaryNotFound => {
            println!("MCP:     skipped (binary not found)");
        }
    }

    if !dry_run && !verify_results.is_empty() {
        println!("\nVerification:");
        for vr in verify_results {
            let (marker, detail) = match &vr.status {
                VerifyStatus::Ok(msg) => ("OK", msg.as_str()),
                VerifyStatus::Warning(msg) => ("WARN", msg.as_str()),
                VerifyStatus::Error(msg) => ("ERR", msg.as_str()),
            };
            println!("  [{marker:<4}] {} ({detail})", vr.check);
        }
    }

    println!();
    if dry_run {
        println!("Run without --dry-run to apply changes.");
    } else {
        println!("Ready! Restart Claude Code to pick up MCP server.");
    }
}

// ── Entry point ──────────────────────────────────────────────────────────────

pub fn run_setup(dry_run: bool, force: bool) -> Result<()> {
    if dry_run {
        println!("[DRY RUN] Simulating setup (no files will be modified)...\n");
    }

    // Step 1: Detect mode
    let mode = detect_mode();
    match &mode {
        SetupMode::Repo { project_root } => {
            println!("Detected repo mode: {}", project_root.display());
        }
        SetupMode::Standalone => {
            println!("Detected standalone mode (no workspace found).");
        }
    }

    // Step 2: Resolve config directory
    let config_dir = resolve_config_dir(&mode);
    println!("Config directory: {}\n", config_dir.display());

    // Step 3: Ensure directory structure
    ensure_config_dir(&config_dir, dry_run)?;

    // Step 3b: Copy/merge default files
    let defaults = defaults::all_defaults();
    let defaults_backup_dir = config_dir.join(".defaults");
    let mut file_results: Vec<(&str, CopyResult)> = Vec::new();

    for df in &defaults {
        // Skip runtime files (should never happen with embedded defaults, but defensive)
        if RUNTIME_FILES.iter().any(|rf| df.rel_path.starts_with(rf)) {
            continue;
        }

        let target_path = config_dir.join(df.rel_path);
        let result = ensure_file(
            &target_path,
            df.content,
            &defaults_backup_dir,
            df.rel_path,
            dry_run,
            force,
        )?;

        if dry_run {
            match &result {
                CopyResult::Created => {
                    println!("  [would create] {}", df.rel_path);
                }
                CopyResult::UpToDate => {
                    println!("  [up-to-date]   {}", df.rel_path);
                }
                CopyResult::PreservedCustom => {
                    println!(
                        "  [would preserve] {} (custom, default -> .defaults/)",
                        df.rel_path
                    );
                }
                CopyResult::Overwritten => {
                    println!("  [would overwrite] {}", df.rel_path);
                }
            }
        }

        file_results.push((df.rel_path, result));
    }

    // Step 4: Register hooks
    let hooks_ok;
    if dry_run {
        println!("\n  [would register] Pre/PostToolUse/PermissionRequest hooks in ~/.claude/settings.json");
        hooks_ok = false;
    } else {
        println!("\nRegistering hooks...");
        match crate::install::run_install() {
            Ok(()) => {
                hooks_ok = true;
            }
            Err(e) => {
                eprintln!("WARNING: Hook registration failed: {e}");
                hooks_ok = false;
            }
        }
    }

    // Step 5: Register MCP server
    let mcp_result = register_mcp(dry_run)?;

    // Step 6: Verify setup (skip in dry-run)
    let verify_results = if dry_run {
        Vec::new()
    } else {
        verify_setup(&config_dir)
    };

    // Step 7: Print summary
    print_summary(
        dry_run,
        &mode,
        &config_dir,
        &file_results,
        hooks_ok,
        &mcp_result,
        &verify_results,
    );

    Ok(())
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ensure_file_creates_new() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("test.yaml");
        let backup_dir = dir.path().join(".defaults");
        let content = "key: value\n";

        let result = ensure_file(&target, content, &backup_dir, "test.yaml", false, false).unwrap();

        assert_eq!(result, CopyResult::Created);
        assert_eq!(std::fs::read_to_string(&target).unwrap(), content);
    }

    #[test]
    fn test_ensure_file_up_to_date() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("test.yaml");
        let backup_dir = dir.path().join(".defaults");
        let content = "key: value\n";

        std::fs::write(&target, content).unwrap();

        let result = ensure_file(&target, content, &backup_dir, "test.yaml", false, false).unwrap();

        assert_eq!(result, CopyResult::UpToDate);
    }

    #[test]
    fn test_ensure_file_preserves_custom() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("test.yaml");
        let backup_dir = dir.path().join(".defaults");
        let custom_content = "key: custom_value\n";
        let default_content = "key: default_value\n";

        std::fs::write(&target, custom_content).unwrap();

        let result =
            ensure_file(&target, default_content, &backup_dir, "test.yaml", false, false).unwrap();

        assert_eq!(result, CopyResult::PreservedCustom);
        // Custom file preserved
        assert_eq!(std::fs::read_to_string(&target).unwrap(), custom_content);
        // Default saved to .defaults/
        let backup_path = backup_dir.join("test.yaml");
        assert!(backup_path.exists());
        assert_eq!(
            std::fs::read_to_string(&backup_path).unwrap(),
            default_content
        );
    }

    #[test]
    fn test_ensure_file_force_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("test.yaml");
        let backup_dir = dir.path().join(".defaults");
        let custom_content = "key: custom_value\n";
        let default_content = "key: default_value\n";

        std::fs::write(&target, custom_content).unwrap();

        let result =
            ensure_file(&target, default_content, &backup_dir, "test.yaml", false, true).unwrap();

        assert_eq!(result, CopyResult::Overwritten);
        assert_eq!(std::fs::read_to_string(&target).unwrap(), default_content);
    }

    #[test]
    fn test_ensure_file_dry_run_no_write() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("test.yaml");
        let backup_dir = dir.path().join(".defaults");
        let content = "key: value\n";

        let result = ensure_file(&target, content, &backup_dir, "test.yaml", true, false).unwrap();

        assert_eq!(result, CopyResult::Created);
        // File should NOT exist — dry run
        assert!(!target.exists());
    }

    #[test]
    fn test_runtime_files_never_touched() {
        let defaults = defaults::all_defaults();
        for df in &defaults {
            for rf in RUNTIME_FILES {
                assert!(
                    !df.rel_path.starts_with(rf),
                    "Default file '{}' overlaps with runtime file '{}'",
                    df.rel_path,
                    rf
                );
            }
        }
    }

    #[test]
    fn test_register_mcp_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let mcp_path = dir.path().join(".mcp.json");

        // Simulate new MCP file creation
        let config = serde_json::json!({
            "mcpServers": {
                "colmena": {
                    "command": "/usr/local/bin/colmena-mcp",
                    "args": [],
                    "type": "stdio"
                }
            }
        });

        let json = serde_json::to_string_pretty(&config).unwrap();
        atomic_write(&mcp_path, &json).unwrap();

        let parsed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&mcp_path).unwrap()).unwrap();
        assert!(parsed["mcpServers"]["colmena"]["command"]
            .as_str()
            .unwrap()
            .contains("colmena-mcp"));
    }

    #[test]
    fn test_register_mcp_merge_existing() {
        let dir = tempfile::tempdir().unwrap();
        let mcp_path = dir.path().join(".mcp.json");

        // Write existing config with another server
        let existing = serde_json::json!({
            "mcpServers": {
                "other-tool": {
                    "command": "/usr/local/bin/other-tool",
                    "args": [],
                    "type": "stdio"
                }
            }
        });
        std::fs::write(&mcp_path, serde_json::to_string_pretty(&existing).unwrap()).unwrap();

        // Merge colmena into it
        let mut config: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&mcp_path).unwrap()).unwrap();
        let servers = config["mcpServers"].as_object_mut().unwrap();
        servers.insert(
            "colmena".to_string(),
            serde_json::json!({
                "command": "/usr/local/bin/colmena-mcp",
                "args": [],
                "type": "stdio"
            }),
        );
        atomic_write(
            &mcp_path,
            &serde_json::to_string_pretty(&config).unwrap(),
        )
        .unwrap();

        let parsed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&mcp_path).unwrap()).unwrap();
        // Both servers present
        assert!(parsed["mcpServers"]["other-tool"]["command"]
            .as_str()
            .is_some());
        assert!(parsed["mcpServers"]["colmena"]["command"]
            .as_str()
            .is_some());
    }

    #[test]
    fn test_register_mcp_already_registered() {
        let dir = tempfile::tempdir().unwrap();
        let mcp_path = dir.path().join(".mcp.json");

        let config = serde_json::json!({
            "mcpServers": {
                "colmena": {
                    "command": "/usr/local/bin/colmena-mcp",
                    "args": [],
                    "type": "stdio"
                }
            }
        });
        std::fs::write(&mcp_path, serde_json::to_string_pretty(&config).unwrap()).unwrap();

        // Re-read and check — no mutation needed
        let parsed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&mcp_path).unwrap()).unwrap();
        let existing_cmd = parsed["mcpServers"]["colmena"]["command"]
            .as_str()
            .unwrap();
        assert_eq!(existing_cmd, "/usr/local/bin/colmena-mcp");
    }
}
