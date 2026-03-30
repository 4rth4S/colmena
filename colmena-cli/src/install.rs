use std::path::PathBuf;

use anyhow::{Context, Result};
use serde_json::{json, Value};

/// Register colmena as a PreToolUse hook in ~/.claude/settings.json.
/// Preserves all existing content (hooks, env, plugins, statusLine, etc).
pub fn run_install() -> Result<()> {
    let settings_path = settings_json_path();

    println!("Installing colmena hook into {}", settings_path.display());

    // Read existing settings or start with empty object
    let mut settings: Value = if settings_path.exists() {
        let contents = std::fs::read_to_string(&settings_path)
            .with_context(|| format!("Failed to read {}", settings_path.display()))?;
        serde_json::from_str(&contents)
            .with_context(|| format!("Failed to parse {}", settings_path.display()))?
    } else {
        json!({})
    };

    // Resolve binary and config paths
    let binary_path = colmena_binary_path();
    let config_path = colmena_config_path();
    let hook_command = format!("{} hook --config {}", binary_path, config_path);

    // Ensure hooks object exists
    let hooks = settings
        .as_object_mut()
        .context("settings.json root must be an object")?
        .entry("hooks")
        .or_insert_with(|| json!({}));

    let hooks_obj = hooks
        .as_object_mut()
        .context("hooks must be an object")?;

    // Ensure PreToolUse array exists
    let pre_tool_use = hooks_obj
        .entry("PreToolUse")
        .or_insert_with(|| json!([]));

    let arr = pre_tool_use
        .as_array_mut()
        .context("PreToolUse must be an array")?;

    // Check if colmena hook is already installed (check inside hooks arrays too)
    let already_installed = arr.iter().any(|entry| {
        // Check new format: { "matcher": "", "hooks": [{ "command": "..." }] }
        if let Some(inner_hooks) = entry.get("hooks").and_then(|h| h.as_array()) {
            inner_hooks.iter().any(|h| {
                h.get("command")
                    .and_then(|c| c.as_str())
                    .is_some_and(|c| c.contains("colmena hook"))
            })
        } else {
            // Check legacy format: { "matcher": "", "command": "..." }
            entry
                .get("command")
                .and_then(|c| c.as_str())
                .is_some_and(|c| c.contains("colmena hook"))
        }
    });

    if already_installed {
        println!("Colmena hook is already installed.");
        return Ok(());
    }

    // Add the hook entry (CC hooks format: matcher + hooks array)
    arr.push(json!({
        "matcher": "",
        "hooks": [
            {
                "type": "command",
                "command": hook_command
            }
        ]
    }));

    // Write back preserving formatting
    let json = serde_json::to_string_pretty(&settings)
        .context("Failed to serialize settings")?;

    // Ensure parent directory exists
    if let Some(parent) = settings_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    std::fs::write(&settings_path, json)
        .with_context(|| format!("Failed to write {}", settings_path.display()))?;

    println!("Hook installed successfully.");
    println!("  Command: {hook_command}");
    println!("\nBuild the release binary first: cargo build --release");

    // Verify the binary exists
    let binary = colmena_binary_path();
    let binary_path_buf = std::path::Path::new(&binary);
    if !binary_path_buf.exists() {
        eprintln!("WARNING: Binary not found at {binary}");
        eprintln!("  Run `cargo build --release` before using the hook.");
    } else {
        // Dry-run with a test payload
        let test_payload = r#"{"session_id":"verify","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"/tmp/test"},"tool_use_id":"verify","cwd":"/tmp"}"#;
        let config = colmena_config_path();
        match std::process::Command::new(&binary)
            .args(["hook", "--config", &config])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write as _;
                child.stdin.take().unwrap().write_all(test_payload.as_bytes()).unwrap();
                child.wait_with_output()
            }) {
            Ok(output) if output.status.success() => {
                println!("  Verification: hook dry-run passed.");
            }
            Ok(output) => {
                eprintln!("WARNING: Hook dry-run failed (exit {}).", output.status.code().unwrap_or(-1));
            }
            Err(e) => {
                eprintln!("WARNING: Could not run hook verification: {e}");
            }
        }
    }

    Ok(())
}

fn settings_json_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| {
        eprintln!("ERROR: HOME environment variable is not set.");
        std::process::exit(1);
    });
    PathBuf::from(home).join(".claude/settings.json")
}

fn colmena_binary_path() -> String {
    std::env::current_exe()
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| {
                eprintln!("ERROR: HOME environment variable is not set.");
                std::process::exit(1);
            });
            std::path::PathBuf::from(format!("{home}/colmena/target/release/colmena"))
        })
        .to_string_lossy()
        .to_string()
}

fn colmena_config_path() -> String {
    let exe = std::env::current_exe().unwrap_or_default();
    if let Some(target_dir) = exe.parent() {
        if let Some(target) = target_dir.parent() {
            if let Some(project_root) = target.parent() {
                let config = project_root.join("config/trust-firewall.yaml");
                if config.exists() {
                    return config.to_string_lossy().to_string();
                }
            }
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| {
        eprintln!("ERROR: HOME environment variable is not set.");
        std::process::exit(1);
    });
    format!("{home}/colmena/config/trust-firewall.yaml")
}
