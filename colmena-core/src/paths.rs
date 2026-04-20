use std::path::PathBuf;

/// Resolve the colmena home directory.
/// Priority: COLMENA_HOME env > directory containing the running binary > ~/colmena fallback
pub fn colmena_home() -> PathBuf {
    if let Ok(home) = std::env::var("COLMENA_HOME") {
        return PathBuf::from(home);
    }
    if let Ok(exe) = std::env::current_exe() {
        // Binary is at <colmena_home>/target/{release,debug}/colmena
        if let Some(target_dir) = exe.parent() {
            if let Some(target) = target_dir.parent() {
                if let Some(project_root) = target.parent() {
                    if project_root.join("config/trust-firewall.yaml").exists() {
                        return project_root.to_path_buf();
                    }
                }
            }
        }
    }
    // Fix 10 (DREAD 7.2): fail explicitly if HOME is not set instead of falling back to /tmp
    let home = std::env::var("HOME").unwrap_or_else(|_| {
        eprintln!("ERROR: HOME environment variable is not set. Set HOME or COLMENA_HOME.");
        std::process::exit(1);
    });
    PathBuf::from(home).join("colmena")
}

/// Default config directory: <colmena_home>/config
pub fn default_config_dir() -> PathBuf {
    colmena_home().join("config")
}

/// Return the target directory for Claude Code subagent files.
///
/// Precedence:
/// 1. `COLMENA_AGENTS_DIR` env var (testing, custom setups)
/// 2. `$HOME/.claude/agents/`
///
/// Errors if `HOME` is unset (per CLAUDE.md: fallback to /tmp is banned).
pub fn default_agents_dir() -> anyhow::Result<std::path::PathBuf> {
    if let Ok(override_dir) = std::env::var("COLMENA_AGENTS_DIR") {
        return Ok(std::path::PathBuf::from(override_dir));
    }
    let home = std::env::var("HOME").map_err(|_| {
        anyhow::anyhow!("HOME env var not set — cannot resolve subagents directory")
    })?;
    Ok(std::path::PathBuf::from(home)
        .join(".claude")
        .join("agents"))
}

#[cfg(test)]
mod default_agents_dir_tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_default_agents_dir_uses_override() {
        // Use a unique override path for this test to avoid leaking state
        let override_path = "/tmp/colmena-agents-dir-test-a1b2c3";
        std::env::set_var("COLMENA_AGENTS_DIR", override_path);
        let result = default_agents_dir().unwrap();
        assert_eq!(result, PathBuf::from(override_path));
        std::env::remove_var("COLMENA_AGENTS_DIR");
    }

    #[test]
    fn test_default_agents_dir_falls_back_to_home() {
        std::env::remove_var("COLMENA_AGENTS_DIR");
        std::env::set_var("HOME", "/tmp/fake-home-xyz");
        let result = default_agents_dir().unwrap();
        assert_eq!(result, PathBuf::from("/tmp/fake-home-xyz/.claude/agents"));
    }
}
